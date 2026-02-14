"""
Cloud Function entry point for Email Threat Scorer.

Receives extracted email data from the Gmail Add-on,
runs it through analysis modules, and returns a risk score
with per-signal explainability.
"""

import os
import json
import functions_framework

from analyzers import (
    analyze_sender,
    analyze_headers,
    analyze_content,
    analyze_links,
    analyze_attachments,
    assess_trust_level
)
from scoring import compute_score

# Shared secret for request authentication.
# Stored as env var in Cloud Function config — never hardcoded.
# In production you'd use IAM or OAuth. This is a deliberate simplification.
API_SECRET = os.environ.get("API_SECRET", "dev-secret-key")
SAFE_BROWSING_KEY = os.environ.get("SAFE_BROWSING_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_KEY", "")


@functions_framework.http
def analyze_email(request):
    """
    HTTP entry point. Expects a POST with JSON body containing
    extracted email data from the Apps Script frontend.

    Returns JSON with score, verdict, and full signal breakdown.
    """

    # ── CORS preflight (needed for Apps Script UrlFetchApp) ──
    if request.method == "OPTIONS":
        return ("", 204, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST",
            "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
            "Access-Control-Max-Age": "3600"
        })

    cors_headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
    }

    # ── Auth check ──
    api_key = request.headers.get("X-API-Key", "")
    if api_key != API_SECRET:
        return (json.dumps({"error": "unauthorized"}), 401, cors_headers)

    # ── Parse request ──
    try:
        data = request.get_json(force=True)
    except Exception:
        return (json.dumps({"error": "invalid JSON body"}), 400, cors_headers)

    if not data or "from" not in data:
        return (json.dumps({"error": "missing required email data"}), 400, cors_headers)

    # ── Run all analyzers ──
    header_result = analyze_headers(data)
    results = {
        "sender":      analyze_sender(data),
        "headers":     header_result,
        "content":     analyze_content(data),
        "links":       analyze_links(data, SAFE_BROWSING_KEY),
        "attachments": analyze_attachments(data, VIRUSTOTAL_KEY)
    }

    # ── Trust assessment — reduces false positives for verified senders ──
    trust = assess_trust_level(data, header_result)

    # ── Blacklist check (sent from frontend, user-specific) ──
    blacklisted = data.get("blacklisted", False)
    blacklist_match = data.get("blacklistMatch", None)

    # ── Sender history (from frontend scan log) ──
    sender_history = data.get("senderHistory", None)

    # ── Score and verdict ──
    score, verdict, breakdown = compute_score(
        results, blacklisted, blacklist_match, trust, sender_history
    )

    response = {
        "score": score,
        "verdict": verdict,
        "breakdown": breakdown
    }

    return (json.dumps(response), 200, cors_headers)
