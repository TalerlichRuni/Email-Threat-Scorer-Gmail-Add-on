"""
Scoring engine for Email Threat Scorer.

Takes results from all analyzers and produces a final risk score (0-100)
with a human-readable verdict and per-category breakdown.

Design: weighted linear sum with trust-aware dampening.
Each analyzer returns a normalized score (0.0-1.0), multiplied by its weight.
If the sender is a verified trusted source (passes auth + known domain),
content and sender scores are dampened to reduce false positives.

This is intentionally simple and fully transparent.
A production system would use ML — but for an MVP, linear scoring
with trust context maximizes explainability.
"""

# Signal weights — sum to 100.
# Weights reflect how deeply we actually analyze each category.
# Content gets the most because we do the deepest analysis (7 attack
# categories, regex patterns, multi-category detection).
# Links and attachments both use external API enrichment (Safe Browsing
# and VirusTotal respectively) so they carry real detection weight.
WEIGHTS = {
    "sender":      15,   # From/Reply-To anomalies, impersonation, lookalike domains
    "headers":     15,   # SPF, DKIM, DMARC authentication
    "content":     25,   # Social engineering language patterns (deepest analysis)
    "links":       25,   # URL reputation via Safe Browsing + pattern analysis
    "attachments": 20,   # Metadata + VirusTotal hash reputation check
}

VERDICT_THRESHOLDS = [
    (20,  "Safe"),
    (50,  "Suspicious"),
    (100, "Malicious"),
]

BLACKLIST_PENALTY = 50

# If an external threat intelligence API (Safe Browsing or VirusTotal)
# flags a URL or attachment, we add a flat penalty on top of the normal
# weighted score. These APIs have high confidence — if they say it's bad,
# it's almost certainly bad. This guarantees at least a "Suspicious" verdict.
EXTERNAL_API_THREAT_PENALTY = 60

# Categories dampened when sender is trusted.
# Links, attachments, and content are NOT dampened — a compromised
# legit account could still send phishing language and malicious links.
# Only sender reputation and header analysis are reduced, since those
# are the signals that authenticated senders legitimately satisfy.
TRUST_DAMPENED_CATEGORIES = {"sender", "headers"}

# Dampening factors by trust level.
# "high" = all auth passed + known domain → reduce sender/content/header scores by 50%
# "medium" = all auth passed but unknown domain → reduce by 25%
# "self" = user's own sent email → reduce by 40%
# These are intentionally moderate — we'd rather flag a legitimate email
# than miss a real threat. Trust is a hint, not a bypass.
TRUST_DAMPENING = {
    "high": 0.5,
    "medium": 0.75,
    "self": 0.6,
    "none": 1.0,
}


def compute_score(results, blacklisted=False, blacklist_match=None, trust=None,
                   sender_history=None):
    """
    Compute final risk score from analyzer outputs.

    Args:
        results: dict mapping analyzer name -> {"score": float, "signals": list}
        blacklisted: bool — whether sender is on user's personal blacklist
        blacklist_match: dict with matchType and matchValue, or None
        trust: dict with "level" and "reason" from assess_trust_level(), or None

    Returns:
        (score, verdict, breakdown) where:
        - score: int 0-100
        - verdict: "Safe" | "Suspicious" | "Malicious"
        - breakdown: list of per-category contribution details
    """
    trust_level = trust.get("level", "none") if trust else "none"
    trust_reason = trust.get("reason", "") if trust else ""
    dampen_factor = TRUST_DAMPENING.get(trust_level, 1.0)

    # ── Dynamic weight redistribution ──
    # If a category has no data to analyze (no links, no attachments, empty body),
    # its weight is 0 and the freed points go to active categories — mainly content.
    NO_DATA_MARKERS = {"no links", "no attachments", "empty email"}
    empty_categories = set()
    for cat_name in ("links", "attachments", "content"):
        result = results.get(cat_name, {})
        signals = result.get("signals", [])
        if result.get("score", 0) == 0 and all(s.get("severity") == "info" for s in signals):
            for s in signals:
                if any(marker in s.get("description", "").lower() for marker in NO_DATA_MARKERS):
                    empty_categories.add(cat_name)
                    break

    effective_weights = dict(WEIGHTS)
    if empty_categories:
        freed = sum(WEIGHTS[c] for c in empty_categories)
        for c in empty_categories:
            effective_weights[c] = 0

        active = [c for c in WEIGHTS if c not in empty_categories]
        if active:
            # 60% of freed weight goes to content (if active), rest split proportionally
            content_bonus = 0
            if "content" in active:
                content_bonus = round(freed * 0.6)
                effective_weights["content"] += content_bonus

            remaining = freed - content_bonus
            other_active = [c for c in active if c != "content"]
            if other_active:
                per_cat = round(remaining / len(other_active))
                for c in other_active:
                    effective_weights[c] += per_cat

    breakdown = []
    total = 0.0

    for category, base_weight in WEIGHTS.items():
        weight = effective_weights[category]
        result = results.get(category, {"score": 0.0, "signals": []})
        raw = result.get("score", 0.0)

        # Apply trust dampening to applicable categories
        if category in TRUST_DAMPENED_CATEGORIES and dampen_factor < 1.0:
            effective_score = raw * dampen_factor
        else:
            effective_score = raw

        contribution = round(effective_score * weight, 1)
        total += contribution

        actionable = [s for s in result.get("signals", []) if s.get("severity") != "info"]
        info_signals = [s for s in result.get("signals", []) if s.get("severity") == "info"]

        breakdown.append({
            "category": category,
            "weight": weight,
            "raw_score": round(raw, 2),
            "contribution": contribution,
            "max_possible": weight,
            "signals": actionable,
            "info": info_signals,
        })

    # ── External API threat override ──
    # If Safe Browsing or VirusTotal flagged something as malicious,
    # add a flat penalty to guarantee at least "Suspicious" verdict.
    # These are high-confidence external signals — not heuristics.
    api_threats = []
    for cat_name in ("links", "attachments"):
        result = results.get(cat_name, {"signals": []})
        for sig in result.get("signals", []):
            desc = sig.get("description", "").lower()
            if sig.get("severity") == "critical":
                if "safe browsing" in desc or "virustotal" in desc:
                    api_threats.append(sig.get("description", ""))

    if api_threats:
        total += EXTERNAL_API_THREAT_PENALTY
        breakdown.append({
            "category": "threat_intel",
            "weight": 0,
            "raw_score": 0,
            "contribution": EXTERNAL_API_THREAT_PENALTY,
            "max_possible": EXTERNAL_API_THREAT_PENALTY,
            "signals": [{
                "description": "External threat intelligence confirmed malicious — automatic escalation (+{} pts)".format(
                    EXTERNAL_API_THREAT_PENALTY),
                "severity": "critical"
            }],
            "info": [{
                "description": t,
                "severity": "info"
            } for t in api_threats],
        })

    # ── Trust info — show in breakdown so user understands the dampening ──
    if trust_level != "none":
        breakdown.insert(0, {
            "category": "trust",
            "weight": 0,
            "raw_score": 0,
            "contribution": 0,
            "max_possible": 0,
            "signals": [],
            "info": [{
                "description": trust_reason,
                "severity": "info"
            }],
        })

    # ── History-based signals (repeat offender + baseline deviation) ──
    if sender_history:
        h_total = sender_history.get("totalScans", 0)
        h_avg = sender_history.get("avgScore", 0)
        h_flagged = sender_history.get("flaggedCount", 0)

        h_signals = []
        h_info = []
        h_penalty = 0

        # Signal A: Repeat offender — domain was flagged before
        if h_flagged >= 2:
            h_penalty = 8 if h_flagged < 4 else 15
            h_signals.append({
                "description": "Domain flagged {} time(s) in past scans (avg score: {})".format(
                    h_flagged, h_avg),
                "severity": "high" if h_flagged >= 4 else "medium"
            })

        # Signal B: Baseline deviation — normally safe sender acting suspicious
        # Requires at least 3 prior scans to establish a baseline
        if h_total >= 3 and h_avg < 15:
            current_raw = total  # score before history penalty
            deviation = round(current_raw - h_avg)
            if deviation >= 20:
                h_signals.append({
                    "description": "Score deviates +{} pts from sender baseline (avg: {}) — possible compromise".format(
                        deviation, h_avg),
                    "severity": "medium"
                })
                h_penalty = max(h_penalty, 5)

        # Always show history context as info if no actionable signals
        if not h_signals and h_total > 0:
            h_info.append({
                "description": "Sender scanned {} time(s) before (avg score: {})".format(
                    h_total, h_avg),
                "severity": "info"
            })

        if h_signals or h_info:
            total += h_penalty
            breakdown.append({
                "category": "history",
                "weight": 0,
                "raw_score": 0,
                "contribution": h_penalty,
                "max_possible": 0,
                "signals": h_signals,
                "info": h_info,
            })

    # ── Blacklist penalty — applied on top, overrides trust ──
    if blacklisted:
        total += BLACKLIST_PENALTY
        match_desc = ""
        if blacklist_match:
            match_desc = " (matched {}: {})".format(
                blacklist_match.get("matchType", ""),
                blacklist_match.get("matchValue", ""))
        breakdown.append({
            "category": "blacklist",
            "weight": BLACKLIST_PENALTY,
            "raw_score": 1.0,
            "contribution": BLACKLIST_PENALTY,
            "max_possible": BLACKLIST_PENALTY,
            "signals": [{
                "description": "Sender is on your personal blacklist" + match_desc,
                "severity": "critical"
            }],
            "info": [],
        })

    final_score = min(round(total), 100)
    verdict = _map_verdict(final_score)

    return final_score, verdict, breakdown


def _map_verdict(score):
    """Map a numeric score to a human-readable verdict."""
    for threshold, label in VERDICT_THRESHOLDS:
        if score <= threshold:
            return label
    return "Malicious"
