"""
Analysis modules for Email Threat Scorer.

Each analyzer receives the raw email data dict and returns:
  {
    "score": float 0.0-1.0  (normalized severity),
    "signals": [{"description": str, "severity": "info|low|medium|high|critical"}]
  }

Pattern databases are informed by real-world phishing campaigns and threat
intelligence from sources including the Canadian Centre for Cyber Security
(ITSAP.00.100), APWG phishing reports, and common enterprise email
threat patterns.

Design note: heuristic-based pattern detectors, not ML.
Full explainability — every signal traces to a concrete rule.
"""

import re
import requests


# ═══════════════════════════════════════════════
# Pattern Databases
# ═══════════════════════════════════════════════

# ── Phrases by Attack Category ──
# Categorized to give the user not just "suspicious phrase found"
# but what type of attack it indicates.

CREDENTIAL_HARVESTING = [
    "verify your account", "confirm your identity", "update your payment",
    "verify your identity", "confirm your account", "validate your account",
    "reactivate your account", "restore your account", "unlock your account",
    "verify your email", "confirm your email address", "update your information",
    "verify your billing", "confirm your billing details",
    "enter your credentials", "provide your password", "update your password",
    "reset your password", "change your password immediately",
    "your account has been compromised", "unauthorized access to your account",
    "unusual activity detected", "suspicious login attempt",
    "your account will be suspended", "your account has been suspended",
    "your account is at risk", "your account will be closed",
    "sign in to verify", "log in to confirm", "click here to verify",
    "update your security information", "verify your phone number",
]

FINANCIAL_SCAM = [
    "wire transfer", "bank transfer", "payment confirmation required",
    "outstanding payment", "overdue invoice", "unpaid invoice",
    "payment failed", "billing problem", "update payment method",
    "refund pending", "tax refund", "claim your refund",
    "inheritance fund", "lottery winner", "you have won",
    "million dollars", "investment opportunity",
    "western union", "moneygram", "purchase gift cards",
    "buy itunes cards", "buy google play cards",
    "outstanding balance", "collection agency",
]

DELIVERY_SCAM = [
    "package delivery failed", "delivery attempt failed", "track your package",
    "shipping confirmation", "delivery notification", "customs clearance required",
    "package could not be delivered", "reschedule delivery",
    "delivery fee required", "shipping fee required",
    "parcel is waiting", "package is on hold", "customs fee",
    "tracking number", "failed delivery attempt",
]

URGENCY_PRESSURE = [
    "act now", "act immediately", "immediate action required",
    "urgent action required", "respond immediately", "time sensitive",
    "within 24 hours", "within 48 hours", "expires today",
    "last chance", "final warning", "final notice",
    "limited time", "failure to respond will result",
    "your account will be terminated", "legal action will be taken",
    "law enforcement", "we will be forced to",
    "respond within", "deadline", "don't ignore this",
]

CEO_FRAUD_BEC = [
    "i need you to handle", "can you help me with something",
    "are you available right now", "i need a favor from you",
    "please handle this quietly", "keep this between us",
    "don't tell anyone about this", "keep this confidential",
    "i'm in a meeting right now", "i'll explain later",
    "transfer the funds", "make the payment today",
    "i need this done urgently", "process this wire",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer",
    "dear account holder", "dear sir/madam", "dear sir or madam",
    "dear member", "dear subscriber", "dear client",
    "dear valued member", "to whom it may concern",
    "dear email user", "dear recipient",
]

TECH_SUPPORT_SCAM = [
    "your computer has been infected", "virus detected on your",
    "malware detected", "security warning for your",
    "call this number immediately", "call our support team",
    "remote access required", "your license has expired",
    "renew your subscription", "storage is full",
    "mailbox is full", "mailbox quota exceeded",
    "email account will be deactivated",
]

# All categories combined with their labels (for reporting)
PHRASE_CATEGORIES = [
    ("Credential harvesting", CREDENTIAL_HARVESTING),
    ("Financial scam", FINANCIAL_SCAM),
    ("Delivery scam", DELIVERY_SCAM),
    ("Urgency/pressure tactics", URGENCY_PRESSURE),
    ("Business email compromise", CEO_FRAUD_BEC),
    ("Generic greeting", GENERIC_GREETINGS),
    ("Tech support scam", TECH_SUPPORT_SCAM),
]

# ── Sensitive Information Patterns ──
SENSITIVE_INFO_PATTERNS = [
    (r"(password|passcode)\s*(:|is|was)?\s*\S+", "Password appears in email body"),
    (r"(credit card|debit card)\s*(number|#|:)", "Requests credit/debit card number"),
    (r"(social security|social insurance)\s*(number|#|:)", "Requests social security/insurance number"),
    (r"\bssn\b\s*(:|#|number)", "Requests SSN"),
    (r"\bpin\b\s*(code|number|#|:)", "Requests PIN"),
    (r"(enter|provide|confirm|send|update|verify)\s+(your\s+)?(password|credentials|login|bank\s*account|routing\s*number)",
     "Requests sensitive credentials"),
    (r"(bank|account|routing)\s*(number|#|details|information)", "Requests banking details"),
    (r"(date of birth|mother'?s? maiden|passport number)", "Requests personal identity details"),
]

# ── Sender Reputation ──

IMPERSONATED_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "facebook", "meta", "instagram", "linkedin", "twitter", "whatsapp",
    "dropbox", "spotify", "zoom", "slack", "github", "adobe",
    "chase", "wells fargo", "bank of america", "citibank", "hsbc",
    "barclays", "td bank", "capital one", "american express", "visa",
    "mastercard", "coinbase", "binance", "blockchain",
    "dhl", "fedex", "ups", "usps", "royal mail", "canada post",
    "irs", "hmrc", "cra", "social security administration",
    "docusign", "sharepoint", "onedrive", "office 365", "outlook",
]

FREE_EMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "icloud.com", "gmx.com", "mail.ru",
    "tutanota.com", "cock.li", "guerrillamail.com",
]

# Character substitutions used in lookalike domains
LOOKALIKE_SUBSTITUTIONS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l", "!"],
    "e": ["3"],
    "a": ["@", "4"],
    "s": ["5", "$"],
    "g": ["9", "q"],
    "rn": ["m"],   # rn looks like m in many fonts
    "cl": ["d"],   # cl looks like d
    "vv": ["w"],   # vv looks like w
}

# High-value domains attackers create lookalikes of
TARGET_DOMAINS = [
    "paypal.com", "microsoft.com", "apple.com", "google.com",
    "amazon.com", "netflix.com", "facebook.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "linkedin.com",
    "dropbox.com", "icloud.com", "outlook.com",
]

# ── Link Analysis ──

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "short.link", "cutt.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "lnkd.in",
]

# TLDs frequently abused in phishing (cheap/free registration)
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".buzz", ".work", ".click", ".loan",
    ".gq", ".cf", ".tk", ".ml", ".ga",
    ".info", ".biz", ".win", ".review", ".download",
    ".racing", ".science", ".stream", ".party", ".date",
    ".faith", ".accountant", ".cricket",
]

# URL path segments that indicate credential harvesting pages
CREDENTIAL_URL_PATHS = [
    "/login", "/signin", "/sign-in", "/log-in",
    "/verify", "/secure", "/account", "/confirm",
    "/update", "/auth", "/authenticate",
    "/webscr", "/password", "/credential",
    "/banking", "/wallet", "/recover",
]

# ── Attachment Analysis ──

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".msi", ".ps1", ".jar", ".cpl", ".hta", ".reg",
    ".inf", ".lnk", ".sct", ".msp",
]

MACRO_EXTENSIONS = [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam"]

ARCHIVE_EXTENSIONS = [".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img"]

# ── Trusted Sender Domains ──
# Major legitimate email senders. When these domains pass SPF/DKIM/DMARC,
# their emails are almost certainly legitimate — even if they contain
# phrases like "verify your account" (which is normal for security notifications).
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "youtube.com",
    "microsoft.com", "outlook.com", "live.com", "hotmail.com", "office365.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk",
    "facebook.com", "meta.com", "instagram.com", "whatsapp.com",
    "linkedin.com", "twitter.com", "x.com",
    "github.com", "gitlab.com",
    "dropbox.com", "zoom.us", "slack.com",
    "paypal.com", "stripe.com",
    "netflix.com", "spotify.com",
    "fedex.com", "ups.com", "dhl.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "adobe.com", "salesforce.com",
]


# ═══════════════════════════════════════════════
# Analyzer 1: Sender Reputation
# Weight: 15
# ═══════════════════════════════════════════════

def analyze_sender(data):
    """
    Checks sender identity for impersonation and spoofing signals.

    Based on CCCS guidance: verify sender's email matches the official
    address, watch for misspelled names, invalid domains.

    Signals:
    - Reply-To mismatch (common in phishing to redirect responses)
    - Brand impersonation from free email provider
    - Lookalike domain detection (e.g., paypa1.com, rnicrosoft.com)
    - Email address embedded in display name
    """
    signals = []
    score = 0.0

    from_field = data.get("from", "")
    reply_to = data.get("replyTo", "")

    display_name, email_addr = _parse_from(from_field)
    email_domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""

    # ── Reply-To mismatch ──
    if reply_to:
        _, reply_email = _parse_from(reply_to)
        if reply_email.lower() != email_addr.lower():
            reply_domain = reply_email.split("@")[-1].lower() if "@" in reply_email else ""
            # Different domain is more suspicious than different address at same domain
            if reply_domain != email_domain:
                score += 0.5
                signals.append({
                    "description": "Reply-To domain ({}) differs from sender domain ({}) — responses would go to a different organization".format(
                        reply_domain, email_domain),
                    "severity": "high"
                })
            else:
                score += 0.2
                signals.append({
                    "description": "Reply-To ({}) differs from sender ({})".format(reply_email, email_addr),
                    "severity": "medium"
                })

    # ── Brand impersonation: brand name in display name + free email ──
    display_lower = display_name.lower()
    if email_domain in FREE_EMAIL_PROVIDERS:
        for brand in IMPERSONATED_BRANDS:
            if brand in display_lower:
                score += 0.6
                signals.append({
                    "description": "Display name impersonates '{}' but sent from free provider ({}) — likely phishing".format(
                        brand, email_domain),
                    "severity": "high"
                })
                break

    # ── Lookalike domain detection ──
    if email_domain and email_domain not in FREE_EMAIL_PROVIDERS:
        lookalike = _check_lookalike_domain(email_domain)
        if lookalike:
            score += 0.5
            signals.append({
                "description": "Sender domain '{}' resembles '{}' — possible typosquatting".format(
                    email_domain, lookalike),
                "severity": "high"
            })

    # ── Display name contains an email address ──
    if re.search(r"[\w.-]+@[\w.-]+\.\w+", display_name):
        score += 0.3
        signals.append({
            "description": "Display name embeds an email address — impersonation technique to make the sender look official",
            "severity": "medium"
        })

    # ── Display name is just the email address repeated ──
    if display_name.lower().strip() == email_addr.lower():
        score += 0.1
        signals.append({
            "description": "Display name is identical to the email address (no proper name set)",
            "severity": "low"
        })

    if not signals:
        signals.append({"description": "No sender anomalies detected", "severity": "info"})

    return {"score": min(score, 1.0), "signals": signals}


# ═══════════════════════════════════════════════
# Analyzer 2: Header Anomalies
# Weight: 15
# ═══════════════════════════════════════════════

def analyze_headers(data):
    """
    Analyzes email authentication headers — SPF, DKIM, DMARC.

    These are the backbone of email authentication. Failures mean the
    sending server could not be verified as authorized for the domain.
    Legitimate organizations almost always pass all three.
    """
    signals = []
    score = 0.0

    spf_header = data.get("spf", "").lower()
    auth_results = data.get("authResults", "").lower()
    dkim = data.get("dkim", "")

    auth_pass_count = 0
    auth_fail_count = 0

    # ── SPF — check both Received-SPF header and Authentication-Results ──
    spf_status = "unknown"
    if "pass" in spf_header:
        spf_status = "pass"
    elif "fail" in spf_header and "softfail" not in spf_header:
        spf_status = "fail"
    elif "softfail" in spf_header:
        spf_status = "softfail"

    # Also check Authentication-Results for SPF (many servers only put it here)
    if spf_status == "unknown" and auth_results:
        if "spf=pass" in auth_results:
            spf_status = "pass"
        elif "spf=fail" in auth_results:
            spf_status = "fail"
        elif "spf=softfail" in auth_results:
            spf_status = "softfail"

    if spf_status == "fail":
        score += 0.5
        auth_fail_count += 1
        signals.append({
            "description": "SPF hard fail — sending server IP is not authorized for this domain",
            "severity": "high"
        })
    elif spf_status == "softfail":
        score += 0.25
        signals.append({
            "description": "SPF softfail — sending server not fully authorized",
            "severity": "medium"
        })
    elif spf_status == "pass":
        auth_pass_count += 1
        signals.append({"description": "SPF passed", "severity": "info"})
    else:
        score += 0.1
        signals.append({"description": "SPF status could not be determined", "severity": "low"})

    # ── DKIM ──
    if auth_results:
        if "dkim=fail" in auth_results:
            score += 0.4
            auth_fail_count += 1
            signals.append({
                "description": "DKIM signature verification failed — email content may have been tampered with",
                "severity": "high"
            })
        elif "dkim=pass" in auth_results:
            auth_pass_count += 1
            signals.append({"description": "DKIM passed", "severity": "info"})

        # ── DMARC ──
        if "dmarc=fail" in auth_results:
            score += 0.4
            auth_fail_count += 1
            signals.append({
                "description": "DMARC check failed — sender's domain policy was violated",
                "severity": "high"
            })
        elif "dmarc=pass" in auth_results:
            auth_pass_count += 1
            signals.append({"description": "DMARC passed", "severity": "info"})
    else:
        if not dkim:
            score += 0.1
            signals.append({
                "description": "No authentication results or DKIM signature found",
                "severity": "low"
            })

    # Bonus signal: multiple auth failures is very suspicious
    if auth_fail_count >= 2:
        score += 0.2
        signals.append({
            "description": "Multiple authentication failures ({}) — strong indicator of spoofed sender".format(auth_fail_count),
            "severity": "high"
        })

    return {"score": min(score, 1.0), "signals": signals}


# ═══════════════════════════════════════════════
# Analyzer 3: Content Patterns
# Weight: 20
# ═══════════════════════════════════════════════

def analyze_content(data):
    """
    Scans email body and subject for social engineering indicators.

    Uses categorized phrase databases informed by real phishing campaigns
    to detect: credential harvesting, financial scams, delivery scams,
    CEO fraud/BEC, urgency tactics, and tech support scams.

    Also detects: requests for sensitive information, excessive urgency
    markers, and generic impersonal greetings.
    """
    signals = []
    score = 0.0

    body = data.get("plainBody", "").lower()
    subject = data.get("subject", "").lower()
    combined = subject + " " + body
    original_body = data.get("plainBody", "")

    if not combined.strip():
        return {"score": 0.0, "signals": [{"description": "Empty email body", "severity": "info"}]}

    # ── Categorized phrase matching ──
    total_matches = 0
    categories_hit = []

    for category_name, phrases in PHRASE_CATEGORIES:
        found = [p for p in phrases if p in combined]
        if found:
            total_matches += len(found)
            preview = ", ".join(["'" + f + "'" for f in found[:3]])
            if len(found) > 3:
                preview += " (+{} more)".format(len(found) - 3)
            categories_hit.append(category_name)

            # Generic greetings are lower severity than active attack phrases
            if category_name == "Generic greeting":
                score += 0.1
                signals.append({
                    "description": "{}: {}".format(category_name, preview),
                    "severity": "low"
                })
            else:
                cat_score = min(len(found) * 0.12, 0.4)
                score += cat_score
                signals.append({
                    "description": "{}: {}".format(category_name, preview),
                    "severity": "high" if len(found) >= 2 else "medium"
                })

    # Multiple attack categories in one email is a strong indicator
    if len(categories_hit) >= 3:
        score += 0.2
        signals.append({
            "description": "Email matches {} different attack categories — highly suspicious".format(len(categories_hit)),
            "severity": "high"
        })

    # ── Sensitive information requests (regex) ──
    for pattern, description in SENSITIVE_INFO_PATTERNS:
        if re.search(pattern, combined):
            score += 0.25
            signals.append({
                "description": description,
                "severity": "high"
            })
            break  # one match is enough

    # ── Urgency markers (exclamation marks, ALL CAPS) ──
    exclamation_count = combined.count("!")
    caps_words = len(re.findall(r"\b[A-Z]{4,}\b", original_body))
    if exclamation_count > 5 or caps_words > 5:
        score += 0.1
        signals.append({
            "description": "Excessive urgency markers ({} exclamation marks, {} ALL-CAPS words)".format(
                exclamation_count, caps_words),
            "severity": "medium"
        })

    # ── Threatening language ──
    threat_patterns = [
        r"(legal action|lawsuit|prosecut|arrest|warrant)",
        r"(terminate|suspend|deactivat|disabl).*account",
        r"(report|forward).*(police|authorities|fbi|law enforcement)",
    ]
    for pattern in threat_patterns:
        if re.search(pattern, combined):
            score += 0.15
            signals.append({
                "description": "Threatening language detected — pressure tactic to force action",
                "severity": "medium"
            })
            break

    if not signals:
        signals.append({"description": "No suspicious content patterns found", "severity": "info"})

    return {"score": min(score, 1.0), "signals": signals}


# ═══════════════════════════════════════════════
# Analyzer 4: Link Analysis
# Weight: 25
# ═══════════════════════════════════════════════

def analyze_links(data, safe_browsing_key=""):
    """
    Analyzes URLs found in the email body.

    Informed by CCCS guidance: do not click links, verify URLs,
    be suspicious of shortened URLs, check for domain mismatches.

    Checks:
    - Anchor text vs. actual href mismatch (classic phishing trick)
    - URL shorteners (obscure real destination)
    - Raw IP addresses in URLs (no legitimate service uses these)
    - Suspicious TLDs (.xyz, .top, etc. — commonly abused)
    - Credential harvesting paths (/login, /verify, /secure)
    - Lookalike domains in URLs
    - Google Safe Browsing API reputation check
    """
    signals = []
    score = 0.0

    links = data.get("links", [])
    if not links:
        return {"score": 0.0, "signals": [{"description": "No links in email body", "severity": "info"}]}

    unique_domains = set()
    urls_to_check = []
    mismatches_found = 0

    for link in links:
        href = link.get("href", "")
        text = link.get("text", "")
        domain = _extract_domain(href)

        if domain:
            unique_domains.add(domain)
        if href.startswith("http"):
            urls_to_check.append(href)

        # ── Anchor text / href mismatch ──
        if text and _looks_like_url(text):
            text_domain = _extract_domain(text)
            href_domain = _extract_domain(href)
            if text_domain and href_domain and text_domain != href_domain:
                mismatches_found += 1
                if mismatches_found <= 3:  # don't flood with signals
                    score += 0.35
                    signals.append({
                        "description": "Deceptive link: displays '{}' but actually goes to '{}'".format(
                            text_domain, href_domain),
                        "severity": "high"
                    })

        # ── URL shortener ──
        if domain in URL_SHORTENERS:
            score += 0.15
            signals.append({
                "description": "URL shortener hides real destination: {}".format(domain),
                "severity": "medium"
            })

        # ── Raw IP in URL ──
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", href):
            score += 0.3
            signals.append({
                "description": "URL uses raw IP address instead of domain name: {}".format(href[:80]),
                "severity": "high"
            })

        # ── Suspicious TLD ──
        if domain:
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    score += 0.15
                    signals.append({
                        "description": "Link uses suspicious TLD ({}): {}".format(tld, domain),
                        "severity": "medium"
                    })
                    break

        # ── Credential harvesting URL path ──
        href_lower = href.lower()
        for path in CREDENTIAL_URL_PATHS:
            if path in href_lower:
                score += 0.2
                signals.append({
                    "description": "Link points to login/credential page: ...{}".format(path),
                    "severity": "medium"
                })
                break

        # ── Lookalike domain in URL ──
        if domain:
            lookalike = _check_lookalike_domain(domain)
            if lookalike:
                score += 0.4
                signals.append({
                    "description": "Link domain '{}' resembles '{}' — possible phishing site".format(
                        domain, lookalike),
                    "severity": "high"
                })

    # Multiple deceptive links
    if mismatches_found > 3:
        signals.append({
            "description": "{} deceptive links found in total".format(mismatches_found),
            "severity": "high"
        })

    # Many external domains
    if len(unique_domains) > 5:
        score += 0.1
        signals.append({
            "description": "Email contains links to {} different domains".format(len(unique_domains)),
            "severity": "low"
        })

    # ── Google Safe Browsing ──
    if safe_browsing_key and urls_to_check:
        sb_hits = _check_safe_browsing(urls_to_check, safe_browsing_key)
        if sb_hits:
            score += 0.5
            for hit in sb_hits:
                signals.append({
                    "description": "Google Safe Browsing flagged: {} as {}".format(
                        hit["url"][:60], hit["threat_type"].replace("_", " ").lower()),
                    "severity": "critical"
                })
        else:
            signals.append({
                "description": "All {} URLs passed Google Safe Browsing check".format(len(urls_to_check)),
                "severity": "info"
            })

    if not [s for s in signals if s["severity"] != "info"]:
        signals.append({"description": "No suspicious link patterns detected", "severity": "info"})

    return {"score": min(score, 1.0), "signals": signals}


# ═══════════════════════════════════════════════
# Analyzer 5: Attachment Risk
# Weight: 25
# ═══════════════════════════════════════════════

def analyze_attachments(data, virustotal_key=""):
    """
    Checks attachment metadata and reputation for malicious characteristics.

    Informed by CCCS guidance: do not open attachments from unknown senders,
    watch for strange file names or multiple extensions, block macros.

    Signals:
    - Known dangerous file extensions (.exe, .js, .ps1, etc.)
    - Macro-enabled Office documents (.docm, .xlsm)
    - Double extension trick (e.g., invoice.pdf.exe)
    - Password-protected archives (common malware delivery)
    - Extension / MIME type mismatch
    - VirusTotal hash reputation (if API key configured)
    """
    signals = []
    score = 0.0

    attachments = data.get("attachments", [])
    if not attachments:
        return {"score": 0.0, "signals": [{"description": "No attachments", "severity": "info"}]}

    for att in attachments:
        name = att.get("name", "")
        name_lower = name.lower()
        content_type = att.get("contentType", "").lower()
        size = att.get("size", 0)

        flagged = False

        # ── Dangerous extension ──
        for ext in DANGEROUS_EXTENSIONS:
            if name_lower.endswith(ext):
                score += 0.6
                signals.append({
                    "description": "Dangerous executable file type: {} ({})".format(name, ext),
                    "severity": "critical"
                })
                flagged = True
                break

        # ── Macro-enabled documents ──
        if not flagged:
            for ext in MACRO_EXTENSIONS:
                if name_lower.endswith(ext):
                    score += 0.4
                    signals.append({
                        "description": "Macro-enabled document: {} — macros can execute malicious code".format(name),
                        "severity": "high"
                    })
                    flagged = True
                    break

        # ── Double extension (e.g., file.pdf.exe) ──
        parts = name_lower.rsplit(".", 2)
        if len(parts) >= 3:
            final_ext = "." + parts[-1]
            if final_ext in DANGEROUS_EXTENSIONS:
                score += 0.5
                signals.append({
                    "description": "Double extension trick detected: {} — real type is {}".format(name, final_ext),
                    "severity": "critical"
                })

        # ── Password-protected archives ──
        for ext in ARCHIVE_EXTENSIONS:
            if name_lower.endswith(ext):
                score += 0.2
                signals.append({
                    "description": "Archive attachment: {} — archives can hide malicious files from scanners".format(name),
                    "severity": "medium"
                })
                break

        # ── Extension vs MIME type mismatch ──
        if name_lower.endswith(".pdf") and "pdf" not in content_type:
            score += 0.3
            signals.append({
                "description": "MIME type mismatch: {} claims PDF but actual type is {}".format(name, content_type),
                "severity": "medium"
            })
        elif name_lower.endswith(".docx") and "word" not in content_type and "document" not in content_type:
            score += 0.3
            signals.append({
                "description": "MIME type mismatch: {} claims Word doc but actual type is {}".format(name, content_type),
                "severity": "medium"
            })

        # ── Suspiciously small executable (stub/dropper) ──
        if flagged and size > 0 and size < 5000:
            score += 0.1
            signals.append({
                "description": "Very small executable ({} bytes) — could be a dropper/downloader".format(size),
                "severity": "medium"
            })

        # ── VirusTotal hash reputation check ──
        sha256 = att.get("sha256", "")
        if virustotal_key and sha256:
            vt_result = _check_virustotal(sha256, virustotal_key)
            if vt_result:
                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)
                total_engines = sum(vt_result.values())
                threats = malicious + suspicious

                if malicious >= 10:
                    score += 0.8
                    signals.append({
                        "description": "VirusTotal: {}/{} engines flagged '{}' as malicious".format(
                            malicious, total_engines, name),
                        "severity": "critical"
                    })
                elif threats >= 1:
                    score += 0.4
                    signals.append({
                        "description": "VirusTotal: {}/{} engines flagged '{}' ({} malicious, {} suspicious)".format(
                            threats, total_engines, name, malicious, suspicious),
                        "severity": "high"
                    })
                else:
                    signals.append({
                        "description": "'{}' passed VirusTotal check ({} engines, 0 detections)".format(
                            name, total_engines),
                        "severity": "info"
                    })
            # vt_result is None = API error or hash not found, silently skip

    if not signals:
        signals.append({"description": "Attachments appear safe", "severity": "info"})

    return {"score": min(score, 1.0), "signals": signals}


# ═══════════════════════════════════════════════
# Trust Assessment
# ═══════════════════════════════════════════════

def assess_trust_level(data, header_result):
    """
    Determines how much to trust the sender based on authentication
    results and domain reputation.

    Trust levels:
    - "self":   email is from the user themselves (sent mail)
    - "high":   all auth passed + sender is a well-known domain
    - "medium": all auth passed but domain is not in trusted list
    - "none":   auth failed or mixed results

    This is used by the scoring engine to dampen false positives.
    Legitimate senders like Google use phrases ("verify your account")
    that would otherwise trigger content analysis.
    """
    from_field = data.get("from", "")
    to_field = data.get("to", "")
    _, email_addr = _parse_from(from_field)
    email_domain = email_addr.split("@")[-1].lower() if "@" in email_addr else ""

    # Check if this is a self-sent email (sent mail folder)
    _, to_email = _parse_from(to_field.split(",")[0]) if to_field else ("", "")
    if email_addr.lower() == to_email.lower() and email_addr:
        return {"level": "self", "reason": "Self-sent email — your own outgoing message"}

    # Check authentication results from header analyzer
    header_signals = header_result.get("signals", [])
    auth_passes = sum(1 for s in header_signals if s.get("severity") == "info" and "passed" in s.get("description", "").lower())
    auth_fails = sum(1 for s in header_signals if s.get("severity") in ("high", "medium"))
    header_score = header_result.get("score", 0.0)

    # All auth passed (score is 0 or very low) + trusted domain
    if header_score <= 0.1 and auth_passes >= 1:
        # Check if domain or parent domain is in trusted list
        is_trusted = False
        for trusted in TRUSTED_DOMAINS:
            if email_domain == trusted or email_domain.endswith("." + trusted):
                is_trusted = True
                break

        if is_trusted:
            return {
                "level": "high",
                "reason": "Verified trusted sender: {} (authentication passed, known domain)".format(email_domain)
            }
        else:
            return {
                "level": "medium",
                "reason": "Authenticated sender: {} (SPF/DKIM passed)".format(email_domain)
            }

    return {"level": "none", "reason": ""}


# ═══════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════

def _parse_from(from_str):
    """Parse 'Display Name <email@domain.com>' into (name, email)."""
    match = re.match(r"^(.*?)\s*<([^>]+)>", from_str)
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip()
    return "", from_str.strip()


def _extract_domain(url):
    """Extract domain from a URL string."""
    match = re.search(r"https?://([^/:\s]+)", url)
    if match:
        return match.group(1).lower()
    return ""


def _looks_like_url(text):
    """Check if text looks like a URL or domain name."""
    return bool(re.search(r"(https?://|www\.|\.\w{2,4}(/|$))", text.lower()))


def _check_lookalike_domain(domain):
    """
    Check if domain is a lookalike of a known target domain.
    Uses character substitution patterns that attackers commonly employ.

    Returns the target domain it resembles, or None.
    """
    # Strip any subdomain to get the registerable domain
    parts = domain.split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
    else:
        base = domain

    for target in TARGET_DOMAINS:
        if base == target:
            continue  # exact match, not a lookalike

        target_base = target.split(".")[0]  # e.g., "paypal"
        domain_base = base.split(".")[0]    # e.g., "paypa1"

        if domain_base == target_base:
            continue  # same base, different TLD is less suspicious

        # Check edit distance — lookalikes are typically 1-2 chars different
        if _edit_distance(domain_base, target_base) <= 2 and len(domain_base) >= 4:
            return target

        # Check specific substitutions
        normalized = domain_base
        for original, subs in LOOKALIKE_SUBSTITUTIONS.items():
            for sub in subs:
                normalized = normalized.replace(sub, original)
        if normalized == target_base and domain_base != target_base:
            return target

    return None


def _edit_distance(s1, s2):
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _edit_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


def _check_virustotal(sha256, api_key):
    """
    Query VirusTotal API v3 for file hash reputation.
    Sends the SHA-256 hash — does NOT upload the file.

    Returns dict with detection counts: {malicious, suspicious, undetected, harmless}
    Returns None on error or if hash is not in VirusTotal's database (404).

    Free tier: 4 requests/minute, 500/day — enough for an MVP.
    """
    endpoint = "https://www.virustotal.com/api/v3/files/{}".format(sha256)

    try:
        resp = requests.get(
            endpoint,
            headers={"x-apikey": api_key},
            timeout=5
        )
        if resp.status_code == 404:
            return None  # hash not in database — file never uploaded to VT
        if resp.status_code != 200:
            return None  # API error — graceful degradation

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats  # e.g. {"malicious": 12, "suspicious": 2, "undetected": 30, "harmless": 25}
    except Exception:
        return None  # timeout or network error — skip silently


def _check_safe_browsing(urls, api_key):
    """
    Query Google Safe Browsing API v4 for URL reputation.
    Limit to 10 URLs per request (free-tier rate limit).
    Best-effort — graceful degradation on API failure.
    """
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    body = {
        "client": {
            "clientId": "email-threat-scorer",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls[:10]]
        }
    }

    try:
        resp = requests.post(
            endpoint,
            params={"key": api_key},
            json=body,
            timeout=5
        )
        if resp.status_code != 200:
            return []

        matches = resp.json().get("matches", [])
        return [
            {"url": m["threat"]["url"], "threat_type": m["threatType"]}
            for m in matches
        ]
    except Exception:
        return []
