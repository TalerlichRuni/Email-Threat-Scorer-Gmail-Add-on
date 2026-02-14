# Email Threat Scorer — Gmail Add-on

A Gmail Add-on that analyzes emails for phishing and social engineering threats.
When you open any email, it runs five analysis modules on the content, metadata, and links,
then shows a risk score (0–100) with a clear verdict — **Safe**, **Suspicious**, or **Malicious** —
and a full breakdown of every signal that contributed to the score.

---

## Architecture

The system is split into a **frontend** (Google Apps Script) and a **backend** (Google Cloud Function, Python).

```
┌──────────────────┐       HTTPS + API Key       ┌──────────────────────┐
│   Gmail Add-on   │ ──────────────────────────►  │   Cloud Function     │
│   (Apps Script)  │                              │   (Python)           │
│                  │  ◄──────────────────────────  │                      │
│  - Extract data  │    JSON: score + breakdown   │  - 5 analyzers       │
│  - Blacklist     │                              │  - Trust assessment  │
│  - History query │                              │  - Scoring engine    │
│  - Render UI     │                              │  - Safe Browsing API │
└──────────────────┘                              │  - VirusTotal API    │
        │                                         └──────────────────────┘
        ▼
  Google Sheet (scan history)
```

**Frontend (Apps Script)** — Runs inside Gmail. Extracts email data (sender, headers, body, links, attachments), checks the user's blacklist, queries past scan history from a Google Sheet, sends everything to the backend, and renders the result as a two-card UI in the sidebar.

**Backend (Cloud Function, Python)** — Receives the extracted data, runs five independent analyzers, assesses sender trust, computes a weighted risk score, and returns a JSON response with the score, verdict, and per-signal breakdown.

**Why separate?** Python is better for text analysis and pattern matching. API keys (Safe Browsing, VirusTotal) stay server-side. The scoring logic can be updated or tested independently without touching the add-on.

**Authentication:** Shared API key in the `X-API-Key` header. Not production-grade — a deliberate simplification. In production, this would be IAM or OAuth.

---

## APIs Used

| API / Service | Purpose |
|---------------|---------|
| **Gmail API** (`GmailApp`, raw content parsing) | Extract email data, headers, authentication results, attachments |
| **Google Safe Browsing API v4** | Check URLs against Google's malware and phishing threat lists |
| **VirusTotal API v3** | Check attachment SHA-256 hashes against 70+ antivirus engines |
| **Google Sheets API** (`SpreadsheetApp`) | Store scan history, query it for repeat offender detection |
| **Google Cloud Functions** | Host the Python analysis backend |
| **PropertiesService** (User / Script) | Store per-user blacklist and backend configuration |
| **CacheService** | Cache scan results for card-to-card navigation |

---

## Implemented Features

### Five Analysis Modules

Each analyzer returns a normalized score (0.0–1.0) and a list of signals with severity levels.

1. **Sender Analysis (15 pts)** — Reply-To mismatches, brand impersonation from free email providers, lookalike domain detection (Levenshtein distance + character substitution maps), display name tricks.

2. **Header Authentication (15 pts)** — SPF, DKIM, DMARC verification. Parsed from `GmailApp.getRawContent()` because the Gmail REST API doesn't reliably return auth headers through contextual trigger tokens.

3. **Content Analysis (25 pts)** — The highest-weighted category because it has the deepest analysis. Pattern matching against seven categorized attack types (credential harvesting, financial scam, delivery scam, urgency/pressure, CEO fraud/BEC, generic greetings, tech support scam). Also detects sensitive info requests, threatening language, and excessive urgency markers. Phrase databases informed by CCCS ITSAP.00.100 guidelines and real phishing patterns.

4. **Link Analysis (25 pts)** — Anchor/href mismatches, URL shorteners, raw IPs, suspicious TLDs, credential harvesting URL paths, lookalike domains in links, Google Safe Browsing API reputation check.

5. **Attachment Analysis (20 pts)** — Dangerous extensions (22 types), macro-enabled documents, double extension tricks, archive files, MIME type mismatches, SHA-256 hash computation, and **VirusTotal hash reputation check** against 70+ antivirus engines. VirusTotal catches known malware that metadata analysis alone would miss. Files not in VirusTotal's database (never uploaded by anyone) are silently skipped — "unknown" is not treated as safe or dangerous.

### Scoring Engine

Weighted linear sum — each analyzer score is multiplied by its weight, totaling 100. Weights reflect how deeply we actually analyze each category and whether external APIs provide real enrichment.

| Category | Weight | Analysis Depth |
|----------|--------|---------------|
| Content | 25 | Deepest — 7 attack categories, regex, multi-category detection |
| Links | 25 | Strong — pattern analysis + Google Safe Browsing API |
| Attachments | 20 | Solid — metadata analysis + VirusTotal hash reputation |
| Sender | 15 | Good — lookalike detection, impersonation, reply-to mismatch |
| Headers | 15 | Good — real SPF/DKIM/DMARC verification |

- **External API threat override (+60 pts):** If Google Safe Browsing flags a URL or VirusTotal flags an attachment as malicious, a flat +60 points is added on top of the normal score. These are high-confidence external signals — if a threat intelligence API says it's bad, we escalate immediately to at least Suspicious. This overrides the normal weighted calculation.
- **Trust-aware dampening:** Verified senders (SPF/DKIM pass + known domain) get reduced sender/header scores. Content, links, and attachments are *never* dampened — a compromised legitimate account can still send phishing.
- **History-based signals:** The system queries past scans from the same sender domain. Domains flagged 2+ times get a repeat offender penalty (+8 to +15 pts). If a normally-safe sender's score deviates 20+ points from their baseline, it flags possible account compromise.
- **Blacklist penalty:** +50 points flat for blacklisted senders/domains.

Verdict mapping: 0–30 = Safe, 31–60 = Suspicious, 61–100 = Malicious.

### User-Managed Blacklist

Users can block specific email addresses or entire domains directly from the add-on UI. Entries are stored per-user in `PropertiesService`. Blacklisted senders get a +50 point penalty that overrides trust.

### Scan History

Every scan is logged to a Google Sheet (one row per unique email, deduplicated by message ID). Columns: timestamp, sender, subject, score, verdict (color-coded), key signals, link/attachment counts. The history feeds the repeat offender and baseline deviation scoring signals.

### Two-Screen UI

- **Screen 1 (Verdict):** Large icon + color-coded verdict + score. Immediate answer: is this safe?
- **Screen 2 (Analysis):** Full per-category breakdown with severity icons, signal descriptions, trust info, history context, and blacklist management actions.

---

## Limitations

- **No attachment content scanning.** VirusTotal checks file hashes against known threats, but we don't open or execute files — that would require a sandbox. Brand new malware not yet in VirusTotal's database won't be detected by hash alone.
- **VirusTotal rate limits.** Free tier allows 4 requests/minute and 500/day. Sufficient for an MVP but not for production scale.
- **Can't scan spam.** Gmail blocks add-ons from accessing the Spam folder.
- **Static pattern databases.** Phrase lists and domain lists are hardcoded. A production system would use live threat intelligence feeds.
- **No image/QR code analysis.** Can't detect quishing (phishing via QR codes in images).
- **English only.** Phrase matching is English-only. Non-English phishing won't trigger content signals.
- **History doesn't scale infinitely.** The Google Sheet approach works for hundreds of scans. At thousands of rows, the linear scan would slow down.
- **Hardcoded trusted domains.** The ~30 trusted domains are static. A production system would learn trust dynamically.
- **Not production-ready.** No rate limiting, no monitoring, no automated tests, no CI/CD. Auth is a shared secret, not IAM/OAuth.

---

## Future Ideas

- **ML model alongside heuristics** — Train a classifier on scan history data to catch patterns that static rules miss. Keep heuristics for explainability, add ML for a confidence score.
- **Shared database and cross-user learning** — Replace Google Sheets with a real database. Aggregate scan data across users so a domain flagged by many users becomes a signal for everyone.
- **"Mark as Safe" feedback loop** — Let users correct false positives. The system learns from this feedback and adjusts scoring over time, making it self-correcting.
