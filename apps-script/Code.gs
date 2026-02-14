/**
 * Gmail Add-on — Email Threat Scorer
 *
 * Frontend: extracts email data, sends it to the Cloud Function backend,
 * and renders a scored verdict card with per-signal explainability.
 * Includes user-managed blacklist stored in PropertiesService.
 */

// ── Configuration ──
// Read backend URL from Script Properties (set manually in Apps Script editor)
var BACKEND_URL = PropertiesService.getScriptProperties().getProperty("BACKEND_URL") || "";
// Read shared secret API key — must match the one set in Cloud Function env vars
var API_SECRET  = PropertiesService.getScriptProperties().getProperty("API_SECRET")  || "dev-secret-key";


// ──────────────────────────────────────────────
// Entry Point — Gmail calls this when user opens any email
// ──────────────────────────────────────────────

function onEmailOpen(e) { // e = event object from Gmail, contains message metadata
  var messageId = e.messageMetadata.messageId; // unique ID of the opened email
  GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken); // authorize access to this specific email

  var msg = GmailApp.getMessageById(messageId); // get the full message object from Gmail
  var emailData = extractEmailData(msg, messageId, e.messageMetadata.accessToken); // pull out all fields we need

  // Check if sender is on the user's personal blacklist
  var blCheck = checkBlacklist(emailData); // returns {matched: bool, matchType, matchValue}
  emailData.blacklisted = blCheck.matched; // attach blacklist flag to the data we send to backend
  if (blCheck.matched) {
    emailData.blacklistMatch = { matchType: blCheck.matchType, matchValue: blCheck.matchValue }; // attach match details
  }

  // Query scan history — have we seen emails from this domain before?
  var senderEmail = parseSenderEmail(emailData.from); // extract "john@evil.com" from "John <john@evil.com>"
  var senderDomain = senderEmail.split("@").pop(); // extract "evil.com" from "john@evil.com"
  try {
    var history = querySenderHistory(senderDomain); // check Google Sheet for past scans from this domain
    if (history) { emailData.senderHistory = history; } // attach history data so backend can use it for scoring
  } catch (histErr) {
    Logger.log("History query skipped: " + histErr.message); // non-critical — continue without history
  }

  if (BACKEND_URL) { // only proceed if backend is configured
    try {
      var result = callBackend(emailData); // send all data to Cloud Function, get back score + signals
      // Log this scan to the history sheet (best-effort — don't crash if Sheet has issues)
      try { logScanToHistory(emailData, result); } catch (logErr) {
        Logger.log("History log failed: " + logErr.message); // non-critical — user still gets result
      }
      // Cache the result for 10 minutes so "View Full Analysis" can retrieve it without re-scanning
      CacheService.getUserCache().put(
        "last_scan_" + emailData.messageId, // cache key = "last_scan_" + messageId
        JSON.stringify({ emailData: emailData, result: result }), // cache value = JSON string of data + result
        600 // TTL = 600 seconds = 10 minutes
      );
      return [buildVerdictCard(emailData, result)]; // build Screen 1 (verdict) and return to Gmail for display
    } catch (err) {
      return [buildErrorCard("Backend error: " + err.message)]; // show error card if backend call fails
    }
  } else {
    return [buildSetupCard(emailData)]; // no backend URL configured — show setup instructions
  }
}


// ──────────────────────────────────────────────
// Backend Communication — sends data to Cloud Function
// ──────────────────────────────────────────────

function callBackend(emailData) {
  var options = {
    method: "post", // HTTP POST — we're sending data
    contentType: "application/json", // tell server the body is JSON
    headers: { "X-API-Key": API_SECRET }, // attach our secret key for authentication
    payload: JSON.stringify(emailData), // convert JS object to JSON string for the request body
    muteHttpExceptions: true // don't throw on HTTP errors (4xx/5xx) — let us handle them
  };

  var response = UrlFetchApp.fetch(BACKEND_URL, options); // send HTTP request to backend
  var code = response.getResponseCode(); // get HTTP status code (200 = success)

  if (code !== 200) { // anything other than 200 is an error
    throw new Error("HTTP " + code + ": " + response.getContentText().substring(0, 200)); // throw with error details
  }

  return JSON.parse(response.getContentText()); // parse JSON response into JS object: {score, verdict, breakdown}
}


// ──────────────────────────────────────────────
// Data Extraction — pulls all relevant fields from the email
// ──────────────────────────────────────────────

function extractEmailData(msg, messageId, accessToken) {
  var headers = fetchRawHeaders(messageId, accessToken); // get SPF/DKIM/DMARC headers from raw email
  var htmlBody = msg.getBody() || ""; // HTML version of the email body (for link extraction)
  var plainBody = msg.getPlainBody() || ""; // plain text version (for content analysis)

  return { // build the object that gets sent to the backend
    messageId: messageId, // unique email ID (used for dedup in history)
    subject: msg.getSubject() || "(no subject)", // email subject line
    from: msg.getFrom(), // sender — format: "Display Name <email@domain.com>"
    to: msg.getTo(), // recipient(s)
    cc: msg.getCc() || "", // CC recipients
    replyTo: msg.getReplyTo() || "", // Reply-To header (can differ from From — phishing signal)
    date: msg.getDate().toISOString(), // send date in ISO format
    spf: extractHeaderValue(headers, "Received-SPF"), // SPF authentication result
    dkim: extractHeaderValue(headers, "DKIM-Signature"), // DKIM signature header
    authResults: extractHeaderValue(headers, "Authentication-Results"), // combined auth results (SPF+DKIM+DMARC)
    plainBody: plainBody, // full plain text body for content analysis
    bodyLength: plainBody.length, // body length in characters
    links: extractLinks(htmlBody), // array of {href, text} objects extracted from HTML
    attachments: extractAttachmentInfo(msg) // array of {name, contentType, size, sha256} objects
  };
}

/**
 * Extracts email headers by parsing the raw message content.
 * We use GmailApp.getRawContent() instead of the Gmail REST API
 * because the REST API via contextual trigger tokens has limited
 * access to authentication headers (bug we discovered during development).
 */
function fetchRawHeaders(messageId, accessToken) {
  try {
    var msg = GmailApp.getMessageById(messageId); // get message object
    var raw = msg.getRawContent(); // get the ENTIRE raw email as a string (headers + body)

    // In a raw email, headers end at the first blank line (\r\n\r\n)
    var headerEnd = raw.indexOf("\r\n\r\n"); // find where headers end (Windows line endings)
    if (headerEnd === -1) headerEnd = raw.indexOf("\n\n"); // fallback: Unix line endings
    // Cut only the header section — don't load full body into memory. Cap at 50KB for safety.
    var headerSection = headerEnd > 0 ? raw.substring(0, Math.min(headerEnd, 50000)) : raw.substring(0, 50000);

    return parseRawHeaders(headerSection); // parse the raw text into structured {name, value} objects
  } catch (err) {
    Logger.log("Header fetch failed: " + err.message); // graceful degradation — return empty array
    return [];
  }
}

/**
 * Parses raw email header text into an array of {name, value} objects.
 * Handles multi-line headers (continuation lines that start with whitespace).
 */
function parseRawHeaders(headerText) {
  var headers = []; // result array
  var lines = headerText.split(/\r?\n/); // split into lines (handles both \r\n and \n)
  var currentName = ""; // name of the header we're currently building
  var currentValue = ""; // value of the header we're currently building

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    // Continuation line — starts with space or tab, belongs to the previous header
    if (/^\s/.test(line) && currentName) { // regex: does line start with whitespace?
      currentValue += " " + line.trim(); // append to current header value
    } else {
      // New header line — save the previous one first
      if (currentName) {
        headers.push({ name: currentName, value: currentValue }); // save completed header
      }
      // Parse "HeaderName: HeaderValue"
      var colonIdx = line.indexOf(":"); // find the colon separator
      if (colonIdx > 0) {
        currentName = line.substring(0, colonIdx).trim(); // everything before colon = name
        currentValue = line.substring(colonIdx + 1).trim(); // everything after colon = value
      } else {
        currentName = ""; // not a valid header line
        currentValue = "";
      }
    }
  }
  // Don't forget the last header in the file
  if (currentName) {
    headers.push({ name: currentName, value: currentValue });
  }

  return headers; // array of {name: "Received-SPF", value: "pass ..."} objects
}

// Search the headers array for a specific header by name (case-insensitive)
function extractHeaderValue(headers, name) {
  var lowerName = name.toLowerCase(); // normalize to lowercase for comparison
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === lowerName) return headers[i].value; // found — return value
  }
  return ""; // not found — return empty string
}

// Extract all links from HTML body using regex
function extractLinks(html) {
  var links = []; // result array
  // Regex: find <a href="URL">Text</a> tags, capture (1) the URL and (2) the display text
  var regex = /<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  var match;
  while ((match = regex.exec(html)) !== null) { // loop through all matches
    var href = match[1].trim(); // the actual URL the link points to
    var text = match[2].replace(/<[^>]+>/g, "").trim(); // the visible text (strip inner HTML tags)
    if (href && !href.toLowerCase().startsWith("mailto:")) { // skip mailto: links
      links.push({ href: href, text: text }); // add to results
    }
  }
  return links; // array of {href: "https://evil.com/login", text: "Click here"}
}

// Extract metadata for each attachment (we don't scan content — just metadata + hash)
function extractAttachmentInfo(msg) {
  var attachments = msg.getAttachments(); // get array of attachment objects
  if (!attachments || attachments.length === 0) return []; // no attachments
  return attachments.map(function(att) { // transform each attachment into our format
    var bytes = att.getBytes(); // get raw bytes of the file
    return {
      name: att.getName(), // filename, e.g. "invoice.pdf"
      contentType: att.getContentType(), // MIME type, e.g. "application/pdf"
      size: bytes.length, // file size in bytes
      sha256: computeSHA256(bytes) // SHA-256 hash of file content (for identification)
    };
  });
}

// Compute SHA-256 hash of a byte array — returns hex string like "a1b2c3..."
function computeSHA256(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes); // Google's built-in SHA-256
  return digest.map(function(b) {
    // Convert each byte to 2-char hex. (b+256)%256 handles Java's signed bytes (-128 to 127 → 0 to 255)
    return ("0" + ((b + 256) % 256).toString(16)).slice(-2);
  }).join(""); // join all hex pairs into one string
}


// ──────────────────────────────────────────────
// Blacklist — Storage (UserProperties, per-user)
// Format: JSON array stored as string in UserProperties
// Example: [{"type":"domain","value":"evil.com"}, {"type":"email","value":"scam@evil.com"}]
// ──────────────────────────────────────────────

// Read the blacklist from storage — returns array of {type, value} objects
function getBlacklist() {
  var json = PropertiesService.getUserProperties().getProperty("blacklist"); // read from per-user storage
  return json ? JSON.parse(json) : []; // parse JSON, or return empty array if nothing stored
}

// Write the blacklist to storage
function saveBlacklist(list) {
  PropertiesService.getUserProperties().setProperty("blacklist", JSON.stringify(list)); // convert to JSON and save
}

// Add a new entry to the blacklist (prevents duplicates)
function addToBlacklist(type, value) { // type = "domain" or "email", value = "evil.com" or "scam@evil.com"
  var list = getBlacklist(); // read current list
  var lowerVal = value.toLowerCase().trim(); // normalize to lowercase
  var exists = list.some(function(entry) { // check if already exists
    return entry.type === type && entry.value === lowerVal;
  });
  if (!exists) { // only add if not already present
    list.push({ type: type, value: lowerVal }); // add new entry
    saveBlacklist(list); // persist to storage
  }
  return list; // return updated list
}

// Remove an entry from the blacklist by value
function removeFromBlacklist(value) {
  var list = getBlacklist(); // read current list
  list = list.filter(function(entry) { // keep everything that does NOT match the value
    return entry.value !== value.toLowerCase().trim();
  });
  saveBlacklist(list); // persist updated list
  return list;
}

// Check if the current email's sender matches any blacklist entry
// Returns {matched: bool, matchType: string, matchValue: string}
function checkBlacklist(emailData) {
  var list = getBlacklist(); // read blacklist
  if (list.length === 0) return { matched: false }; // empty blacklist — nothing to check

  var fromField = emailData.from || ""; // e.g. "John Doe <john@evil.com>"
  var match = /^(.*?)\s*<([^>]+)>/.exec(fromField); // regex: extract email from "Name <email>" format
  var email = match ? match[2].toLowerCase() : fromField.toLowerCase(); // get just the email address
  var domain = email.split("@").pop(); // get just the domain part

  for (var i = 0; i < list.length; i++) { // check each blacklist entry
    var entry = list[i];
    if (entry.type === "email" && entry.value === email) { // exact email match
      return { matched: true, matchType: "email", matchValue: entry.value };
    }
    if (entry.type === "domain" && entry.value === domain) { // domain match
      return { matched: true, matchType: "domain", matchValue: entry.value };
    }
  }
  return { matched: false }; // no match found
}


// ──────────────────────────────────────────────
// Blacklist — Action Handlers (called when user clicks buttons)
// ──────────────────────────────────────────────

// Called when user clicks "Block domain" button
function onBlacklistDomain(e) {
  var domain = e.commonEventObject.parameters.domain; // get domain from button parameters
  addToBlacklist("domain", domain); // add to blacklist
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText("Added " + domain + " to blacklist") // show toast notification
    )
    .build();
}

// Called when user clicks "Block sender email" button
function onBlacklistEmail(e) {
  var email = e.commonEventObject.parameters.email; // get email from button parameters
  addToBlacklist("email", email); // add to blacklist
  return CardService.newActionResponseBuilder()
    .setNotification(
      CardService.newNotification().setText("Added " + email + " to blacklist") // show toast
    )
    .build();
}

// Called when user clicks "Remove" button next to a blacklist entry
function onRemoveBlacklistEntry(e) {
  var value = e.commonEventObject.parameters.value; // get entry value from button parameters
  removeFromBlacklist(value); // remove from blacklist
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(buildBlacklistCard()) // rebuild and replace the blacklist card
    )
    .setNotification(
      CardService.newNotification().setText("Removed " + value + " from blacklist") // show toast
    )
    .build();
}

// Called when user submits the custom blacklist entry text input
function onAddCustomBlacklist(e) {
  var input = e.commonEventObject.formInputs; // get form data from the text input
  if (!input || !input.custom_entry) { // validate: did user type something?
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain or email address"))
      .build();
  }

  var value = input.custom_entry.stringInputs.value[0].trim().toLowerCase(); // get the typed value
  if (!value) { // validate: not empty after trimming
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain or email address"))
      .build();
  }

  // Auto-detect type: if it contains @, treat as email address; otherwise treat as domain
  var type = value.indexOf("@") !== -1 ? "email" : "domain";
  addToBlacklist(type, value); // add to blacklist

  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(buildBlacklistCard()) // refresh the blacklist card
    )
    .setNotification(
      CardService.newNotification().setText("Added " + value + " as " + type) // show toast
    )
    .build();
}

// Called when user clicks "Manage Blacklist" button — navigates to blacklist card
function onShowBlacklist(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(buildBlacklistCard()) // push new card onto navigation stack
    )
    .build();
}


// ──────────────────────────────────────────────
// Card 1: Verdict Card — the first screen the user sees
// Shows a big icon + verdict + score, plus action buttons
// ──────────────────────────────────────────────

function buildVerdictCard(emailData, result) {
  var score = result.score; // numeric score 0-100
  var verdict = result.verdict; // "Safe", "Suspicious", or "Malicious"

  var builder = CardService.newCardBuilder(); // create a new card

  // Card header — shown at the top with a small shield icon
  builder.setHeader(
    CardService.newCardHeader()
      .setTitle("Scan Result") // main title
      .setSubtitle(emailData.from) // subtitle = sender address
      .setImageUrl("https://img.icons8.com/color/48/security-checked--v1.png") // small shield icon
      .setImageStyle(CardService.ImageStyle.CIRCLE) // make icon circular
  );

  // ── Big verdict section — different icon/color/text based on score ──
  var verdictSection = CardService.newCardSection(); // create a section

  if (score <= 30) { // ── SAFE ──
    verdictSection.addWidget(CardService.newImage().setImageUrl( // big green checkmark image
      "https://img.icons8.com/color/240/verified-account.png"
    ));
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // "SAFE" in green + score
        "<b><font color='#1b5e20'>SAFE</font></b><br>" +
        "<font color='#2e7d32'>Risk Score: " + score + " / 100</font>"
      )
    );
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // reassurance message
        "<font color='#2e7d32'>This email passed security analysis.<br>No significant threats detected.</font>"
      )
    );
  } else if (score <= 60) { // ── SUSPICIOUS ──
    verdictSection.addWidget(CardService.newImage().setImageUrl( // orange warning icon
      "https://img.icons8.com/color/240/error--v1.png"
    ));
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // "SUSPICIOUS" in orange + score
        "<b><font color='#e65100'>SUSPICIOUS</font></b><br>" +
        "<font color='#ef6c00'>Risk Score: " + score + " / 100</font>"
      )
    );
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // caution message
        "<font color='#e65100'><b>Proceed with caution.</b><br>Suspicious indicators were found. Review the analysis.</font>"
      )
    );
  } else { // ── MALICIOUS (score > 60) ──
    verdictSection.addWidget(CardService.newImage().setImageUrl( // red X icon
      "https://img.icons8.com/color/240/cancel--v1.png"
    ));
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // "MALICIOUS" in red + score
        "<b><font color='#b71c1c'>MALICIOUS</font></b><br>" +
        "<font color='#c62828'>Risk Score: " + score + " / 100</font>"
      )
    );
    verdictSection.addWidget(
      CardService.newTextParagraph().setText( // warning message
        "<font color='#c62828'><b>Do not click links or open attachments.</b><br>Multiple threat indicators detected.</font>"
      )
    );
  }

  builder.addSection(verdictSection); // add verdict section to card

  // ── Email info section — subject and date ──
  var infoSection = CardService.newCardSection();
  // DecoratedText = label on top + text below. Good for key-value display.
  infoSection.addWidget(CardService.newDecoratedText().setTopLabel("Subject").setText(emailData.subject).setWrapText(true));
  infoSection.addWidget(CardService.newDecoratedText().setTopLabel("Date").setText(emailData.date));
  builder.addSection(infoSection);

  // ── Action buttons section ──
  var actionSection = CardService.newCardSection();
  // Button: "View Full Analysis" — clicking calls onShowAnalysis() which pushes the analysis card
  actionSection.addWidget(
    CardService.newTextButton()
      .setText("🔍 View Full Analysis")
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("onShowAnalysis") // function to call when clicked
          .setParameters({ messageId: emailData.messageId }) // pass messageId to retrieve cached result
      )
  );
  // Button: "View Scan History" — opens the Google Sheet in a new tab
  actionSection.addWidget(
    CardService.newTextButton()
      .setText("📊 View Scan History")
      .setOpenLink( // opens a URL instead of calling a function
        CardService.newOpenLink()
          .setUrl(getHistorySheetUrl()) // URL of the scan history Google Sheet
          .setOpenAs(CardService.OpenAs.FULL_SIZE) // open in full browser tab
      )
  );
  builder.addSection(actionSection);

  return builder.build(); // finalize and return the card object for Gmail to render
}

// Action handler: called when user clicks "View Full Analysis" on the verdict card
function onShowAnalysis(e) {
  var messageId = e.commonEventObject.parameters.messageId; // get messageId from button parameters
  var cached = CacheService.getUserCache().get("last_scan_" + messageId); // retrieve cached scan result

  if (!cached) { // cache expired (after 10 min) — can't show analysis without re-scanning
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Scan expired — reopen the email to rescan"))
      .build();
  }

  var data = JSON.parse(cached); // parse cached JSON back into {emailData, result}
  var card = buildAnalysisCard(data.emailData, data.result); // build the detailed analysis card

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card)) // push analysis card onto navigation stack
    .build();
}


// ──────────────────────────────────────────────
// Card 2: Analysis Card — detailed per-category breakdown
// Shows every signal that contributed to the score
// ──────────────────────────────────────────────

function buildAnalysisCard(emailData, result) {
  var score = result.score; // numeric score 0-100
  var verdict = result.verdict; // "Safe" / "Suspicious" / "Malicious"
  var breakdown = result.breakdown || []; // array of per-category results from backend
  var verdictColor = score <= 30 ? "#1b5e20" : (score <= 60 ? "#e65100" : "#b71c1c"); // green/orange/red

  var builder = CardService.newCardBuilder(); // create card

  // Card header with search icon
  builder.setHeader(
    CardService.newCardHeader()
      .setTitle("Detailed Analysis")
      .setSubtitle("Score: " + score + "/100 — " + verdict)
      .setImageUrl("https://img.icons8.com/color/48/search--v1.png") // magnifying glass icon
      .setImageStyle(CardService.ImageStyle.CIRCLE)
  );

  // ── Sort categories: issues first, clean ones last ──
  var categoriesWithIssues = []; // categories that have actionable signals
  var categoriesClean = []; // categories with no issues
  for (var i = 0; i < breakdown.length; i++) {
    if ((breakdown[i].signals || []).length > 0) {
      categoriesWithIssues.push(breakdown[i]); // has problems — show first
    } else {
      categoriesClean.push(breakdown[i]); // clean — show at bottom
    }
  }

  var allCategories = categoriesWithIssues.concat(categoriesClean); // issues first, then clean
  for (var i = 0; i < allCategories.length; i++) {
    var cat = allCategories[i]; // current category (e.g. {category: "content", contribution: 15, signals: [...]})
    var catLabel = categoryLabel(cat.category); // human-readable name, e.g. "Content Analysis"
    var catIcon = categoryIcon(cat.category); // emoji icon, e.g. "📝"

    // Build section header: "📝 Content Analysis — 15/30 pts"
    var scoreTag = cat.max_possible > 0
      ? "  —  " + cat.contribution + "/" + cat.max_possible + " pts" // show score contribution
      : ""; // no score tag for info-only categories (trust, history)
    var catSection = CardService.newCardSection().setHeader(
      catIcon + " " + catLabel + scoreTag // section header text
    );

    // ── Display signals (actionable issues) ──
    var signals = cat.signals || [];
    if (signals.length === 0) { // no issues in this category
      catSection.addWidget(
        CardService.newTextParagraph().setText(
          "<font color='#2e7d32'>✓ No issues detected</font>" // green checkmark
        )
      );
    } else { // has issues — show each one with severity icon
      for (var j = 0; j < signals.length; j++) {
        var sig = signals[j]; // e.g. {description: "SPF hard fail", severity: "high"}
        catSection.addWidget(
          CardService.newTextParagraph().setText(
            severityIcon(sig.severity) + " " + sig.description // e.g. "🟠 SPF hard fail — ..."
          )
        );
      }
    }

    // ── Display info signals (non-actionable context) in grey ──
    var info = cat.info || [];
    for (var k = 0; k < info.length; k++) {
      catSection.addWidget(
        CardService.newTextParagraph().setText(
          "<font color='#9e9e9e'>ℹ️ " + info[k].description + "</font>" // grey info text
        )
      );
    }

    builder.addSection(catSection); // add this category section to the card
  }

  // ── Actions section — scan history + blacklist management ──
  var actionsSection = CardService.newCardSection().setHeader("Actions");

  // Button: open scan history spreadsheet
  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("📊 View Scan History")
      .setOpenLink(
        CardService.newOpenLink()
          .setUrl(getHistorySheetUrl()) // get URL of the Google Sheet
          .setOpenAs(CardService.OpenAs.FULL_SIZE)
      )
  );

  // Show blacklist status if sender is blacklisted
  var senderEmail = parseSenderEmail(emailData.from); // extract email from From field
  var senderDomain = senderEmail.split("@").pop(); // extract domain

  if (emailData.blacklisted) { // sender is on the blacklist
    actionsSection.addWidget(
      CardService.newTextParagraph().setText(
        "<font color='#c62828'><b>⚫ Sender is on your blacklist</b></font>"
      )
    );
  }

  // Button: block this sender's domain
  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("🚫 Block domain: " + senderDomain)
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("onBlacklistDomain") // calls onBlacklistDomain() when clicked
          .setParameters({ domain: senderDomain }) // pass domain as parameter
      )
  );

  // Button: block this specific sender email
  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("🚫 Block sender: " + truncate(senderEmail, 35)) // truncate long emails
      .setOnClickAction(
        CardService.newAction()
          .setFunctionName("onBlacklistEmail") // calls onBlacklistEmail() when clicked
          .setParameters({ email: senderEmail }) // pass email as parameter
      )
  );

  // Button: open the blacklist management card
  actionsSection.addWidget(
    CardService.newTextButton()
      .setText("📋 Manage Blacklist (" + getBlacklist().length + ")") // show count of entries
      .setOnClickAction(
        CardService.newAction().setFunctionName("onShowBlacklist") // navigate to blacklist card
      )
  );

  builder.addSection(actionsSection);

  return builder.build(); // finalize and return card
}


// ──────────────────────────────────────────────
// Card 3: Blacklist Management Card
// Lets user add/remove entries from their personal blacklist
// ──────────────────────────────────────────────

function buildBlacklistCard() {
  var builder = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Manage Blacklist")
        .setSubtitle("Domains and emails that always raise alerts")
    );

  var list = getBlacklist(); // read current blacklist

  // ── Add custom entry section ──
  var addSection = CardService.newCardSection().setHeader("Add Entry");
  addSection.addWidget(
    CardService.newTextInput() // text input field
      .setFieldName("custom_entry") // form field name (used in onAddCustomBlacklist to read value)
      .setTitle("Domain or email address")
      .setHint("e.g., evil.com or scammer@evil.com") // placeholder hint text
  );
  addSection.addWidget(
    CardService.newTextButton()
      .setText("+ Add to Blacklist")
      .setOnClickAction(
        CardService.newAction().setFunctionName("onAddCustomBlacklist") // submit the form
      )
  );
  builder.addSection(addSection);

  // ── Current entries section ──
  var listSection = CardService.newCardSection().setHeader(
    "Current Entries (" + list.length + ")" // show count in header
  );

  if (list.length === 0) { // empty blacklist
    listSection.addWidget(
      CardService.newTextParagraph().setText("No blacklist entries yet.")
    );
  } else { // show each entry with a delete button
    for (var i = 0; i < list.length; i++) {
      var entry = list[i];
      var icon = entry.type === "domain" ? "🌐" : "📧"; // globe for domain, envelope for email
      listSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(entry.type.toUpperCase()) // "DOMAIN" or "EMAIL"
          .setText(icon + " " + entry.value) // "🌐 evil.com"
          .setButton( // delete button on the right side
            CardService.newImageButton()
              .setIconUrl("https://fonts.gstatic.com/s/i/googlematerialicons/delete/v6/24px.svg") // trash icon
              .setAltText("Remove")
              .setOnClickAction(
                CardService.newAction()
                  .setFunctionName("onRemoveBlacklistEntry") // call remove function
                  .setParameters({ value: entry.value }) // pass which entry to remove
              )
          )
      );
    }
  }
  builder.addSection(listSection);

  return builder.build(); // finalize and return card
}


// ──────────────────────────────────────────────
// Scan History — stored in a Google Sheet, one row per unique email
// ──────────────────────────────────────────────

var HISTORY_SHEET_NAME = "Email Threat Scorer — Scan History"; // name of the spreadsheet

// Get existing history sheet, or create a new one if it doesn't exist
function getOrCreateHistorySheet() {
  var props = PropertiesService.getUserProperties();
  var sheetId = props.getProperty("history_sheet_id"); // check if we cached the sheet ID before

  // Try to open the existing sheet
  if (sheetId) {
    try {
      return SpreadsheetApp.openById(sheetId); // open by cached ID
    } catch (err) {
      Logger.log("Cached sheet not found, creating new one"); // sheet was deleted — create fresh
    }
  }

  // Create a brand new spreadsheet with formatted headers
  var ss = SpreadsheetApp.create(HISTORY_SHEET_NAME); // create new spreadsheet
  var sheet = ss.getActiveSheet(); // get the default sheet
  sheet.setName("Scans"); // rename it to "Scans"
  sheet.appendRow([ // add header row
    "Timestamp", "From", "Subject", "Score", "Verdict",
    "Key Signals", "Links", "Attachments", "Message ID"
  ]);

  sheet.getRange(1, 1, 1, 9).setFontWeight("bold"); // bold the header row
  sheet.setFrozenRows(1); // freeze header row so it stays visible when scrolling

  // Set column widths for readability
  sheet.setColumnWidth(1, 160);  // Timestamp
  sheet.setColumnWidth(2, 220);  // From
  sheet.setColumnWidth(3, 280);  // Subject
  sheet.setColumnWidth(4, 60);   // Score
  sheet.setColumnWidth(5, 90);   // Verdict
  sheet.setColumnWidth(6, 400);  // Key Signals

  props.setProperty("history_sheet_id", ss.getId()); // cache the sheet ID for next time

  return ss;
}

// Query past scans from the same sender domain — used for repeat offender detection
// Returns {totalScans, avgScore, flaggedCount} or null if no history
function querySenderHistory(senderDomain) {
  try {
    var props = PropertiesService.getUserProperties();
    var sheetId = props.getProperty("history_sheet_id"); // get cached sheet ID
    if (!sheetId) return null; // no history sheet yet

    var ss;
    try { ss = SpreadsheetApp.openById(sheetId); } catch (err) { return null; } // sheet deleted
    var sheet = ss.getSheetByName("Scans");
    if (!sheet || sheet.getLastRow() < 2) return null; // empty sheet (only header row)

    var data = sheet.getDataRange().getValues(); // read all rows as 2D array
    // Columns: Timestamp(0), From(1), Subject(2), Score(3), Verdict(4), Signals(5), Links(6), Attachments(7), MsgId(8)

    var totalScans = 0; // how many unique emails from this domain
    var scoreSum = 0; // sum of scores (for average calculation)
    var flaggedCount = 0; // how many were Suspicious or Malicious
    var lowerDomain = senderDomain.toLowerCase();
    var seenIds = {};  // track message IDs we've already counted (deduplication)

    for (var i = 1; i < data.length; i++) { // start at 1 to skip header row
      var from = (data[i][1] || "").toString().toLowerCase(); // From column
      var msgId = (data[i][8] || "").toString(); // Message ID column (0-indexed: 8)
      if (from.indexOf(lowerDomain) !== -1 && !seenIds[msgId]) { // domain matches AND not a duplicate
        seenIds[msgId] = true; // mark as seen
        totalScans++;
        var score = parseInt(data[i][3]) || 0; // Score column
        scoreSum += score;
        var verdict = (data[i][4] || "").toString(); // Verdict column
        if (verdict === "Suspicious" || verdict === "Malicious") {
          flaggedCount++; // count how many times this domain was flagged
        }
      }
    }

    if (totalScans === 0) return null; // never seen this domain before

    return {
      totalScans: totalScans, // e.g. 5
      avgScore: Math.round(scoreSum / totalScans), // e.g. 42
      flaggedCount: flaggedCount // e.g. 3
    };
  } catch (err) {
    Logger.log("History query failed: " + err.message);
    return null; // graceful degradation
  }
}


// Log a scan result to the history sheet — called after every successful analysis
function logScanToHistory(emailData, result) {
  var ss = getOrCreateHistorySheet(); // get or create the spreadsheet
  var sheet = ss.getSheetByName("Scans");

  // Deduplication — check if this messageId is already in the sheet
  if (sheet.getLastRow() >= 2) { // only check if there are data rows
    var msgIdCol = sheet.getRange(2, 9, sheet.getLastRow() - 1, 1).getValues(); // read Message ID column
    for (var r = 0; r < msgIdCol.length; r++) {
      if (msgIdCol[r][0] === emailData.messageId) { // already logged
        Logger.log("Scan already logged for " + emailData.messageId + ", skipping");
        return; // don't write a duplicate row
      }
    }
  }

  // Summarize key signals (non-info only) into a single string for the log
  var keySignals = [];
  var breakdown = result.breakdown || [];
  for (var i = 0; i < breakdown.length; i++) {
    var signals = breakdown[i].signals || []; // actionable signals only (not info)
    for (var j = 0; j < signals.length; j++) {
      keySignals.push(signals[j].description); // collect all signal descriptions
    }
  }
  var signalSummary = keySignals.length > 0 ? keySignals.join("; ") : "No issues"; // join with semicolons

  // Append one row with all the scan data
  sheet.appendRow([
    new Date().toISOString(), // Timestamp
    emailData.from, // From
    emailData.subject, // Subject
    result.score, // Score (number)
    result.verdict, // Verdict ("Safe"/"Suspicious"/"Malicious")
    signalSummary, // Key Signals (semicolon-separated string)
    emailData.links.length, // number of links
    emailData.attachments.length, // number of attachments
    emailData.messageId // Message ID (for deduplication)
  ]);

  // Color-code the verdict cell for visual scanning
  var lastRow = sheet.getLastRow(); // the row we just wrote
  var verdictCell = sheet.getRange(lastRow, 5); // column 5 = Verdict
  if (result.verdict === "Safe") {
    verdictCell.setBackground("#c8e6c9"); // light green
  } else if (result.verdict === "Suspicious") {
    verdictCell.setBackground("#fff9c4"); // light yellow
  } else {
    verdictCell.setBackground("#ffcdd2"); // light red
  }
}

// Returns the URL of the scan history Google Sheet (for the "View Scan History" button)
function getHistorySheetUrl() {
  var ss = getOrCreateHistorySheet(); // get or create the sheet
  return ss.getUrl(); // returns something like "https://docs.google.com/spreadsheets/d/abc123/edit"
}


// ──────────────────────────────────────────────
// Card UI — Setup Card (shown when backend is not configured)
// ──────────────────────────────────────────────

function buildSetupCard(emailData) {
  var builder = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Threat Scorer")
        .setSubtitle("Setup Required")
    );

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newTextParagraph().setText(
      "<b>Backend not configured.</b><br><br>" +
      "Set BACKEND_URL and API_SECRET in Script Properties."
    )
  );
  section.addWidget(CardService.newDecoratedText().setTopLabel("From").setText(emailData.from)); // show who sent it
  section.addWidget(CardService.newDecoratedText().setTopLabel("Subject").setText(emailData.subject)); // show subject
  builder.addSection(section);

  return builder.build();
}

// Error card — shown when backend call fails or other errors occur
function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Threat Scorer")
        .setSubtitle("Error")
    )
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          "<font color='#c62828'><b>⚠ Analysis Failed</b></font><br><br>" + message // show error in red
        )
      )
    )
    .build();
}


// ──────────────────────────────────────────────
// Utility Functions — small helpers used throughout the code
// ──────────────────────────────────────────────

// Extract email address from "Display Name <email@domain.com>" format
function parseSenderEmail(fromField) {
  var match = /^(.*?)\s*<([^>]+)>/.exec(fromField); // regex: capture what's inside < >
  return match ? match[2].toLowerCase() : fromField.toLowerCase(); // return email, or the whole string if no < >
}

// Truncate a string to maxLen characters, adding "..." if truncated
function truncate(str, maxLen) {
  if (!str) return "";
  return str.length > maxLen ? str.substring(0, maxLen) + "..." : str;
}

// Capitalize first letter of a string
function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// Map severity level to a colored circle emoji for the UI
function severityIcon(severity) {
  switch (severity) {
    case "critical": return "🔴"; // red
    case "high":     return "🟠"; // orange
    case "medium":   return "🟡"; // yellow
    case "low":      return "🔵"; // blue
    default:         return "⚪"; // white/grey
  }
}

// Map severity level to a hex color (used for text coloring)
function severityColor(severity) {
  switch (severity) {
    case "critical": return "#b71c1c"; // dark red
    case "high":     return "#d84315"; // dark orange
    case "medium":   return "#f57f17"; // dark yellow
    case "low":      return "#1565c0"; // dark blue
    default:         return "#757575"; // grey
  }
}

// Map category name to an emoji icon for section headers
function categoryIcon(category) {
  switch (category) {
    case "sender":      return "👤"; // person
    case "headers":     return "📨"; // mail
    case "content":     return "📝"; // notepad
    case "links":       return "🔗"; // chain link
    case "attachments": return "📎"; // paperclip
    case "threat_intel": return "🚨";
    case "history":     return "📈"; // chart (scan history signals)
    case "blacklist":   return "⛔"; // stop sign
    case "trust":       return "🔒"; // lock (sender trust info)
    default:            return "📌"; // pin
  }
}

// Map category name to a human-readable label for section headers
function categoryLabel(category) {
  switch (category) {
    case "sender":      return "Sender Analysis";
    case "headers":     return "Authentication";
    case "content":     return "Content Analysis";
    case "links":       return "Link Analysis";
    case "attachments": return "Attachments";
    case "threat_intel": return "Threat Intelligence";
    case "history":     return "Scan History";
    case "blacklist":   return "Blacklist";
    case "trust":       return "Sender Trust";
    default:            return capitalize(category); // fallback: capitalize the raw name
  }
}

// Convert bytes to human-readable format (used for attachment display)
function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B"; // bytes
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB"; // kilobytes
  return (bytes / 1048576).toFixed(1) + " MB"; // megabytes
}
