/**
 * Gmail Add-on — Email Threat Scorer
 *
 * Frontend: extracts email data, sends it to the Cloud Function backend,
 * and renders a scored verdict card with per-signal explainability.
 * Includes user-managed blacklist (PropertiesService) and scan history (Google Sheets).
 */

// ── Configuration — read from Script Properties (set in Apps Script editor) ──
var BACKEND_URL = PropertiesService.getScriptProperties().getProperty("BACKEND_URL") || "";
var API_SECRET  = PropertiesService.getScriptProperties().getProperty("API_SECRET")  || "dev-secret-key";


// ──────────────────────────────────────────────
// Entry Point — Gmail calls this when user opens any email
// ──────────────────────────────────────────────

function onEmailOpen(e) {
  var messageId = e.messageMetadata.messageId;
  // Authorize access to this specific email via the contextual trigger token
  GmailApp.setCurrentMessageAccessToken(e.messageMetadata.accessToken);

  var msg = GmailApp.getMessageById(messageId);
  var emailData = extractEmailData(msg, messageId, e.messageMetadata.accessToken);

  // Check blacklist before sending to backend
  var blCheck = checkBlacklist(emailData);
  emailData.blacklisted = blCheck.matched;
  if (blCheck.matched) {
    emailData.blacklistMatch = { matchType: blCheck.matchType, matchValue: blCheck.matchValue };
  }

  // Query scan history for repeat offender / baseline deviation detection
  var senderEmail = parseSenderEmail(emailData.from);
  var senderDomain = senderEmail.split("@").pop();
  try {
    var history = querySenderHistory(senderDomain);
    if (history) { emailData.senderHistory = history; }
  } catch (histErr) {
    Logger.log("History query skipped: " + histErr.message);
  }

  if (BACKEND_URL) {
    try {
      var result = callBackend(emailData);
      // Log scan to history (best-effort — don't crash if Sheet errors)
      try { logScanToHistory(emailData, result); } catch (logErr) {
        Logger.log("History log failed: " + logErr.message);
      }
      // Cache result for 10 min so "View Full Analysis" can retrieve it without re-scanning
      CacheService.getUserCache().put(
        "last_scan_" + emailData.messageId,
        JSON.stringify({ emailData: emailData, result: result }),
        600
      );
      return [buildVerdictCard(emailData, result)];
    } catch (err) {
      return [buildErrorCard("Backend error: " + err.message)];
    }
  } else {
    return [buildSetupCard(emailData)];
  }
}


// ──────────────────────────────────────────────
// Backend Communication
// ──────────────────────────────────────────────

function callBackend(emailData) {
  var options = {
    method: "post",
    contentType: "application/json",
    headers: { "X-API-Key": API_SECRET },
    payload: JSON.stringify(emailData),
    muteHttpExceptions: true  // let us handle HTTP errors manually
  };

  var response = UrlFetchApp.fetch(BACKEND_URL, options);
  var code = response.getResponseCode();

  if (code !== 200) {
    throw new Error("HTTP " + code + ": " + response.getContentText().substring(0, 200));
  }

  return JSON.parse(response.getContentText());
}


// ──────────────────────────────────────────────
// Data Extraction
// ──────────────────────────────────────────────

function extractEmailData(msg, messageId, accessToken) {
  var headers = fetchRawHeaders(messageId, accessToken);
  var htmlBody = msg.getBody() || "";
  var plainBody = msg.getPlainBody() || "";

  return {
    messageId: messageId,
    subject: msg.getSubject() || "(no subject)",
    from: msg.getFrom(),
    to: msg.getTo(),
    cc: msg.getCc() || "",
    replyTo: msg.getReplyTo() || "",
    date: msg.getDate().toISOString(),
    spf: extractHeaderValue(headers, "Received-SPF"),
    dkim: extractHeaderValue(headers, "DKIM-Signature"),
    authResults: extractHeaderValue(headers, "Authentication-Results"),
    plainBody: plainBody,
    bodyLength: plainBody.length,
    links: extractLinks(htmlBody),
    attachments: extractAttachmentInfo(msg)
  };
}

/**
 * Extracts email headers by parsing the raw message content.
 * We use GmailApp.getRawContent() instead of the Gmail REST API because
 * the REST API via contextual trigger tokens doesn't reliably return
 * authentication headers (SPF, DKIM, DMARC).
 * Only parses the header section (before the first blank line).
 */
function fetchRawHeaders(messageId, accessToken) {
  try {
    var msg = GmailApp.getMessageById(messageId);
    var raw = msg.getRawContent();

    // Headers end at the first blank line — only parse that part
    var headerEnd = raw.indexOf("\r\n\r\n");
    if (headerEnd === -1) headerEnd = raw.indexOf("\n\n");
    var headerSection = headerEnd > 0 ? raw.substring(0, Math.min(headerEnd, 50000)) : raw.substring(0, 50000);

    return parseRawHeaders(headerSection);
  } catch (err) {
    Logger.log("Header fetch failed: " + err.message);
    return [];
  }
}

/**
 * Parses raw email header text into [{name, value}] objects.
 * Handles multi-line headers (continuation lines starting with whitespace).
 */
function parseRawHeaders(headerText) {
  var headers = [];
  var lines = headerText.split(/\r?\n/);
  var currentName = "";
  var currentValue = "";

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];

    if (/^\s/.test(line) && currentName) {
      // Continuation line — append to previous header
      currentValue += " " + line.trim();
    } else {
      if (currentName) {
        headers.push({ name: currentName, value: currentValue });
      }
      var colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        currentName = line.substring(0, colonIdx).trim();
        currentValue = line.substring(colonIdx + 1).trim();
      } else {
        currentName = "";
        currentValue = "";
      }
    }
  }
  if (currentName) {
    headers.push({ name: currentName, value: currentValue });
  }

  return headers;
}

// Search headers array for a specific header by name (case-insensitive)
function extractHeaderValue(headers, name) {
  var lowerName = name.toLowerCase();
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].name.toLowerCase() === lowerName) return headers[i].value;
  }
  return "";
}

// Extract all <a href="...">text</a> links from HTML body
function extractLinks(html) {
  var links = [];
  var regex = /<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  var match;
  while ((match = regex.exec(html)) !== null) {
    var href = match[1].trim();
    var text = match[2].replace(/<[^>]+>/g, "").trim();
    if (href && !href.toLowerCase().startsWith("mailto:")) {
      links.push({ href: href, text: text });
    }
  }
  return links;
}

// Extract metadata for each attachment (name, MIME type, size, SHA-256 hash)
function extractAttachmentInfo(msg) {
  var attachments = msg.getAttachments();
  if (!attachments || attachments.length === 0) return [];
  return attachments.map(function(att) {
    var bytes = att.getBytes();
    return {
      name: att.getName(),
      contentType: att.getContentType(),
      size: bytes.length,
      sha256: computeSHA256(bytes)
    };
  });
}

// Compute SHA-256 hash of a byte array — returns hex string
function computeSHA256(bytes) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map(function(b) {
    // (b+256)%256 handles Java's signed bytes (-128..127 → 0..255)
    return ("0" + ((b + 256) % 256).toString(16)).slice(-2);
  }).join("");
}


// ──────────────────────────────────────────────
// Blacklist — stored as JSON array in UserProperties (per-user)
// Format: [{"type":"domain","value":"evil.com"}, {"type":"email","value":"scam@evil.com"}]
// ──────────────────────────────────────────────

function getBlacklist() {
  var json = PropertiesService.getUserProperties().getProperty("blacklist");
  return json ? JSON.parse(json) : [];
}

function saveBlacklist(list) {
  PropertiesService.getUserProperties().setProperty("blacklist", JSON.stringify(list));
}

function addToBlacklist(type, value) {
  var list = getBlacklist();
  var lowerVal = value.toLowerCase().trim();
  var exists = list.some(function(entry) {
    return entry.type === type && entry.value === lowerVal;
  });
  if (!exists) {
    list.push({ type: type, value: lowerVal });
    saveBlacklist(list);
  }
  return list;
}

function removeFromBlacklist(value) {
  var list = getBlacklist();
  list = list.filter(function(entry) {
    return entry.value !== value.toLowerCase().trim();
  });
  saveBlacklist(list);
  return list;
}

// Check if sender matches any blacklist entry (by email or domain)
function checkBlacklist(emailData) {
  var list = getBlacklist();
  if (list.length === 0) return { matched: false };

  var fromField = emailData.from || "";
  var match = /^(.*?)\s*<([^>]+)>/.exec(fromField);
  var email = match ? match[2].toLowerCase() : fromField.toLowerCase();
  var domain = email.split("@").pop();

  for (var i = 0; i < list.length; i++) {
    var entry = list[i];
    if (entry.type === "email" && entry.value === email) {
      return { matched: true, matchType: "email", matchValue: entry.value };
    }
    if (entry.type === "domain" && entry.value === domain) {
      return { matched: true, matchType: "domain", matchValue: entry.value };
    }
  }
  return { matched: false };
}


// ──────────────────────────────────────────────
// Blacklist — Action Handlers (called on button clicks)
// ──────────────────────────────────────────────

function onBlacklistDomain(e) {
  var domain = e.commonEventObject.parameters.domain;
  addToBlacklist("domain", domain);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + domain + " to blacklist"))
    .build();
}

function onBlacklistEmail(e) {
  var email = e.commonEventObject.parameters.email;
  addToBlacklist("email", email);
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Added " + email + " to blacklist"))
    .build();
}

function onRemoveBlacklistEntry(e) {
  var value = e.commonEventObject.parameters.value;
  removeFromBlacklist(value);
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildBlacklistCard()))
    .setNotification(CardService.newNotification().setText("Removed " + value + " from blacklist"))
    .build();
}

function onAddCustomBlacklist(e) {
  var input = e.commonEventObject.formInputs;
  if (!input || !input.custom_entry) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain or email address"))
      .build();
  }

  var value = input.custom_entry.stringInputs.value[0].trim().toLowerCase();
  if (!value) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Please enter a domain or email address"))
      .build();
  }

  // Auto-detect: contains @ → email, otherwise → domain
  var type = value.indexOf("@") !== -1 ? "email" : "domain";
  addToBlacklist(type, value);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildBlacklistCard()))
    .setNotification(CardService.newNotification().setText("Added " + value + " as " + type))
    .build();
}

function onShowBlacklist(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildBlacklistCard()))
    .build();
}


// ──────────────────────────────────────────────
// Card 1: Verdict Card — big icon + score + verdict
// ──────────────────────────────────────────────

function buildVerdictCard(emailData, result) {
  var score = result.score;
  var verdict = result.verdict;
  var builder = CardService.newCardBuilder();

  builder.setHeader(
    CardService.newCardHeader()
      .setTitle("Scan Result")
      .setSubtitle(emailData.from)
      .setImageUrl("https://img.icons8.com/color/48/security-checked--v1.png")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
  );

  var verdictSection = CardService.newCardSection();

  if (score <= 30) {
    verdictSection.addWidget(CardService.newImage().setImageUrl("https://img.icons8.com/color/240/verified-account.png"));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<b><font color='#1b5e20'>SAFE</font></b><br><font color='#2e7d32'>Risk Score: " + score + " / 100</font>"
    ));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<font color='#2e7d32'>This email passed security analysis.<br>No significant threats detected.</font>"
    ));
  } else if (score <= 60) {
    verdictSection.addWidget(CardService.newImage().setImageUrl("https://img.icons8.com/color/240/error--v1.png"));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<b><font color='#e65100'>SUSPICIOUS</font></b><br><font color='#ef6c00'>Risk Score: " + score + " / 100</font>"
    ));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<font color='#e65100'><b>Proceed with caution.</b><br>Suspicious indicators were found. Review the analysis.</font>"
    ));
  } else {
    verdictSection.addWidget(CardService.newImage().setImageUrl("https://img.icons8.com/color/240/cancel--v1.png"));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<b><font color='#b71c1c'>MALICIOUS</font></b><br><font color='#c62828'>Risk Score: " + score + " / 100</font>"
    ));
    verdictSection.addWidget(CardService.newTextParagraph().setText(
      "<font color='#c62828'><b>Do not click links or open attachments.</b><br>Multiple threat indicators detected.</font>"
    ));
  }

  builder.addSection(verdictSection);

  var infoSection = CardService.newCardSection();
  infoSection.addWidget(CardService.newDecoratedText().setTopLabel("Subject").setText(emailData.subject).setWrapText(true));
  infoSection.addWidget(CardService.newDecoratedText().setTopLabel("Date").setText(emailData.date));
  builder.addSection(infoSection);

  var actionSection = CardService.newCardSection();
  actionSection.addWidget(
    CardService.newTextButton().setText("🔍 View Full Analysis")
      .setOnClickAction(CardService.newAction().setFunctionName("onShowAnalysis").setParameters({ messageId: emailData.messageId }))
  );
  actionSection.addWidget(
    CardService.newTextButton().setText("📊 View Scan History")
      .setOpenLink(CardService.newOpenLink().setUrl(getHistorySheetUrl()).setOpenAs(CardService.OpenAs.FULL_SIZE))
  );
  builder.addSection(actionSection);

  return builder.build();
}

// Navigate from verdict card to detailed analysis card (retrieves cached result)
function onShowAnalysis(e) {
  var messageId = e.commonEventObject.parameters.messageId;
  var cached = CacheService.getUserCache().get("last_scan_" + messageId);

  if (!cached) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText("Scan expired — reopen the email to rescan"))
      .build();
  }

  var data = JSON.parse(cached);
  var card = buildAnalysisCard(data.emailData, data.result);

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(card))
    .build();
}


// ──────────────────────────────────────────────
// Card 2: Analysis Card — per-category signal breakdown
// ──────────────────────────────────────────────

function buildAnalysisCard(emailData, result) {
  var score = result.score;
  var verdict = result.verdict;
  var breakdown = result.breakdown || [];

  var builder = CardService.newCardBuilder();
  builder.setHeader(
    CardService.newCardHeader()
      .setTitle("Detailed Analysis")
      .setSubtitle("Score: " + score + "/100 — " + verdict)
      .setImageUrl("https://img.icons8.com/color/48/search--v1.png")
      .setImageStyle(CardService.ImageStyle.CIRCLE)
  );

  // Sort: categories with issues first, clean ones last
  var categoriesWithIssues = [];
  var categoriesClean = [];
  for (var i = 0; i < breakdown.length; i++) {
    if ((breakdown[i].signals || []).length > 0) {
      categoriesWithIssues.push(breakdown[i]);
    } else {
      categoriesClean.push(breakdown[i]);
    }
  }

  var allCategories = categoriesWithIssues.concat(categoriesClean);
  for (var i = 0; i < allCategories.length; i++) {
    var cat = allCategories[i];
    var catLabel = categoryLabel(cat.category);
    var catIcon = categoryIcon(cat.category);

    var scoreTag = cat.max_possible > 0
      ? "  —  " + cat.contribution + "/" + cat.max_possible + " pts"
      : "";
    var catSection = CardService.newCardSection().setHeader(catIcon + " " + catLabel + scoreTag);

    var signals = cat.signals || [];
    if (signals.length === 0) {
      catSection.addWidget(CardService.newTextParagraph().setText("<font color='#2e7d32'>✓ No issues detected</font>"));
    } else {
      for (var j = 0; j < signals.length; j++) {
        catSection.addWidget(CardService.newTextParagraph().setText(
          severityIcon(signals[j].severity) + " " + signals[j].description
        ));
      }
    }

    var info = cat.info || [];
    for (var k = 0; k < info.length; k++) {
      catSection.addWidget(CardService.newTextParagraph().setText(
        "<font color='#9e9e9e'>ℹ️ " + info[k].description + "</font>"
      ));
    }

    builder.addSection(catSection);
  }

  // ── Actions: history + blacklist ──
  var actionsSection = CardService.newCardSection().setHeader("Actions");

  actionsSection.addWidget(
    CardService.newTextButton().setText("📊 View Scan History")
      .setOpenLink(CardService.newOpenLink().setUrl(getHistorySheetUrl()).setOpenAs(CardService.OpenAs.FULL_SIZE))
  );

  var senderEmail = parseSenderEmail(emailData.from);
  var senderDomain = senderEmail.split("@").pop();

  if (emailData.blacklisted) {
    actionsSection.addWidget(CardService.newTextParagraph().setText(
      "<font color='#c62828'><b>⚫ Sender is on your blacklist</b></font>"
    ));
  }

  actionsSection.addWidget(
    CardService.newTextButton().setText("🚫 Block domain: " + senderDomain)
      .setOnClickAction(CardService.newAction().setFunctionName("onBlacklistDomain").setParameters({ domain: senderDomain }))
  );
  actionsSection.addWidget(
    CardService.newTextButton().setText("🚫 Block sender: " + truncate(senderEmail, 35))
      .setOnClickAction(CardService.newAction().setFunctionName("onBlacklistEmail").setParameters({ email: senderEmail }))
  );
  actionsSection.addWidget(
    CardService.newTextButton().setText("📋 Manage Blacklist (" + getBlacklist().length + ")")
      .setOnClickAction(CardService.newAction().setFunctionName("onShowBlacklist"))
  );

  builder.addSection(actionsSection);
  return builder.build();
}


// ──────────────────────────────────────────────
// Card 3: Blacklist Management
// ──────────────────────────────────────────────

function buildBlacklistCard() {
  var builder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Manage Blacklist").setSubtitle("Domains and emails that always raise alerts"));

  var list = getBlacklist();

  var addSection = CardService.newCardSection().setHeader("Add Entry");
  addSection.addWidget(CardService.newTextInput().setFieldName("custom_entry").setTitle("Domain or email address").setHint("e.g., evil.com or scammer@evil.com"));
  addSection.addWidget(CardService.newTextButton().setText("+ Add to Blacklist").setOnClickAction(CardService.newAction().setFunctionName("onAddCustomBlacklist")));
  builder.addSection(addSection);

  var listSection = CardService.newCardSection().setHeader("Current Entries (" + list.length + ")");
  if (list.length === 0) {
    listSection.addWidget(CardService.newTextParagraph().setText("No blacklist entries yet."));
  } else {
    for (var i = 0; i < list.length; i++) {
      var entry = list[i];
      var icon = entry.type === "domain" ? "🌐" : "📧";
      listSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(entry.type.toUpperCase())
          .setText(icon + " " + entry.value)
          .setButton(
            CardService.newImageButton()
              .setIconUrl("https://fonts.gstatic.com/s/i/googlematerialicons/delete/v6/24px.svg")
              .setAltText("Remove")
              .setOnClickAction(CardService.newAction().setFunctionName("onRemoveBlacklistEntry").setParameters({ value: entry.value }))
          )
      );
    }
  }
  builder.addSection(listSection);
  return builder.build();
}


// ──────────────────────────────────────────────
// Scan History (Google Sheets)
// ──────────────────────────────────────────────

var HISTORY_SHEET_NAME = "Email Threat Scorer — Scan History";

// Get existing history sheet or create a new one with formatted headers
function getOrCreateHistorySheet() {
  var props = PropertiesService.getUserProperties();
  var sheetId = props.getProperty("history_sheet_id");

  if (sheetId) {
    try { return SpreadsheetApp.openById(sheetId); } catch (err) {
      Logger.log("Cached sheet not found, creating new one");
    }
  }

  var ss = SpreadsheetApp.create(HISTORY_SHEET_NAME);
  var sheet = ss.getActiveSheet();
  sheet.setName("Scans");
  sheet.appendRow(["Timestamp", "From", "Subject", "Score", "Verdict", "Key Signals", "Links", "Attachments", "Message ID"]);
  sheet.getRange(1, 1, 1, 9).setFontWeight("bold");
  sheet.setFrozenRows(1);
  sheet.setColumnWidth(1, 160);
  sheet.setColumnWidth(2, 220);
  sheet.setColumnWidth(3, 280);
  sheet.setColumnWidth(4, 60);
  sheet.setColumnWidth(5, 90);
  sheet.setColumnWidth(6, 400);

  props.setProperty("history_sheet_id", ss.getId());
  return ss;
}

/**
 * Query past scans from the same sender domain.
 * Returns {totalScans, avgScore, flaggedCount} or null.
 * Deduplicates by messageId to avoid counting rescans.
 */
function querySenderHistory(senderDomain) {
  try {
    var props = PropertiesService.getUserProperties();
    var sheetId = props.getProperty("history_sheet_id");
    if (!sheetId) return null;

    var ss;
    try { ss = SpreadsheetApp.openById(sheetId); } catch (err) { return null; }
    var sheet = ss.getSheetByName("Scans");
    if (!sheet || sheet.getLastRow() < 2) return null;

    var data = sheet.getDataRange().getValues();
    var totalScans = 0;
    var scoreSum = 0;
    var flaggedCount = 0;
    var lowerDomain = senderDomain.toLowerCase();
    var seenIds = {};

    for (var i = 1; i < data.length; i++) {
      var from = (data[i][1] || "").toString().toLowerCase();
      var msgId = (data[i][8] || "").toString();
      if (from.indexOf(lowerDomain) !== -1 && !seenIds[msgId]) {
        seenIds[msgId] = true;
        totalScans++;
        var score = parseInt(data[i][3]) || 0;
        scoreSum += score;
        var verdict = (data[i][4] || "").toString();
        if (verdict === "Suspicious" || verdict === "Malicious") {
          flaggedCount++;
        }
      }
    }

    if (totalScans === 0) return null;
    return { totalScans: totalScans, avgScore: Math.round(scoreSum / totalScans), flaggedCount: flaggedCount };
  } catch (err) {
    Logger.log("History query failed: " + err.message);
    return null;
  }
}

// Log scan result to history sheet (deduplicated by messageId)
function logScanToHistory(emailData, result) {
  var ss = getOrCreateHistorySheet();
  var sheet = ss.getSheetByName("Scans");

  // Skip if this email was already logged
  if (sheet.getLastRow() >= 2) {
    var msgIdCol = sheet.getRange(2, 9, sheet.getLastRow() - 1, 1).getValues();
    for (var r = 0; r < msgIdCol.length; r++) {
      if (msgIdCol[r][0] === emailData.messageId) return;
    }
  }

  // Collect signal descriptions for the summary column
  var keySignals = [];
  var breakdown = result.breakdown || [];
  for (var i = 0; i < breakdown.length; i++) {
    var signals = breakdown[i].signals || [];
    for (var j = 0; j < signals.length; j++) {
      keySignals.push(signals[j].description);
    }
  }

  sheet.appendRow([
    new Date().toISOString(), emailData.from, emailData.subject,
    result.score, result.verdict,
    keySignals.length > 0 ? keySignals.join("; ") : "No issues",
    emailData.links.length, emailData.attachments.length, emailData.messageId
  ]);

  // Color-code the verdict cell
  var lastRow = sheet.getLastRow();
  var verdictCell = sheet.getRange(lastRow, 5);
  if (result.verdict === "Safe") verdictCell.setBackground("#c8e6c9");
  else if (result.verdict === "Suspicious") verdictCell.setBackground("#fff9c4");
  else verdictCell.setBackground("#ffcdd2");
}

function getHistorySheetUrl() {
  return getOrCreateHistorySheet().getUrl();
}


// ──────────────────────────────────────────────
// Setup / Error Cards
// ──────────────────────────────────────────────

function buildSetupCard(emailData) {
  var builder = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Email Threat Scorer").setSubtitle("Setup Required"));
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText("<b>Backend not configured.</b><br><br>Set BACKEND_URL and API_SECRET in Script Properties."));
  section.addWidget(CardService.newDecoratedText().setTopLabel("From").setText(emailData.from));
  section.addWidget(CardService.newDecoratedText().setTopLabel("Subject").setText(emailData.subject));
  builder.addSection(section);
  return builder.build();
}

function buildErrorCard(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Email Threat Scorer").setSubtitle("Error"))
    .addSection(CardService.newCardSection().addWidget(
      CardService.newTextParagraph().setText("<font color='#c62828'><b>⚠ Analysis Failed</b></font><br><br>" + message)
    ))
    .build();
}


// ──────────────────────────────────────────────
// Utility
// ──────────────────────────────────────────────

// Extract email address from "Display Name <email@domain.com>" format
function parseSenderEmail(fromField) {
  var match = /^(.*?)\s*<([^>]+)>/.exec(fromField);
  return match ? match[2].toLowerCase() : fromField.toLowerCase();
}

function truncate(str, maxLen) {
  if (!str) return "";
  return str.length > maxLen ? str.substring(0, maxLen) + "..." : str;
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

// Map severity → colored circle emoji
function severityIcon(severity) {
  switch (severity) {
    case "critical": return "🔴";
    case "high":     return "🟠";
    case "medium":   return "🟡";
    case "low":      return "🔵";
    default:         return "⚪";
  }
}

function severityColor(severity) {
  switch (severity) {
    case "critical": return "#b71c1c";
    case "high":     return "#d84315";
    case "medium":   return "#f57f17";
    case "low":      return "#1565c0";
    default:         return "#757575";
  }
}

// Map category name → emoji icon
function categoryIcon(category) {
  switch (category) {
    case "sender":      return "👤";
    case "headers":     return "📨";
    case "content":     return "📝";
    case "links":       return "🔗";
    case "attachments": return "📎";
    case "threat_intel": return "🚨";
    case "history":     return "📈";
    case "blacklist":   return "⛔";
    case "trust":       return "🔒";
    default:            return "📌";
  }
}

// Map category name → human-readable label
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
    default:            return capitalize(category);
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}


// ──────────────────────────────────────────────
// Test function — sends EICAR hash to backend to verify VirusTotal integration
// Run manually from Apps Script editor to test
// ──────────────────────────────────────────────

function testVirusTotal() {
  var fakeEmail = {
    messageId: "test-vt-check",
    from: "test@test.com",
    to: "you@gmail.com",
    subject: "VirusTotal Test",
    plainBody: "test",
    date: new Date().toISOString(),
    spf: "", dkim: "", authResults: "", replyTo: "", cc: "",
    bodyLength: 4,
    links: [],
    attachments: [{
      name: "eicar.txt",
      contentType: "text/plain",
      size: 68,
      sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    }]
  };

  var result = callBackend(fakeEmail);
  Logger.log("Score: " + result.score);
  Logger.log("Verdict: " + result.verdict);
  Logger.log(JSON.stringify(result.breakdown, null, 2));
}
