/**
 * Gmail Add-on contextual trigger entry point.
 * Shows a loading card first, then resolves into a result card after backend analysis.
 */
function onGmailMessageOpen(e) {
  return [buildLoadingCard(), buildResultCard_(e)];
}

function buildLoadingCard() {
  const section = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText("Analyzing message security signals...")
  );

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(section)
    .build();
}

function buildResultCard_(e) {
  try {
    const payload = buildAnalyzePayload_(e);
    const analysis = callBackend_(payload);
    return createVerdictCard_(analysis);
  } catch (error) {
    return buildErrorCard_(error);
  }
}

function buildAnalyzePayload_(e) {
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);

  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const bodyText = message.getPlainBody() || "";

  return {
    headers: {
      subject: message.getSubject(),
      from: message.getFrom(),
      replyTo: message.getReplyTo(),
      returnPath: "",
      authenticationResults: ""
    },
    bodyText: bodyText.substring(0, 15000),
    attachments: message.getAttachments().map(function (attachment) {
      return {
        fileName: attachment.getName(),
        mimeType: attachment.getContentType(),
        sizeBytes: attachment.getSize()
      };
    })
  };
}

function callBackend_(payload) {
  const scriptProperties = PropertiesService.getScriptProperties();
  const backendUrl = scriptProperties.getProperty("BACKEND_URL");

  if (!backendUrl) {
    throw new Error("Missing BACKEND_URL in script properties.");
  }

  const response = UrlFetchApp.fetch(backendUrl + "/analyze", {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const statusCode = response.getResponseCode();
  const body = response.getContentText();

  if (statusCode < 200 || statusCode >= 300) {
    throw new Error("Backend request failed with status " + statusCode + ": " + body);
  }

  const parsed = JSON.parse(body);
  if (
    typeof parsed.score !== "number" ||
    typeof parsed.verdict !== "string" ||
    !Array.isArray(parsed.reasoning)
  ) {
    throw new Error("Backend response format is invalid.");
  }

  return parsed;
}

function createVerdictCard_(analysis) {
  const style = verdictStyle_(analysis.verdict);
  const scoreText = "<b>" + analysis.score + "/100</b>";
  const verdictText = "Verdict: <b>" + analysis.verdict + "</b>";
  const explanationText =
    analysis.classificationExplanation ||
    "This verdict is based on the detected risk signals in headers, body text, and links.";
  const scoreView = buildScoreView_(analysis.score, analysis.verdict);
  const alertText =
    style.alertPrefix +
    " " +
    (analysis.verdict === "Safe"
      ? "No severe threat signal was detected."
      : "Potential threat detected. Review the reasons below.");

  const summarySection = CardService.newCardSection()
    .setHeader(style.sectionTitle)
    .addWidget(CardService.newTextParagraph().setText("<b>" + alertText + "</b>"))
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Risk Score")
        .setText(scoreText + "  " + scoreView.label)
        .setBottomLabel(scoreView.bar + "  " + scoreView.summary)
        .setWrapText(true)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Classification")
        .setText(style.icon + " " + verdictText)
        .setWrapText(true)
    )
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("Why this classification")
        .setText(explanationText)
        .setWrapText(true)
    );

  const keySignalsSection = CardService.newCardSection().setHeader("Top Signals");
  const topSignals = analysis.topSignals || [];
  if (topSignals.length === 0) {
    keySignalsSection.addWidget(
      CardService.newTextParagraph().setText("- No major signals were triggered.")
    );
  } else {
    topSignals.forEach(function (signal) {
      keySignalsSection.addWidget(CardService.newTextParagraph().setText("- " + signal));
    });
  }

  const reasoningSection = CardService.newCardSection().setHeader("Detailed Explanation");
  if (analysis.reasoning.length === 0) {
    reasoningSection.addWidget(
      CardService.newTextParagraph().setText("No suspicious indicators were detected.")
    );
  } else {
    analysis.reasoning.forEach(function (reason) {
      reasoningSection.addWidget(CardService.newTextParagraph().setText("- " + reason));
    });
  }

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Malicious Email Scorer")
        .setSubtitle(style.label)
    )
    .addSection(summarySection)
    .addSection(keySignalsSection)
    .addSection(reasoningSection)
    .build();
}

function verdictStyle_(verdict) {
  if (verdict === "Malicious") {
    return {
      label: "High Risk (Red)",
      icon: "\u26D4",
      alertPrefix: "\uD83D\uDD34 ALERT",
      sectionTitle: "Threat Analysis"
    };
  }

  if (verdict === "Suspicious") {
    return {
      label: "Medium Risk (Orange)",
      icon: "\u26A0",
      alertPrefix: "\uD83D\uDFE0 Warning",
      sectionTitle: "Threat Analysis"
    };
  }

  return {
    label: "Low Risk (Green)",
    icon: "\u2705",
    alertPrefix: "\uD83D\uDFE2 Normal",
    sectionTitle: "Threat Analysis"
  };
}

function scoreMeter_(score) {
  var filled = Math.max(0, Math.min(10, Math.round(score / 10)));
  var empty = 10 - filled;
  return "[" + "\u2588".repeat(filled) + "\u2591".repeat(empty) + "]";
}

function buildScoreView_(score, verdict) {
  var meter = scoreMeter_(score);

  if (verdict === "Malicious") {
    return {
      label: "Critical",
      bar: meter,
      summary: "Immediate attention required"
    };
  }

  if (verdict === "Suspicious") {
    return {
      label: "Elevated",
      bar: meter,
      summary: "Review sender and links carefully"
    };
  }

  return {
    label: "Low",
    bar: meter,
    summary: "No major threat indicators found"
  };
}

function buildErrorCard_(error) {
  const section = CardService.newCardSection()
    .setHeader("Could not analyze this message")
    .addWidget(
      CardService.newTextParagraph().setText(
        "The scorer is temporarily unavailable. Please try again later."
      )
    )
    .addWidget(CardService.newTextParagraph().setText("Details: " + error.message));

  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("Malicious Email Scorer"))
    .addSection(section)
    .build();
}
