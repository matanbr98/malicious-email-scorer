function evaluateHeaderTextSignals(headers) {
  const findings = [];
  const subject = String(headers.subject || "").toLowerCase();
  const from = String(headers.from || "").toLowerCase();
  const headerText = `${subject} ${from}`.trim();

  if (!headerText) {
    return findings;
  }

  const aggressivePatterns = [
    "kill you",
    "i will kill",
    "shoot you",
    "you will pay",
    "die",
    "motherfucker",
    "bastard",
    "terror",
    "bomb",
    "אני אהרוג אותך",
    "אני ירצח אותך",
    "מחבל",
    "טרור",
    "פיגוע",
    "תמות",
    "אתה מת"
  ];

  const aggressiveMatches = collectMatches(headerText, aggressivePatterns);
  if (aggressiveMatches.length > 0) {
    findings.push({
      points: Math.min(40, 16 + aggressiveMatches.length * 8),
      reason: `Threatening language detected in header fields (${aggressiveMatches.length} hit(s)): ${aggressiveMatches.join(", ")}.`
    });
  }

  const explicitDeathThreatPatterns = [
    "i will kill you",
    "i am going to kill you",
    "i'm going to kill you",
    "kill you",
    "אני אהרוג אותך",
    "אני ירצח אותך"
  ];

  const explicitMatches = collectMatches(headerText, explicitDeathThreatPatterns);
  if (explicitMatches.length > 0) {
    findings.push({
      points: 55,
      forceMalicious: true,
      reason: `Explicit death threat detected in subject/header text: ${explicitMatches.join(", ")}.`
    });
  }

  return findings;
}

function collectMatches(text, patterns) {
  const matches = [];

  patterns.forEach((pattern) => {
    if (text.includes(pattern) && !matches.includes(pattern)) {
      matches.push(pattern);
    }
  });

  return matches.slice(0, 6);
}

module.exports = { evaluateHeaderTextSignals };
