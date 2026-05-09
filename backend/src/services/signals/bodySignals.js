function evaluateBodySignals(bodyText) {
  const findings = [];
  const text = String(bodyText || "").toLowerCase();

  const urgencyPatterns = [
    "urgent",
    "immediately",
    "act now",
    "verify your account",
    "password expires",
    "suspended",
    "click below",
    "limited time",
    "wire transfer",
    "final warning",
    "avoid suspension",
    "confirm now",
    "update billing",
    "right now",
    "asap",
    "דחוף",
    "מיידי",
    "מייד",
    "פעל עכשיו",
    "האימות נכשל",
    "החשבון ייחסם",
    "אימות חשבון"
  ];

  const urgencyMatches = collectMatches(text, urgencyPatterns);
  const urgencyHits = urgencyMatches.length;

  if (urgencyHits >= 1) {
    findings.push({
      points: Math.min(24, urgencyHits * 6),
      reason: `Urgency/phishing language detected (${urgencyHits} hit(s)): ${urgencyMatches.join(", ")}.`
    });
  }

  const threatPatterns = [
    "kill you",
    "i will kill",
    "hurt you",
    "shoot you",
    "you will pay",
    "i will find you",
    "die",
    "dead",
    "motherfucker",
    "bastard",
    "slaughter",
    "massacre",
    "bomb",
    "explode",
    "behead",
    "מחבל",
    "טרור",
    "פיגוע",
    "אני אהרוג אותך",
    "אני ירצח אותך",
    "אני אפגע בך",
    "אתה מת",
    "תמות",
    "בן זונה",
    "לך תזדיין",
    "מניאק"
  ];

  const threatMatches = collectMatches(text, threatPatterns);
  const threatHits = threatMatches.length;

  // Aggressive or threatening language is treated as a strong risk signal.
  if (threatHits >= 1) {
    findings.push({
      points: Math.min(45, 20 + threatHits * 8),
      reason: `Threatening/aggressive language detected (${threatHits} hit(s)): ${threatMatches.join(", ")}.`
    });
  }

  const terrorPatterns = [
    "terror attack",
    "join isis",
    "jihad",
    "suicide bomb",
    "al qaeda",
    "חמאס",
    "דעאש",
    "דאעש",
    "ג'יהאד",
    "גיהאד",
    "פיגוע התאבדות",
    "מטען חבלה",
    "נפוצץ",
    "נחסל"
  ];

  const terrorMatches = collectMatches(text, terrorPatterns);
  const terrorHits = terrorMatches.length;
  if (terrorHits >= 1) {
    findings.push({
      points: Math.min(55, 28 + terrorHits * 10),
      reason: `Terror/violent intent indicators detected (${terrorHits} hit(s)): ${terrorMatches.join(", ")}.`
    });
  }

  const explicitDeathThreatPatterns = [
    "i will kill you",
    "kill you",
    "i am going to kill you",
    "i'm going to kill you",
    "אני אהרוג אותך",
    "אני ירצח אותך",
    "terror attack",
    "פיגוע"
  ];

  const explicitDeathThreatMatches = collectMatches(text, explicitDeathThreatPatterns);
  if (explicitDeathThreatMatches.length > 0) {
    findings.push({
      points: 55,
      forceMalicious: true,
      reason: `Explicit death threat detected: ${explicitDeathThreatMatches.join(", ")}.`
    });
  }

  return findings;
}

function collectMatches(text, patterns) {
  const uniqueMatches = [];

  patterns.forEach((pattern) => {
    if (text.includes(pattern) && !uniqueMatches.includes(pattern)) {
      uniqueMatches.push(pattern);
    }
  });

  return uniqueMatches.slice(0, 6);
}

module.exports = { evaluateBodySignals };
