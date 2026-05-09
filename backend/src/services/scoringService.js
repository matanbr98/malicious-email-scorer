const { evaluateHeaderSignals } = require("./signals/headerSignals");
const { evaluateHeaderTextSignals } = require("./signals/headerTextSignals");
const { evaluateSenderSignals } = require("./signals/senderSignals");
const { evaluateBodySignals } = require("./signals/bodySignals");
const { evaluateUrlSignals } = require("./signals/urlSignals");

const VERDICTS = [
  { maxScore: 29, verdict: "Safe" },
  { maxScore: 69, verdict: "Suspicious" },
  { maxScore: 100, verdict: "Malicious" }
];

function scoreEmail(payload) {
  const breakdown = [
    ...evaluateHeaderSignals(payload.headers || {}),
    ...evaluateHeaderTextSignals(payload.headers || {}),
    ...evaluateSenderSignals(payload.headers || {}),
    ...evaluateBodySignals(payload.bodyText || ""),
    ...evaluateUrlSignals(payload.bodyText || "")
  ];

  const rawScore = breakdown.reduce((sum, item) => sum + item.points, 0);
  const hasForcedMaliciousSignal = breakdown.some((item) => item.forceMalicious === true);
  const baseScore = Math.max(0, Math.min(100, rawScore));
  const score = hasForcedMaliciousSignal ? Math.max(baseScore, 75) : baseScore;
  const verdict = VERDICTS.find((item) => score <= item.maxScore).verdict;
  const reasoning = buildReasoning(breakdown, score, verdict, hasForcedMaliciousSignal);
  const topSignals = breakdown
    .slice()
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map((item) => item.reason);

  return {
    score,
    verdict,
    reasoning,
    classificationExplanation: buildClassificationExplanation(verdict, score, breakdown.length),
    topSignals,
    signalBreakdown: breakdown
  };
}

function buildReasoning(breakdown, score, verdict, hasForcedMaliciousSignal) {
  if (breakdown.length === 0) {
    return [
      `Classified as ${verdict} with score ${score}/100 because no suspicious signals were detected.`
    ];
  }

  const reasons = breakdown.map((item) => item.reason);
  if (hasForcedMaliciousSignal) {
    reasons.unshift("Score floor rule applied: explicit death threat forces minimum score 75/100.");
  }
  return reasons;
}

function buildClassificationExplanation(verdict, score, signalCount) {
  if (verdict === "Malicious") {
    return `Marked red (${score}/100) due to ${signalCount} detected signal(s), including high-risk threat indicators.`;
  }

  if (verdict === "Suspicious") {
    return `Marked orange (${score}/100) due to ${signalCount} moderate-risk indicator(s) that require attention.`;
  }

  return `Marked green (${score}/100) because risk indicators are low and no severe threat signals were detected.`;
}

module.exports = { scoreEmail };
