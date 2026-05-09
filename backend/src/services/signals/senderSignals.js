const { extractDomainFromEmail, extractEmailFromHeader } = require("../../utils/domain");

function evaluateSenderSignals(headers) {
  const findings = [];
  const fromHeader = String(headers.from || "");
  const replyTo = String(headers.replyTo || "");
  const returnPath = String(headers.returnPath || "");

  const fromEmail = extractEmailFromHeader(fromHeader);
  const fromDomain = extractDomainFromEmail(fromEmail);
  const replyDomain = extractDomainFromEmail(extractEmailFromHeader(replyTo));
  const returnDomain = extractDomainFromEmail(extractEmailFromHeader(returnPath));

  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    findings.push({
      points: 18,
      reason: "Reply-To domain differs from From domain."
    });
  }

  if (fromDomain && returnDomain && fromDomain !== returnDomain) {
    findings.push({
      points: 14,
      reason: "Return-Path domain differs from From domain."
    });
  }

  // Common spoofing pattern: trusted brand in display name but unrelated domain in address.
  const displayName = fromHeader.replace(/<.*?>/g, "").toLowerCase();
  const brandWords = ["microsoft", "google", "paypal", "apple", "amazon", "bank"];

  if (displayName && fromDomain) {
    const matchedBrand = brandWords.find((brand) => displayName.includes(brand));
    if (matchedBrand && !fromDomain.includes(matchedBrand)) {
      findings.push({
        points: 22,
        reason: `Display name suggests ${matchedBrand} but sender domain is ${fromDomain}.`
      });
    }
  }

  return findings;
}

module.exports = { evaluateSenderSignals };
