const { extractDomainFromUrl, looksLikeTyposquatting } = require("../../utils/domain");

function evaluateUrlSignals(bodyText) {
  const findings = [];
  const text = String(bodyText || "");
  const urls = text.match(/https?:\/\/[^\s)]+/gi) || [];
  const suspiciousTlds = [".zip", ".top", ".xyz", ".click", ".shop", ".cam", ".gq", ".work"];
  const shortenerDomains = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "ow.ly"];
  const riskyPathWords = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "wallet",
    "signin",
    "reset-password",
    "billing"
  ];
  const suspiciousQueryKeys = ["token", "session", "password", "redirect", "verify", "auth"];

  if (urls.length === 0) {
    return findings;
  }

  let riskPoints = 0;
  const reasons = [];

  urls.forEach((url) => {
    const domain = extractDomainFromUrl(url);
    if (!domain) {
      return;
    }

    if (suspiciousTlds.some((tld) => domain.endsWith(tld))) {
      riskPoints += 10;
      reasons.push(`${domain} uses a frequently abused TLD.`);
    }

    if (looksLikeTyposquatting(domain)) {
      riskPoints += 18;
      reasons.push(`${domain} resembles a known brand domain (possible typosquatting).`);
    }

    if (shortenerDomains.includes(domain)) {
      riskPoints += 12;
      reasons.push(`${domain} is a URL shortener that can hide destination intent.`);
    }

    if (domain.includes("xn--")) {
      riskPoints += 16;
      reasons.push(`${domain} uses punycode (possible homograph deception).`);
    }

    if (isIpv4(domain)) {
      riskPoints += 14;
      reasons.push(`${domain} is a raw IP address instead of a regular domain.`);
    }

    if (hasAtSignObfuscation(url)) {
      riskPoints += 16;
      reasons.push(`URL uses '@' obfuscation to disguise the real destination.`);
    }

    const lowerUrl = url.toLowerCase();
    if (riskyPathWords.some((word) => lowerUrl.includes(word))) {
      riskPoints += 8;
      reasons.push(`URL contains account/security bait keywords in path or hostname.`);
    }

    if (containsSuspiciousQuery(url, suspiciousQueryKeys)) {
      riskPoints += 10;
      reasons.push(`URL query contains sensitive parameters often used in phishing flows.`);
    }
  });

  if (riskPoints > 0) {
    findings.push({
      points: Math.min(45, riskPoints),
      reason: reasons.join(" ")
    });
  }

  return findings;
}

function isIpv4(domain) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
}

function hasAtSignObfuscation(url) {
  return /https?:\/\/[^/\s]*@/i.test(url);
}

function containsSuspiciousQuery(url, suspiciousKeys) {
  try {
    const parsed = new URL(url);
    const keys = Array.from(parsed.searchParams.keys()).map((key) => key.toLowerCase());
    return keys.some((key) => suspiciousKeys.includes(key));
  } catch (_error) {
    return false;
  }
}

module.exports = { evaluateUrlSignals };
