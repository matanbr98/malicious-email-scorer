function extractEmailFromHeader(value) {
  const input = String(value || "");
  const match = input.match(/<([^>]+)>/);
  const email = match ? match[1] : input.trim();
  return email.toLowerCase();
}

function extractDomainFromEmail(email) {
  const value = String(email || "").toLowerCase().trim();
  const parts = value.split("@");
  return parts.length === 2 ? parts[1] : "";
}

function extractDomainFromUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase();
  } catch (_error) {
    return "";
  }
}

function looksLikeTyposquatting(domain) {
  const trusted = ["microsoft.com", "google.com", "paypal.com", "apple.com", "amazon.com"];
  return trusted.some((target) => {
    if (domain === target) return false;
    const compactDomain = domain.replace(/[-.]/g, "");
    const compactTarget = target.replace(/[-.]/g, "");
    return compactDomain.includes(compactTarget.slice(0, -2));
  });
}

module.exports = {
  extractEmailFromHeader,
  extractDomainFromEmail,
  extractDomainFromUrl,
  looksLikeTyposquatting
};
