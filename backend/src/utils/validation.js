function validateAnalyzePayload(payload) {
  const errors = [];
  const value = payload || {};

  if (typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, errors: ["Payload must be a JSON object."] };
  }

  if (!value.headers || typeof value.headers !== "object" || Array.isArray(value.headers)) {
    errors.push("headers must be an object.");
  }

  if (typeof value.bodyText !== "string") {
    errors.push("bodyText must be a string.");
  }

  if (!Array.isArray(value.attachments)) {
    errors.push("attachments must be an array.");
  } else {
    value.attachments.forEach((attachment, index) => {
      if (typeof attachment !== "object" || attachment === null) {
        errors.push(`attachments[${index}] must be an object.`);
      }
    });
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  return { ok: true, value };
}

module.exports = { validateAnalyzePayload };
