const { validateAnalyzePayload } = require("../utils/validation");
const { scoreEmail } = require("../services/scoringService");

function analyzeEmail(req, res) {
  const validation = validateAnalyzePayload(req.body);

  if (!validation.ok) {
    return res.status(400).json({
      error: "BadRequest",
      message: "Request payload is invalid.",
      details: validation.errors
    });
  }

  const result = scoreEmail(validation.value);
  return res.json(result);
}

module.exports = { analyzeEmail };
