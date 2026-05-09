const express = require("express");
const { analyzeEmail } = require("../controllers/analyzeController");

const router = express.Router();

router.post("/", analyzeEmail);

module.exports = router;
