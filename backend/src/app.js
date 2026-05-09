const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const analyzeRouter = require("./routes/analyze");

const app = express();
const corsOrigin = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(cors({ origin: corsOrigin }));
app.use(express.json({ limit: "200kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/analyze", analyzeRouter);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({
    error: "InternalServerError",
    message: "An unexpected server error occurred."
  });
});

module.exports = app;
