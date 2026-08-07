import { Router } from "express";
import { analyzeUrls } from "../utils/urlAnalyzer.js";
import {
  calculateRiskScore,
  determineRiskLevel,
  getRecommendation,
} from "../utils/riskCalculator.js";

const router = Router();

router.post("/", (request, response) => {
  const url = request.body?.url;

  if (typeof url !== "string" || url.trim().length === 0) {
    return response.status(400).json({
      error: "Please provide a URL to analyze.",
    });
  }

  const cleanedUrl = url.trim();

  if (cleanedUrl.length > 2048) {
    return response.status(400).json({
      error: "The URL is too long.",
    });
  }

  const flags = analyzeUrls(cleanedUrl);

  const riskScore = calculateRiskScore(flags);
  const riskLevel = determineRiskLevel(riskScore);

  const summary =
    flags.length === 0
      ? "Sentri did not detect any common suspicious URL indicators."
      : `Sentri detected ${flags.length} suspicious URL ${
          flags.length === 1 ? "indicator" : "indicators"
        }.`;

  return response.json({
    riskScore,
    riskLevel,
    flags,
    summary,
    recommendation: getRecommendation(riskLevel),
  });
});

export default router;