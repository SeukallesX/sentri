import {
  Router,
} from "express";

import {
  analyzeUrlIntelligence,
} from "../utils/urlAnalyzer.js";

import {
  calculateRiskScore,
  determineRiskLevel,
  getRecommendation,
} from "../utils/riskCalculator.js";

import {
  classifyThreat,
} from "../utils/threatClassifier.js";

import {
  correlateThreats,
} from "../utils/threatCorrelation.js";

import {
  saveScan,
} from "../services/scanService.js";

const router =
  Router();

router.post(
  "/",
  (
    req,
    res,
  ) => {
    try {
      const url =
        typeof req.body?.url ===
        "string"
          ? req.body.url.trim()
          : "";

      if (!url) {
        return res
          .status(400)
          .json({
            error:
              "A URL is required for analysis.",
          });
      }

      if (
        url.length >
        2048
      ) {
        return res
          .status(400)
          .json({
            error:
              "The URL is too long.",
          });
      }

      /*
       * Run URL structural analysis.
       */
      const analysis =
        analyzeUrlIntelligence(
          url,
        );

      /*
       * Calculate risk.
       */
      const riskScore =
        calculateRiskScore(
          analysis.flags,
        );

      const riskLevel =
        determineRiskLevel(
          riskScore,
        );

      /*
       * Primary classification.
       */
      const classification =
        classifyThreat(
          analysis.flags,
        );

      /*
       * Correlate multiple indicators.
       */
      const correlation =
        correlateThreats(
          analysis.flags,
        );

      /*
       * Generate summary.
       */
      const summary =
        analysis.flags
          .length === 0
          ? "Sentri did not detect any common suspicious URL indicators."
          : `Sentri detected ${analysis.flags.length} suspicious URL ${
              analysis.flags
                .length === 1
                ? "indicator"
                : "indicators"
            }.`;

      /*
       * Complete result object.
       */
      const result = {
        riskScore,

        riskLevel,

        threatCategory:
          classification.threatCategory,

        confidence:
          classification.confidence,

        attackVector:
          classification.attackVector,

        correlatedThreat:
          correlation.correlatedThreat,

        correlationScore:
          correlation.correlationScore,

        matchedSignals:
          correlation.matchedSignals,

        correlationExplanation:
          correlation.explanation,

        flags:
          analysis.flags,

        summary,

        recommendation:
          getRecommendation(
            riskLevel,
          ),
      };

      /*
       * Save scan to history.
       */
      saveScan(
        "URL",

        analysis
          .intelligence
          ?.normalizedUrl ??
          url,

        result,
      );

      /*
       * Return result plus URL intelligence.
       */
      return res
        .status(200)
        .json({
          ...result,

          intelligence:
            analysis.intelligence,
        });
    } catch (
      error
    ) {
      console.error(
        "URL analysis failed:",
        error,
      );

      return res
        .status(500)
        .json({
          error:
            "Unable to analyze the URL.",
        });
    }
  },
);

export default router;