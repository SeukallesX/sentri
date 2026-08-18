import { Router } from "express";

import {
  analyzeMessage,
} from "../services/scamAnalyzer.js";

import {
  saveScan,
} from "../services/scanService.js";

const router = Router();

router.post("/", (req, res) => {
  try {
    const message =
      typeof req.body?.message === "string"
        ? req.body.message.trim()
        : "";

    if (!message) {
      return res.status(400).json({
        error:
          "A message is required for analysis.",
      });
    }

    if (message.length > 10000) {
      return res.status(400).json({
        error:
          "The message is too long.",
      });
    }

    /*
     * analyzeMessage() now returns the full result:
     *
     * - riskScore
     * - riskLevel
     * - threatCategory
     * - confidence
     * - attackVector
     * - flags
     * - summary
     * - recommendation
     */
    const result =
      analyzeMessage(message);

    /*
     * Save the complete analysis to scan history.
     *
     * This means classification data is stored too,
     * as long as scanService stores the result object.
     */
    saveScan(
      "Message",
      message,
      result,
    );

    return res.status(200).json(
      result,
    );
  } catch (error) {
    console.error(
      "Message analysis failed:",
      error,
    );

    return res.status(500).json({
      error:
        "Unable to analyze the message.",
    });
  }
});

export default router;