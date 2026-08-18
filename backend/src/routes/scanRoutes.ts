import { Router } from "express";

import {
  clearScans,
  getScans,
} from "../services/scanService.js";

const router = Router();

/*
 * GET /api/scans
 *
 * Example:
 * /api/scans
 * /api/scans?limit=10
 */
router.get("/", (req, res) => {
  try {
    const requestedLimit =
      typeof req.query.limit === "string"
        ? Number.parseInt(
            req.query.limit,
            10,
          )
        : 10;

    const limit =
      Number.isFinite(
        requestedLimit,
      )
        ? requestedLimit
        : 10;

    const scans =
      getScans(limit);

    return res
      .status(200)
      .json({
        scans,
      });
  } catch (error) {
    console.error(
      "Unable to retrieve scans:",
      error,
    );

    return res
      .status(500)
      .json({
        error:
          "Unable to retrieve scan history.",
      });
  }
});

/*
 * DELETE /api/scans
 *
 * Clears the in-memory scan archive.
 */
router.delete("/", (_req, res) => {
  try {
    clearScans();

    return res
      .status(200)
      .json({
        message:
          "Scan history cleared successfully.",
      });
  } catch (error) {
    console.error(
      "Unable to clear scans:",
      error,
    );

    return res
      .status(500)
      .json({
        error:
          "Unable to clear scan history.",
      });
  }
});

export default router;