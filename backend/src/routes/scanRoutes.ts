import {
  Router,
} from "express";

import {
  clearScans,
  getRecentScans,
} from "../services/scanService.js";

const router = Router();

router.get(
  "/",
  (request, response) => {
    const requestedLimit =
      Number(
        request.query.limit,
      );

    const limit =
      Number.isFinite(
        requestedLimit,
      )
        ? requestedLimit
        : 10;

    const scans =
      getRecentScans(limit);

    return response.json({
      scans,
    });
  },
);

router.delete(
  "/",
  (_request, response) => {
    clearScans();

    return response.json({
      success: true,
      message:
        "Scan history cleared.",
    });
  },
);

export default router;