import { Router } from "express";

import { database } from "../database/database.js";

const router = Router();

router.get("/", (_request, response) => {
  const totalRow = database
    .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
    `)
    .get() as { total: number };

  const highRow = database
    .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'High'
    `)
    .get() as { total: number };

  const mediumRow = database
    .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'Medium'
    `)
    .get() as { total: number };

  const lowRow = database
    .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'Low'
    `)
    .get() as { total: number };

  return response.json({
    totalScans: totalRow.total,
    highRisk: highRow.total,
    mediumRisk: mediumRow.total,
    lowRisk: lowRow.total,
  });
});

export default router;