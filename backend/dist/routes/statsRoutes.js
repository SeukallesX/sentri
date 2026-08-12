import { Router } from "express";
import { database } from "../database/database.js";
const router = Router();
router.get("/", (_request, response) => {
    const totalRow = database
        .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
    `)
        .get();
    const highRow = database
        .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'High'
    `)
        .get();
    const mediumRow = database
        .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'Medium'
    `)
        .get();
    const lowRow = database
        .prepare(`
      SELECT COUNT(*) AS total
      FROM scans
      WHERE risk_level = 'Low'
    `)
        .get();
    return response.json({
        totalScans: totalRow.total,
        highRisk: highRow.total,
        mediumRisk: mediumRow.total,
        lowRisk: lowRow.total,
    });
});
export default router;
//# sourceMappingURL=statsRoutes.js.map