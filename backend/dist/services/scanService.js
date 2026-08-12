import { randomUUID, } from "node:crypto";
import { database, } from "../database/database.js";
function rowToScan(row) {
    let flags = [];
    try {
        flags =
            JSON.parse(row.flags_json);
    }
    catch {
        flags = [];
    }
    return {
        id: row.id,
        type: row.type,
        content: row.content,
        result: {
            riskScore: row.risk_score,
            riskLevel: row.risk_level,
            flags,
            summary: row.summary,
            recommendation: row.recommendation,
        },
        createdAt: row.created_at,
    };
}
export function saveScan(type, content, result) {
    const scan = {
        id: randomUUID(),
        type,
        content,
        result,
        createdAt: new Date().toISOString(),
    };
    const statement = database.prepare(`
      INSERT INTO scans (
        id,
        type,
        content,
        risk_score,
        risk_level,
        summary,
        recommendation,
        flags_json,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    statement.run(scan.id, scan.type, scan.content, scan.result.riskScore, scan.result.riskLevel, scan.result.summary, scan.result.recommendation, JSON.stringify(scan.result.flags), scan.createdAt);
    return scan;
}
export function getRecentScans(limit = 10) {
    const safeLimit = Math.min(Math.max(limit, 1), 100);
    const statement = database.prepare(`
      SELECT
        id,
        type,
        content,
        risk_score,
        risk_level,
        summary,
        recommendation,
        flags_json,
        created_at
      FROM scans
      ORDER BY created_at DESC
      LIMIT ?
    `);
    const rows = statement.all(safeLimit);
    return rows.map(rowToScan);
}
export function clearScans() {
    database.exec(`
    DELETE FROM scans;
  `);
}
//# sourceMappingURL=scanService.js.map