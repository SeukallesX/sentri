import {
  randomUUID,
} from "node:crypto";

import {
  database,
} from "../database/database.js";

import type {
  AnalysisResult,
  ScamFlag,
} from "../types/analysis.js";

import type {
  ScanType,
  StoredScan,
} from "../types/scan.js";

interface ScanRow {
  id: string;
  type: ScanType;
  content: string;
  risk_score: number;
  risk_level: "Low" | "Medium" | "High";
  summary: string;
  recommendation: string;
  flags_json: string;
  created_at: string;
}

function rowToScan(
  row: ScanRow,
): StoredScan {
  let flags: ScamFlag[] = [];

  try {
    flags =
      JSON.parse(
        row.flags_json,
      ) as ScamFlag[];
  } catch {
    flags = [];
  }

  return {
    id: row.id,

    type: row.type,

    content: row.content,

    result: {
      riskScore:
        row.risk_score,

      riskLevel:
        row.risk_level,

      flags,

      summary:
        row.summary,

      recommendation:
        row.recommendation,
    },

    createdAt:
      row.created_at,
  };
}

export function saveScan(
  type: ScanType,
  content: string,
  result: AnalysisResult,
): StoredScan {
  const scan: StoredScan = {
    id: randomUUID(),

    type,

    content,

    result,

    createdAt:
      new Date().toISOString(),
  };

  const statement =
    database.prepare(`
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

  statement.run(
    scan.id,
    scan.type,
    scan.content,
    scan.result.riskScore,
    scan.result.riskLevel,
    scan.result.summary,
    scan.result.recommendation,
    JSON.stringify(
      scan.result.flags,
    ),
    scan.createdAt,
  );

  return scan;
}

export function getRecentScans(
  limit = 10,
): StoredScan[] {
  const safeLimit =
    Math.min(
      Math.max(limit, 1),
      100,
    );

  const statement =
    database.prepare(`
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

  const rows =
    statement.all(
      safeLimit,
    ) as unknown as ScanRow[];

  return rows.map(
    rowToScan,
  );
}

export function clearScans() {
  database.exec(`
    DELETE FROM scans;
  `);
}