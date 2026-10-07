import { randomUUID } from "node:crypto";

import { database } from "../database/database.js";

import type {
  AnalysisResult,
  SecurityEventReference,
} from "../types/analysis.js";

import type {
  ScanType,
  StoredScan,
} from "../types/scan.js";

/*
 * ---------------------------------------
 * DATABASE ROW TYPES
 * ---------------------------------------
 */

interface ScanRow {
  id: string;

  event_id: string | null;

  type: ScanType;

  content: string;

  risk_score: number;

  risk_level:
    | "Low"
    | "Medium"
    | "High";

  threat_category: string | null;

  confidence: number | null;

  attack_vector: string | null;

  correlated_threat: string | null;

  correlation_score: number | null;

  matched_signals_json:
    | string
    | null;

  correlation_explanation:
    | string
    | null;

  summary: string;

  recommendation: string;

  flags_json: string;

  created_at: string;
}

interface CountRow {
  count: number;
}

/*
 * ---------------------------------------
 * JSON HELPERS
 * ---------------------------------------
 */

function parseJsonArray<T>(
  value: string | null,
): T[] {
  if (!value) {
    return [];
  }

  try {
    const parsed =
      JSON.parse(value);

    return Array.isArray(parsed)
      ? (parsed as T[])
      : [];
  } catch {
    return [];
  }
}

/*
 * ---------------------------------------
 * CONVERT DATABASE ROW TO STORED SCAN
 * ---------------------------------------
 */

function rowToStoredScan(
  row: ScanRow,
): StoredScan {
  const event:
    SecurityEventReference |
    undefined =
    row.event_id
      ? getEventReference(
          row.event_id,
        )
      : undefined;

  const result:
    AnalysisResult = {
      riskScore:
        row.risk_score,

      riskLevel:
        row.risk_level,

      threatCategory:
        row.threat_category ??
        "Unknown",

      confidence:
        row.confidence ??
        0,

      attackVector:
        row.attack_vector ??
        "Unknown",

      correlatedThreat:
        row.correlated_threat ??
        "None",

      correlationScore:
        row.correlation_score ??
        0,

      matchedSignals:
        parseJsonArray<string>(
          row.matched_signals_json,
        ),

      correlationExplanation:
        row.correlation_explanation ??
        "No correlation data available.",

      flags:
        parseJsonArray<
          AnalysisResult["flags"][number]
        >(
          row.flags_json,
        ),

      summary:
        row.summary,

      recommendation:
        row.recommendation,

      event,
    };

  return {
    id:
      row.id,

    type:
      row.type,

    content:
      row.content,

    result,

    event,

    createdAt:
      row.created_at,
  };
}

/*
 * ---------------------------------------
 * GET EVENT REFERENCE
 * ---------------------------------------
 */

function getEventReference(
  eventId: string,
):
  | SecurityEventReference
  | undefined {
  const statement =
    database.prepare(`
      SELECT
        id,
        type,
        source,
        timestamp
      FROM security_events
      WHERE id = ?
      LIMIT 1
    `);

  const row =
    statement.get(
      eventId,
    ) as
      | {
          id: string;
          type:
            SecurityEventReference["type"];
          source:
            SecurityEventReference["source"];
          timestamp: string;
        }
      | undefined;

  if (!row) {
    return undefined;
  }

  return {
    id:
      row.id,

    type:
      row.type,

    source:
      row.source,

    timestamp:
      row.timestamp,
  };
}

/*
 * ---------------------------------------
 * SAVE SECURITY EVENT
 * ---------------------------------------
 */

function saveSecurityEvent(
  event:
    SecurityEventReference,

  content: string,
): void {
  const statement =
    database.prepare(`
      INSERT OR IGNORE INTO security_events (
        id,
        type,
        source,
        content,
        timestamp,
        metadata_json,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

  statement.run(
    event.id,
    event.type,
    event.source,
    content,
    event.timestamp,
    JSON.stringify({}),
    new Date().toISOString(),
  );
}

/*
 * ---------------------------------------
 * SAVE SCAN
 * ---------------------------------------
 */

export function saveScan(
  type: ScanType,

  content: string,

  result: AnalysisResult,

  event?: SecurityEventReference,
): StoredScan {
  const id =
    randomUUID();

  const createdAt =
    new Date().toISOString();

  /*
   * The event must be inserted first
   * because scans.event_id references it.
   */

  if (event) {
    saveSecurityEvent(
      event,
      content,
    );
  }

  const statement =
    database.prepare(`
      INSERT INTO scans (
        id,
        event_id,
        type,
        content,
        risk_score,
        risk_level,
        threat_category,
        confidence,
        attack_vector,
        correlated_threat,
        correlation_score,
        matched_signals_json,
        correlation_explanation,
        summary,
        recommendation,
        flags_json,
        created_at
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?
      )
    `);

  statement.run(
    id,

    event?.id ??
      null,

    type,

    content,

    result.riskScore,

    result.riskLevel,

    result.threatCategory,

    result.confidence,

    result.attackVector,

    result.correlatedThreat,

    result.correlationScore,

    JSON.stringify(
      result.matchedSignals,
    ),

    result.correlationExplanation,

    result.summary,

    result.recommendation,

    JSON.stringify(
      result.flags,
    ),

    createdAt,
  );

  return {
    id,

    type,

    content,

    result: {
      ...result,

      event,
    },

    event,

    createdAt,
  };
}

/*
 * ---------------------------------------
 * GET SCANS
 * ---------------------------------------
 */

export function getScans(
  limit = 10,
): StoredScan[] {
  const safeLimit =
    Math.max(
      1,
      Math.min(
        limit,
        100,
      ),
    );

  const statement =
    database.prepare(`
      SELECT
        id,
        event_id,
        type,
        content,
        risk_score,
        risk_level,
        threat_category,
        confidence,
        attack_vector,
        correlated_threat,
        correlation_score,
        matched_signals_json,
        correlation_explanation,
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
    rowToStoredScan,
  );
}

/*
 * ---------------------------------------
 * CLEAR SCANS
 * ---------------------------------------
 */

export function clearScans():
  void {
  /*
   * Remove scans first because they
   * reference security_events.
   */

  database.exec(`
    DELETE FROM scans;
  `);

  database.exec(`
    DELETE FROM security_events;
  `);
}

/*
 * ---------------------------------------
 * DASHBOARD STATISTICS
 * ---------------------------------------
 */

export function getScanStats() {
  const totalRow =
    database
      .prepare(`
        SELECT COUNT(*) AS count
        FROM scans
      `)
      .get() as unknown as CountRow;

  const highRow =
    database
      .prepare(`
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'High'
      `)
      .get() as unknown as CountRow;

  const mediumRow =
    database
      .prepare(`
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'Medium'
      `)
      .get() as unknown as CountRow;

  const lowRow =
    database
      .prepare(`
        SELECT COUNT(*) AS count
        FROM scans
        WHERE risk_level = 'Low'
      `)
      .get() as unknown as CountRow;

  return {
    totalScans:
      Number(
        totalRow.count,
      ),

    highRisk:
      Number(
        highRow.count,
      ),

    mediumRisk:
      Number(
        mediumRow.count,
      ),

    lowRisk:
      Number(
        lowRow.count,
      ),
  };
}