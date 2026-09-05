import {
  randomUUID,
} from "node:crypto";

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
 * LOAD PERSISTED ARCHIVE
 * ---------------------------------------
 */

const scans:
  StoredScan[] = [];

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
  const scan:
    StoredScan = {
      id:
        randomUUID(),

      type,

      content,

      result,

      event,

      createdAt:
        new Date()
          .toISOString(),
    };

  scans.unshift(
    scan,
  );

  /*
   * Prevent the local prototype
   * archive from growing forever.
   */
  if (
    scans.length >
    1000
  ) {
    scans.length =
      1000;
  }

  return scan;
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

  return scans.slice(
    0,
    safeLimit,
  );
}

/*
 * ---------------------------------------
 * CLEAR SCANS
 * ---------------------------------------
 */

export function clearScans():
  void {
  scans.length = 0;

}

/*
 * ---------------------------------------
 * DASHBOARD STATISTICS
 * ---------------------------------------
 */

export function getScanStats() {
  const totalScans =
    scans.length;

  const highRisk =
    scans.filter(
      (scan) =>
        scan.result
          .riskLevel ===
        "High",
    ).length;

  const mediumRisk =
    scans.filter(
      (scan) =>
        scan.result
          .riskLevel ===
        "Medium",
    ).length;

  const lowRisk =
    scans.filter(
      (scan) =>
        scan.result
          .riskLevel ===
        "Low",
    ).length;

  return {
    totalScans,

    highRisk,

    mediumRisk,

    lowRisk,
  };
}