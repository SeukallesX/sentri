import {
  randomUUID,
} from "node:crypto";

import type {
  AnalysisResult,
} from "../types/analysis.js";

import type {
  ScanType,
  StoredScan,
} from "../types/scan.js";

const scans: StoredScan[] = [];

export function saveScan(
  type: ScanType,
  content: string,
  result: AnalysisResult,
): StoredScan {
  const scan: StoredScan = {
    id:
      randomUUID(),

    type,

    content,

    result,

    createdAt:
      new Date().toISOString(),
  };

  scans.unshift(scan);

  return scan;
}

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

export function clearScans(): void {
  scans.length = 0;
}

export function getScanStats() {
  const totalScans =
    scans.length;

  const highRisk =
    scans.filter(
      (scan) =>
        scan.result.riskLevel ===
        "High",
    ).length;

  const mediumRisk =
    scans.filter(
      (scan) =>
        scan.result.riskLevel ===
        "Medium",
    ).length;

  const lowRisk =
    scans.filter(
      (scan) =>
        scan.result.riskLevel ===
        "Low",
    ).length;

  return {
    totalScans,
    highRisk,
    mediumRisk,
    lowRisk,
  };
}