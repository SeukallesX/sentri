
import type { StoredScan } from "../services/api";

/**
 * SENTRI V3
 * Security Investigation Report Generator
 *
 * Generates local JSON and TXT reports from
 * existing message and URL scan records.
 *
 * No external API requests are made.
 */

export type ReportFormat = "json" | "txt";

export interface ReportEvidence {
  description: string;
  value?: string;
}

export interface ReportFlag {
  category: string;
  description: string;
  points: number;
  signalId?: string;
  severity?: string;
  source?: string;
  evidence?: ReportEvidence[];
}

export interface InvestigationReport {
  reportVersion: "1.1";
  reportId: string;
  generatedAt: string;
  generator: "Sentri v3";

  scan: {
    id: string;
    type: string;
    createdAt: string;
    content: string;
  };

  assessment: {
    riskScore: number;
    riskLevel: string;
    threatCategory: string;
    confidence: number | null;
    attackVector: string;
    summary: string;
    recommendation: string;
  };

  correlation: {
    correlatedThreat: string | null;
    correlationScore: number | null;
    matchedSignals: string[];
    explanation: string | null;
  };

  evidence: ReportFlag[];

  disclaimer: string;
}

const REPORT_DISCLAIMER =
  "This report contains automated heuristic security " +
  "findings. These findings do not confirm malicious " +
  "activity. Verify important conclusions independently.";

function safeString(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }

  return "";
}

function safeNumber(
  value: unknown,
): number | null {
  return typeof value === "number" &&
    Number.isFinite(value)
    ? value
    : null;
}

function safeStringArray(
  value: unknown,
): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(
    (item): item is string =>
      typeof item === "string",
  );
}

function normalizeEvidence(
  value: unknown,
): ReportEvidence[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter(
      (entry): entry is Record<string, unknown> =>
        typeof entry === "object" &&
        entry !== null &&
        !Array.isArray(entry),
    )
    .map((entry) => ({
      description:
        safeString(entry.description) ||
        safeString(entry.label) ||
        "Recorded evidence",

      ...(typeof entry.value === "string"
        ? { value: entry.value }
        : {}),
    }));
}

function normalizeFlags(
  value: unknown,
): ReportFlag[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter(
      (flag): flag is Record<string, unknown> =>
        typeof flag === "object" &&
        flag !== null &&
        !Array.isArray(flag),
    )
    .map((flag) => ({
      category:
        safeString(flag.category) ||
        "Uncategorized",

      description:
        safeString(flag.description) ||
        "No description recorded",

      points: safeNumber(flag.points) ?? 0,

      ...(typeof flag.signalId === "string"
        ? { signalId: flag.signalId }
        : {}),

      ...(typeof flag.severity === "string"
        ? { severity: flag.severity }
        : {}),

      ...(typeof flag.source === "string"
        ? { source: flag.source }
        : {}),

      evidence: normalizeEvidence(
        flag.evidence,
      ),
    }));
}

/**
 * Convert one stored scan into a structured
 * investigation report.
 */
export function generateInvestigationReport(
  scan: StoredScan,
): InvestigationReport {
  const result = scan.result;

  return {
    reportVersion: "1.1",

    reportId: `SENTRI-${scan.id}`,

    generatedAt: new Date().toISOString(),

    generator: "Sentri v3",

    scan: {
      id: String(scan.id),
      type: String(scan.type),
      createdAt: String(scan.createdAt),
      content: String(scan.content),
    },

    assessment: {
      riskScore:
        safeNumber(result.riskScore) ?? 0,

      riskLevel:
        safeString(result.riskLevel) ||
        "Unknown",

      threatCategory:
        safeString(result.threatCategory) ||
        "Unclassified",

      confidence: safeNumber(
        result.confidence,
      ),

      attackVector:
        safeString(result.attackVector) ||
        "Unknown",

      summary:
        safeString(result.summary) ||
        "No analysis summary recorded.",

      recommendation:
        safeString(result.recommendation) ||
        "Review this scan before taking action.",
    },

    correlation: {
      correlatedThreat:
        safeString(result.correlatedThreat) ||
        null,

      correlationScore: safeNumber(
        result.correlationScore,
      ),

      matchedSignals: safeStringArray(
        result.matchedSignals,
      ),

      explanation:
        safeString(
          result.correlationExplanation,
        ) || null,
    },

    evidence: normalizeFlags(result.flags),

    disclaimer: REPORT_DISCLAIMER,
  };
}

/**
 * Format the report as readable plain text.
 */
export function reportToText(
  report: InvestigationReport,
): string {
  const lines: string[] = [
    "==========================================",
    "SENTRI SECURITY INVESTIGATION REPORT",
    "==========================================",
    "",
    `Report ID: ${report.reportId}`,
    `Generated: ${report.generatedAt}`,
    `Generator: ${report.generator}`,
    `Report Version: ${report.reportVersion}`,
    "",
    "SCAN INFORMATION",
    "------------------------------------------",
    `Scan ID: ${report.scan.id}`,
    `Scan Type: ${report.scan.type}`,
    `Scan Timestamp: ${report.scan.createdAt}`,
    "",
    "ORIGINAL SCAN CONTENT",
    "------------------------------------------",
    report.scan.content,
    "",
    "RISK ASSESSMENT",
    "------------------------------------------",
    `Risk Score: ${report.assessment.riskScore}/100`,
    `Risk Level: ${report.assessment.riskLevel}`,
    `Threat Category: ${report.assessment.threatCategory}`,
    `Confidence: ${
      report.assessment.confidence === null
        ? "Not recorded"
        : `${report.assessment.confidence}%`
    }`,
    `Attack Vector: ${report.assessment.attackVector}`,
    "",
    "ANALYSIS SUMMARY",
    "------------------------------------------",
    report.assessment.summary,
    "",
    "THREAT CORRELATION",
    "------------------------------------------",
    `Correlated Threat: ${
      report.correlation.correlatedThreat ??
      "Not recorded"
    }`,
    `Correlation Score: ${
      report.correlation.correlationScore ??
      "Not recorded"
    }`,
    `Matched Signals: ${
      report.correlation.matchedSignals.join(", ") ||
      "None recorded"
    }`,
    "",
    report.correlation.explanation ??
      "No correlation explanation recorded.",
    "",
    "DETECTION EVIDENCE",
    "------------------------------------------",
  ];

  if (report.evidence.length === 0) {
    lines.push(
      "No detection flags were recorded.",
    );
  } else {
    report.evidence.forEach(
      (flag, index) => {
        lines.push(
          "",
          `${index + 1}. ${flag.category}`,
          `   Description: ${flag.description}`,
          `   Risk Points: ${flag.points}`,
        );

        if (flag.signalId) {
          lines.push(
            `   Signal ID: ${flag.signalId}`,
          );
        }

        if (flag.severity) {
          lines.push(
            `   Severity: ${flag.severity}`,
          );
        }

        if (flag.source) {
          lines.push(
            `   Source: ${flag.source}`,
          );
        }

        flag.evidence?.forEach(
          (entry, evidenceIndex) => {
            lines.push(
              `   Evidence ${evidenceIndex + 1}: ${entry.description}`,
            );

            if (entry.value) {
              lines.push(
                `   Value: ${entry.value}`,
              );
            }
          },
        );
      },
    );
  }

  lines.push(
    "",
    "RECOMMENDED RESPONSE",
    "------------------------------------------",
    report.assessment.recommendation,
    "",
    "IMPORTANT DISCLAIMER",
    "------------------------------------------",
    report.disclaimer,
    "",
    "==========================================",
    "END OF SENTRI REPORT",
    "==========================================",
  );

  return lines.join("\n");
}

/**
 * Download a generated report locally.
 *
 * The report is created in the browser and
 * is not uploaded to a remote service.
 */
export function downloadInvestigationReport(
  scan: StoredScan,
  format: ReportFormat,
): void {
  const report =
    generateInvestigationReport(scan);

  const content =
    format === "json"
      ? JSON.stringify(report, null, 2)
      : reportToText(report);

  const mimeType =
    format === "json"
      ? "application/json"
      : "text/plain";

  const blob = new Blob([content], {
    type: `${mimeType};charset=utf-8`,
  });

  const url = URL.createObjectURL(blob);

  try {
    const anchor =
      document.createElement("a");

    anchor.href = url;

    const safeId = String(scan.id)
      .replace(/[^a-zA-Z0-9_-]/g, "_");

    anchor.download =
      `sentri-report-${safeId}.${format}`;

    document.body.appendChild(anchor);

    anchor.click();

    anchor.remove();
  } finally {
    window.setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);
  }
}
