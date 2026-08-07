import type { AnalysisResult } from "../services/api";

interface ExportReportButtonProps {
  message: string;
  result: AnalysisResult | null;
}

function ExportReportButton({
  message,
  result,
}: ExportReportButtonProps) {
  function handleExport() {
    if (!result) {
      return;
    }

    const flagText =
      result.flags.length === 0
        ? "No indicators detected."
        : result.flags
            .map(
              (flag, index) =>
                `${index + 1}. ${flag.category}
   ${flag.description}
   Score Contribution: +${flag.points}`,
            )
            .join("\n\n");

    const report = `
SENTRI SECURITY REPORT
==============================

Generated:
${new Date().toLocaleString()}

SCAN TYPE:
Message Analysis

RISK SCORE:
${result.riskScore}/100

RISK LEVEL:
${result.riskLevel}

SUMMARY:
${result.summary}

ANALYZED MESSAGE:
${message}

DETECTED INDICATORS:
${flagText}

RECOMMENDED ACTION:
${result.recommendation}

==============================
Sentri Digital Threat Defense System
Rule-Based Security Engine
`.trim();

    const blob = new Blob([report], {
      type: "text/plain;charset=utf-8",
    });

    const url = URL.createObjectURL(blob);

    const anchor = document.createElement("a");

    anchor.href = url;
    anchor.download = `sentri-report-${Date.now()}.txt`;

    document.body.appendChild(anchor);

    anchor.click();

    document.body.removeChild(anchor);

    URL.revokeObjectURL(url);
  }

  return (
    <button
      type="button"
      className="secondary-button export-button"
      onClick={handleExport}
      disabled={!result}
    >
      Export Report
    </button>
  );
}

export default ExportReportButton;