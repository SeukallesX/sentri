
import type { AnalysisResult } from "../services/api";

interface ResultsCardProps {
  result: AnalysisResult | null;
}

type SignalSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface SignalEvidence {
  description: string;
  value?: string;
}

interface StructuredFlag {
  category: string;
  description: string;
  points: number;
  signalId?: string;
  severity?: SignalSeverity;
  source?: string;
  evidence?: SignalEvidence[];
}

function getSeverity(
  flag: StructuredFlag,
): SignalSeverity {
  if (flag.severity) {
    return flag.severity;
  }

  if (flag.points >= 30) return "critical";
  if (flag.points >= 20) return "high";
  if (flag.points >= 10) return "medium";
  if (flag.points > 0) return "low";

  return "info";
}

function getSeverityClass(
  severity: SignalSeverity,
): string {
  return `sentri-severity-${severity}`;
}

function formatSource(source?: string): string {
  if (!source) return "LEGACY RULE";

  return source.replace(/-/g, " ").toUpperCase();
}

function ResultsCard({ result }: ResultsCardProps) {
  const riskLevel = result?.riskLevel ?? "Low";

  const riskClass = result
    ? `risk-${riskLevel.toLowerCase()}`
    : "risk-low";

  const score = result?.riskScore ?? 0;

  const flags: StructuredFlag[] =
    result?.flags ?? [];

  const indicatorCount = flags.filter(
    (flag) => flag.points > 0,
  ).length;

  const structuredCount = flags.filter(
    (flag) => Boolean(flag.signalId),
  ).length;

  const informationalCount = flags.filter(
    (flag) => flag.points === 0,
  ).length;

  const threatCategory =
    result?.threatCategory ?? "Unknown";

  const confidence = result?.confidence ?? 0;

  const attackVector =
    result?.attackVector ??
    "No dominant attack vector detected";

  const correlatedThreat =
    result?.correlatedThreat ??
    "No Correlated Threat";

  const correlationScore =
    result?.correlationScore ?? 0;

  const matchedSignals =
    result?.matchedSignals ?? [];

  const correlationExplanation =
    result?.correlationExplanation ??
    "No meaningful combination of threat indicators was detected.";

  const systemStatus = result
    ? riskLevel === "High"
      ? "THREAT DETECTED"
      : riskLevel === "Medium"
        ? "CAUTION"
        : "NOMINAL"
    : "STANDBY";

  const riskPercentage = Math.max(
    0,
    Math.min(100, score),
  );

  const correlationPercentage = Math.max(
    0,
    Math.min(100, correlationScore),
  );

  return (
    <section className="results-card jarvis-results-card">
      {/* =====================================
          THREAT ASSESSMENT HEADER
      ===================================== */}

      <div className="results-hud-header">
        <div>
          <p className="eyebrow">
            Threat Assessment
          </p>

          <h3>
            {result
              ? `${riskLevel} Risk Detected`
              : "Awaiting Analysis"}
          </h3>
        </div>

        <div
          className={`hud-status-chip ${riskClass}`}
        >
          <span className="hud-status-dot" />
          {systemStatus}
        </div>
      </div>

      {/* =====================================
          RADAR AND SYSTEM READOUT
      ===================================== */}

      <div className="results-hud-body">
        <div className="hud-radar-area">
          <div className="hud-coordinate hud-coordinate-top">
            000
          </div>

          <div className="hud-coordinate hud-coordinate-right">
            090
          </div>

          <div className="hud-coordinate hud-coordinate-bottom">
            180
          </div>

          <div className="hud-coordinate hud-coordinate-left">
            270
          </div>

          <div className="hud-radar">
            <div className="hud-ring hud-ring-outer" />
            <div className="hud-ring hud-ring-middle" />
            <div className="hud-ring hud-ring-inner" />

            <div className="hud-axis hud-axis-horizontal" />
            <div className="hud-axis hud-axis-vertical" />

            <div className="hud-radar-sweep" />
            <div className="hud-tick-ring" />

            <div className="hud-node hud-node-one" />
            <div className="hud-node hud-node-two" />
            <div className="hud-node hud-node-three" />

            <div className={`hud-core ${riskClass}`}>
              <span className="hud-core-label">
                SENTRI
              </span>

              <strong>{score}</strong>
              <small>/100</small>
            </div>
          </div>

          <div className="hud-radar-caption">
            <span
              className={`hud-caption-dot ${riskClass}`}
            />

            {result
              ? `${riskLevel.toUpperCase()} THREAT PROFILE`
              : "SCAN ENGINE READY"}
          </div>
        </div>

        <div className="hud-readout">
          <div className="hud-readout-title">
            <span>SYSTEM READOUT</span>
            <small>RULE-X // LOCAL</small>
          </div>

          <div className="hud-readout-grid">
            <div className="hud-readout-item">
              <span>Risk Index</span>

              <strong className={riskClass}>
                {score.toString().padStart(3, "0")}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>Indicators</span>

              <strong>
                {indicatorCount
                  .toString()
                  .padStart(2, "0")}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>Threat Level</span>

              <strong className={riskClass}>
                {result
                  ? riskLevel.toUpperCase()
                  : "READY"}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>Engine</span>
              <strong>RULE-X</strong>
            </div>

            <div className="hud-readout-item">
              <span>Primary Threat</span>

              <strong className={riskClass}>
                {result
                  ? threatCategory.toUpperCase()
                  : "NONE"}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>Confidence</span>

              <strong>
                {result ? `${confidence}%` : "0%"}
              </strong>
            </div>
          </div>

          <div className="hud-signal-line">
            <span>SIGNAL ANALYSIS</span>

            <div className="hud-signal-track">
              <div
                className={`hud-signal-fill ${riskClass}`}
                style={{
                  width: `${riskPercentage}%`,
                }}
              />
            </div>

            <strong className={riskClass}>
              {systemStatus}
            </strong>
          </div>

          <div className="hud-summary">
            <p className="radar-label">
              Attack Vector
            </p>

            <p>{attackVector}</p>
          </div>

          <div className="hud-summary">
            <p className="radar-label">
              Intelligence Summary
            </p>

            <p>
              {result
                ? result.summary
                : "Sentri is standing by. Initialize a scan to activate threat analysis."}
            </p>
          </div>
        </div>
      </div>

      {result && (
        <>
          {/* =====================================
              CORRELATION ANALYSIS
          ===================================== */}

          <div className="hud-divider">
            <span>CORRELATION ANALYSIS</span>
          </div>

          <div className="correlation-panel">
            <div className="correlation-header">
              <div>
                <p className="radar-label">
                  Correlated Threat
                </p>

                <h4 className={riskClass}>
                  {correlatedThreat.toUpperCase()}
                </h4>
              </div>

              <div className="correlation-score">
                <span>CORRELATION</span>

                <strong className={riskClass}>
                  {correlationScore}%
                </strong>
              </div>
            </div>

            <div className="correlation-track">
              <div
                className={`correlation-fill ${riskClass}`}
                style={{
                  width: `${correlationPercentage}%`,
                }}
              />
            </div>

            <div className="correlation-explanation">
              <span>ANALYSIS</span>
              <p>{correlationExplanation}</p>
            </div>

            <div className="correlation-signals">
              <span className="correlation-signals-label">
                MATCHED SIGNALS
              </span>

              {matchedSignals.length === 0 ? (
                <p className="correlation-no-signals">
                  No correlated signals detected.
                </p>
              ) : (
                <div className="correlation-signal-list">
                  {matchedSignals.map(
                    (signal, index) => (
                      <span
                        className="correlation-signal"
                        key={`${signal}-${index}`}
                      >
                        {signal.toUpperCase()}
                      </span>
                    ),
                  )}
                </div>
              )}
            </div>
          </div>

          {/* =====================================
              STRUCTURED SECURITY SIGNALS
          ===================================== */}

          <div className="hud-divider">
            <span>
              DETECTED SECURITY SIGNALS
            </span>
          </div>

          <div className="sentri-signal-overview">
            <div className="sentri-signal-stat">
              <span>RISK INDICATORS</span>
              <strong>{indicatorCount}</strong>
            </div>

            <div className="sentri-signal-stat">
              <span>STRUCTURED SIGNALS</span>
              <strong>{structuredCount}</strong>
            </div>

            <div className="sentri-signal-stat">
              <span>INFORMATIONAL</span>
              <strong>{informationalCount}</strong>
            </div>
          </div>

          <div className="hud-flags">
            {flags.length === 0 ? (
              <div className="hud-clear-state">
                <span className="hud-clear-icon">
                  ✓
                </span>

                <div>
                  <strong>
                    No major indicators detected
                  </strong>

                  <p>
                    The analyzed content did not
                    match Sentri's current
                    detection rules.
                  </p>
                </div>
              </div>
            ) : (
              flags.map((flag, index) => {
                const severity =
                  getSeverity(flag);

                const evidence =
                  flag.evidence ?? [];

                return (
                  <article
                    className={`hud-flag sentri-signal-card ${getSeverityClass(
                      severity,
                    )}`}
                    key={`${
                      flag.signalId ??
                      flag.category
                    }-${index}`}
                  >
                    <div className="hud-flag-index">
                      {(index + 1)
                        .toString()
                        .padStart(2, "0")}
                    </div>

                    <div className="hud-flag-content">
                      <span>
                        SECURITY INDICATOR
                      </span>

                      <strong>
                        {flag.category}
                      </strong>

                      <div className="sentri-signal-metadata">
                        <span className="sentri-signal-id">
                          {flag.signalId ??
                            "LEGACY-SIGNAL"}
                        </span>

                        <span className="sentri-signal-severity">
                          {severity}
                        </span>

                        <span className="sentri-signal-source">
                          {formatSource(
                            flag.source,
                          )}
                        </span>
                      </div>

                      <p>{flag.description}</p>

                      {evidence.length > 0 && (
                        <div className="sentri-signal-evidence">
                          <span>
                            DETECTION EVIDENCE
                          </span>

                          {evidence.map(
                            (
                              item,
                              evidenceIndex,
                            ) => (
                              <div
                                key={evidenceIndex}
                              >
                                <p>
                                  {item.description}
                                </p>

                                {item.value && (
                                  <code>
                                    {item.value}
                                  </code>
                                )}
                              </div>
                            ),
                          )}
                        </div>
                      )}
                    </div>

                    <div className="hud-flag-points">
                      +{flag.points}
                    </div>
                  </article>
                );
              })
            )}
          </div>

          {/* =====================================
              DEFENSE GUIDANCE
          ===================================== */}

          <div className="hud-guidance">
            <div className="hud-guidance-header">
              <div>
                <p className="radar-label">
                  Defense Guidance
                </p>

                <h4>
                  Recommended Action
                </h4>
              </div>

              <span className={riskClass}>
                RESPONSE PROTOCOL
              </span>
            </div>

            <p>{result.recommendation}</p>
          </div>
        </>
      )}
    </section>
  );
}

export default ResultsCard;
