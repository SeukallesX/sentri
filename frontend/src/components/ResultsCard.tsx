import type { AnalysisResult } from "../services/api";

interface ResultsCardProps {
  result: AnalysisResult | null;
}

function ResultsCard({
  result,
}: ResultsCardProps) {
  const riskLevel =
    result?.riskLevel ?? "Low";

  const riskClass =
    result
      ? `risk-${riskLevel.toLowerCase()}`
      : "risk-low";

  const score =
    result?.riskScore ?? 0;

  const indicatorCount =
    result?.flags.length ?? 0;

  const systemStatus =
    result
      ? riskLevel === "High"
        ? "THREAT DETECTED"
        : riskLevel === "Medium"
          ? "CAUTION"
          : "NOMINAL"
      : "STANDBY";

  return (
    <section className="results-card jarvis-results-card">
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

              <strong>
                {score}
              </strong>

              <small>
                /100
              </small>
            </div>
          </div>

          <div className="hud-radar-caption">
            <span className={`hud-caption-dot ${riskClass}`} />

            {result
              ? `${riskLevel.toUpperCase()} THREAT PROFILE`
              : "SCAN ENGINE READY"}
          </div>
        </div>

        <div className="hud-readout">
          <div className="hud-readout-title">
            <span>
              SYSTEM READOUT
            </span>

            <small>
              RULE-X // LOCAL
            </small>
          </div>

          <div className="hud-readout-grid">
            <div className="hud-readout-item">
              <span>
                Risk Index
              </span>

              <strong className={riskClass}>
                {score
                  .toString()
                  .padStart(3, "0")}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>
                Indicators
              </span>

              <strong>
                {indicatorCount
                  .toString()
                  .padStart(2, "0")}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>
                Threat Level
              </span>

              <strong className={riskClass}>
                {result
                  ? riskLevel.toUpperCase()
                  : "READY"}
              </strong>
            </div>

            <div className="hud-readout-item">
              <span>
                Engine
              </span>

              <strong>
                RULE-X
              </strong>
            </div>
          </div>

          <div className="hud-signal-line">
            <span>
              SIGNAL ANALYSIS
            </span>

            <div className="hud-signal-track">
              <div
                className={`hud-signal-fill ${riskClass}`}
                style={{
                  width: `${score}%`,
                }}
              />
            </div>

            <strong className={riskClass}>
              {systemStatus}
            </strong>
          </div>

          <div className="hud-summary">
            <p className="radar-label">
              Intelligence Summary
            </p>

            <p>
              {result
                ? result.summary
                : "Sentri is standing by. Initialize a message scan to activate threat analysis."}
            </p>
          </div>
        </div>
      </div>

      {result && (
        <>
          <div className="hud-divider">
            <span>
              DETECTED SIGNALS
            </span>
          </div>

          <div className="hud-flags">
            {result.flags.length === 0 ? (
              <div className="hud-clear-state">
                <span className="hud-clear-icon">
                  ✓
                </span>

                <div>
                  <strong>
                    No major indicators detected
                  </strong>

                  <p>
                    The analyzed message did not match Sentri's common scam rules.
                  </p>
                </div>
              </div>
            ) : (
              result.flags.map(
                (
                  flag,
                  index,
                ) => (
                  <article
                    className="hud-flag"
                    key={`${flag.category}-${index}`}
                  >
                    <div className="hud-flag-index">
                      {(index + 1)
                        .toString()
                        .padStart(2, "0")}
                    </div>

                    <div className="hud-flag-content">
                      <span>
                        INDICATOR
                      </span>

                      <strong>
                        {flag.category}
                      </strong>

                      <p>
                        {flag.description}
                      </p>
                    </div>

                    <div className="hud-flag-points">
                      +{flag.points}
                    </div>
                  </article>
                ),
              )
            )}
          </div>

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

            <p>
              {result.recommendation}
            </p>
          </div>
        </>
      )}
    </section>
  );
}

export default ResultsCard;