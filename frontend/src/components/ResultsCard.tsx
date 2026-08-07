import type { AnalysisResult } from "../services/api";

interface ResultsCardProps {
  result: AnalysisResult | null;
}

function ResultsCard({ result }: ResultsCardProps) {
  const riskClass = result
    ? `risk-${result.riskLevel.toLowerCase()}`
    : "risk-idle";

  return (
    <div className="results-card" aria-live="polite">
      {!result ? (
        <div className="empty-state">
          <div className="threat-radar idle-radar">
            <div className="radar-ring radar-ring-1" />
            <div className="radar-ring radar-ring-2" />
            <div className="radar-ring radar-ring-3" />
            <div className="radar-sweep" />

            <div className="radar-center">
              <span>S</span>
            </div>
          </div>

          <h3>Awaiting Analysis</h3>

          <p>
            Scan a suspicious message to activate the Sentri threat radar.
          </p>
        </div>
      ) : (
        <div className="results-content">
          <div className="results-header">
            <div>
              <p className="eyebrow">Threat Assessment</p>
              <h3>{result.riskLevel} Risk Detected</h3>
            </div>

            <span className={`threat-status ${riskClass}`}>
              {result.riskLevel === "High"
                ? "Threat"
                : result.riskLevel === "Medium"
                  ? "Caution"
                  : "Clear"}
            </span>
          </div>

          <div className="radar-result-layout">
            <div className={`threat-radar active-radar ${riskClass}`}>
              <div className="radar-ring radar-ring-1" />
              <div className="radar-ring radar-ring-2" />
              <div className="radar-ring radar-ring-3" />

              <div className="radar-crosshair radar-crosshair-x" />
              <div className="radar-crosshair radar-crosshair-y" />

              <div className="radar-sweep" />

              <span className="threat-point point-1" />
              <span className="threat-point point-2" />
              <span className="threat-point point-3" />

              <div className="radar-score">
                <strong>{result.riskScore}</strong>
                <span>/100</span>
              </div>
            </div>

            <div className="radar-summary">
              <p className="radar-label">SYSTEM SUMMARY</p>

              <p>{result.summary}</p>

              <div className="radar-metrics">
                <div>
                  <span>Risk Level</span>
                  <strong className={riskClass}>
                    {result.riskLevel}
                  </strong>
                </div>

                <div>
                  <span>Indicators</span>
                  <strong>{result.flags.length}</strong>
                </div>
              </div>
            </div>
          </div>

          <div className="risk-bar">
            <div
              className={`risk-fill ${riskClass}`}
              style={{
                width: `${result.riskScore}%`,
              }}
            />
          </div>

          <div className="result-section">
            <h4>Detected Indicators</h4>

            {result.flags.length === 0 ? (
              <p className="no-flags">
                No common scam indicators detected.
              </p>
            ) : (
              <div className="flag-list">
                {result.flags.map((flag) => (
                  <div
                    key={flag.category}
                    className="flag-card"
                  >
                    <div>
                      <h5>{flag.category}</h5>
                      <p>{flag.description}</p>
                    </div>

                    <span>+{flag.points}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="recommendation">
            <p className="radar-label">DEFENSE GUIDANCE</p>

            <h4>Recommended Action</h4>

            <p>{result.recommendation}</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default ResultsCard;