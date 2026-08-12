import type { ScanHistoryItem } from "./ScanHistory";

interface ThreatIndexProps {
  history: ScanHistoryItem[];
}

function ThreatIndex({
  history,
}: ThreatIndexProps) {
  const averageRisk =
    history.length === 0
      ? 0
      : Math.round(
          history.reduce(
            (total, item) =>
              total + item.result.riskScore,
            0,
          ) / history.length,
        );

  let status = "Clear";
  let description =
    "No meaningful threat activity detected.";

  if (averageRisk >= 70) {
    status = "Critical";
    description =
      "Recent activity contains multiple high-risk threat indicators.";
  } else if (averageRisk >= 45) {
    status = "Elevated";
    description =
      "Recent scans show increased suspicious activity.";
  } else if (averageRisk >= 20) {
    status = "Guarded";
    description =
      "Some suspicious indicators have been detected.";
  }

  const securityScore =
    Math.max(0, 100 - averageRisk);

  const riskClass =
    averageRisk >= 70
      ? "risk-high"
      : averageRisk >= 45
        ? "risk-medium"
        : "risk-low";

  return (
    <section className="threat-index-card">
      <div className="threat-index-header">
        <div>
          <p className="eyebrow">
            Environment Intelligence
          </p>

          <h3>
            Threat Index
          </h3>
        </div>

        <span
          className={`threat-index-status ${riskClass}`}
        >
          {status}
        </span>
      </div>

      <div className="threat-index-content">
        <div className={`index-orb ${riskClass}`}>
          <div className="index-ring index-ring-one" />
          <div className="index-ring index-ring-two" />

          <div className="index-score">
            <strong>
              {averageRisk}
            </strong>

            <span>
              THREAT
            </span>
          </div>
        </div>

        <div className="index-details">
          <div className="index-detail-heading">
            <span>
              Current Environment
            </span>

            <strong className={riskClass}>
              {status.toUpperCase()}
            </strong>
          </div>

          <p>
            {description}
          </p>

          <div className="index-progress">
            <div
              className={`index-progress-fill ${riskClass}`}
              style={{
                width: `${averageRisk}%`,
              }}
            />
          </div>

          <div className="index-metrics">
            <div>
              <span>
                Security Score
              </span>

              <strong>
                {securityScore}%
              </strong>
            </div>

            <div>
              <span>
                Recent Scans
              </span>

              <strong>
                {history.length}
              </strong>
            </div>

            <div>
              <span>
                High Risk
              </span>

              <strong>
                {
                  history.filter(
                    (item) =>
                      item.result.riskLevel ===
                      "High",
                  ).length
                }
              </strong>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ThreatIndex;