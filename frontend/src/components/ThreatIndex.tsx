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

  const securityScore =
    Math.max(
      0,
      100 - averageRisk,
    );

  const highRiskCount =
    history.filter(
      (item) =>
        item.result.riskLevel ===
        "High",
    ).length;

  const mediumRiskCount =
    history.filter(
      (item) =>
        item.result.riskLevel ===
        "Medium",
    ).length;

  const lowRiskCount =
    history.filter(
      (item) =>
        item.result.riskLevel ===
        "Low",
    ).length;

  let status = "CLEAR";
  let statusLabel =
    "ENVIRONMENT NOMINAL";

  let description =
    "No meaningful threat activity detected.";

  let riskClass =
    "risk-low";

  if (averageRisk >= 70) {
    status = "CRITICAL";
    statusLabel =
      "HIGH THREAT ACTIVITY";

    description =
      "Recent scans contain multiple severe threat indicators and require immediate review.";

    riskClass =
      "risk-high";
  } else if (
    averageRisk >= 45
  ) {
    status = "ELEVATED";
    statusLabel =
      "THREAT LEVEL ELEVATED";

    description =
      "Recent scan activity contains several suspicious indicators that should be reviewed.";

    riskClass =
      "risk-medium";
  } else if (
    averageRisk >= 20
  ) {
    status = "GUARDED";
    statusLabel =
      "MONITORING ACTIVITY";

    description =
      "Some suspicious indicators have been detected. Continue monitoring and verify questionable activity.";

    riskClass =
      "risk-medium";
  }

  return (
    <section className="threat-index-card threat-command-card">
      <div className="threat-command-header">
        <div>
          <p className="eyebrow">
            Environment Intelligence
          </p>

          <h3>
            Threat Index
          </h3>
        </div>

        <div
          className={`threat-command-status ${riskClass}`}
        >
          <span />

          {status}
        </div>
      </div>

      <div className="threat-command-body">
        <div className="threat-hud-zone">
          <div className="threat-hud">
            <div className="threat-hud-ring threat-hud-ring-a" />

            <div className="threat-hud-ring threat-hud-ring-b" />

            <div className="threat-hud-ring threat-hud-ring-c" />

            <div className="threat-hud-ticks" />

            <div className="threat-hud-axis threat-hud-axis-x" />

            <div className="threat-hud-axis threat-hud-axis-y" />

            <div className="threat-hud-sweep" />

            <div className="threat-hud-node node-a" />

            <div className="threat-hud-node node-b" />

            <div className="threat-hud-node node-c" />

            <div className={`threat-hud-core ${riskClass}`}>
              <span>
                THREAT
              </span>

              <strong>
                {averageRisk
                  .toString()
                  .padStart(3, "0")}
              </strong>

              <small>
                INDEX
              </small>
            </div>
          </div>

          <div className="threat-hud-footer">
            <span className={riskClass} />

            {statusLabel}
          </div>
        </div>

        <div className="threat-command-readout">
          <div className="threat-readout-top">
            <div>
              <span>
                CURRENT ENVIRONMENT
              </span>

              <strong className={riskClass}>
                {status}
              </strong>
            </div>

            <small>
              SENTRI CORE // RULE-X
            </small>
          </div>

          <p className="threat-command-description">
            {description}
          </p>

          <div className="threat-meter-block">
            <div className="threat-meter-heading">
              <span>
                ENVIRONMENT RISK
              </span>

              <strong className={riskClass}>
                {averageRisk}%
              </strong>
            </div>

            <div className="threat-meter-track">
              <div
                className={`threat-meter-fill ${riskClass}`}
                style={{
                  width: `${averageRisk}%`,
                }}
              />
            </div>
          </div>

          <div className="threat-system-grid">
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

              <strong className="risk-high">
                {highRiskCount}
              </strong>
            </div>

            <div>
              <span>
                Medium
              </span>

              <strong className="risk-medium">
                {mediumRiskCount}
              </strong>
            </div>

            <div>
              <span>
                Low
              </span>

              <strong className="risk-low">
                {lowRiskCount}
              </strong>
            </div>

            <div>
              <span>
                Engine
              </span>

              <strong>
                ONLINE
              </strong>
            </div>
          </div>

          <div className="threat-system-footer">
            <span>
              ENV MONITOR
            </span>

            <div className="threat-system-wave">
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
              <i />
            </div>

            <strong>
              ACTIVE
            </strong>
          </div>
        </div>
      </div>
    </section>
  );
}

export default ThreatIndex;