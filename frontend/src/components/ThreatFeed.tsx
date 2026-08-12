import type { ScanHistoryItem } from "./ScanHistory";

interface ThreatFeedProps {
  history: ScanHistoryItem[];
}

function ThreatFeed({
  history,
}: ThreatFeedProps) {
  return (
    <section className="threat-feed">
      <div className="threat-feed-header">
        <div>
          <p className="eyebrow">
            Threat Intelligence
          </p>

          <h3>
            Live Threat Feed
          </h3>
        </div>

        <span className="private-label">
          LIVE
        </span>
      </div>

      {history.length === 0 ? (
        <div className="feed-empty">
          <p>
            No recent threat activity.
          </p>
        </div>
      ) : (
        <div className="feed-list">
          {history.map((scan) => (
            <div
              className="feed-item"
              key={scan.id}
            >
              <div
                className={`feed-status risk-${scan.result.riskLevel.toLowerCase()}`}
              />

              <div className="feed-content">
                <div className="feed-title-row">
                  <span className="scan-type-badge">
                    {scan.type}
                  </span>

                  <strong>
                    {scan.result.riskLevel} Risk
                  </strong>
                </div>

                <p>
                  {scan.result.summary}
                </p>

                <small>
                  {new Date(
                    scan.createdAt,
                  ).toLocaleTimeString()}
                </small>
              </div>

              <div
                className={`feed-score risk-${scan.result.riskLevel.toLowerCase()}`}
              >
                {scan.result.riskScore}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default ThreatFeed;