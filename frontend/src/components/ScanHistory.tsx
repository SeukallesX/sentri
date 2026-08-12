import type { AnalysisResult } from "../services/api";

export type ScanType = "Message" | "URL";

export interface ScanHistoryItem {
  id: string;
  type: ScanType;
  content: string;
  result: AnalysisResult;
  createdAt: string;
}

interface ScanHistoryProps {
  history: ScanHistoryItem[];
  onSelect: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
}

function ScanHistory({
  history,
  onSelect,
  onClearHistory,
}: ScanHistoryProps) {
  return (
    <section className="history-section">
      <div className="history-header">
        <div>
          <p className="eyebrow">Security Archive</p>
          <h3>Recent Scans</h3>
        </div>

        {history.length > 0 && (
          <button
            type="button"
            className="secondary-button"
            onClick={onClearHistory}
          >
            Clear History
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <div className="history-empty">
          <p>No scans recorded.</p>
          <span>Message and URL scans will appear here.</span>
        </div>
      ) : (
        <div className="history-list">
          {history.map((item) => (
            <button
              type="button"
              className="history-item"
              key={item.id}
              onClick={() => onSelect(item)}
            >
              <div className="history-message">
                <div className="history-title-row">
                  <span className="scan-type-badge">
                    {item.type}
                  </span>

                  <strong>
                    {item.result.riskLevel} Risk
                  </strong>
                </div>

                <p>{item.content}</p>
              </div>

              <div className="history-meta">
                <span
                  className={`history-risk risk-${item.result.riskLevel.toLowerCase()}`}
                >
                  {item.result.riskScore}
                </span>

                <small>
                  {new Date(item.createdAt).toLocaleString()}
                </small>
              </div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

export default ScanHistory;