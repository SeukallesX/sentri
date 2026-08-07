import type { AnalysisResult } from "../services/api";

export interface ScanHistoryItem {
  id: string;
  message: string;
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
          <p className="eyebrow">Recent Scans</p>
          <h3>Scan History</h3>
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
          <p>No scans yet.</p>
          <span>Your recent Sentri analyses will appear here.</span>
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
                <strong>{item.result.riskLevel} Risk</strong>

                <p>{item.message}</p>
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