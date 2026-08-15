import type { StoredScan } from "../services/api";

export type ScanHistoryItem = StoredScan;

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
    <section className="history-section incident-archive">
      <div className="history-header incident-archive-header">
        <div>
          <p className="eyebrow">
            Security Archive
          </p>

          <h3>
            Incident Log
          </h3>
        </div>

        <div className="archive-header-actions">
          <span className="archive-status">
            DATABASE ONLINE
          </span>

          {history.length > 0 && (
            <button
              type="button"
              className="secondary-button"
              onClick={onClearHistory}
            >
              Purge Archive
            </button>
          )}
        </div>
      </div>

      <div className="archive-table-header">
        <span>
          ID
        </span>

        <span>
          TYPE
        </span>

        <span>
          TARGET
        </span>

        <span>
          RISK
        </span>

        <span>
          SCORE
        </span>

        <span>
          TIMESTAMP
        </span>
      </div>

      {history.length === 0 ? (
        <div className="archive-empty-state">
          <div className="archive-empty-radar">
            <div />
            <div />
            <div />
          </div>

          <strong>
            NO INCIDENTS LOGGED
          </strong>

          <p>
            Message and URL scans stored by Sentri will appear in the
            security archive.
          </p>

          <span>
            ARCHIVE NODE // READY
          </span>
        </div>
      ) : (
        <div className="incident-list">
          {history.map(
            (
              item,
              index,
            ) => {
              const riskClass =
                `risk-${item.result.riskLevel.toLowerCase()}`;

              const shortId =
                item.id
                  .replace(
                    /-/g,
                    "",
                  )
                  .slice(
                    0,
                    8,
                  )
                  .toUpperCase();

              return (
                <button
                  type="button"
                  className="incident-row"
                  key={item.id}
                  onClick={() =>
                    onSelect(
                      item,
                    )
                  }
                >
                  <div className="incident-id">
                    <span>
                      {String(
                        index +
                          1,
                      ).padStart(
                        2,
                        "0",
                      )}
                    </span>

                    <strong>
                      {shortId}
                    </strong>
                  </div>

                  <div className="incident-type">
                    <span
                      className={`scan-type-badge scan-type-${item.type.toLowerCase()}`}
                    >
                      {
                        item.type
                      }
                    </span>
                  </div>

                  <div className="incident-target">
                    <strong>
                      {
                        item.content
                      }
                    </strong>

                    <span>
                      {
                        item.result
                          .summary
                      }
                    </span>
                  </div>

                  <div className="incident-risk">
                    <span
                      className={`incident-risk-dot ${riskClass}`}
                    />

                    <strong
                      className={
                        riskClass
                      }
                    >
                      {
                        item.result
                          .riskLevel
                      }
                    </strong>
                  </div>

                  <div
                    className={`incident-score ${riskClass}`}
                  >
                    {
                      item.result
                        .riskScore
                    }
                  </div>

                  <div className="incident-time">
                    <strong>
                      {new Date(
                        item.createdAt,
                      ).toLocaleTimeString(
                        [],
                        {
                          hour:
                            "2-digit",
                          minute:
                            "2-digit",
                        },
                      )}
                    </strong>

                    <span>
                      {new Date(
                        item.createdAt,
                      ).toLocaleDateString()}
                    </span>
                  </div>
                </button>
              );
            },
          )}
        </div>
      )}

      <div className="archive-footer">
        <span>
          SENTRI // INCIDENT DATABASE
        </span>

        <strong>
          {history.length
            .toString()
            .padStart(
              2,
              "0",
            )}{" "}
          RECORDS
        </strong>
      </div>
    </section>
  );
}

export default ScanHistory;