
import { useMemo, useState } from "react";
import type { StoredScan } from "../services/api";

import {
  downloadInvestigationReport,
  type ReportFormat,
} from "../utils/reportGenerator";

import "../styles/securityTimeline.css";

export type ScanHistoryItem = StoredScan;

interface ScanHistoryProps {
  history: ScanHistoryItem[];
  onSelect: (item: ScanHistoryItem) => void;
  onClearHistory: () => void;
}

type RiskFilter = "all" | "High" | "Medium" | "Low";
type TypeFilter = "all" | "message" | "url";
type SortOrder = "newest" | "oldest" | "highest";

interface EvidenceFlag {
  category: string;
  description: string;
  points: number;
  signalId?: string;
  severity?: string;
  source?: string;
  evidence?: {
    description: string;
    value?: string;
  }[];
}

function formatDate(value: string): string {
  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "Unknown date"
    : date.toLocaleDateString();
}

function formatTime(value: string): string {
  const date = new Date(value);

  return Number.isNaN(date.getTime())
    ? "--:--"
    : date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
}

function ScanHistory({
  history,
  onSelect,
  onClearHistory,
}: ScanHistoryProps) {
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] =
    useState<RiskFilter>("all");
  const [typeFilter, setTypeFilter] =
    useState<TypeFilter>("all");
  const [sortOrder, setSortOrder] =
    useState<SortOrder>("newest");

  const [expandedId, setExpandedId] =
    useState<string | null>(null);

  const [confirmClear, setConfirmClear] =
    useState(false);

  const [exportError, setExportError] =
    useState<string | null>(null);

  const filteredHistory = useMemo(() => {
    const query = search.trim().toLowerCase();

    const filtered = history.filter((item) => {
      const flags: EvidenceFlag[] =
        item.result.flags ?? [];

      const searchableText = [
        item.id,
        item.type,
        item.content,
        item.result.summary,
        item.result.threatCategory,
        item.result.riskLevel,
        ...flags.flatMap((flag) => [
          flag.category,
          flag.description,
          flag.signalId ?? "",
        ]),
      ]
        .join(" ")
        .toLowerCase();

      const matchesSearch =
        query.length === 0 ||
        searchableText.includes(query);

      const matchesRisk =
        riskFilter === "all" ||
        item.result.riskLevel === riskFilter;

      const matchesType =
        typeFilter === "all" ||
        item.type.toLowerCase() === typeFilter;

      return (
        matchesSearch &&
        matchesRisk &&
        matchesType
      );
    });

    return filtered.sort((a, b) => {
      if (sortOrder === "highest") {
        return (
          b.result.riskScore -
          a.result.riskScore
        );
      }

      const aTime = new Date(
        a.createdAt,
      ).getTime();

      const bTime = new Date(
        b.createdAt,
      ).getTime();

      const safeA = Number.isNaN(aTime)
        ? 0
        : aTime;

      const safeB = Number.isNaN(bTime)
        ? 0
        : bTime;

      return sortOrder === "oldest"
        ? safeA - safeB
        : safeB - safeA;
    });
  }, [
    history,
    search,
    riskFilter,
    typeFilter,
    sortOrder,
  ]);

  const hasActiveFilters =
    search.trim() !== "" ||
    riskFilter !== "all" ||
    typeFilter !== "all" ||
    sortOrder !== "newest";

  function resetFilters() {
    setSearch("");
    setRiskFilter("all");
    setTypeFilter("all");
    setSortOrder("newest");
  }

  function handleClearHistory() {
    if (!confirmClear) {
      setConfirmClear(true);
      return;
    }

    onClearHistory();
    setConfirmClear(false);
    setExpandedId(null);
    setExportError(null);
  }

  function handleExport(
    item: ScanHistoryItem,
    format: ReportFormat,
  ) {
    setExportError(null);

    try {
      downloadInvestigationReport(
        item,
        format,
      );
    } catch (error) {
      console.error(
        "Sentri report export failed:",
        error,
      );

      setExportError(
        "Unable to export this report. Please try again.",
      );
    }
  }

  return (
    <section className="history-section incident-archive sentri-timeline">
      {/* HEADER */}

      <div className="history-header incident-archive-header">
        <div>
          <p className="eyebrow">
            Security Archive
          </p>

          <h3>Incident Log</h3>
        </div>

        <div className="archive-header-actions">
          <span className="archive-status">
            STORED SCAN ARCHIVE
          </span>

          {history.length > 0 && (
            <div className="sentri-archive-clear-actions">
              {confirmClear && (
                <button
                  type="button"
                  className="sentri-clear-cancel"
                  onClick={() =>
                    setConfirmClear(false)
                  }
                >
                  Cancel
                </button>
              )}

              <button
                type="button"
                className="secondary-button"
                onClick={handleClearHistory}
              >
                {confirmClear
                  ? "Confirm Purge"
                  : "Purge Archive"}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* FILTER CONTROLS */}

      <div className="sentri-timeline-controls">
        <div className="sentri-timeline-search">
          <label htmlFor="sentri-history-search">
            SEARCH SECURITY EVENTS
          </label>

          <input
            id="sentri-history-search"
            type="search"
            placeholder="Search scans, domains, signals..."
            value={search}
            onChange={(event) =>
              setSearch(event.target.value)
            }
          />
        </div>

        <div className="sentri-timeline-select">
          <label htmlFor="sentri-history-type">
            SCAN TYPE
          </label>

          <select
            id="sentri-history-type"
            value={typeFilter}
            onChange={(event) =>
              setTypeFilter(
                event.target.value as TypeFilter,
              )
            }
          >
            <option value="all">All Types</option>
            <option value="message">Message</option>
            <option value="url">URL</option>
          </select>
        </div>

        <div className="sentri-timeline-select">
          <label htmlFor="sentri-history-risk">
            RISK LEVEL
          </label>

          <select
            id="sentri-history-risk"
            value={riskFilter}
            onChange={(event) =>
              setRiskFilter(
                event.target.value as RiskFilter,
              )
            }
          >
            <option value="all">All Risks</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        <div className="sentri-timeline-select">
          <label htmlFor="sentri-history-sort">
            SORT BY
          </label>

          <select
            id="sentri-history-sort"
            value={sortOrder}
            onChange={(event) =>
              setSortOrder(
                event.target.value as SortOrder,
              )
            }
          >
            <option value="newest">Newest</option>
            <option value="oldest">Oldest</option>
            <option value="highest">
              Highest Risk
            </option>
          </select>
        </div>
      </div>

      <div className="sentri-timeline-status">
        <span>
          DISPLAYING {filteredHistory.length} OF{" "}
          {history.length} SCANS
        </span>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={resetFilters}
          >
            RESET FILTERS
          </button>
        )}
      </div>

      {/* TABLE HEADER */}

      <div className="archive-table-header">
        <span>ID</span>
        <span>TYPE</span>
        <span>TARGET</span>
        <span>RISK</span>
        <span>SCORE</span>
        <span>TIMESTAMP</span>
      </div>

      {/* EMPTY STATE */}

      {history.length === 0 ? (
        <div className="archive-empty-state">
          <div className="archive-empty-radar">
            <div />
            <div />
            <div />
          </div>

          <strong>NO SCANS LOGGED</strong>

          <p>
            Message and URL scans stored by Sentri
            will appear in the security archive.
          </p>

          <span>ARCHIVE NODE // READY</span>
        </div>
      ) : filteredHistory.length === 0 ? (
        <div className="archive-empty-state">
          <strong>NO MATCHING RECORDS</strong>

          <p>
            No stored scans match the current
            search and filter settings.
          </p>

          <button
            type="button"
            className="sentri-timeline-reset"
            onClick={resetFilters}
          >
            RESET FILTERS
          </button>
        </div>
      ) : (
        <div className="incident-list">
          {filteredHistory.map((item, index) => {
            const riskClass =
              `risk-${item.result.riskLevel.toLowerCase()}`;

            const shortId = item.id
              .replace(/-/g, "")
              .slice(0, 8)
              .toUpperCase();

            const expanded =
              expandedId === item.id;

            const flags: EvidenceFlag[] =
              item.result.flags ?? [];

            return (
              <div
                key={item.id}
                className={`sentri-incident-entry ${
                  expanded
                    ? "sentri-incident-expanded"
                    : ""
                }`}
              >
                {/* SCAN ROW */}

                <button
                  type="button"
                  className="incident-row"
                  aria-expanded={expanded}
                  aria-controls={`sentri-evidence-${item.id}`}
                  onClick={() => {
                    setExpandedId(
                      expanded ? null : item.id,
                    );
                    setExportError(null);
                  }}
                >
                  <div className="incident-id">
                    <span>
                      {String(index + 1).padStart(
                        2,
                        "0",
                      )}
                    </span>

                    <strong>{shortId}</strong>
                  </div>

                  <div className="incident-type">
                    <span
                      className={`scan-type-badge scan-type-${item.type.toLowerCase()}`}
                    >
                      {item.type}
                    </span>
                  </div>

                  <div className="incident-target">
                    <strong>{item.content}</strong>

                    <span>
                      {item.result.summary}
                    </span>
                  </div>

                  <div className="incident-risk">
                    <span
                      className={`incident-risk-dot ${riskClass}`}
                    />

                    <strong className={riskClass}>
                      {item.result.riskLevel}
                    </strong>
                  </div>

                  <div
                    className={`incident-score ${riskClass}`}
                  >
                    {item.result.riskScore}
                  </div>

                  <div className="incident-time">
                    <strong>
                      {formatTime(item.createdAt)}
                    </strong>

                    <span>
                      {formatDate(item.createdAt)}
                    </span>
                  </div>
                </button>

                {/* INVESTIGATION PANEL */}

                {expanded && (
                  <div
                    id={`sentri-evidence-${item.id}`}
                    className="sentri-investigation-panel"
                  >
                    <div className="sentri-investigation-heading">
                      <div>
                        <span>
                          SENTRI // EVENT INSPECTION
                        </span>

                        <h4>Security Evidence</h4>
                      </div>

                      <div className="sentri-investigation-actions">
                        <button
                          type="button"
                          className="sentri-inspect-button"
                          onClick={() =>
                            onSelect(item)
                          }
                        >
                          Inspect Scan
                        </button>

                        <button
                          type="button"
                          className="sentri-export-button"
                          onClick={() =>
                            handleExport(item, "json")
                          }
                        >
                          Export JSON
                        </button>

                        <button
                          type="button"
                          className="sentri-export-button"
                          onClick={() =>
                            handleExport(item, "txt")
                          }
                        >
                          Export TXT
                        </button>
                      </div>
                    </div>

                    {exportError && (
                      <p
                        className="sentri-export-error"
                        role="alert"
                      >
                        {exportError}
                      </p>
                    )}

                    {/* METRICS */}

                    <div className="sentri-investigation-metrics">
                      <div>
                        <span>THREAT CATEGORY</span>
                        <strong>
                          {item.result.threatCategory ||
                            "Unknown"}
                        </strong>
                      </div>

                      <div>
                        <span>ATTACK VECTOR</span>
                        <strong>
                          {item.result.attackVector ||
                            "Unknown"}
                        </strong>
                      </div>

                      <div>
                        <span>CONFIDENCE</span>
                        <strong>
                          {item.result.confidence}%
                        </strong>
                      </div>

                      <div>
                        <span>RISK SCORE</span>
                        <strong>
                          {item.result.riskScore}/100
                        </strong>
                      </div>
                    </div>

                    {/* ORIGINAL CONTENT */}

                    <div className="sentri-investigation-content">
                      <span>
                        ORIGINAL SCAN CONTENT
                      </span>

                      <p>{item.content}</p>
                    </div>

                    {/* DETECTION EVIDENCE */}

                    <div className="sentri-investigation-signals">
                      <div className="sentri-investigation-section-heading">
                        <h5>Detection Evidence</h5>

                        <span>
                          {flags.length} SIGNALS
                        </span>
                      </div>

                      {flags.length === 0 ? (
                        <p className="sentri-no-evidence">
                          No detection flags were
                          recorded for this scan.
                        </p>
                      ) : (
                        <div className="sentri-evidence-list">
                          {flags.map((flag, flagIndex) => (
                            <article
                              key={`${item.id}-${flag.signalId ?? flag.category}-${flagIndex}`}
                              className="sentri-evidence-card"
                            >
                              <div className="sentri-evidence-header">
                                <strong>
                                  {flag.category}
                                </strong>

                                <span>
                                  +{flag.points} PTS
                                </span>
                              </div>

                              <p>
                                {flag.description}
                              </p>

                              <div className="sentri-evidence-metadata">
                                {flag.signalId && (
                                  <code>
                                    {flag.signalId}
                                  </code>
                                )}

                                {flag.severity && (
                                  <span>
                                    {flag.severity.toUpperCase()}
                                  </span>
                                )}

                                {flag.source && (
                                  <span>
                                    {flag.source}
                                  </span>
                                )}
                              </div>

                              {flag.evidence &&
                                flag.evidence.length > 0 && (
                                  <div className="sentri-evidence-details">
                                    {flag.evidence.map(
                                      (evidence, evidenceIndex) => (
                                        <div
                                          key={evidenceIndex}
                                        >
                                          <span>
                                            {evidence.description}
                                          </span>

                                          {evidence.value && (
                                            <code>
                                              {evidence.value}
                                            </code>
                                          )}
                                        </div>
                                      ),
                                    )}
                                  </div>
                                )}
                            </article>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* RESPONSE GUIDANCE */}

                    <div className="sentri-investigation-guidance">
                      <span>
                        RECOMMENDED RESPONSE
                      </span>

                      <p>
                        {item.result.recommendation}
                      </p>
                    </div>

                    <p className="sentri-report-privacy">
                      Reports are generated locally
                      and may contain sensitive scan
                      content. Review before sharing.
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* FOOTER */}

      <div className="archive-footer">
        <span>
          SENTRI // SCAN DATABASE
        </span>

        <strong>
          {history.length
            .toString()
            .padStart(2, "0")}{" "}
          RECORDS
        </strong>
      </div>
    </section>
  );
}

export default ScanHistory;
