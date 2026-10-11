
import { useMemo, useState } from "react";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import type { ScanHistoryItem } from "./ScanHistory";

import ThreatAnalyticsFilters, {
  type ThreatAnalyticsFilterState,
} from "./ThreatAnalyticsFilters";

import "../styles/threatAnalytics.css";

interface ThreatAnalyticsProps {
  history: ScanHistoryItem[];
}

type SignalSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface AnalyticsFlag {
  category: string;
  description: string;
  points: number;
  signalId?: string;
  severity?: SignalSeverity;
  source?: string;
}

const RISK_COLORS: Record<string, string> = {
  High: "#ff6572",
  Medium: "#f7c75d",
  Low: "#46e6ae",
};

const SEVERITY_COLORS: Record<
  SignalSeverity,
  string
> = {
  critical: "#ff5367",
  high: "#ff9254",
  medium: "#ffd166",
  low: "#69c9ff",
  info: "#5de4c7",
};

const CHART_TOOLTIP_STYLE = {
  background: "#081422",
  border: "1px solid rgba(78,232,211,0.18)",
  borderRadius: "10px",
  color: "#d9e7f5",
};

const AXIS_TICK_STYLE = {
  fill: "#8098af",
  fontSize: 10,
};

const GRID_COLOR = "rgba(120,170,210,0.08)";

function getSignalSeverity(
  flag: AnalyticsFlag,
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

function formatSignalName(
  signalId: string,
): string {
  return signalId
    .replace(/^RX-/, "")
    .replace(/^URL-/, "")
    .replace(/-/g, " ");
}

function ThreatAnalytics({
  history,
}: ThreatAnalyticsProps) {
  const [filters, setFilters] =
    useState<ThreatAnalyticsFilterState>({
      scanType: "all",
      riskLevel: "all",
    });

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesType =
        filters.scanType === "all" ||
        String(item.type) === String(filters.scanType);

      const matchesRisk =
        filters.riskLevel === "all" ||
        String(item.result.riskLevel) ===
          String(filters.riskLevel);

      return matchesType && matchesRisk;
    });
  }, [history, filters]);

  const analytics = useMemo(() => {
    const riskCounts = {
      High: 0,
      Medium: 0,
      Low: 0,
    };

    const categoryMap = new Map<string, number>();
    const signalMap = new Map<string, number>();

    const severityCounts: Record<
      SignalSeverity,
      number
    > = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    let riskTotal = 0;
    let highestRisk = 0;
    let totalIndicators = 0;
    let structuredSignals = 0;
    let informationalSignals = 0;

    for (const item of filteredHistory) {
      const result = item.result;

      if (result.riskLevel in riskCounts) {
        riskCounts[result.riskLevel] += 1;
      }

      riskTotal += result.riskScore;

      highestRisk = Math.max(
        highestRisk,
        result.riskScore,
      );

      const flags: AnalyticsFlag[] =
        result.flags ?? [];

      for (const flag of flags) {
        const severity = getSignalSeverity(flag);

        severityCounts[severity] += 1;

        if (flag.points === 0) {
          informationalSignals += 1;
        } else {
          totalIndicators += 1;
        }

        if (flag.signalId) {
          structuredSignals += 1;

          signalMap.set(
            flag.signalId,
            (signalMap.get(flag.signalId) ?? 0) + 1,
          );
        }

        if (flag.points > 0) {
          categoryMap.set(
            flag.category,
            (categoryMap.get(flag.category) ?? 0) + 1,
          );
        }
      }
    }

    const riskData = [
      { name: "High", value: riskCounts.High },
      { name: "Medium", value: riskCounts.Medium },
      { name: "Low", value: riskCounts.Low },
    ];

    const severityData = (
      [
        "critical",
        "high",
        "medium",
        "low",
        "info",
      ] as SignalSeverity[]
    ).map((severity) => ({
      name:
        severity.charAt(0).toUpperCase() +
        severity.slice(1),
      value: severityCounts[severity],
      severity,
    }));

    const categoryData = Array.from(
      categoryMap.entries(),
    )
      .map(([name, value]) => ({
        name,
        value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);

    const topSignals = Array.from(
      signalMap.entries(),
    )
      .map(([id, count]) => ({
        id,
        name: formatSignalName(id),
        count,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const trendData = [...filteredHistory]
      .reverse()
      .map((item, index) => ({
        name: `Scan ${index + 1}`,
        score: item.result.riskScore,
        type: item.type,
        level: item.result.riskLevel,
      }));

    return {
      riskData,
      severityData,
      categoryData,
      topSignals,
      trendData,

      averageRisk:
        filteredHistory.length === 0
          ? 0
          : Math.round(
              riskTotal / filteredHistory.length,
            ),

      highestRisk,
      totalIndicators,
      structuredSignals,
      informationalSignals,
      highRiskCount: riskCounts.High,
      criticalSignalCount: severityCounts.critical,
    };
  }, [filteredHistory]);

  const {
    riskData,
    severityData,
    categoryData,
    topSignals,
    trendData,
    averageRisk,
    highestRisk,
    totalIndicators,
    structuredSignals,
    informationalSignals,
    highRiskCount,
    criticalSignalCount,
  } = analytics;

  return (
    <section className="analytics-section">
      {/* =====================================
          HEADER
      ===================================== */}

      <div className="analytics-header">
        <div>
          <p className="eyebrow">
            Threat Intelligence
          </p>

          <h3>Threat Analytics</h3>
        </div>

        <span className="private-label">
          STORED SCAN DATA
        </span>
      </div>

      {/* =====================================
          FILTER CONTROLS
      ===================================== */}

      <ThreatAnalyticsFilters
        filters={filters}
        onChange={setFilters}
        totalCount={history.length}
        filteredCount={filteredHistory.length}
      />

      {filteredHistory.length === 0 ? (
        <div className="analytics-empty">
          <p>
            {history.length === 0
              ? "No scan data available yet."
              : "No scans match your filters."}
          </p>

          <span>
            {history.length === 0
              ? "Run message or URL scans to populate the dashboard."
              : "Try another scan type or risk level."}
          </span>
        </div>
      ) : (
        <>
          {/* =====================================
              SUMMARY METRICS
          ===================================== */}

          <div className="analytics-summary-grid">
            <article className="analytics-summary-card">
              <span>Average Risk</span>
              <strong>{averageRisk}</strong>
              <small>/100</small>
            </article>

            <article className="analytics-summary-card">
              <span>Highest Risk</span>
              <strong className="risk-high">
                {highestRisk}
              </strong>
              <small>/100</small>
            </article>

            <article className="analytics-summary-card">
              <span>Risk Indicators</span>
              <strong>{totalIndicators}</strong>
              <small>detected</small>
            </article>

            <article className="analytics-summary-card">
              <span>Data Window</span>
              <strong>
                {filteredHistory.length}
              </strong>
              <small>filtered scans</small>
            </article>
          </div>

          {/* =====================================
              INTELLIGENCE METRICS
          ===================================== */}

          <div className="analytics-summary-grid">
            <article className="analytics-summary-card">
              <span>High-Risk Scans</span>
              <strong className="risk-high">
                {highRiskCount}
              </strong>
              <small>scans</small>
            </article>

            <article className="analytics-summary-card">
              <span>Critical Signals</span>
              <strong className="risk-high">
                {criticalSignalCount}
              </strong>
              <small>detections</small>
            </article>

            <article className="analytics-summary-card">
              <span>Structured Signals</span>
              <strong>
                {structuredSignals}
              </strong>
              <small>Rule-X / URL</small>
            </article>

            <article className="analytics-summary-card">
              <span>Informational</span>
              <strong>
                {informationalSignals}
              </strong>
              <small>zero-point signals</small>
            </article>
          </div>

          {/* =====================================
              CHARTS
          ===================================== */}

          <div className="analytics-grid">
            {/* RISK DISTRIBUTION */}

            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    RISK DISTRIBUTION
                  </p>
                  <h4>Scan Severity</h4>
                </div>
              </div>

              <div className="chart-wrapper">
                <ResponsiveContainer
                  width="100%"
                  height={260}
                >
                  <PieChart>
                    <Pie
                      data={riskData}
                      dataKey="value"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={58}
                      outerRadius={92}
                      paddingAngle={4}
                    >
                      {riskData.map((item) => (
                        <Cell
                          key={item.name}
                          fill={
                            RISK_COLORS[item.name]
                          }
                        />
                      ))}
                    </Pie>

                    <Tooltip
                      contentStyle={
                        CHART_TOOLTIP_STYLE
                      }
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="analytics-legend">
                {riskData.map((item) => (
                  <div key={item.name}>
                    <span
                      className="legend-dot"
                      style={{
                        background:
                          RISK_COLORS[item.name],
                      }}
                    />

                    <p>{item.name}</p>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </article>

            {/* THREAT CATEGORIES */}

            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    THREAT CATEGORIES
                  </p>
                  <h4>Common Indicators</h4>
                </div>
              </div>

              {categoryData.length === 0 ? (
                <div className="chart-empty">
                  <p>
                    No risk indicators detected.
                  </p>
                </div>
              ) : (
                <div className="chart-wrapper">
                  <ResponsiveContainer
                    width="100%"
                    height={300}
                  >
                    <BarChart
                      data={categoryData}
                      layout="vertical"
                      margin={{
                        top: 10,
                        right: 20,
                        bottom: 10,
                        left: 35,
                      }}
                    >
                      <CartesianGrid
                        strokeDasharray="3 3"
                        stroke={GRID_COLOR}
                      />

                      <XAxis
                        type="number"
                        allowDecimals={false}
                        tick={AXIS_TICK_STYLE}
                        axisLine={false}
                        tickLine={false}
                      />

                      <YAxis
                        type="category"
                        dataKey="name"
                        width={120}
                        tick={{
                          fill: "#8098af",
                          fontSize: 9,
                        }}
                        axisLine={false}
                        tickLine={false}
                      />

                      <Tooltip
                        contentStyle={
                          CHART_TOOLTIP_STYLE
                        }
                      />

                      <Bar
                        dataKey="value"
                        name="Detections"
                        fill="#4ee8d3"
                        radius={[0, 6, 6, 0]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </article>

            {/* SIGNAL SEVERITY */}

            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    RULE-X INTELLIGENCE
                  </p>
                  <h4>Signal Severity</h4>
                </div>
              </div>

              <div className="chart-wrapper">
                <ResponsiveContainer
                  width="100%"
                  height={280}
                >
                  <BarChart
                    data={severityData}
                    margin={{
                      top: 15,
                      right: 15,
                      bottom: 10,
                      left: 0,
                    }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke={GRID_COLOR}
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: "#8098af",
                        fontSize: 10,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      allowDecimals={false}
                      tick={AXIS_TICK_STYLE}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={
                        CHART_TOOLTIP_STYLE
                      }
                    />

                    <Bar
                      dataKey="value"
                      name="Signals"
                      radius={[6, 6, 0, 0]}
                    >
                      {severityData.map(
                        (item) => (
                          <Cell
                            key={item.severity}
                            fill={
                              SEVERITY_COLORS[
                                item.severity
                              ]
                            }
                          />
                        ),
                      )}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </article>

            {/* TOP RULE-X SIGNALS */}

            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    DETECTION ENGINE
                  </p>
                  <h4>Top Security Signals</h4>
                </div>
              </div>

              {topSignals.length === 0 ? (
                <div className="chart-empty">
                  <p>
                    No structured signal
                    history available yet.
                  </p>
                </div>
              ) : (
                <div className="sentri-top-signals">
                  {topSignals.map(
                    (signal, index) => {
                      const maximum =
                        topSignals[0]?.count ?? 1;

                      const percentage =
                        (signal.count / maximum) *
                        100;

                      return (
                        <div
                          key={signal.id}
                          className="sentri-top-signal"
                        >
                          <div className="sentri-top-signal-header">
                            <span className="sentri-top-signal-name">
                              {String(
                                index + 1,
                              ).padStart(2, "0")}
                              {" // "}
                              {signal.name}
                            </span>

                            <strong className="sentri-top-signal-count">
                              {signal.count}
                            </strong>
                          </div>

                          <div className="sentri-top-signal-track">
                            <div
                              className="sentri-top-signal-fill"
                              style={{
                                width: `${percentage}%`,
                              }}
                            />
                          </div>

                          <small className="sentri-top-signal-id">
                            {signal.id}
                          </small>
                        </div>
                      );
                    },
                  )}
                </div>
              )}
            </article>

            {/* RISK TREND */}

            <article className="analytics-card analytics-card-wide">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    RISK TREND
                  </p>

                  <h4>
                    Threat Score Across Scans
                  </h4>
                </div>
              </div>

              <div className="chart-wrapper">
                <ResponsiveContainer
                  width="100%"
                  height={290}
                >
                  <LineChart
                    data={trendData}
                    margin={{
                      top: 15,
                      right: 20,
                      bottom: 5,
                      left: 0,
                    }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke={GRID_COLOR}
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: "#607b95",
                        fontSize: 10,
                      }}
                      axisLine={false}
                      tickLine={false}
                    />

                    <YAxis
                      domain={[0, 100]}
                      tick={AXIS_TICK_STYLE}
                      axisLine={false}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={
                        CHART_TOOLTIP_STYLE
                      }
                      labelStyle={{
                        color: "#4ee8d3",
                      }}
                    />

                    <Line
                      type="monotone"
                      dataKey="score"
                      name="Risk Score"
                      stroke="#4ee8d3"
                      strokeWidth={3}
                      dot={{
                        r: 4,
                        fill: "#4ee8d3",
                        stroke: "#07111f",
                        strokeWidth: 2,
                      }}
                      activeDot={{
                        r: 6,
                        fill: "#6af7e3",
                      }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </article>
          </div>

          <p className="sentri-analytics-disclaimer">
            Analytics reflect the scan records
            currently loaded in Sentri.
            Signal severity uses Rule-X metadata
            when available and estimated
            severity for legacy records.
            Heuristic detections are not
            confirmed security incidents.
          </p>
        </>
      )}
    </section>
  );
}

export default ThreatAnalytics;
