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

interface ThreatAnalyticsProps {
  history: ScanHistoryItem[];
}

function ThreatAnalytics({
  history,
}: ThreatAnalyticsProps) {
  const riskData = [
    {
      name: "High",
      value: history.filter(
        (item) =>
          item.result.riskLevel === "High",
      ).length,
    },
    {
      name: "Medium",
      value: history.filter(
        (item) =>
          item.result.riskLevel === "Medium",
      ).length,
    },
    {
      name: "Low",
      value: history.filter(
        (item) =>
          item.result.riskLevel === "Low",
      ).length,
    },
  ];

  const categoryMap = new Map<
    string,
    number
  >();

  for (const item of history) {
    for (const flag of item.result.flags) {
      const current =
        categoryMap.get(flag.category) ?? 0;

      categoryMap.set(
        flag.category,
        current + 1,
      );
    }
  }

  const categoryData = Array.from(
    categoryMap.entries(),
  )
    .map(([name, value]) => ({
      name,
      value,
    }))
    .sort(
      (a, b) =>
        b.value - a.value,
    )
    .slice(0, 6);

  const trendData = [...history]
    .reverse()
    .map((item, index) => ({
      name: `Scan ${index + 1}`,
      score: item.result.riskScore,
      type: item.type,
      level: item.result.riskLevel,
    }));

  const pieColors = [
    "#ff6572",
    "#f7c75d",
    "#46e6ae",
  ];

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

  const highestRisk =
    history.length === 0
      ? 0
      : Math.max(
          ...history.map(
            (item) =>
              item.result.riskScore,
          ),
        );

  const totalIndicators =
    history.reduce(
      (total, item) =>
        total + item.result.flags.length,
      0,
    );

  return (
    <section className="analytics-section">
      <div className="analytics-header">
        <div>
          <p className="eyebrow">
            Threat Intelligence
          </p>

          <h3>
            Threat Analytics
          </h3>
        </div>

        <span className="private-label">
          LIVE DATA
        </span>
      </div>

      {history.length === 0 ? (
        <div className="analytics-empty">
          <p>
            No scan data available yet.
          </p>

          <span>
            Run several message or URL scans to
            populate the threat intelligence
            dashboard.
          </span>
        </div>
      ) : (
        <>
          <div className="analytics-summary-grid">
            <article className="analytics-summary-card">
              <span>
                Average Risk
              </span>

              <strong>
                {averageRisk}
              </strong>

              <small>
                /100
              </small>
            </article>

            <article className="analytics-summary-card">
              <span>
                Highest Risk
              </span>

              <strong className="risk-high">
                {highestRisk}
              </strong>

              <small>
                /100
              </small>
            </article>

            <article className="analytics-summary-card">
              <span>
                Indicators
              </span>

              <strong>
                {totalIndicators}
              </strong>

              <small>
                detected
              </small>
            </article>

            <article className="analytics-summary-card">
              <span>
                Data Window
              </span>

              <strong>
                {history.length}
              </strong>

              <small>
                recent scans
              </small>
            </article>
          </div>

          <div className="analytics-grid">
            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    RISK DISTRIBUTION
                  </p>

                  <h4>
                    Scan Severity
                  </h4>
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
                      {riskData.map(
                        (_, index) => (
                          <Cell
                            key={`risk-cell-${index}`}
                            fill={
                              pieColors[
                                index %
                                  pieColors.length
                              ]
                            }
                          />
                        ),
                      )}
                    </Pie>

                    <Tooltip
                      contentStyle={{
                        background:
                          "#081422",
                        border:
                          "1px solid rgba(78,232,211,0.18)",
                        borderRadius:
                          "10px",
                        color:
                          "#d9e7f5",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="analytics-legend">
                {riskData.map(
                  (item, index) => (
                    <div key={item.name}>
                      <span
                        className="legend-dot"
                        style={{
                          background:
                            pieColors[index],
                        }}
                      />

                      <p>
                        {item.name}
                      </p>

                      <strong>
                        {item.value}
                      </strong>
                    </div>
                  ),
                )}
              </div>
            </article>

            <article className="analytics-card">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    THREAT CATEGORIES
                  </p>

                  <h4>
                    Common Indicators
                  </h4>
                </div>
              </div>

              {categoryData.length === 0 ? (
                <div className="chart-empty">
                  <p>
                    No indicators detected yet.
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
                        stroke="rgba(120,170,210,0.08)"
                      />

                      <XAxis
                        type="number"
                        allowDecimals={false}
                        tick={{
                          fill: "#607b95",
                          fontSize: 10,
                        }}
                        axisLine={{
                          stroke:
                            "rgba(120,170,210,0.08)",
                        }}
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
                        contentStyle={{
                          background:
                            "#081422",
                          border:
                            "1px solid rgba(78,232,211,0.18)",
                          borderRadius:
                            "10px",
                          color:
                            "#d9e7f5",
                        }}
                      />

                      <Bar
                        dataKey="value"
                        fill="#4ee8d3"
                        radius={[
                          0,
                          6,
                          6,
                          0,
                        ]}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </article>

            <article className="analytics-card analytics-card-wide">
              <div className="analytics-card-header">
                <div>
                  <p className="radar-label">
                    RISK TREND
                  </p>

                  <h4>
                    Threat Score Over Time
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
                      stroke="rgba(120,170,210,0.08)"
                    />

                    <XAxis
                      dataKey="name"
                      tick={{
                        fill: "#607b95",
                        fontSize: 10,
                      }}
                      axisLine={{
                        stroke:
                          "rgba(120,170,210,0.08)",
                      }}
                      tickLine={false}
                    />

                    <YAxis
                      domain={[0, 100]}
                      tick={{
                        fill: "#607b95",
                        fontSize: 10,
                      }}
                      axisLine={{
                        stroke:
                          "rgba(120,170,210,0.08)",
                      }}
                      tickLine={false}
                    />

                    <Tooltip
                      contentStyle={{
                        background:
                          "#081422",
                        border:
                          "1px solid rgba(78,232,211,0.18)",
                        borderRadius:
                          "10px",
                        color:
                          "#d9e7f5",
                      }}
                      labelStyle={{
                        color:
                          "#4ee8d3",
                      }}
                    />

                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#4ee8d3"
                      strokeWidth={3}
                      dot={{
                        r: 4,
                        fill:
                          "#4ee8d3",
                        stroke:
                          "#07111f",
                        strokeWidth: 2,
                      }}
                      activeDot={{
                        r: 6,
                        fill:
                          "#6af7e3",
                      }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </article>
          </div>
        </>
      )}
    </section>
  );
}

export default ThreatAnalytics;