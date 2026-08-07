import type { DashboardStatTotals } from "../types/stats";

interface DashboardStatsProps {
  stats: DashboardStatTotals;
}

function DashboardStats({
  stats,
}: DashboardStatsProps) {
  return (
    <section className="stats-grid">
      <article className="stat-card">
        <p>Total Scans</p>
        <strong>{stats.totalScans}</strong>
        <span>Lifetime analyses</span>
      </article>

      <article className="stat-card">
        <p>High Risk</p>
        <strong className="risk-high">
          {stats.highRisk}
        </strong>
        <span>Potential threats</span>
      </article>

      <article className="stat-card">
        <p>Medium Risk</p>
        <strong className="risk-medium">
          {stats.mediumRisk}
        </strong>
        <span>Needs verification</span>
      </article>

      <article className="stat-card">
        <p>Low Risk</p>
        <strong className="risk-low">
          {stats.lowRisk}
        </strong>
        <span>Few indicators found</span>
      </article>
    </section>
  );
}

export default DashboardStats;