
import type { ChangeEvent } from "react";

export type ScanTypeFilter =
  | "all"
  | "message"
  | "url";

export type RiskFilter =
  | "all"
  | "High"
  | "Medium"
  | "Low";

export interface ThreatAnalyticsFilterState {
  scanType: ScanTypeFilter;
  riskLevel: RiskFilter;
}

interface ThreatAnalyticsFiltersProps {
  filters: ThreatAnalyticsFilterState;
  onChange: (
    filters: ThreatAnalyticsFilterState,
  ) => void;
  totalCount: number;
  filteredCount: number;
}

function ThreatAnalyticsFilters({
  filters,
  onChange,
  totalCount,
  filteredCount,
}: ThreatAnalyticsFiltersProps) {
  function handleScanTypeChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    onChange({
      ...filters,
      scanType:
        event.target.value as ScanTypeFilter,
    });
  }

  function handleRiskChange(
    event: ChangeEvent<HTMLSelectElement>,
  ) {
    onChange({
      ...filters,
      riskLevel:
        event.target.value as RiskFilter,
    });
  }

  function resetFilters() {
    onChange({
      scanType: "all",
      riskLevel: "all",
    });
  }

  const hasActiveFilters =
    filters.scanType !== "all" ||
    filters.riskLevel !== "all";

  return (
    <div className="sentri-analytics-filters">
      <div className="sentri-filter-header">
        <div>
          <span className="sentri-filter-eyebrow">
            INTELLIGENCE CONTROLS
          </span>

          <h4>Filter Scan History</h4>
        </div>

        <span className="sentri-filter-count">
          {filteredCount} / {totalCount} SCANS
        </span>
      </div>

      <div className="sentri-filter-controls">
        <label className="sentri-filter-field">
          <span>SCAN TYPE</span>

          <select
            value={filters.scanType}
            onChange={handleScanTypeChange}
          >
            <option value="all">
              All Scans
            </option>

            <option value="message">
              Message Scans
            </option>

            <option value="url">
              URL Scans
            </option>
          </select>
        </label>

        <label className="sentri-filter-field">
          <span>RISK LEVEL</span>

          <select
            value={filters.riskLevel}
            onChange={handleRiskChange}
          >
            <option value="all">
              All Risk Levels
            </option>

            <option value="High">
              High Risk
            </option>

            <option value="Medium">
              Medium Risk
            </option>

            <option value="Low">
              Low Risk
            </option>
          </select>
        </label>

        <button
          type="button"
          className="sentri-filter-reset"
          onClick={resetFilters}
          disabled={!hasActiveFilters}
        >
          RESET FILTERS
        </button>
      </div>
    </div>
  );
}

export default ThreatAnalyticsFilters;

