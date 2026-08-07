interface DashboardControlsProps {
  onResetStats: () => void;
}

function DashboardControls({
  onResetStats,
}: DashboardControlsProps) {
  return (
    <div className="dashboard-controls">
      <button
        type="button"
        className="secondary-button"
        onClick={onResetStats}
      >
        Reset Dashboard Stats
      </button>
    </div>
  );
}

export default DashboardControls;