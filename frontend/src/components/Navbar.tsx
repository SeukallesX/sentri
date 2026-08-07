function Navbar() {
  return (
    <header className="navbar">
      <div className="brand">
        <div className="brand-icon">S</div>

        <div>
          <h1>Sentri</h1>
          <p>Scam Detection Dashboard</p>
        </div>
      </div>

      <div className="status">
        <span className="status-dot" />
        Rule-Based Protection Active
      </div>
    </header>
  );
}

export default Navbar;