function Navbar() {
  return (
    <header className="navbar">
      <div className="brand">
        <div className="brand-icon">
          S
        </div>

        <div>
          <h1>SENTRI</h1>

          <p>
            Threat Intelligence System
          </p>
        </div>
      </div>

      <div className="navbar-system-status">
        <div className="status">
          <span className="status-dot" />

          System Online
        </div>

        <div className="navbar-module">
          <span>
            ENGINE
          </span>

          <strong>
            RULE-X
          </strong>
        </div>

        <div className="navbar-module">
          <span>
            MODE
          </span>

          <strong>
            LOCAL
          </strong>
        </div>
      </div>
    </header>
  );
}

export default Navbar;