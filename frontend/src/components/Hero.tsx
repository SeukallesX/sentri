function Hero() {
  return (
    <section className="hero">
      <div className="hero-copy">
        <div className="hero-badge">
          <span className="hero-badge-dot" />

          SENTRI CORE ONLINE
        </div>

        <h2>
          Detect the signal.
          <br />

          <span className="hero-gradient">
            Expose the threat.
          </span>
        </h2>

        <p>
          Sentri analyzes suspicious messages and links using a local
          rule-based security engine designed to detect phishing,
          impersonation, fraud patterns, suspicious URLs, and social
          engineering indicators.
        </p>

        <div className="hero-system-info">
          <div>
            <span>
              ENGINE
            </span>

            <strong>
              RULE-X v1.0
            </strong>
          </div>

          <div>
            <span>
              STATUS
            </span>

            <strong className="online-text">
              ONLINE
            </strong>
          </div>

          <div>
            <span>
              ANALYSIS
            </span>

            <strong>
              LOCAL
            </strong>
          </div>

          <div>
            <span>
              DATABASE
            </span>

            <strong>
              SQLITE
            </strong>
          </div>
        </div>
      </div>

      <div className="hero-orb-area">
        <div className="orb-shell">
          <div className="orb-ring orb-ring-one" />

          <div className="orb-ring orb-ring-two" />

          <div className="orb-ring orb-ring-three" />

          <div className="orbit-node node-one" />
          <div className="orbit-node node-two" />
          <div className="orbit-node node-three" />

          <div className="orb-core">
            <span>
              S
            </span>
          </div>
        </div>

        <div className="orb-label">
          <span />

          SENTRI CORE ACTIVE
        </div>
      </div>
    </section>
  );
}

export default Hero;