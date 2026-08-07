function Hero() {
  return (
    <section className="hero">
      <div className="hero-copy">
        <div className="hero-badge">
          <span className="hero-badge-dot" />
          Digital Threat Defense System
        </div>

        <h2>
          Scan the
          <span className="hero-gradient"> digital layer.</span>
          <br />
          Stop the threat.
        </h2>

        <p>
          Sentri analyzes suspicious messages and links using a rule-based
          cybersecurity engine designed to identify phishing, fraud,
          impersonation, malicious URLs, and social engineering techniques.
        </p>

        <div className="hero-system-info">
          <div>
            <span>ENGINE</span>
            <strong>RULE-X v1.0</strong>
          </div>

          <div>
            <span>STATUS</span>
            <strong className="online-text">ONLINE</strong>
          </div>

          <div>
            <span>MODE</span>
            <strong>LOCAL ANALYSIS</strong>
          </div>
        </div>
      </div>

      <div className="hero-orb-area">
        <div className="orb-shell">
          <div className="orb-ring orb-ring-one" />
          <div className="orb-ring orb-ring-two" />
          <div className="orb-ring orb-ring-three" />

          <div className="orb-core">
            <span>S</span>
          </div>

          <span className="orbit-node node-one" />
          <span className="orbit-node node-two" />
          <span className="orbit-node node-three" />
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