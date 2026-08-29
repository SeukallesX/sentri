import {
  useEffect,
  useState,
} from "react";

function Navbar() {
  const [menuOpen, setMenuOpen] =
    useState(false);

  const [settingsOpen, setSettingsOpen] =
    useState(false);

  useEffect(() => {
    if (
      !menuOpen &&
      !settingsOpen
    ) {
      return;
    }

    function handleEscape(
      event: KeyboardEvent,
    ) {
      if (event.key === "Escape") {
        setMenuOpen(false);
        setSettingsOpen(false);
      }
    }

    document.addEventListener(
      "keydown",
      handleEscape,
    );

    return () => {
      document.removeEventListener(
        "keydown",
        handleEscape,
      );
    };
  }, [
    menuOpen,
    settingsOpen,
  ]);

  function scrollToSection(
    sectionId: string,
  ) {
    const section =
      document.getElementById(
        sectionId,
      );

    if (section) {
      section.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }

    setMenuOpen(false);
  }

  function openSettings() {
    setMenuOpen(false);
    setSettingsOpen(true);
  }

  return (
    <>
      <header className="navbar">
        <div className="brand">
          <div className="brand-icon">
            S
          </div>

          <div>
            <h1>
              SENTRI
            </h1>

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

          <button
            type="button"
            className={`sentri-menu-button ${
              menuOpen
                ? "is-open"
                : ""
            }`}
            aria-label={
              menuOpen
                ? "Close Sentri menu"
                : "Open Sentri menu"
            }
            aria-expanded={
              menuOpen
            }
            onClick={() =>
              setMenuOpen(
                (current) =>
                  !current,
              )
            }
          >
            <span />
            <span />
            <span />
          </button>
        </div>
      </header>

      {menuOpen && (
        <>
          <button
            type="button"
            className="sentri-menu-backdrop"
            aria-label="Close menu"
            onClick={() =>
              setMenuOpen(false)
            }
          />

          <aside className="sentri-menu-panel">
            <div className="sentri-menu-header">
              <div>
                <span className="sentri-menu-kicker">
                  SENTRI // NAV
                </span>

                <h2>
                  Control Panel
                </h2>
              </div>

              <button
                type="button"
                className="sentri-panel-close"
                aria-label="Close menu"
                onClick={() =>
                  setMenuOpen(
                    false,
                  )
                }
              >
                ×
              </button>
            </div>

            <div className="sentri-menu-status">
              <span className="status-dot" />

              <div>
                <strong>
                  SYSTEM ONLINE
                </strong>

                <small>
                  RULE-X operational
                </small>
              </div>
            </div>

            <nav
              className="sentri-menu-nav"
              aria-label="Sentri navigation"
            >
              <button
                type="button"
                onClick={() =>
                  scrollToSection(
                    "threat-overview",
                  )
                }
              >
                <span>
                  01
                </span>

                <div>
                  <strong>
                    Dashboard
                  </strong>

                  <small>
                    Threat overview
                  </small>
                </div>
              </button>

              <button
                type="button"
                onClick={() =>
                  scrollToSection(
                    "message-analysis",
                  )
                }
              >
                <span>
                  02
                </span>

                <div>
                  <strong>
                    Message Analysis
                  </strong>

                  <small>
                    Scam detection
                  </small>
                </div>
              </button>

              <button
                type="button"
                onClick={() =>
                  scrollToSection(
                    "link-intelligence",
                  )
                }
              >
                <span>
                  03
                </span>

                <div>
                  <strong>
                    Link Intelligence
                  </strong>

                  <small>
                    URL scanner
                  </small>
                </div>
              </button>

              <button
                type="button"
                onClick={() =>
                  scrollToSection(
                    "threat-telemetry",
                  )
                }
              >
                <span>
                  04
                </span>

                <div>
                  <strong>
                    Threat Telemetry
                  </strong>

                  <small>
                    Detection metrics
                  </small>
                </div>
              </button>

              <button
                type="button"
                onClick={() =>
                  scrollToSection(
                    "security-archive",
                  )
                }
              >
                <span>
                  05
                </span>

                <div>
                  <strong>
                    Security Archive
                  </strong>

                  <small>
                    Scan history
                  </small>
                </div>
              </button>
            </nav>

            <div className="sentri-menu-divider">
              SYSTEM
            </div>

            <button
              type="button"
              className="sentri-settings-link"
              onClick={
                openSettings
              }
            >
              <span className="sentri-settings-icon">
                ⚙
              </span>

              <div>
                <strong>
                  Settings
                </strong>

                <small>
                  Configure Sentri
                </small>
              </div>

              <span className="sentri-menu-arrow">
                ›
              </span>
            </button>

            <div className="sentri-menu-footer">
              <span>
                SENTRI
              </span>

              <span>
                v0.5.1
              </span>
            </div>
          </aside>
        </>
      )}

      {settingsOpen && (
        <>
          <button
            type="button"
            className="sentri-menu-backdrop"
            aria-label="Close settings"
            onClick={() =>
              setSettingsOpen(
                false,
              )
            }
          />

          <aside className="sentri-menu-panel sentri-settings-panel">
            <div className="sentri-menu-header">
              <div>
                <span className="sentri-menu-kicker">
                  SENTRI // CONFIG
                </span>

                <h2>
                  Settings
                </h2>
              </div>

              <button
                type="button"
                className="sentri-panel-close"
                aria-label="Close settings"
                onClick={() =>
                  setSettingsOpen(
                    false,
                  )
                }
              >
                ×
              </button>
            </div>

            <section className="sentri-settings-section">
              <div className="sentri-settings-heading">
                <span>
                  01
                </span>

                <div>
                  <strong>
                    Interface
                  </strong>

                  <small>
                    HUD preferences
                  </small>
                </div>
              </div>

              <label className="sentri-setting-row">
                <div>
                  <strong>
                    Reduce Animations
                  </strong>

                  <small>
                    Minimize HUD motion
                  </small>
                </div>

                <input
                  type="checkbox"
                />
              </label>

              <label className="sentri-setting-row">
                <div>
                  <strong>
                    Compact HUD
                  </strong>

                  <small>
                    Reduce panel spacing
                  </small>
                </div>

                <input
                  type="checkbox"
                />
              </label>
            </section>

            <section className="sentri-settings-section">
              <div className="sentri-settings-heading">
                <span>
                  02
                </span>

                <div>
                  <strong>
                    Scanner
                  </strong>

                  <small>
                    Analysis preferences
                  </small>
                </div>
              </div>

              <label className="sentri-setting-row">
                <div>
                  <strong>
                    Informational Signals
                  </strong>

                  <small>
                    Show +0 indicators
                  </small>
                </div>

                <input
                  type="checkbox"
                  defaultChecked
                />
              </label>

              <label className="sentri-setting-row">
                <div>
                  <strong>
                    Auto-scroll
                  </strong>

                  <small>
                    Jump to scan results
                  </small>
                </div>

                <input
                  type="checkbox"
                  defaultChecked
                />
              </label>
            </section>

            <section className="sentri-settings-section">
              <div className="sentri-settings-heading">
                <span>
                  03
                </span>

                <div>
                  <strong>
                    System
                  </strong>

                  <small>
                    Runtime information
                  </small>
                </div>
              </div>

              <div className="sentri-system-setting">
                <span>
                  Engine
                </span>

                <strong>
                  RULE-X
                </strong>
              </div>

              <div className="sentri-system-setting">
                <span>
                  Processing
                </span>

                <strong>
                  LOCAL
                </strong>
              </div>

              <div className="sentri-system-setting">
                <span>
                  Version
                </span>

                <strong>
                  v0.5.1
                </strong>
              </div>

              <div className="sentri-system-setting">
                <span>
                  Status
                </span>

                <strong className="intel-good">
                  OPERATIONAL
                </strong>
              </div>
            </section>

            <button
              type="button"
              className="sentri-settings-back"
              onClick={() => {
                setSettingsOpen(
                  false,
                );

                setMenuOpen(
                  true,
                );
              }}
            >
              ← Back to Menu
            </button>
          </aside>
        </>
      )}
    </>
  );
}

export default Navbar;