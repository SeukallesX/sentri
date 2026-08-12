import { useCallback, useEffect, useState } from "react";
import type { SubmitEvent } from "react";

import "./App.css";

import AnalyzerCard from "./components/AnalyzerCard";
import DashboardControls from "./components/DashboardControls";
import DashboardStats from "./components/DashboardStats";
import ExportReportButton from "./components/ExportReportButton";
import Hero from "./components/Hero";
import Navbar from "./components/Navbar";
import ResultsCard from "./components/ResultsCard";
import ScanHistory from "./components/ScanHistory";
import ThreatAnalytics from "./components/ThreatAnalytics";
import ThreatFeed from "./components/ThreatFeed";
import ThreatIndex from "./components/ThreatIndex";
import UrlScanner from "./components/UrlScanner";

import type { ScanHistoryItem } from "./components/ScanHistory";
import type { DashboardStatTotals } from "./types/stats";

import {
  analyzeMessage,
  clearScans,
  getScans,
  getStats,
  type AnalysisResult,
} from "./services/api";

const defaultStats: DashboardStatTotals = {
  totalScans: 0,
  highRisk: 0,
  mediumRisk: 0,
  lowRisk: 0,
};

function App() {
  const [message, setMessage] = useState("");

  const [result, setResult] =
    useState<AnalysisResult | null>(null);

  const [isLoading, setIsLoading] = useState(false);

  const [historyLoading, setHistoryLoading] =
    useState(true);

  const [dashboardLoading, setDashboardLoading] =
    useState(true);

  const [error, setError] = useState("");

  const [historyError, setHistoryError] =
    useState("");

  const [history, setHistory] =
    useState<ScanHistoryItem[]>([]);

  const [stats, setStats] =
    useState<DashboardStatTotals>(defaultStats);

  const loadHistory = useCallback(async () => {
    try {
      setHistoryLoading(true);
      setHistoryError("");

      const scans = await getScans(10);

      setHistory(scans);
    } catch (requestError) {
      setHistoryError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load scan history.",
      );
    } finally {
      setHistoryLoading(false);
    }
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const dashboardStats = await getStats();

      setStats(dashboardStats);
    } catch (requestError) {
      console.error(
        "Unable to load Sentri dashboard stats:",
        requestError,
      );

      setStats(defaultStats);
    }
  }, []);

  const refreshDashboard = useCallback(async () => {
    await Promise.all([
      loadHistory(),
      loadStats(),
    ]);
  }, [loadHistory, loadStats]);

  useEffect(() => {
    async function initializeDashboard() {
      try {
        setDashboardLoading(true);

        await refreshDashboard();
      } finally {
        setDashboardLoading(false);
      }
    }

    void initializeDashboard();
  }, [refreshDashboard]);

  async function handleAnalyze(
    event: SubmitEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    const cleanedMessage = message.trim();

    if (!cleanedMessage) {
      setError(
        "Please enter a suspicious message.",
      );

      return;
    }

    try {
      setIsLoading(true);
      setError("");
      setResult(null);

      const data =
        await analyzeMessage(
          cleanedMessage,
        );

      setResult(data);

      await refreshDashboard();
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Something went wrong.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  async function handleUrlScanComplete(
    _scanResult: AnalysisResult,
    _url: string,
  ) {
    await refreshDashboard();
  }

  function handleMessageChange(
    value: string,
  ) {
    setMessage(value);

    if (error) {
      setError("");
    }
  }

  function handleClear() {
    setMessage("");
    setResult(null);
    setError("");
  }

  function handleSelectHistory(
    item: ScanHistoryItem,
  ) {
    setError("");

    if (item.type === "Message") {
      setMessage(item.content);
      setResult(item.result);

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });

      return;
    }

    if (item.type === "URL") {
      window.alert(
        `URL Scan

${item.content}

Risk: ${item.result.riskLevel}
Score: ${item.result.riskScore}/100`,
      );
    }
  }

  async function handleClearHistory() {
    try {
      setHistoryError("");

      await clearScans();

      setHistory([]);
      setStats(defaultStats);
    } catch (requestError) {
      setHistoryError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to clear scan history.",
      );
    }
  }

  async function handleResetStats() {
    /*
      Stats now come directly from the scans table.

      Because of that, there is no separate stats record to reset.
      Resetting stats means clearing the stored scan data.
    */

    const shouldReset = window.confirm(
      "Resetting dashboard stats will also clear the stored scan history. Continue?",
    );

    if (!shouldReset) {
      return;
    }

    await handleClearHistory();
  }

  return (
    <div className="app">
      <div className="metaverse-background">
        <div className="cyber-grid" />

        <div className="ambient-orb ambient-one" />
        <div className="ambient-orb ambient-two" />
        <div className="ambient-orb ambient-three" />

        <div className="vertical-beam beam-one" />
        <div className="vertical-beam beam-two" />
      </div>

      <Navbar />

      <main className="main-content">
        <Hero />

        <div className="section-marker">
          <span>01</span>
          NETWORK OVERVIEW
        </div>

        {dashboardLoading ? (
          <div className="history-loading">
            Synchronizing Sentri Core...
          </div>
        ) : (
          <>
            <DashboardStats
              stats={stats}
            />

            <DashboardControls
              onResetStats={
                handleResetStats
              }
            />

            <ThreatIndex
              history={history}
            />
          </>
        )}

        <div className="section-marker">
          <span>02</span>
          THREAT ANALYSIS
        </div>

        <section className="dashboard">
          <AnalyzerCard
            message={message}
            isLoading={isLoading}
            error={error}
            onMessageChange={
              handleMessageChange
            }
            onAnalyze={
              handleAnalyze
            }
            onClear={
              handleClear
            }
          />

          <ResultsCard
            result={result}
          />
        </section>

        <div className="report-actions">
          <ExportReportButton
            message={message}
            result={result}
          />
        </div>

        <div className="section-marker">
          <span>03</span>
          LINK INTELLIGENCE
        </div>

        <div className="intel-grid">
          <UrlScanner
            onScanComplete={
              handleUrlScanComplete
            }
          />

          <ThreatFeed
            history={history}
          />
        </div>

        <div className="section-marker">
          <span>04</span>
          THREAT ANALYTICS
        </div>

        <ThreatAnalytics
          history={history}
        />

        <section className="feature-grid">
          <article>
            <div className="feature-icon">
              <span>⌁</span>
            </div>

            <span className="feature-number">
              01
            </span>

            <h3>
              Threat Detection
            </h3>

            <p>
              Detects phishing patterns,
              urgency, impersonation,
              fraudulent payments, fake
              prizes, and social engineering.
            </p>
          </article>

          <article>
            <div className="feature-icon">
              <span>◎</span>
            </div>

            <span className="feature-number">
              02
            </span>

            <h3>
              Risk Intelligence
            </h3>

            <p>
              Converts detected indicators
              into a dynamic threat score
              from zero to one hundred.
            </p>
          </article>

          <article>
            <div className="feature-icon">
              <span>◇</span>
            </div>

            <span className="feature-number">
              03
            </span>

            <h3>
              Defense Guidance
            </h3>

            <p>
              Provides security
              recommendations without
              depending on an external
              artificial intelligence
              provider.
            </p>
          </article>
        </section>

        <div className="section-marker">
          <span>05</span>
          SECURITY ARCHIVE
        </div>

        {historyLoading && (
          <div className="history-loading">
            Loading security archive...
          </div>
        )}

        {historyError && (
          <div
            className="error-message"
            role="alert"
          >
            {historyError}
          </div>
        )}

        {!historyLoading && (
          <ScanHistory
            history={history}
            onSelect={
              handleSelectHistory
            }
            onClearHistory={
              handleClearHistory
            }
          />
        )}

        <footer className="sentri-footer">
          <div>
            <strong>SENTRI</strong>

            <span>
              Digital Threat Defense System
            </span>
          </div>

          <p>
            Rule-Based Security Engine •
            SQLite Persistence • Full-Stack V1.0
          </p>
        </footer>
      </main>
    </div>
  );
}

export default App;