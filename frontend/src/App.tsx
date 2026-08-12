import { useEffect, useState } from "react";
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
  type AnalysisResult,
} from "./services/api";

const HISTORY_KEY = "sentri-scan-history";
const STATS_KEY = "sentri-dashboard-stats";

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

  const [error, setError] = useState("");

  const [history, setHistory] =
    useState<ScanHistoryItem[]>([]);

  const [stats, setStats] =
    useState<DashboardStatTotals>(defaultStats);

  useEffect(() => {
    const savedHistory =
      localStorage.getItem(HISTORY_KEY);

    if (savedHistory) {
      try {
        const parsedHistory =
          JSON.parse(savedHistory) as ScanHistoryItem[];

        const migratedHistory =
          parsedHistory
            .map((item) => {
              if (
                item.type &&
                item.content
              ) {
                return item;
              }

              const oldItem = item as ScanHistoryItem & {
                message?: string;
              };

              if (oldItem.message) {
                return {
                  ...item,
                  type: "Message" as const,
                  content: oldItem.message,
                };
              }

              return null;
            })
            .filter(
              (
                item,
              ): item is ScanHistoryItem =>
                item !== null,
            );

        setHistory(migratedHistory);

        localStorage.setItem(
          HISTORY_KEY,
          JSON.stringify(migratedHistory),
        );
      } catch {
        localStorage.removeItem(HISTORY_KEY);
      }
    }

    const savedStats =
      localStorage.getItem(STATS_KEY);

    if (savedStats) {
      try {
        const parsedStats =
          JSON.parse(savedStats) as DashboardStatTotals;

        setStats(parsedStats);
      } catch {
        localStorage.removeItem(STATS_KEY);
      }
    }
  }, []);

  function saveHistory(
    items: ScanHistoryItem[],
  ) {
    setHistory(items);

    localStorage.setItem(
      HISTORY_KEY,
      JSON.stringify(items),
    );
  }

  function addHistoryItem(
    item: ScanHistoryItem,
  ) {
    setHistory((currentHistory) => {
      const updatedHistory = [
        item,
        ...currentHistory,
      ].slice(0, 10);

      localStorage.setItem(
        HISTORY_KEY,
        JSON.stringify(updatedHistory),
      );

      return updatedHistory;
    });
  }

  function updateStats(
    scanResult: AnalysisResult,
  ) {
    setStats((currentStats) => {
      const updatedStats: DashboardStatTotals = {
        ...currentStats,
        totalScans:
          currentStats.totalScans + 1,
      };

      if (
        scanResult.riskLevel === "High"
      ) {
        updatedStats.highRisk += 1;
      }

      if (
        scanResult.riskLevel === "Medium"
      ) {
        updatedStats.mediumRisk += 1;
      }

      if (
        scanResult.riskLevel === "Low"
      ) {
        updatedStats.lowRisk += 1;
      }

      localStorage.setItem(
        STATS_KEY,
        JSON.stringify(updatedStats),
      );

      return updatedStats;
    });
  }

  async function handleAnalyze(
    event: SubmitEvent<HTMLFormElement>,
  ) {
    event.preventDefault();

    const cleanedMessage =
      message.trim();

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

      updateStats(data);

      const historyItem: ScanHistoryItem = {
        id: crypto.randomUUID(),
        type: "Message",
        content: cleanedMessage,
        result: data,
        createdAt:
          new Date().toISOString(),
      };

      addHistoryItem(historyItem);
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

  function handleUrlScanComplete(
    scanResult: AnalysisResult,
    url: string,
  ) {
    updateStats(scanResult);

    const historyItem: ScanHistoryItem = {
      id: crypto.randomUUID(),
      type: "URL",
      content: url,
      result: scanResult,
      createdAt:
        new Date().toISOString(),
    };

    addHistoryItem(historyItem);
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

    if (
      item.type === "Message"
    ) {
      setMessage(item.content);
      setResult(item.result);

      window.scrollTo({
        top: 0,
        behavior: "smooth",
      });

      return;
    }

    if (
      item.type === "URL"
    ) {
      window.alert(
        `URL Scan\n\n${item.content}\n\nRisk: ${item.result.riskLevel}\nScore: ${item.result.riskScore}/100`,
      );
    }
  }

  function handleClearHistory() {
    saveHistory([]);
  }

  function handleResetStats() {
    setStats(defaultStats);

    localStorage.removeItem(
      STATS_KEY,
    );
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

        <ScanHistory
          history={history}
          onSelect={
            handleSelectHistory
          }
          onClearHistory={
            handleClearHistory
          }
        />

        <footer className="sentri-footer">
          <div>
            <strong>SENTRI</strong>

            <span>
              Digital Threat Defense System
            </span>
          </div>

          <p>
            Rule-Based Security Engine •
            Local Analysis • V1.0
          </p>
        </footer>
      </main>
    </div>
  );
}

export default App;