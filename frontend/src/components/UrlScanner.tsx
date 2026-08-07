import { useState } from "react";

import {
  analyzeUrl,
  type AnalysisResult,
} from "../services/api";

interface UrlScannerProps {
  onScanComplete: (result: AnalysisResult) => void;
}

function UrlScanner({
  onScanComplete,
}: UrlScannerProps) {
  const [url, setUrl] = useState("");

  const [result, setResult] =
    useState<AnalysisResult | null>(null);

  const [error, setError] = useState("");

  const [isLoading, setIsLoading] = useState(false);

  async function handleScan() {
    const cleanedUrl = url.trim();

    if (!cleanedUrl) {
      setError("Enter a URL to scan.");
      return;
    }

    const normalizedUrl =
      cleanedUrl.startsWith("http://") ||
      cleanedUrl.startsWith("https://") ||
      cleanedUrl.startsWith("www.")
        ? cleanedUrl
        : `https://${cleanedUrl}`;

    try {
      setIsLoading(true);
      setError("");
      setResult(null);

      const data = await analyzeUrl(normalizedUrl);

      setResult(data);

      onScanComplete(data);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to scan the URL.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  function handleClear() {
    setUrl("");
    setResult(null);
    setError("");
  }

  return (
    <section className="url-scanner-section">
      <div className="url-scanner-header">
        <div>
          <p className="eyebrow">
            Link Intelligence
          </p>

          <h3>
            Scan a suspicious URL
          </h3>
        </div>

        <span className="private-label">
          Static Analysis
        </span>
      </div>

      <p className="url-scanner-description">
        Sentri inspects the structure of a URL for common phishing and
        malicious-link indicators without opening the destination.
      </p>

      <div className="url-input-group">
        <input
          type="text"
          value={url}
          onChange={(event) => {
            setUrl(event.target.value);

            if (error) {
              setError("");
            }
          }}
          onKeyDown={(event) => {
            if (
              event.key === "Enter" &&
              !isLoading &&
              url.trim()
            ) {
              void handleScan();
            }
          }}
          placeholder="https://example.com"
          autoComplete="off"
          spellCheck={false}
        />

        <button
          type="button"
          className="primary-button"
          onClick={handleScan}
          disabled={isLoading || !url.trim()}
        >
          {isLoading ? "Scanning..." : "Scan URL"}
        </button>

        <button
          type="button"
          className="secondary-button"
          onClick={handleClear}
          disabled={isLoading}
        >
          Clear
        </button>
      </div>

      {error && (
        <div
          className="error-message"
          role="alert"
        >
          {error}
        </div>
      )}

      {result && (
        <div className="url-result">
          <div className="url-result-heading">
            <div>
              <p className="eyebrow">
                Link Assessment
              </p>

              <h4>
                {result.riskLevel} Risk
              </h4>
            </div>

            <div
              className={`risk-score risk-${result.riskLevel.toLowerCase()}`}
            >
              <strong>
                {result.riskScore}
              </strong>

              <span>/100</span>
            </div>
          </div>

          <div
            className="risk-bar"
            role="progressbar"
            aria-label="URL risk score"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={result.riskScore}
          >
            <div
              className={`risk-fill risk-${result.riskLevel.toLowerCase()}`}
              style={{
                width: `${result.riskScore}%`,
              }}
            />
          </div>

          <p className="summary">
            {result.summary}
          </p>

          <div className="result-section">
            <h4>
              Detected URL Indicators
            </h4>

            {result.flags.length === 0 ? (
              <p className="no-flags">
                No common suspicious URL indicators were detected.
              </p>
            ) : (
              <div className="flag-list">
                {result.flags.map((flag) => (
                  <div
                    className="flag-card"
                    key={flag.category}
                  >
                    <div>
                      <h5>
                        {flag.category}
                      </h5>

                      <p>
                        {flag.description}
                      </p>
                    </div>

                    <span>
                      +{flag.points}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="recommendation">
            <p className="radar-label">
              DEFENSE GUIDANCE
            </p>

            <h4>
              Recommended Action
            </h4>

            <p>
              {result.recommendation}
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

export default UrlScanner;