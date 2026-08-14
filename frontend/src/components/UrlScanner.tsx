import { useState } from "react";

import {
  analyzeUrl,
  type AnalysisResult,
  type UrlAnalysisResult,
} from "../services/api";

interface UrlScannerProps {
  onScanComplete: (
    result: AnalysisResult,
    url: string,
  ) => void;
}

function UrlScanner({
  onScanComplete,
}: UrlScannerProps) {
  const [url, setUrl] =
    useState("");

  const [result, setResult] =
    useState<
      UrlAnalysisResult | null
    >(null);

  const [error, setError] =
    useState("");

  const [
    isLoading,
    setIsLoading,
  ] = useState(false);

  async function handleScan() {
    const cleanedUrl =
      url.trim();

    if (!cleanedUrl) {
      setError(
        "Enter a URL to scan.",
      );

      return;
    }

    const normalizedUrl =
      cleanedUrl.startsWith(
        "http://",
      ) ||
      cleanedUrl.startsWith(
        "https://",
      ) ||
      cleanedUrl.startsWith(
        "www.",
      )
        ? cleanedUrl
        : `https://${cleanedUrl}`;

    try {
      setIsLoading(true);

      setError("");

      setResult(null);

      const data =
        await analyzeUrl(
          normalizedUrl,
        );

      setResult(data);

      onScanComplete(
        data,

        data.intelligence
          ?.normalizedUrl ??
          normalizedUrl,
      );
    } catch (
      requestError
    ) {
      setError(
        requestError instanceof
          Error
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

  function getStatusText(
    value: boolean,
  ) {
    return value
      ? "Detected"
      : "Clear";
  }

  function getStatusClass(
    value: boolean,
    reversed = false,
  ) {
    if (reversed) {
      return value
        ? "intel-good"
        : "intel-warning";
    }

    return value
      ? "intel-warning"
      : "intel-good";
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
        Sentri analyzes URL
        structure without visiting
        the destination. It checks
        shortened links, suspicious
        domains, brand
        impersonation,
        typosquatting, suspicious
        paths, query parameters,
        redirects, encoded domains,
        and other phishing
        indicators.
      </p>

      <div className="url-input-group">
        <input
          type="text"
          value={url}
          onChange={(event) => {
            setUrl(
              event.target.value,
            );

            if (error) {
              setError("");
            }
          }}
          onKeyDown={(event) => {
            if (
              event.key ===
                "Enter" &&
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
          onClick={
            handleScan
          }
          disabled={
            isLoading ||
            !url.trim()
          }
        >
          {isLoading
            ? "Scanning..."
            : "Scan URL"}
        </button>

        <button
          type="button"
          className="secondary-button"
          onClick={
            handleClear
          }
          disabled={
            isLoading
          }
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
                {result.riskLevel}{" "}
                Risk
              </h4>
            </div>

            <div
              className={`risk-score risk-${result.riskLevel.toLowerCase()}`}
            >
              <strong>
                {result.riskScore}
              </strong>

              <span>
                /100
              </span>
            </div>
          </div>

          <div
            className="risk-bar"
            role="progressbar"
            aria-label="URL risk score"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={
              result.riskScore
            }
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

          {result.intelligence && (
            <div className="url-intelligence-panel">
              <div className="intel-panel-header">
                <div>
                  <p className="radar-label">
                    URL INTELLIGENCE
                  </p>

                  <h4>
                    Structural
                    Analysis
                  </h4>
                </div>

                <span className="private-label">
                  LOCAL
                </span>
              </div>

              <div className="intel-domain-card">
                <span>
                  HOSTNAME
                </span>

                <strong>
                  {
                    result
                      .intelligence
                      .hostname
                  }
                </strong>

                <small>
                  {
                    result
                      .intelligence
                      .normalizedUrl
                  }
                </small>
              </div>

              <div className="intel-grid">
                <div className="intel-item">
                  <span>
                    Protocol
                  </span>

                  <strong>
                    {result.intelligence.protocol.toUpperCase()}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    HTTPS
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .usesHttps,

                      true,
                    )}
                  >
                    {result
                      .intelligence
                      .usesHttps
                      ? "Secure"
                      : "Not Used"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Shortened URL
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .isShortened,
                    )}
                  >
                    {getStatusText(
                      result
                        .intelligence
                        .isShortened,
                    )}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    IP Address
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .isIpAddress,
                    )}
                  >
                    {getStatusText(
                      result
                        .intelligence
                        .isIpAddress,
                    )}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Suspicious TLD
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .hasSuspiciousTld,
                    )}
                  >
                    {result
                      .intelligence
                      .suspiciousTld ??
                      "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Deep Subdomains
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .hasLongSubdomainChain,
                    )}
                  >
                    {getStatusText(
                      result
                        .intelligence
                        .hasLongSubdomainChain,
                    )}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Brand
                    Impersonation
                  </span>

                  <strong
                    className={
                      result
                        .intelligence
                        .impersonatedBrand
                        ? "intel-danger"
                        : "intel-good"
                    }
                  >
                    {result
                      .intelligence
                      .impersonatedBrand
                      ? result.intelligence.impersonatedBrand.toUpperCase()
                      : "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Typosquatting
                  </span>

                  <strong
                    className={
                      result
                        .intelligence
                        .suspectedTyposquatBrand
                        ? "intel-danger"
                        : "intel-good"
                    }
                  >
                    {result
                      .intelligence
                      .suspectedTyposquatBrand
                      ? result.intelligence.suspectedTyposquatBrand.toUpperCase()
                      : "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Suspicious Path
                  </span>

                  <strong
                    className={
                      result
                        .intelligence
                        .suspiciousPathKeywords
                        .length > 0
                        ? "intel-warning"
                        : "intel-good"
                    }
                  >
                    {result
                      .intelligence
                      .suspiciousPathKeywords
                      .length > 0
                      ? result.intelligence.suspiciousPathKeywords.join(
                          ", ",
                        )
                      : "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Query Parameters
                  </span>

                  <strong
                    className={
                      result
                        .intelligence
                        .suspiciousQueryKeywords
                        .length > 0
                        ? "intel-warning"
                        : "intel-good"
                    }
                  >
                    {result
                      .intelligence
                      .suspiciousQueryKeywords
                      .length > 0
                      ? result.intelligence.suspiciousQueryKeywords.join(
                          ", ",
                        )
                      : "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Nested URL
                  </span>

                  <strong
                    className={
                      result
                        .intelligence
                        .containsNestedUrl
                        ? "intel-danger"
                        : "intel-good"
                    }
                  >
                    {result
                      .intelligence
                      .containsNestedUrl
                      ? "Detected"
                      : "Clear"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Subdomain Depth
                  </span>

                  <strong>
                    {
                      result
                        .intelligence
                        .subdomainDepth
                    }
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Domain Length
                  </span>

                  <strong>
                    {
                      result
                        .intelligence
                        .domainLength
                    }{" "}
                    chars
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    @ Obfuscation
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .containsAtSymbol,
                    )}
                  >
                    {getStatusText(
                      result
                        .intelligence
                        .containsAtSymbol,
                    )}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Punycode
                  </span>

                  <strong
                    className={getStatusClass(
                      result
                        .intelligence
                        .containsPunycode,
                    )}
                  >
                    {getStatusText(
                      result
                        .intelligence
                        .containsPunycode,
                    )}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Port
                  </span>

                  <strong>
                    {result
                      .intelligence
                      .port ??
                      "Default"}
                  </strong>
                </div>

                <div className="intel-item">
                  <span>
                    Path
                  </span>

                  <strong className="intel-path">
                    {result
                      .intelligence
                      .pathname ||
                      "/"}
                  </strong>
                </div>
              </div>
            </div>
          )}

          <div className="result-section">
            <h4>
              Detected URL
              Indicators
            </h4>

            {result.flags.length ===
            0 ? (
              <p className="no-flags">
                No common suspicious
                URL indicators were
                detected.
              </p>
            ) : (
              <div className="flag-list">
                {result.flags.map(
                  (flag) => (
                    <div
                      className="flag-card"
                      key={
                        flag.category
                      }
                    >
                      <div>
                        <h5>
                          {
                            flag.category
                          }
                        </h5>

                        <p>
                          {
                            flag.description
                          }
                        </p>
                      </div>

                      <span>
                        +
                        {
                          flag.points
                        }
                      </span>
                    </div>
                  ),
                )}
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
              {
                result.recommendation
              }
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

export default UrlScanner;