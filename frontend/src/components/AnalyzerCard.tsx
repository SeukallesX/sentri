import type { SubmitEvent } from "react";

interface AnalyzerCardProps {
  message: string;
  isLoading: boolean;
  error: string;
  onMessageChange: (value: string) => void;
  onAnalyze: (event: SubmitEvent<HTMLFormElement>) => void;
  onClear: () => void;
}

function AnalyzerCard({
  message,
  isLoading,
  error,
  onMessageChange,
  onAnalyze,
  onClear,
}: AnalyzerCardProps) {
  return (
    <div className="analyzer-card">
      <div className="card-heading">
        <div>
          <p className="eyebrow">Message Scanner</p>
          <h3>Analyze Suspicious Content</h3>
        </div>

        <span className="private-label">Private</span>
      </div>

      <form onSubmit={onAnalyze}>
        <label htmlFor="message">Suspicious Message</label>

        <textarea
          id="message"
          value={message}
          onChange={(event) => onMessageChange(event.target.value)}
          placeholder="Paste a suspicious message here..."
          maxLength={10000}
        />

        <div className="textarea-footer">
          <span>{message.length.toLocaleString()} / 10,000</span>

          <span>
            Do not paste passwords or sensitive information.
          </span>
        </div>

        {error && (
          <div className="error-message" role="alert">
            {error}
          </div>
        )}

        <div className="form-actions">
          <button
            type="button"
            className="secondary-button"
            onClick={onClear}
            disabled={isLoading}
          >
            Clear
          </button>

          <button
            type="submit"
            className="primary-button"
            disabled={isLoading || !message.trim()}
          >
            {isLoading ? "Analyzing..." : "Analyze Message"}
          </button>
        </div>
      </form>
    </div>
  );
}

export default AnalyzerCard;