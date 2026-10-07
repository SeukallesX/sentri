export type SignalSeverity =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type SignalCategory =
  | "social_engineering"
  | "credential_theft"
  | "payment_fraud"
  | "impersonation"
  | "url"
  | "domain"
  | "obfuscation"
  | "account_threat"
  | "investment_fraud"
  | "malware"
  | "identity"
  | "behavior"
  | "unknown";

export type SignalSource =
  | "rule-x"
  | "url-intelligence"
  | "trusted-domain"
  | "correlation"
  | "system";

export interface SecuritySignalEvidence {
  /*
   * Human-readable explanation of
   * what caused the detector to fire.
   */
  description: string;

  /*
   * Optional piece of evidence such as
   * a keyword, hostname, path, or pattern.
   */
  value?: string;
}

export interface SecuritySignal {
  /*
   * Stable machine-readable detector ID.
   *
   * Examples:
   * RX-URGENCY
   * URL-SUSPICIOUS-TLD
   * URL-BRAND-IMPERSONATION
   */
  id: string;

  category: SignalCategory;

  severity: SignalSeverity;

  source: SignalSource;

  /*
   * Short display name.
   */
  name: string;

  /*
   * Risk contribution.
   */
  points: number;

  evidence: SecuritySignalEvidence[];

  /*
   * Optional confidence for detectors
   * that can estimate certainty.
   */
  confidence?: number;
}