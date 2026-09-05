import type {
  SecurityEventSource,
  SecurityEventType,
} from "./securityEvent.js";

/*
 * ---------------------------------------
 * RISK LEVEL
 * ---------------------------------------
 */

export type RiskLevel =
  | "Low"
  | "Medium"
  | "High";

/*
 * ---------------------------------------
 * DETECTION FLAG
 * ---------------------------------------
 */

export interface ScamFlag {
  category: string;

  description: string;

  points: number;
}

/*
 * ---------------------------------------
 * SECURITY EVENT REFERENCE
 * ---------------------------------------
 */

export interface SecurityEventReference {
  id: string;

  type:
    SecurityEventType;

  timestamp: string;

  source:
    SecurityEventSource;
}

/*
 * ---------------------------------------
 * ANALYSIS RESULT
 * ---------------------------------------
 */

export interface AnalysisResult {
  riskScore: number;

  riskLevel:
    RiskLevel;

  /*
   * Threat classification
   */
  threatCategory:
    string;

  confidence:
    number;

  attackVector:
    string;

  /*
   * Threat correlation
   */
  correlatedThreat:
    string;

  correlationScore:
    number;

  matchedSignals:
    string[];

  correlationExplanation:
    string;

  /*
   * Detection evidence
   */
  flags:
    ScamFlag[];

  /*
   * Explainability
   */
  summary:
    string;

  recommendation:
    string;

  /*
   * Security Event
   *
   * Optional for backward
   * compatibility with older
   * stored scan records.
   */
  event?:
    SecurityEventReference;
}