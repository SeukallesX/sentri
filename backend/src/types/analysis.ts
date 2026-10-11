import type {
  SecurityEventSource,
  SecurityEventType,
} from "./securityEvent.js";

import type {
  SecuritySignalEvidence,
  SignalSeverity,
  SignalSource,
} from "./securitySignal.js";

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
 * SCAM / SECURITY FLAG
 * ---------------------------------------
 *
 * Existing Rule-X analyzers can continue
 * using category, description, and points.
 *
 * The optional signal fields allow Sentri
 * v3 to gradually migrate toward the new
 * structured security signal model.
 */

export interface ScamFlag {
  category: string;
  description: string;
  points: number;

  signalId?: string;

  severity?: SignalSeverity;

  source?: SignalSource;

  evidence?: SecuritySignalEvidence[];
}

/*
 * ---------------------------------------
 * SECURITY EVENT REFERENCE
 * ---------------------------------------
 */

export interface SecurityEventReference {
  id: string;

  type: SecurityEventType;

  timestamp: string;

  source: SecurityEventSource;
}

/*
 * ---------------------------------------
 * ANALYSIS RESULT
 * ---------------------------------------
 */

export interface AnalysisResult {
  riskScore: number;

  riskLevel: RiskLevel;

  threatCategory: string;

  confidence: number;

  attackVector: string;

  correlatedThreat: string;

  correlationScore: number;

  matchedSignals: string[];

  correlationExplanation: string;

  flags: ScamFlag[];

  summary: string;

  recommendation: string;

  event?: SecurityEventReference;
}