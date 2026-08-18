export type RiskLevel =
  | "Low"
  | "Medium"
  | "High";

export interface ScamFlag {
  category: string;
  description: string;
  points: number;
}

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
}