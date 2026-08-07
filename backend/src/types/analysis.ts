export type RiskLevel = "Low" | "Medium" | "High";

export interface ScamFlag {
  category: string;
  description: string;
  points: number;
}

export interface AnalysisResult {
  riskScore: number;
  riskLevel: RiskLevel;
  flags: ScamFlag[];
  summary: string;
  recommendation: string;
}