import type {
  AnalysisResult,
} from "./analysis.js";

export type ScanType =
  | "Message"
  | "URL";

export interface StoredScan {
  id: string;

  type: ScanType;

  content: string;

  result: AnalysisResult;

  createdAt: string;
}