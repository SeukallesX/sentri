import type {
  AnalysisResult,
  SecurityEventReference,
} from "./analysis.js";

export type ScanType =
  | "Message"
  | "URL";

export interface StoredScan {
  id: string;

  type: ScanType;

  content: string;

  result: AnalysisResult;

  event?: SecurityEventReference;

  createdAt: string;
}