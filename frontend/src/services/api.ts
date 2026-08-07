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

interface ApiError {
  error?: string;
}

const API_URL =
  import.meta.env.VITE_API_URL ?? "http://localhost:5000";

async function handleResponse(
  response: Response,
): Promise<AnalysisResult> {
  const data = (await response.json()) as
    | AnalysisResult
    | ApiError;

  if (!response.ok) {
    const errorMessage =
      "error" in data && data.error
        ? data.error
        : "The request could not be completed.";

    throw new Error(errorMessage);
  }

  return data as AnalysisResult;
}

export async function analyzeMessage(
  message: string,
): Promise<AnalysisResult> {
  const response = await fetch(
    `${API_URL}/api/analyze`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message,
      }),
    },
  );

  return handleResponse(response);
}

export async function analyzeUrl(
  url: string,
): Promise<AnalysisResult> {
  const response = await fetch(
    `${API_URL}/api/analyze-url`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url,
      }),
    },
  );

  return handleResponse(response);
}