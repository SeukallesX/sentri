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

  flags: ScamFlag[];
  summary: string;
  recommendation: string;
}

export interface UrlIntelligence {
  originalUrl: string;
  normalizedUrl: string;

  protocol: string;
  hostname: string;
  pathname: string;

  usesHttps: boolean;

  isShortened: boolean;
  isIpAddress: boolean;

  hasSuspiciousTld: boolean;
  hasLongSubdomainChain: boolean;

  subdomainDepth: number;

  suspiciousTld:
    | string
    | null;

  domainLength: number;

  containsAtSymbol: boolean;
  containsPunycode: boolean;

  port:
    | string
    | null;

  impersonatedBrand:
    | string
    | null;

  suspectedTyposquatBrand:
    | string
    | null;

  suspiciousPathKeywords:
    string[];

  suspiciousQueryKeywords:
    string[];

  containsNestedUrl: boolean;
}

export interface UrlAnalysisResult
  extends AnalysisResult {
  intelligence:
    | UrlIntelligence
    | null;
}

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

export interface DashboardStatsResponse {
  totalScans: number;
  highRisk: number;
  mediumRisk: number;
  lowRisk: number;
}

interface ApiError {
  error?: string;
}

const API_URL =
  import.meta.env
    .VITE_API_URL ??
  "http://localhost:5000";

async function parseJson<T>(
  response: Response,
): Promise<T> {
  try {
    return (
      await response.json()
    ) as T;
  } catch {
    throw new Error(
      "The server returned an invalid response.",
    );
  }
}

async function handleAnalysisResponse(
  response: Response,
): Promise<AnalysisResult> {
  const data =
    await parseJson<
      | AnalysisResult
      | ApiError
    >(response);

  if (!response.ok) {
    const errorMessage =
      "error" in data &&
      data.error
        ? data.error
        : "The request could not be completed.";

    throw new Error(
      errorMessage,
    );
  }

  return data as AnalysisResult;
}

async function handleUrlAnalysisResponse(
  response: Response,
): Promise<UrlAnalysisResult> {
  const data =
    await parseJson<
      | UrlAnalysisResult
      | ApiError
    >(response);

  if (!response.ok) {
    const errorMessage =
      "error" in data &&
      data.error
        ? data.error
        : "The URL analysis could not be completed.";

    throw new Error(
      errorMessage,
    );
  }

  return data as UrlAnalysisResult;
}

export async function analyzeMessage(
  message: string,
): Promise<AnalysisResult> {
  const response =
    await fetch(
      `${API_URL}/api/analyze`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          message,
        }),
      },
    );

  return handleAnalysisResponse(
    response,
  );
}

export async function analyzeUrl(
  url: string,
): Promise<UrlAnalysisResult> {
  const response =
    await fetch(
      `${API_URL}/api/analyze-url`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json",
        },

        body: JSON.stringify({
          url,
        }),
      },
    );

  return handleUrlAnalysisResponse(
    response,
  );
}

export async function getScans(
  limit = 10,
): Promise<StoredScan[]> {
  const response =
    await fetch(
      `${API_URL}/api/scans?limit=${limit}`,
    );

  const data =
    await parseJson<
      | {
          scans: StoredScan[];
        }
      | ApiError
    >(response);

  if (!response.ok) {
    const errorMessage =
      "error" in data &&
      data.error
        ? data.error
        : "Unable to load scan history.";

    throw new Error(
      errorMessage,
    );
  }

  if (
    !("scans" in data)
  ) {
    return [];
  }

  return data.scans;
}

export async function clearScans(): Promise<void> {
  const response =
    await fetch(
      `${API_URL}/api/scans`,
      {
        method: "DELETE",
      },
    );

  if (!response.ok) {
    const data =
      await parseJson<ApiError>(
        response,
      );

    throw new Error(
      data.error ??
        "Unable to clear scan history.",
    );
  }
}

export async function getStats(): Promise<DashboardStatsResponse> {
  const response =
    await fetch(
      `${API_URL}/api/stats`,
    );

  const data =
    await parseJson<
      | DashboardStatsResponse
      | ApiError
    >(response);

  if (!response.ok) {
    const errorMessage =
      "error" in data &&
      data.error
        ? data.error
        : "Unable to load dashboard statistics.";

    throw new Error(
      errorMessage,
    );
  }

  return data as DashboardStatsResponse;
}