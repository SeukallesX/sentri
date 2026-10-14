
import type { ScamFlag } from "../types/analysis.js";

export type CorrelatedThreat =
  | "Coordinated Phishing"
  | "Credential Harvesting"
  | "Payment Fraud"
  | "Impersonation Attack"
  | "Malicious Link Campaign"
  | "Social Engineering"
  | "No Correlated Threat";

export interface ThreatCorrelationResult {
  correlatedThreat: CorrelatedThreat;
  correlationScore: number;
  matchedSignals: string[];
  explanation: string;
}

/*
 * ---------------------------------------
 * HISTORICAL THREAT INTELLIGENCE TYPES
 * ---------------------------------------
 */

export interface HistoricalScan {
  id: string;
  type: string;
  content: string;
  createdAt: string;
  result: {
    riskScore?: number;
    riskLevel?: string;
    threatCategory?: string;
    correlatedThreat?: string;
    flags?: ScamFlag[];
  };
}

export interface RelatedScan {
  scanId: string;
  scanType: string;
  createdAt: string;
  similarityScore: number;
  sharedDomains: string[];
  sharedSignals: string[];
  sharedThreatCategory: boolean;
  explanation: string;
}

export interface HistoricalCorrelationResult {
  totalScansCompared: number;
  relatedScanCount: number;
  repeatedDomains: string[];
  recurringSignals: string[];
  relatedScans: RelatedScan[];
  correlationScore: number;
  explanation: string;
}

/*
 * ---------------------------------------
 * SHARED HELPERS
 * ---------------------------------------
 */

function normalizeCategory(value: string): string {
  return value.trim().toLowerCase();
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values));
}

function hasSignal(
  flags: ScamFlag[],
  keywords: string[],
): boolean {
  return flags.some((flag) => {
    const category = normalizeCategory(flag.category);

    return keywords.some((keyword) =>
      category.includes(keyword.toLowerCase()),
    );
  });
}

function getMatchedSignals(
  flags: ScamFlag[],
  keywords: string[],
): string[] {
  return flags
    .filter((flag) => {
      const category = normalizeCategory(flag.category);

      return keywords.some((keyword) =>
        category.includes(keyword.toLowerCase()),
      );
    })
    .map((flag) => flag.category);
}

/*
 * ---------------------------------------
 * EXISTING RULE-X CORRELATION
 *
 * Analyzes combinations of indicators
 * within a single scan.
 * ---------------------------------------
 */

export function correlateThreats(
  flags: ScamFlag[],
): ThreatCorrelationResult {
  if (flags.length === 0) {
    return {
      correlatedThreat: "No Correlated Threat",
      correlationScore: 0,
      matchedSignals: [],
      explanation:
        "No meaningful combination of threat indicators was detected.",
    };
  }

  const hasUrgency = hasSignal(flags, [
    "urgency",
    "pressure",
    "threat",
  ]);

  const hasAccountThreat = hasSignal(flags, [
    "account threat",
    "account",
    "verify",
    "verification",
  ]);

  const hasSensitiveInfo = hasSignal(flags, [
    "sensitive information",
    "credential",
    "password",
    "security code",
  ]);

  const hasImpersonation = hasSignal(flags, [
    "impersonation",
    "brand impersonation",
    "typosquatting",
  ]);

  const hasPayment = hasSignal(flags, [
    "suspicious payment",
    "payment",
    "gift card",
    "crypto",
    "wire transfer",
  ]);

  const hasSuspiciousLink = hasSignal(flags, [
    "shortened link",
    "suspicious domain",
    "nested url",
    "punycode",
    "ip-based link",
    "url obfuscation",
    "insecure link",
    "suspicious url path",
  ]);

  const hasSecrecy = hasSignal(flags, [
    "secrecy request",
    "secret",
    "confidential",
  ]);

  const phishingSignals = [
    hasUrgency,
    hasAccountThreat,
    hasSensitiveInfo,
    hasSuspiciousLink,
    hasImpersonation,
  ].filter(Boolean).length;

  if (phishingSignals >= 3) {
    return {
      correlatedThreat: "Coordinated Phishing",
      correlationScore: Math.min(
        100,
        55 + phishingSignals * 9,
      ),
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "urgency",
          "account threat",
          "sensitive information",
          "shortened link",
          "suspicious domain",
          "brand impersonation",
          "typosquatting",
        ]),
      ),
      explanation:
        "Multiple phishing indicators appear together, suggesting a coordinated attempt to pressure the recipient into trusting a malicious message or link.",
    };
  }

  if (
    hasSensitiveInfo &&
    (hasAccountThreat || hasSuspiciousLink)
  ) {
    return {
      correlatedThreat: "Credential Harvesting",
      correlationScore: 82,
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "sensitive information",
          "account threat",
          "shortened link",
          "suspicious domain",
          "login",
          "verification",
        ]),
      ),
      explanation:
        "The scan combines account-access language with requests for sensitive information or suspicious links, which is consistent with credential harvesting.",
    };
  }

  if (
    hasPayment &&
    (hasUrgency || hasSecrecy || hasImpersonation)
  ) {
    return {
      correlatedThreat: "Payment Fraud",
      correlationScore: 80,
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "suspicious payment",
          "urgency",
          "secrecy request",
          "impersonation",
        ]),
      ),
      explanation:
        "The message combines a payment request with pressure, secrecy, or impersonation tactics commonly associated with financial scams.",
    };
  }

  if (
    hasImpersonation &&
    (hasAccountThreat || hasUrgency)
  ) {
    return {
      correlatedThreat: "Impersonation Attack",
      correlationScore: 76,
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "impersonation",
          "brand impersonation",
          "typosquatting",
          "account threat",
          "urgency",
        ]),
      ),
      explanation:
        "The scan shows identity or brand impersonation combined with pressure or account-related claims.",
    };
  }

  if (
    hasSuspiciousLink &&
    (hasImpersonation || hasAccountThreat)
  ) {
    return {
      correlatedThreat: "Malicious Link Campaign",
      correlationScore: 74,
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "suspicious domain",
          "shortened link",
          "nested url",
          "punycode",
          "url obfuscation",
          "brand impersonation",
          "account threat",
        ]),
      ),
      explanation:
        "Suspicious link characteristics appear alongside impersonation or account-related language, increasing the likelihood of a malicious-link campaign.",
    };
  }

  if (
    hasUrgency &&
    (hasSecrecy || hasImpersonation)
  ) {
    return {
      correlatedThreat: "Social Engineering",
      correlationScore: 68,
      matchedSignals: unique(
        getMatchedSignals(flags, [
          "urgency",
          "secrecy request",
          "impersonation",
        ]),
      ),
      explanation:
        "The message combines psychological pressure with secrecy or impersonation tactics, which is consistent with social engineering.",
    };
  }

  return {
    correlatedThreat: "No Correlated Threat",
    correlationScore: 25,
    matchedSignals: flags.map((flag) => flag.category),
    explanation:
      "Suspicious indicators were detected, but they do not currently form a strong correlated attack pattern.",
  };
}

/*
 * ---------------------------------------
 * DOMAIN EXTRACTION
 *
 * Only extracts domains from URLs
 * explicitly present in scan content.
 * ---------------------------------------
 */

export function extractDomains(
  content: string,
): string[] {
  const candidates = content.match(
    /\bhttps?:\/\/[^\s<>"']+|\bwww\.[^\s<>"']+/gi,
  ) ?? [];

  const domains: string[] = [];

  for (const candidate of candidates) {
    try {
      const cleaned = candidate.replace(
        /[.,;!?)\]]+$/,
        "",
      );

      const url = new URL(
        cleaned.startsWith("www.")
          ? `https://${cleaned}`
          : cleaned,
      );

      const hostname = url.hostname
        .toLowerCase()
        .replace(/\.$/, "");

      if (hostname) {
        domains.push(hostname);
      }
    } catch {
      // Ignore malformed URL candidates.
    }
  }

  return unique(domains);
}

/*
 * ---------------------------------------
 * SIGNAL NORMALIZATION
 *
 * Prefer stable Rule-X signal IDs.
 * Fall back to category names.
 * ---------------------------------------
 */

function extractSignals(
  flags: ScamFlag[],
): string[] {
  return unique(
    flags
      .map((flag) =>
        flag.signalId?.trim() ||
        normalizeCategory(flag.category),
      )
      .filter(Boolean),
  );
}

function sharedValues(
  first: string[],
  second: string[],
): string[] {
  const secondSet = new Set(second);

  return first.filter((value) =>
    secondSet.has(value),
  );
}

/*
 * ---------------------------------------
 * HISTORICAL CORRELATION
 *
 * Compares a scan against previously
 * stored scans.
 *
 * Does not change risk scores or
 * claim confirmed malicious activity.
 * ---------------------------------------
 */

export function correlateScanHistory(
  currentScan: HistoricalScan,
  historicalScans: HistoricalScan[],
): HistoricalCorrelationResult {
  const currentDomains = extractDomains(
    currentScan.content,
  );

  const currentSignals = extractSignals(
    currentScan.result.flags ?? [],
  );

  const currentThreat = normalizeCategory(
    currentScan.result.correlatedThreat ?? "",
  );

  const relatedScans: RelatedScan[] = [];

  const repeatedDomains = new Set<string>();
  const recurringSignals = new Set<string>();

  const previousScans = historicalScans.filter(
    (scan) => scan.id !== currentScan.id,
  );

  for (const previousScan of previousScans) {
    const previousDomains = extractDomains(
      previousScan.content,
    );

    const previousSignals = extractSignals(
      previousScan.result.flags ?? [],
    );

    const domains = sharedValues(
      currentDomains,
      previousDomains,
    );

    const signals = sharedValues(
      currentSignals,
      previousSignals,
    );

    const previousThreat = normalizeCategory(
      previousScan.result.correlatedThreat ?? "",
    );

    const sharedThreatCategory =
      currentThreat.length > 0 &&
      currentThreat !== "no correlated threat" &&
      currentThreat === previousThreat;

    /*
     * Weighted similarity:
     *
     * Shared domain: up to 50 points
     * Shared signals: up to 40 points
     * Same threat category: 10 points
     *
     * This is a heuristic similarity
     * score, not a probability.
     */

    const domainScore = Math.min(
      50,
      domains.length * 50,
    );

    const signalScore = Math.min(
      40,
      signals.length * 20,
    );

    const threatScore =
      sharedThreatCategory ? 10 : 0;

    const similarityScore = Math.min(
      100,
      domainScore + signalScore + threatScore,
    );

    /*
     * Require a domain match or at
     * least two shared Rule-X signals.
     *
     * A matching threat label alone
     * is not sufficient.
     */

    const isRelated =
      domains.length > 0 ||
      signals.length >= 2;

    if (!isRelated) {
      continue;
    }

    domains.forEach((domain) =>
      repeatedDomains.add(domain),
    );

    signals.forEach((signal) =>
      recurringSignals.add(signal),
    );

    const reasons: string[] = [];

    if (domains.length > 0) {
      reasons.push(
        `shared domain: ${domains.join(", ")}`,
      );
    }

    if (signals.length > 0) {
      reasons.push(
        `shared Rule-X signals: ${signals.join(", ")}`,
      );
    }

    if (sharedThreatCategory) {
      reasons.push(
        "matching threat classification",
      );
    }

    relatedScans.push({
      scanId: previousScan.id,
      scanType: previousScan.type,
      createdAt: previousScan.createdAt,
      similarityScore,
      sharedDomains: domains,
      sharedSignals: signals,
      sharedThreatCategory,
      explanation:
        `The scans have ${reasons.join("; ")}. ` +
        "This indicates overlapping evidence, not confirmed coordination.",
    });
  }

  relatedScans.sort(
    (a, b) =>
      b.similarityScore - a.similarityScore,
  );

  const correlationScore =
    relatedScans.length > 0
      ? relatedScans[0].similarityScore
      : 0;

  return {
    totalScansCompared: previousScans.length,
    relatedScanCount: relatedScans.length,
    repeatedDomains: Array.from(
      repeatedDomains,
    ).sort(),
    recurringSignals: Array.from(
      recurringSignals,
    ).sort(),
    relatedScans,
    correlationScore,
    explanation:
      relatedScans.length > 0
        ? `${relatedScans.length} related scan(s) were found based on repeated domains or overlapping Rule-X indicators.`
        : "No sufficiently similar scans were identified in the available local history.",
  };
}
