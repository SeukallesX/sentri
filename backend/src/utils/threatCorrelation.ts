import type {
  ScamFlag,
} from "../types/analysis.js";

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

function normalizeCategory(
  value: string,
): string {
  return value
    .trim()
    .toLowerCase();
}

function hasSignal(
  flags: ScamFlag[],
  keywords: string[],
): boolean {
  return flags.some((flag) => {
    const category =
      normalizeCategory(
        flag.category,
      );

    return keywords.some(
      (keyword) =>
        category.includes(
          keyword.toLowerCase(),
        ),
    );
  });
}

function getMatchedSignals(
  flags: ScamFlag[],
  keywords: string[],
): string[] {
  return flags
    .filter((flag) => {
      const category =
        normalizeCategory(
          flag.category,
        );

      return keywords.some(
        (keyword) =>
          category.includes(
            keyword.toLowerCase(),
          ),
      );
    })
    .map(
      (flag) =>
        flag.category,
    );
}

function unique(
  values: string[],
): string[] {
  return Array.from(
    new Set(values),
  );
}

export function correlateThreats(
  flags: ScamFlag[],
): ThreatCorrelationResult {
  if (flags.length === 0) {
    return {
      correlatedThreat:
        "No Correlated Threat",

      correlationScore: 0,

      matchedSignals: [],

      explanation:
        "No meaningful combination of threat indicators was detected.",
    };
  }

  const hasUrgency =
    hasSignal(
      flags,
      [
        "urgency",
        "pressure",
        "threat",
      ],
    );

  const hasAccountThreat =
    hasSignal(
      flags,
      [
        "account threat",
        "account",
        "verify",
        "verification",
      ],
    );

  const hasSensitiveInfo =
    hasSignal(
      flags,
      [
        "sensitive information",
        "credential",
        "password",
        "security code",
      ],
    );

  const hasImpersonation =
    hasSignal(
      flags,
      [
        "impersonation",
        "brand impersonation",
        "typosquatting",
      ],
    );

  const hasPayment =
    hasSignal(
      flags,
      [
        "suspicious payment",
        "payment",
        "gift card",
        "crypto",
        "wire transfer",
      ],
    );

  const hasSuspiciousLink =
    hasSignal(
      flags,
      [
        "shortened link",
        "suspicious domain",
        "nested url",
        "punycode",
        "ip-based link",
        "url obfuscation",
        "insecure link",
        "suspicious url path",
      ],
    );

  const hasSecrecy =
    hasSignal(
      flags,
      [
        "secrecy request",
        "secret",
        "confidential",
      ],
    );

  const phishingSignals =
    [
      hasUrgency,
      hasAccountThreat,
      hasSensitiveInfo,
      hasSuspiciousLink,
      hasImpersonation,
    ].filter(Boolean).length;

  if (
    phishingSignals >= 3
  ) {
    const matched =
      unique([
        ...getMatchedSignals(
          flags,
          [
            "urgency",
            "account threat",
            "sensitive information",
            "shortened link",
            "suspicious domain",
            "brand impersonation",
            "typosquatting",
          ],
        ),
      ]);

    return {
      correlatedThreat:
        "Coordinated Phishing",

      correlationScore:
        Math.min(
          100,
          55 +
            phishingSignals *
              9,
        ),

      matchedSignals:
        matched,

      explanation:
        "Multiple phishing indicators appear together, suggesting a coordinated attempt to pressure the recipient into trusting a malicious message or link.",
    };
  }

  if (
    hasSensitiveInfo &&
    (
      hasAccountThreat ||
      hasSuspiciousLink
    )
  ) {
    const matched =
      unique(
        getMatchedSignals(
          flags,
          [
            "sensitive information",
            "account threat",
            "shortened link",
            "suspicious domain",
            "login",
            "verification",
          ],
        ),
      );

    return {
      correlatedThreat:
        "Credential Harvesting",

      correlationScore: 82,

      matchedSignals:
        matched,

      explanation:
        "The scan combines account-access language with requests for sensitive information or suspicious links, which is consistent with credential harvesting.",
    };
  }

  if (
    hasPayment &&
    (
      hasUrgency ||
      hasSecrecy ||
      hasImpersonation
    )
  ) {
    const matched =
      unique(
        getMatchedSignals(
          flags,
          [
            "suspicious payment",
            "urgency",
            "secrecy request",
            "impersonation",
          ],
        ),
      );

    return {
      correlatedThreat:
        "Payment Fraud",

      correlationScore: 80,

      matchedSignals:
        matched,

      explanation:
        "The message combines a payment request with pressure, secrecy, or impersonation tactics commonly associated with financial scams.",
    };
  }

  if (
    hasImpersonation &&
    (
      hasAccountThreat ||
      hasUrgency
    )
  ) {
    const matched =
      unique(
        getMatchedSignals(
          flags,
          [
            "impersonation",
            "brand impersonation",
            "typosquatting",
            "account threat",
            "urgency",
          ],
        ),
      );

    return {
      correlatedThreat:
        "Impersonation Attack",

      correlationScore: 76,

      matchedSignals:
        matched,

      explanation:
        "The scan shows identity or brand impersonation combined with pressure or account-related claims.",
    };
  }

  if (
    hasSuspiciousLink &&
    (
      hasImpersonation ||
      hasAccountThreat
    )
  ) {
    const matched =
      unique(
        getMatchedSignals(
          flags,
          [
            "suspicious domain",
            "shortened link",
            "nested url",
            "punycode",
            "url obfuscation",
            "brand impersonation",
            "account threat",
          ],
        ),
      );

    return {
      correlatedThreat:
        "Malicious Link Campaign",

      correlationScore: 74,

      matchedSignals:
        matched,

      explanation:
        "Suspicious link characteristics appear alongside impersonation or account-related language, increasing the likelihood of a malicious-link campaign.",
    };
  }

  if (
    hasUrgency &&
    (
      hasSecrecy ||
      hasImpersonation
    )
  ) {
    const matched =
      unique(
        getMatchedSignals(
          flags,
          [
            "urgency",
            "secrecy request",
            "impersonation",
          ],
        ),
      );

    return {
      correlatedThreat:
        "Social Engineering",

      correlationScore: 68,

      matchedSignals:
        matched,

      explanation:
        "The message combines psychological pressure with secrecy or impersonation tactics, which is consistent with social engineering.",
    };
  }

  return {
    correlatedThreat:
      "No Correlated Threat",

    correlationScore: 25,

    matchedSignals:
      flags.map(
        (flag) =>
          flag.category,
      ),

    explanation:
      "Suspicious indicators were detected, but they do not currently form a strong correlated attack pattern.",
  };
}