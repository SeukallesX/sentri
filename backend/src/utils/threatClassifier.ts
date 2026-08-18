import type { ScamFlag } from "../types/analysis.js";

export type ThreatCategory =
  | "Phishing"
  | "Credential Theft"
  | "Financial Scam"
  | "Impersonation"
  | "Malicious Link"
  | "Social Engineering"
  | "Unknown";

export interface ThreatClassification {
  threatCategory: ThreatCategory;
  confidence: number;
  attackVector: string;
}

function hasFlag(
  flags: ScamFlag[],
  category: string,
): boolean {
  return flags.some(
    (flag) =>
      flag.category
        .toLowerCase()
        .includes(
          category.toLowerCase(),
        ),
  );
}

function countMatchingFlags(
  flags: ScamFlag[],
  categories: string[],
): number {
  return categories.filter(
    (category) =>
      hasFlag(
        flags,
        category,
      ),
  ).length;
}

function calculateConfidence(
  matches: number,
  base = 45,
): number {
  const confidence =
    base + matches * 12;

  return Math.min(
    98,
    confidence,
  );
}

export function classifyThreat(
  flags: ScamFlag[],
): ThreatClassification {
  if (flags.length === 0) {
    return {
      threatCategory:
        "Unknown",

      confidence: 15,

      attackVector:
        "No dominant attack vector detected",
    };
  }

  const phishingMatches =
    countMatchingFlags(
      flags,
      [
        "urgency",
        "link",
        "shortened",
        "suspicious url",
        "brand impersonation",
        "typosquatting",
        "login",
        "verification",
        "credential",
      ],
    );

  const credentialMatches =
    countMatchingFlags(
      flags,
      [
        "credential",
        "password",
        "login",
        "verification",
        "account",
        "authentication",
      ],
    );

  const financialMatches =
    countMatchingFlags(
      flags,
      [
        "payment",
        "gift card",
        "crypto",
        "bank",
        "financial",
        "wire transfer",
        "money",
        "prize",
      ],
    );

  const impersonationMatches =
    countMatchingFlags(
      flags,
      [
        "impersonation",
        "brand",
        "typosquatting",
        "spoof",
      ],
    );

  const maliciousLinkMatches =
    countMatchingFlags(
      flags,
      [
        "shortened link",
        "suspicious domain",
        "nested url",
        "punycode",
        "ip-based link",
        "url obfuscation",
        "insecure link",
      ],
    );

  const socialEngineeringMatches =
    countMatchingFlags(
      flags,
      [
        "urgency",
        "pressure",
        "fear",
        "authority",
        "prize",
        "scarcity",
        "threat",
      ],
    );

  const scores = [
    {
      category:
        "Phishing" as ThreatCategory,

      matches:
        phishingMatches,

      attackVector:
        "Message deception and malicious link delivery",
    },

    {
      category:
        "Credential Theft" as ThreatCategory,

      matches:
        credentialMatches,

      attackVector:
        "Account access and credential harvesting",
    },

    {
      category:
        "Financial Scam" as ThreatCategory,

      matches:
        financialMatches,

      attackVector:
        "Payment manipulation or financial fraud",
    },

    {
      category:
        "Impersonation" as ThreatCategory,

      matches:
        impersonationMatches,

      attackVector:
        "Brand or identity impersonation",
    },

    {
      category:
        "Malicious Link" as ThreatCategory,

      matches:
        maliciousLinkMatches,

      attackVector:
        "URL-based deception or redirection",
    },

    {
      category:
        "Social Engineering" as ThreatCategory,

      matches:
        socialEngineeringMatches,

      attackVector:
        "Psychological manipulation",
    },
  ];

  scores.sort(
    (a, b) =>
      b.matches -
      a.matches,
  );

  const top =
    scores[0];

  if (
    !top ||
    top.matches === 0
  ) {
    return {
      threatCategory:
        "Unknown",

      confidence: 30,

      attackVector:
        "Unclassified suspicious activity",
    };
  }

  return {
    threatCategory:
      top.category,

    confidence:
      calculateConfidence(
        top.matches,
      ),

    attackVector:
      top.attackVector,
  };
}