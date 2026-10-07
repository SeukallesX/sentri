import type {
  SecuritySignal,
  SignalCategory,
  SignalSeverity,
  SignalSource,
} from "../types/securitySignal.js";

export interface SignalDefinition {
  id: string;

  name: string;

  category: SignalCategory;

  severity: SignalSeverity;

  source: SignalSource;

  points: number;
}

/*
 * ---------------------------------------
 * RULE-X SIGNAL REGISTRY
 * ---------------------------------------
 *
 * Stable IDs are important.
 *
 * UI text can change later without
 * breaking correlation, analytics,
 * storage, or future ML features.
 */

export const SIGNAL_REGISTRY = {
  URGENCY: {
    id: "RX-URGENCY",

    name:
      "Urgency Language",

    category:
      "social_engineering",

    severity:
      "medium",

    source:
      "rule-x",

    points: 15,
  },

  ACCOUNT_THREAT: {
    id: "RX-ACCOUNT-THREAT",

    name:
      "Account Threat",

    category:
      "account_threat",

    severity:
      "high",

    source:
      "rule-x",

    points: 20,
  },

  SENSITIVE_INFORMATION: {
    id: "RX-SENSITIVE-INFO",

    name:
      "Sensitive Information Request",

    category:
      "credential_theft",

    severity:
      "critical",

    source:
      "rule-x",

    points: 30,
  },

  SUSPICIOUS_PAYMENT: {
    id: "RX-PAYMENT",

    name:
      "Suspicious Payment Request",

    category:
      "payment_fraud",

    severity:
      "critical",

    source:
      "rule-x",

    points: 30,
  },

  PRIZE_REWARD: {
    id: "RX-PRIZE",

    name:
      "Prize or Reward",

    category:
      "social_engineering",

    severity:
      "high",

    source:
      "rule-x",

    points: 20,
  },

  INVESTMENT_PROMISE: {
    id: "RX-INVESTMENT",

    name:
      "Investment Promise",

    category:
      "investment_fraud",

    severity:
      "high",

    source:
      "rule-x",

    points: 25,
  },

  IMPERSONATION: {
    id: "RX-IMPERSONATION",

    name:
      "Impersonation",

    category:
      "impersonation",

    severity:
      "high",

    source:
      "rule-x",

    points: 20,
  },

  SECRECY_REQUEST: {
    id: "RX-SECRECY",

    name:
      "Secrecy Request",

    category:
      "social_engineering",

    severity:
      "high",

    source:
      "rule-x",

    points: 20,
  },

  LINK_DETECTED: {
    id: "URL-LINK",

    name:
      "Link Detected",

    category:
      "url",

    severity:
      "info",

    source:
      "url-intelligence",

    points: 0,
  },

  INSECURE_HTTP: {
    id: "URL-INSECURE-HTTP",

    name:
      "Insecure HTTP",

    category:
      "url",

    severity:
      "medium",

    source:
      "url-intelligence",

    points: 10,
  },

  SHORTENED_URL: {
    id: "URL-SHORTENER",

    name:
      "Shortened URL",

    category:
      "url",

    severity:
      "high",

    source:
      "url-intelligence",

    points: 20,
  },

  IP_ADDRESS_URL: {
    id: "URL-IP-HOST",

    name:
      "IP Address Host",

    category:
      "domain",

    severity:
      "high",

    source:
      "url-intelligence",

    points: 25,
  },

  SUSPICIOUS_TLD: {
    id: "URL-SUSPICIOUS-TLD",

    name:
      "Suspicious TLD",

    category:
      "domain",

    severity:
      "medium",

    source:
      "url-intelligence",

    points: 15,
  },

  DEEP_SUBDOMAIN: {
    id: "URL-DEEP-SUBDOMAIN",

    name:
      "Deep Subdomain Chain",

    category:
      "domain",

    severity:
      "medium",

    source:
      "url-intelligence",

    points: 15,
  },

  AT_OBFUSCATION: {
    id: "URL-AT-OBFUSCATION",

    name:
      "@ Symbol Obfuscation",

    category:
      "obfuscation",

    severity:
      "high",

    source:
      "url-intelligence",

    points: 20,
  },

  PUNYCODE: {
    id: "URL-PUNYCODE",

    name:
      "Punycode Domain",

    category:
      "obfuscation",

    severity:
      "high",

    source:
      "url-intelligence",

    points: 20,
  },

  LONG_DOMAIN: {
    id: "URL-LONG-DOMAIN",

    name:
      "Unusually Long Domain",

    category:
      "domain",

    severity:
      "low",

    source:
      "url-intelligence",

    points: 10,
  },

  BRAND_IMPERSONATION: {
    id: "URL-BRAND-IMPERSONATION",

    name:
      "Brand Impersonation",

    category:
      "impersonation",

    severity:
      "critical",

    source:
      "url-intelligence",

    points: 30,
  },

  TYPOSQUATTING: {
    id: "URL-TYPOSQUATTING",

    name:
      "Typosquatting",

    category:
      "impersonation",

    severity:
      "critical",

    source:
      "url-intelligence",

    points: 30,
  },

  SUSPICIOUS_PATH: {
    id: "URL-SUSPICIOUS-PATH",

    name:
      "Suspicious URL Path",

    category:
      "url",

    severity:
      "medium",

    source:
      "url-intelligence",

    points: 15,
  },

  SUSPICIOUS_QUERY: {
    id: "URL-SUSPICIOUS-QUERY",

    name:
      "Suspicious Query Parameters",

    category:
      "url",

    severity:
      "low",

    source:
      "url-intelligence",

    points: 10,
  },

  NESTED_URL: {
    id: "URL-NESTED",

    name:
      "Nested URL",

    category:
      "obfuscation",

    severity:
      "high",

    source:
      "url-intelligence",

    points: 20,
  },
} as const satisfies Record<
  string,
  SignalDefinition
>;

/*
 * ---------------------------------------
 * SIGNAL FACTORY
 * ---------------------------------------
 */

export function createSignal(
  definition:
    SignalDefinition,

  description: string,

  value?: string,
): SecuritySignal {
  return {
    id:
      definition.id,

    name:
      definition.name,

    category:
      definition.category,

    severity:
      definition.severity,

    source:
      definition.source,

    points:
      definition.points,

    evidence: [
      {
        description,

        ...(value
          ? {
              value,
            }
          : {}),
      },
    ],
  };
}