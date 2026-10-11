
import type {
  AnalysisResult,
  ScamFlag,
} from "../types/analysis.js";

import {
  calculateRiskScore,
  determineRiskLevel,
  getRecommendation,
} from "../utils/riskCalculator.js";

import {
  analyzeUrls,
} from "../utils/urlAnalyzer.js";

import {
  classifyThreat,
} from "../utils/threatClassifier.js";

import {
  correlateThreats,
} from "../utils/threatCorrelation.js";

import {
  SIGNAL_REGISTRY,
  createSignal,
} from "../config/signalRegistry.js";

import type {
  SignalDefinition,
} from "../config/signalRegistry.js";

/*
 * ---------------------------------------
 * RULE-X DETECTION ENGINE
 * SENTRI VERSION 3
 * ---------------------------------------
 */

interface ScamRule {
  category: string;
  description: string;
  signal: SignalDefinition;
  patterns: RegExp[];
}

/*
 * ---------------------------------------
 * MESSAGE DETECTION RULES
 * ---------------------------------------
 */

const scamRules: ScamRule[] = [
  {
    category: "Urgency",
    description:
      "The message uses pressure or urgent language.",
    signal: SIGNAL_REGISTRY.URGENCY,
    patterns: [
      /\bact now\b/i,
      /\bimmediately\b/i,
      /\burgent\b/i,
      /\bfinal warning\b/i,
      /\btime sensitive\b/i,
      /\bwithin 24 hours\b/i,
      /\brespond now\b/i,
      /\bdo not delay\b/i,
    ],
  },

  {
    category: "Account threat",
    description:
      "The message threatens account suspension, closure, or restricted access.",
    signal: SIGNAL_REGISTRY.ACCOUNT_THREAT,
    patterns: [
      /\baccount locked\b/i,
      /\baccount is locked\b/i,
      /\baccount suspended\b/i,
      /\baccount will be suspended\b/i,
      /\baccount will be closed\b/i,
      /\bunauthorized activity\b/i,
      /\bverify your account\b/i,
      /\brestore access\b/i,
      /\bconfirm your identity\b/i,
    ],
  },

  {
    category: "Sensitive information",
    description:
      "The message requests private or security-related information.",
    signal: SIGNAL_REGISTRY.SENSITIVE_INFORMATION,
    patterns: [
      /\bpassword\b/i,
      /\bverification code\b/i,
      /\bone[- ]time code\b/i,
      /\bsecurity code\b/i,
      /\bsocial security\b/i,
      /\bssn\b/i,
      /\bbank account number\b/i,
      /\bcredit card number\b/i,
      /\bdebit card number\b/i,
      /\bpin number\b/i,
    ],
  },

  {
    category: "Suspicious payment",
    description:
      "The message requests an unusual or difficult-to-reverse payment.",
    signal: SIGNAL_REGISTRY.SUSPICIOUS_PAYMENT,
    patterns: [
      /\bgift card\b/i,
      /\bwire transfer\b/i,
      /\bbitcoin\b/i,
      /\bcrypto(?:currency)?\b/i,
      /\bcash app\b/i,
      /\bzelle\b/i,
      /\bvenmo\b/i,
      /\bwestern union\b/i,
      /\bpay a fee\b/i,
      /\bsend money\b/i,
    ],
  },

  {
    category: "Prize or reward",
    description:
      "The message claims the recipient won a prize, reward, or giveaway.",
    signal: SIGNAL_REGISTRY.PRIZE_REWARD,
    patterns: [
      /\bcongratulations\b/i,
      /\byou(?:'ve| have) won\b/i,
      /\bclaim your prize\b/i,
      /\bfree reward\b/i,
      /\blottery winner\b/i,
      /\bselected as a winner\b/i,
      /\bexclusive reward\b/i,
      /\bfree gift\b/i,
    ],
  },

  {
    category: "Investment promise",
    description:
      "The message promises unusually high, fast, or guaranteed investment returns.",
    signal: SIGNAL_REGISTRY.INVESTMENT_PROMISE,
    patterns: [
      /\bguaranteed returns?\b/i,
      /\bdouble your money\b/i,
      /\brisk[- ]free investment\b/i,
      /\bguaranteed profit\b/i,
      /\bget rich quick\b/i,
      /\b100% return\b/i,
      /\binstant profit\b/i,
      /\bpassive income opportunity\b/i,
    ],
  },

  {
    category: "Impersonation",
    description:
      "The sender may be pretending to represent a trusted person or organization.",
    signal: SIGNAL_REGISTRY.IMPERSONATION,
    patterns: [
      /\bthis is the irs\b/i,
      /\bthis is social security\b/i,
      /\bfrom your bank\b/i,
      /\bfrom microsoft support\b/i,
      /\bfrom apple support\b/i,
      /\bfrom amazon support\b/i,
      /\bfrom paypal\b/i,
      /\byour boss asked\b/i,
      /\bi am your manager\b/i,
    ],
  },

  {
    category: "Secrecy request",
    description:
      "The message asks the recipient to keep the request secret.",
    signal: SIGNAL_REGISTRY.SECRECY_REQUEST,
    patterns: [
      /\bdo not tell anyone\b/i,
      /\bkeep this confidential\b/i,
      /\bkeep this secret\b/i,
      /\bdo not contact the bank\b/i,
      /\bdo not call anyone\b/i,
      /\bdon't tell anyone\b/i,
    ],
  },
];

/*
 * ---------------------------------------
 * EXTRACT MATCHED EVIDENCE
 * ---------------------------------------
 */

function extractEvidence(
  message: string,
  patterns: RegExp[],
): string[] {
  const evidence = new Set<string>();

  for (const pattern of patterns) {
    const match = pattern.exec(message);

    if (match?.[0]) {
      evidence.add(match[0]);
    }
  }

  return [...evidence];
}

/*
 * ---------------------------------------
 * RULE-X SIGNAL EXTRACTION
 * ---------------------------------------
 */

function analyzeMessageRules(
  message: string,
): ScamFlag[] {
  const flags: ScamFlag[] = [];

  for (const rule of scamRules) {
    const matches = extractEvidence(
      message,
      rule.patterns,
    );

    if (matches.length === 0) {
      continue;
    }

    const signal = createSignal(
      rule.signal,
      rule.description,
    );

    /*
     * Store the matching phrases as
     * evidence without duplicating points.
     */

    signal.evidence = matches.map(
      (value) => ({
        description:
          "Matched Rule-X detection pattern.",
        value,
      }),
    );

    flags.push({
      category: rule.category,
      description: rule.description,
      points: signal.points,
      signalId: signal.id,
      severity: signal.severity,
      source: signal.source,
      evidence: signal.evidence,
    });
  }

  return flags;
}

/*
 * ---------------------------------------
 * MAIN MESSAGE ANALYZER
 * ---------------------------------------
 */

export function analyzeMessage(
  message: string,
): AnalysisResult {
  /*
   * STEP 1
   * Extract Rule-X security signals.
   */

  const flags: ScamFlag[] =
    analyzeMessageRules(message);

  /*
   * STEP 2
   * Analyze URLs embedded in the message.
   */

  const urlFlags = analyzeUrls(message);

  flags.push(...urlFlags);

  /*
   * STEP 3
   * Calculate overall risk.
   */

  const riskScore =
    calculateRiskScore(flags);

  const riskLevel =
    determineRiskLevel(riskScore);

  /*
   * STEP 4
   * Classify the primary threat.
   */

  const classification =
    classifyThreat(flags);

  /*
   * STEP 5
   * Correlate detected indicators.
   */

  const correlation =
    correlateThreats(flags);

  /*
   * STEP 6
   * Generate an explainable summary.
   */

  const actionableFlags =
    flags.filter(
      (flag) => flag.points > 0,
    );

  const count = actionableFlags.length;

  const summary =
    count === 0
      ? "Sentri did not detect any common scam patterns in this message."
      : `Sentri detected ${count} potential scam ${
          count === 1
            ? "indicator"
            : "indicators"
        }.`;

  /*
   * STEP 7
   * Return the complete analysis.
   */

  return {
    riskScore,
    riskLevel,

    threatCategory:
      classification.threatCategory,

    confidence:
      classification.confidence,

    attackVector:
      classification.attackVector,

    correlatedThreat:
      correlation.correlatedThreat,

    correlationScore:
      correlation.correlationScore,

    matchedSignals:
      correlation.matchedSignals,

    correlationExplanation:
      correlation.explanation,

    flags,
    summary,

    recommendation:
      getRecommendation(riskLevel),
  };
}
