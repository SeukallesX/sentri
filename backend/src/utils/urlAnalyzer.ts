
import type {
  ScamFlag,
} from "../types/analysis.js";

import {
  checkTrustedDomain,
} from "./trustedDomains.js";

import {
  SIGNAL_REGISTRY,
  createSignal,
} from "../config/signalRegistry.js";

import type {
  SignalDefinition,
} from "../config/signalRegistry.js";

/*
 * =======================================
 * SENTRI V3 — URL INTELLIGENCE ENGINE
 * =======================================
 */

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
  suspiciousTld: string | null;
  domainLength: number;
  containsAtSymbol: boolean;
  containsPunycode: boolean;
  port: string | null;
  impersonatedBrand: string | null;
  suspectedTyposquatBrand: string | null;
  suspiciousPathKeywords: string[];
  suspiciousQueryKeywords: string[];
  containsNestedUrl: boolean;
  isTrustedDomain: boolean;
  trustedBrand: string | null;
  trustedDomain: string | null;
}

export interface UrlAnalysis {
  flags: ScamFlag[];
  intelligence: UrlIntelligence | null;
}

/*
 * ---------------------------------------
 * DETECTION CONFIGURATION
 * ---------------------------------------
 */

const shortenerDomains = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "rebrand.ly",
  "goo.gl",
  "is.gd",
  "buff.ly",
  "ow.ly",
  "shorturl.at",
  "cutt.ly",
  "rb.gy",
];

const suspiciousTlds = [
  ".zip",
  ".mov",
  ".top",
  ".xyz",
  ".click",
  ".link",
  ".work",
  ".support",
  ".info",
  ".live",
  ".buzz",
];

const protectedBrands = [
  "paypal",
  "microsoft",
  "apple",
  "amazon",
  "google",
  "facebook",
  "instagram",
  "netflix",
  "chase",
  "bankofamerica",
  "wellsfargo",
  "coinbase",
];

const suspiciousPathKeywords = [
  "login",
  "signin",
  "verify",
  "verification",
  "password",
  "reset",
  "account",
  "billing",
  "payment",
  "wallet",
  "security",
  "confirm",
  "update",
  "auth",
  "authentication",
  "unlock",
  "recover",
  "recovery",
];

const suspiciousQueryTerms = [
  "redirect",
  "return",
  "returnurl",
  "next",
  "url",
  "target",
  "destination",
  "token",
  "session",
  "verify",
  "verification",
  "password",
  "account",
  "login",
  "auth",
];

/*
 * ---------------------------------------
 * SIGNAL FACTORY
 * ---------------------------------------
 *
 * Retains the existing ScamFlag format
 * while attaching structured metadata.
 */

function makeFlag(
  definition: SignalDefinition,
  category: string,
  description: string,
  evidenceValue?: string,
  pointsOverride?: number,
): ScamFlag {
  const signal = createSignal(
    definition,
    description,
    evidenceValue,
  );

  return {
    category,
    description,
    points:
      pointsOverride ?? signal.points,
    signalId: signal.id,
    severity: signal.severity,
    source: signal.source,
    evidence: signal.evidence,
  };
}

/*
 * ---------------------------------------
 * URL NORMALIZATION
 * ---------------------------------------
 */

function normalizeUrl(
  rawUrl: string,
): string {
  const trimmed = rawUrl.trim();

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }

  return `https://${trimmed}`;
}

function cleanExtractedUrl(
  rawUrl: string,
): string {
  return rawUrl.replace(
    /[.,!?;:)\]}]+$/,
    "",
  );
}

function extractUrls(
  content: string,
): string[] {
  const pattern =
    /https?:\/\/[^\s<>"'`]+/gi;

  const matches =
    content.match(pattern) ?? [];

  return Array.from(
    new Set(
      matches
        .map(cleanExtractedUrl)
        .filter(Boolean),
    ),
  );
}

/*
 * ---------------------------------------
 * DOMAIN UTILITIES
 * ---------------------------------------
 */

function isIpAddress(
  hostname: string,
): boolean {
  const ipv4Pattern =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (!ipv4Pattern.test(hostname)) {
    return false;
  }

  return hostname
    .split(".")
    .every((part) => {
      const number = Number(part);

      return (
        Number.isInteger(number) &&
        number >= 0 &&
        number <= 255
      );
    });
}

function getSubdomainDepth(
  hostname: string,
): number {
  if (isIpAddress(hostname)) {
    return 0;
  }

  const parts = hostname
    .split(".")
    .filter(Boolean);

  return Math.max(
    0,
    parts.length - 2,
  );
}

function getSuspiciousTld(
  hostname: string,
): string | null {
  return (
    suspiciousTlds.find(
      (tld) => hostname.endsWith(tld),
    ) ?? null
  );
}

function isShortenedDomain(
  hostname: string,
): boolean {
  return shortenerDomains.some(
    (domain) =>
      hostname === domain ||
      hostname.endsWith(`.${domain}`),
  );
}

/*
 * ---------------------------------------
 * BRAND IMPERSONATION
 * ---------------------------------------
 */

function detectBrandImpersonation(
  hostname: string,
): string | null {
  if (
    checkTrustedDomain(hostname).trusted
  ) {
    return null;
  }

  for (const brand of protectedBrands) {
    if (hostname.includes(brand)) {
      return brand;
    }
  }

  return null;
}

/*
 * ---------------------------------------
 * TYPOSQUATTING DETECTION
 * ---------------------------------------
 */

function levenshteinDistance(
  first: string,
  second: string,
): number {
  const previous = Array.from(
    { length: second.length + 1 },
    (_, index) => index,
  );

  for (
    let i = 1;
    i <= first.length;
    i++
  ) {
    const current: number[] = [i];

    for (
      let j = 1;
      j <= second.length;
      j++
    ) {
      const cost =
        first[i - 1] === second[j - 1]
          ? 0
          : 1;

      current[j] = Math.min(
        previous[j] + 1,
        current[j - 1] + 1,
        previous[j - 1] + cost,
      );
    }

    previous.splice(
      0,
      previous.length,
      ...current,
    );
  }

  return previous[second.length];
}

function getDomainLabel(
  hostname: string,
): string {
  const parts = hostname
    .split(".")
    .filter(Boolean);

  return parts.length >= 2
    ? parts[parts.length - 2]
    : hostname;
}

function normalizeLookalikeCharacters(
  value: string,
): string {
  return value
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/8/g, "b");
}

function detectTyposquatting(
  hostname: string,
): string | null {
  if (
    checkTrustedDomain(hostname).trusted
  ) {
    return null;
  }

  const label = getDomainLabel(hostname)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");

  if (!label) {
    return null;
  }

  const normalizedLabel =
    normalizeLookalikeCharacters(label);

  for (const brand of protectedBrands) {
    if (normalizedLabel === brand) {
      return brand;
    }

    const distance =
      levenshteinDistance(label, brand);

    if (
      distance > 0 &&
      distance <= 2
    ) {
      return brand;
    }

    const normalizedDistance =
      levenshteinDistance(
        normalizedLabel,
        brand,
      );

    if (
      normalizedDistance > 0 &&
      normalizedDistance <= 1
    ) {
      return brand;
    }
  }

  return null;
}

/*
 * ---------------------------------------
 * PATH AND QUERY ANALYSIS
 * ---------------------------------------
 */

function detectSuspiciousPathKeywords(
  pathname: string,
): string[] {
  const path = pathname.toLowerCase();

  return suspiciousPathKeywords.filter(
    (keyword) => path.includes(keyword),
  );
}

function analyzeQueryParameters(
  parsedUrl: URL,
): {
  suspiciousKeywords: string[];
  containsNestedUrl: boolean;
} {
  const keywords = new Set<string>();
  let containsNestedUrl = false;

  for (
    const [key, value] of
    parsedUrl.searchParams.entries()
  ) {
    const normalizedKey =
      key.toLowerCase();

    const normalizedValue =
      value.toLowerCase();

    for (
      const keyword of suspiciousQueryTerms
    ) {
      if (
        normalizedKey.includes(keyword) ||
        normalizedValue.includes(keyword)
      ) {
        keywords.add(keyword);
      }
    }

    let decodedValue = normalizedValue;

    try {
      decodedValue =
        decodeURIComponent(
          normalizedValue,
        );
    } catch {
      // Preserve the original value.
    }

    if (
      /https?:\/\//i.test(normalizedValue) ||
      /https?:\/\//i.test(decodedValue)
    ) {
      containsNestedUrl = true;
    }
  }

  return {
    suspiciousKeywords: [...keywords],
    containsNestedUrl,
  };
}

/*
 * ---------------------------------------
 * ANALYZE URLS IN A MESSAGE
 * ---------------------------------------
 */

export function analyzeUrls(
  content: string,
): ScamFlag[] {
  const flags: ScamFlag[] = [];

  for (const url of extractUrls(content)) {
    const analysis =
      analyzeUrlIntelligence(url);

    flags.push(...analysis.flags);
  }

  return flags;
}

/*
 * ---------------------------------------
 * ANALYZE A SINGLE URL
 * ---------------------------------------
 */

export function analyzeUrlIntelligence(
  rawUrl: string,
): UrlAnalysis {
  const flags: ScamFlag[] = [];

  const normalizedUrl =
    normalizeUrl(rawUrl);

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(normalizedUrl);

    if (
      !["http:", "https:"].includes(
        parsedUrl.protocol,
      ) ||
      !parsedUrl.hostname
    ) {
      throw new Error(
        "Unsupported URL protocol",
      );
    }
  } catch {
    flags.push({
      category: "Malformed link",
      description:
        "The URL could not be parsed correctly.",
      points: 25,
      signalId: "URL-MALFORMED",
      severity: "high",
      source: "url-intelligence",
      evidence: [
        {
          description:
            "Invalid or unsupported URL.",
        },
      ],
    });

    return {
      flags,
      intelligence: null,
    };
  }

  const hostname =
    parsedUrl.hostname.toLowerCase();

  const trustMatch =
    checkTrustedDomain(hostname);

  const usesHttps =
    parsedUrl.protocol === "https:";

  const shortened =
    isShortenedDomain(hostname);

  const ipAddress =
    isIpAddress(hostname);

  const suspiciousTld =
    getSuspiciousTld(hostname);

  const subdomainDepth =
    getSubdomainDepth(hostname);

  const longSubdomainChain =
    subdomainDepth >= 3;

  const containsAtSymbol =
    normalizedUrl.includes("@");

  const containsPunycode =
    hostname.includes("xn--");

  const impersonatedBrand =
    detectBrandImpersonation(hostname);

  const suspectedTyposquatBrand =
    detectTyposquatting(hostname);

  const suspiciousPathMatches =
    detectSuspiciousPathKeywords(
      parsedUrl.pathname,
    );

  const queryAnalysis =
    analyzeQueryParameters(parsedUrl);

  /*
   * Informational signal.
   * A URL alone is not malicious.
   */

  flags.push(
    makeFlag(
      SIGNAL_REGISTRY.LINK_DETECTED,
      "Link detected",
      trustMatch.trusted
        ? `The content contains a URL associated with the trusted ${
            trustMatch.brand ?? "known"
          } domain ${
            trustMatch.matchedDomain ??
            hostname
          }.`
        : "The content contains a URL. Verify the destination before opening it.",
      hostname,
    ),
  );

  if (!usesHttps) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.INSECURE_HTTP,
        "Insecure link",
        "The URL uses HTTP instead of HTTPS.",
        parsedUrl.protocol,
      ),
    );
  }

  if (shortened) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.SHORTENED_URL,
        "Shortened link",
        "The URL uses a shortening service that hides the final destination.",
        hostname,
      ),
    );
  }

  if (ipAddress) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.IP_ADDRESS_URL,
        "IP-based link",
        "The URL uses a raw IP address instead of a normal domain name.",
        hostname,
      ),
    );
  }

  if (suspiciousTld) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.SUSPICIOUS_TLD,
        "Suspicious domain",
        `The domain uses the ${suspiciousTld} ending, which should be treated cautiously.`,
        suspiciousTld,
      ),
    );
  }

  if (longSubdomainChain) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.DEEP_SUBDOMAIN,
        "Misleading domain structure",
        "The domain contains an unusually deep subdomain chain.",
        hostname,
      ),
    );
  }

  if (containsAtSymbol) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.AT_OBFUSCATION,
        "URL obfuscation",
        "The URL contains an @ symbol that may obscure the actual destination.",
        hostname,
      ),
    );
  }

  if (containsPunycode) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.PUNYCODE,
        "Punycode domain",
        "The URL uses an encoded internationalized domain name that may resemble another website.",
        hostname,
      ),
    );
  }

  if (hostname.length > 50) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.LONG_DOMAIN,
        "Long domain",
        "The hostname is unusually long and may be designed to confuse the recipient.",
        hostname,
      ),
    );
  }

  if (impersonatedBrand) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.BRAND_IMPERSONATION,
        "Brand impersonation",
        `The domain contains "${impersonatedBrand}" but is not recognized as an official ${impersonatedBrand} domain.`,
        hostname,
      ),
    );
  }

  if (suspectedTyposquatBrand) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.TYPOSQUATTING,
        "Typosquatting",
        `The domain closely resembles "${suspectedTyposquatBrand}" but is not recognized as an official ${suspectedTyposquatBrand} domain.`,
        hostname,
      ),
    );
  }

  /*
   * Trusted-domain path protection.
   */

  const hasAdditionalUrlRisk =
    shortened ||
    ipAddress ||
    suspiciousTld !== null ||
    longSubdomainChain ||
    containsAtSymbol ||
    containsPunycode ||
    impersonatedBrand !== null ||
    suspectedTyposquatBrand !== null;

  if (
    suspiciousPathMatches.length > 0 &&
    (
      !trustMatch.trusted ||
      hasAdditionalUrlRisk
    )
  ) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.SUSPICIOUS_PATH,
        "Suspicious URL path",
        `The URL path contains security-sensitive terms: ${suspiciousPathMatches.join(
          ", ",
        )}.`,
        suspiciousPathMatches.join(", "),
      ),
    );
  }

  if (
    queryAnalysis.suspiciousKeywords.length >
    0
  ) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.SUSPICIOUS_QUERY,
        "Suspicious query parameters",
        `The URL contains security-sensitive query terms: ${queryAnalysis.suspiciousKeywords.join(
          ", ",
        )}.`,
        queryAnalysis.suspiciousKeywords.join(
          ", ",
        ),
        trustMatch.trusted ? 5 : 10,
      ),
    );
  }

  if (queryAnalysis.containsNestedUrl) {
    flags.push(
      makeFlag(
        SIGNAL_REGISTRY.NESTED_URL,
        "Nested URL",
        "The URL contains another web address inside its query parameters, which may be used for redirects or destination hiding.",
        parsedUrl.hostname,
      ),
    );
  }

  /*
   * ---------------------------------------
   * FINAL INTELLIGENCE OBJECT
   * ---------------------------------------
   */

  const intelligence: UrlIntelligence = {
    originalUrl: rawUrl,
    normalizedUrl,
    protocol:
      parsedUrl.protocol.replace(":", ""),
    hostname,
    pathname: parsedUrl.pathname,
    usesHttps,
    isShortened: shortened,
    isIpAddress: ipAddress,
    hasSuspiciousTld:
      suspiciousTld !== null,
    hasLongSubdomainChain:
      longSubdomainChain,
    subdomainDepth,
    suspiciousTld,
    domainLength: hostname.length,
    containsAtSymbol,
    containsPunycode,
    port: parsedUrl.port || null,
    impersonatedBrand,
    suspectedTyposquatBrand,
    suspiciousPathKeywords:
      suspiciousPathMatches,
    suspiciousQueryKeywords:
      queryAnalysis.suspiciousKeywords,
    containsNestedUrl:
      queryAnalysis.containsNestedUrl,
    isTrustedDomain:
      trustMatch.trusted,
    trustedBrand: trustMatch.brand,
    trustedDomain:
      trustMatch.matchedDomain,
  };

  return {
    flags,
    intelligence,
  };
}
