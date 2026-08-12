import type { ScamFlag } from "../types/analysis.js";

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
}

export interface UrlAnalysis {
  flags: ScamFlag[];
  intelligence: UrlIntelligence | null;
}

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

function normalizeUrl(
  rawUrl: string,
): string {
  const trimmedUrl =
    rawUrl.trim();

  if (
    trimmedUrl.startsWith("http://") ||
    trimmedUrl.startsWith("https://")
  ) {
    return trimmedUrl;
  }

  if (
    trimmedUrl.startsWith("www.")
  ) {
    return `https://${trimmedUrl}`;
  }

  return `https://${trimmedUrl}`;
}

function isIpAddress(
  hostname: string,
): boolean {
  const ipv4Pattern =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (
    !ipv4Pattern.test(hostname)
  ) {
    return false;
  }

  const parts =
    hostname.split(".");

  return parts.every((part) => {
    const number =
      Number(part);

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
  if (
    isIpAddress(hostname)
  ) {
    return 0;
  }

  const parts =
    hostname
      .split(".")
      .filter(Boolean);

  if (
    parts.length <= 2
  ) {
    return 0;
  }

  return parts.length - 2;
}

function getSuspiciousTld(
  hostname: string,
): string | null {
  const detected =
    suspiciousTlds.find(
      (tld) =>
        hostname.endsWith(tld),
    );

  return detected ?? null;
}

function isShortenedDomain(
  hostname: string,
): boolean {
  return shortenerDomains.some(
    (domain) =>
      hostname === domain ||
      hostname.endsWith(
        `.${domain}`,
      ),
  );
}

export function analyzeUrls(
  rawUrl: string,
): ScamFlag[] {
  return analyzeUrlIntelligence(
    rawUrl,
  ).flags;
}

export function analyzeUrlIntelligence(
  rawUrl: string,
): UrlAnalysis {
  const flags: ScamFlag[] = [];

  const normalizedUrl =
    normalizeUrl(rawUrl);

  let parsedUrl: URL;

  try {
    parsedUrl =
      new URL(normalizedUrl);
  } catch {
    flags.push({
      category:
        "Malformed link",
      description:
        "The URL could not be parsed correctly.",
      points: 25,
    });

    return {
      flags,
      intelligence: null,
    };
  }

  const hostname =
    parsedUrl.hostname.toLowerCase();

  const usesHttps =
    parsedUrl.protocol ===
    "https:";

  const shortened =
    isShortenedDomain(
      hostname,
    );

  const ipAddress =
    isIpAddress(
      hostname,
    );

  const suspiciousTld =
    getSuspiciousTld(
      hostname,
    );

  const subdomainDepth =
    getSubdomainDepth(
      hostname,
    );

  const longSubdomainChain =
    subdomainDepth >= 3;

  const containsAtSymbol =
    normalizedUrl.includes("@");

  const containsPunycode =
    hostname.includes("xn--");

  /*
   * Baseline link detection
   */
  flags.push({
    category:
      "Link detected",
    description:
      "The content contains a URL. Verify the destination before opening it.",
    points: 5,
  });

  /*
   * HTTP instead of HTTPS
   */
  if (!usesHttps) {
    flags.push({
      category:
        "Insecure link",
      description:
        "The URL uses HTTP instead of HTTPS.",
      points: 10,
    });
  }

  /*
   * URL shortener
   */
  if (shortened) {
    flags.push({
      category:
        "Shortened link",
      description:
        "The URL uses a shortening service that hides the final destination.",
      points: 20,
    });
  }

  /*
   * Raw IP address
   */
  if (ipAddress) {
    flags.push({
      category:
        "IP-based link",
      description:
        "The URL uses a raw IP address instead of a normal domain name.",
      points: 25,
    });
  }

  /*
   * Suspicious TLD
   */
  if (suspiciousTld) {
    flags.push({
      category:
        "Suspicious domain",
      description:
        `The domain uses the ${suspiciousTld} ending, which should be treated cautiously.`,
      points: 15,
    });
  }

  /*
   * Excessive subdomains
   */
  if (
    longSubdomainChain
  ) {
    flags.push({
      category:
        "Misleading domain structure",
      description:
        "The domain contains an unusually deep subdomain chain.",
      points: 15,
    });
  }

  /*
   * Username-style @ symbol
   */
  if (
    containsAtSymbol
  ) {
    flags.push({
      category:
        "URL obfuscation",
      description:
        "The URL contains an @ symbol that may obscure the actual destination.",
      points: 20,
    });
  }

  /*
   * Punycode / internationalized hostname
   */
  if (
    containsPunycode
  ) {
    flags.push({
      category:
        "Punycode domain",
      description:
        "The URL uses an encoded internationalized domain name that may resemble another website.",
      points: 20,
    });
  }

  /*
   * Extremely long hostname
   */
  if (
    hostname.length > 50
  ) {
    flags.push({
      category:
        "Long domain",
      description:
        "The hostname is unusually long and may be designed to confuse the recipient.",
      points: 10,
    });
  }

  const intelligence:
    UrlIntelligence = {
    originalUrl:
      rawUrl,

    normalizedUrl,

    protocol:
      parsedUrl.protocol.replace(
        ":",
        "",
      ),

    hostname,

    pathname:
      parsedUrl.pathname,

    usesHttps,

    isShortened:
      shortened,

    isIpAddress:
      ipAddress,

    hasSuspiciousTld:
      suspiciousTld !== null,

    hasLongSubdomainChain:
      longSubdomainChain,

    subdomainDepth,

    suspiciousTld,

    domainLength:
      hostname.length,

    containsAtSymbol,

    containsPunycode,

    port:
      parsedUrl.port || null,
  };

  return {
    flags,
    intelligence,
  };
}