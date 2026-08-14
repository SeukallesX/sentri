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

  impersonatedBrand: string | null;
  suspectedTyposquatBrand: string | null;

  suspiciousPathKeywords: string[];

  suspiciousQueryKeywords: string[];
  containsNestedUrl: boolean;
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

const trustedBrandDomains: Record<
  string,
  string[]
> = {
  paypal: ["paypal.com"],

  microsoft: [
    "microsoft.com",
    "live.com",
  ],

  apple: [
    "apple.com",
    "icloud.com",
  ],

  amazon: ["amazon.com"],

  google: ["google.com"],

  facebook: ["facebook.com"],

  instagram: ["instagram.com"],

  netflix: ["netflix.com"],

  chase: ["chase.com"],

  bankofamerica: [
    "bankofamerica.com",
  ],

  wellsfargo: [
    "wellsfargo.com",
  ],

  coinbase: ["coinbase.com"],
};

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

function normalizeUrl(
  rawUrl: string,
): string {
  const trimmedUrl =
    rawUrl.trim();

  if (
    trimmedUrl.startsWith(
      "http://",
    ) ||
    trimmedUrl.startsWith(
      "https://",
    )
  ) {
    return trimmedUrl;
  }

  if (
    trimmedUrl.startsWith(
      "www.",
    )
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

  return parts.every(
    (part) => {
      const number =
        Number(part);

      return (
        Number.isInteger(
          number,
        ) &&
        number >= 0 &&
        number <= 255
      );
    },
  );
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

function isTrustedBrandDomain(
  hostname: string,
  brand: string,
): boolean {
  const allowedDomains =
    trustedBrandDomains[
      brand
    ] ?? [];

  return allowedDomains.some(
    (domain) =>
      hostname === domain ||
      hostname.endsWith(
        `.${domain}`,
      ),
  );
}

function detectBrandImpersonation(
  hostname: string,
): string | null {
  for (
    const brand of
      protectedBrands
  ) {
    if (
      !hostname.includes(
        brand,
      )
    ) {
      continue;
    }

    if (
      !isTrustedBrandDomain(
        hostname,
        brand,
      )
    ) {
      return brand;
    }
  }

  return null;
}

function levenshteinDistance(
  first: string,
  second: string,
): number {
  const matrix: number[][] =
    Array.from(
      {
        length:
          first.length + 1,
      },
      () =>
        Array.from(
          {
            length:
              second.length + 1,
          },
          () => 0,
        ),
    );

  for (
    let i = 0;
    i <= first.length;
    i++
  ) {
    matrix[i][0] = i;
  }

  for (
    let j = 0;
    j <= second.length;
    j++
  ) {
    matrix[0][j] = j;
  }

  for (
    let i = 1;
    i <= first.length;
    i++
  ) {
    for (
      let j = 1;
      j <= second.length;
      j++
    ) {
      const cost =
        first[i - 1] ===
        second[j - 1]
          ? 0
          : 1;

      matrix[i][j] =
        Math.min(
          matrix[i - 1][j] +
            1,

          matrix[i][j - 1] +
            1,

          matrix[i - 1][
            j - 1
          ] + cost,
        );
    }
  }

  return matrix[
    first.length
  ][second.length];
}

function getDomainLabel(
  hostname: string,
): string {
  const parts =
    hostname
      .split(".")
      .filter(Boolean);

  if (
    parts.length < 2
  ) {
    return hostname;
  }

  return parts[
    parts.length - 2
  ];
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
  const label =
    getDomainLabel(
      hostname,
    )
      .toLowerCase()
      .replace(
        /[^a-z0-9]/g,
        "",
      );

  if (!label) {
    return null;
  }

  for (
    const brand of
      protectedBrands
  ) {
    if (
      isTrustedBrandDomain(
        hostname,
        brand,
      )
    ) {
      continue;
    }

    const normalizedLabel =
      normalizeLookalikeCharacters(
        label,
      );

    if (
      normalizedLabel ===
      brand
    ) {
      return brand;
    }

    const distance =
      levenshteinDistance(
        label,
        brand,
      );

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
      normalizedDistance >
        0 &&
      normalizedDistance <=
        1
    ) {
      return brand;
    }
  }

  return null;
}

function detectSuspiciousPathKeywords(
  pathname: string,
): string[] {
  const normalizedPath =
    pathname.toLowerCase();

  return suspiciousPathKeywords.filter(
    (keyword) =>
      normalizedPath.includes(
        keyword,
      ),
  );
}

function analyzeQueryParameters(
  parsedUrl: URL,
): {
  suspiciousKeywords: string[];
  containsNestedUrl: boolean;
} {
  const detectedKeywords =
    new Set<string>();

  let containsNestedUrl =
    false;

  for (
    const [
      key,
      value,
    ] of parsedUrl.searchParams.entries()
  ) {
    const normalizedKey =
      key.toLowerCase();

    const normalizedValue =
      value.toLowerCase();

    for (
      const keyword of
        suspiciousQueryTerms
    ) {
      if (
        normalizedKey.includes(
          keyword,
        ) ||
        normalizedValue.includes(
          keyword,
        )
      ) {
        detectedKeywords.add(
          keyword,
        );
      }
    }

    let decodedValue =
      normalizedValue;

    try {
      decodedValue =
        decodeURIComponent(
          normalizedValue,
        );
    } catch {
      // Keep the original value if decoding fails.
    }

    if (
      normalizedValue.includes(
        "http://",
      ) ||
      normalizedValue.includes(
        "https://",
      ) ||
      decodedValue.includes(
        "http://",
      ) ||
      decodedValue.includes(
        "https://",
      )
    ) {
      containsNestedUrl =
        true;
    }
  }

  return {
    suspiciousKeywords:
      Array.from(
        detectedKeywords,
      ),

    containsNestedUrl,
  };
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
  const flags: ScamFlag[] =
    [];

  const normalizedUrl =
    normalizeUrl(rawUrl);

  let parsedUrl: URL;

  try {
    parsedUrl =
      new URL(
        normalizedUrl,
      );
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
    normalizedUrl.includes(
      "@",
    );

  const containsPunycode =
    hostname.includes(
      "xn--",
    );

  const impersonatedBrand =
    detectBrandImpersonation(
      hostname,
    );

  const suspectedTyposquatBrand =
    detectTyposquatting(
      hostname,
    );

  const suspiciousPathMatches =
    detectSuspiciousPathKeywords(
      parsedUrl.pathname,
    );

  const queryAnalysis =
    analyzeQueryParameters(
      parsedUrl,
    );

  flags.push({
    category:
      "Link detected",

    description:
      "The content contains a URL. Verify the destination before opening it.",

    points: 5,
  });

  if (!usesHttps) {
    flags.push({
      category:
        "Insecure link",

      description:
        "The URL uses HTTP instead of HTTPS.",

      points: 10,
    });
  }

  if (shortened) {
    flags.push({
      category:
        "Shortened link",

      description:
        "The URL uses a shortening service that hides the final destination.",

      points: 20,
    });
  }

  if (ipAddress) {
    flags.push({
      category:
        "IP-based link",

      description:
        "The URL uses a raw IP address instead of a normal domain name.",

      points: 25,
    });
  }

  if (suspiciousTld) {
    flags.push({
      category:
        "Suspicious domain",

      description:
        `The domain uses the ${suspiciousTld} ending, which should be treated cautiously.`,

      points: 15,
    });
  }

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

  if (
    impersonatedBrand
  ) {
    flags.push({
      category:
        "Brand impersonation",

      description:
        `The domain contains "${impersonatedBrand}" but is not an official ${impersonatedBrand} domain.`,

      points: 30,
    });
  }

  if (
    suspectedTyposquatBrand
  ) {
    flags.push({
      category:
        "Typosquatting",

      description:
        `The domain closely resembles "${suspectedTyposquatBrand}" but is not an official ${suspectedTyposquatBrand} domain.`,

      points: 30,
    });
  }

  if (
    suspiciousPathMatches.length >
    0
  ) {
    flags.push({
      category:
        "Suspicious URL path",

      description:
        `The URL path contains security-sensitive terms: ${suspiciousPathMatches.join(", ")}.`,

      points: 15,
    });
  }

  if (
    queryAnalysis
      .suspiciousKeywords
      .length > 0
  ) {
    flags.push({
      category:
        "Suspicious query parameters",

      description:
        `The URL contains security-sensitive query terms: ${queryAnalysis.suspiciousKeywords.join(", ")}.`,

      points: 10,
    });
  }

  if (
    queryAnalysis
      .containsNestedUrl
  ) {
    flags.push({
      category:
        "Nested URL",

      description:
        "The URL contains another web address inside its query parameters, which may be used for redirects or destination hiding.",

      points: 20,
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
      parsedUrl.port ||
      null,

    impersonatedBrand,

    suspectedTyposquatBrand,

    suspiciousPathKeywords:
      suspiciousPathMatches,

    suspiciousQueryKeywords:
      queryAnalysis
        .suspiciousKeywords,

    containsNestedUrl:
      queryAnalysis
        .containsNestedUrl,
  };

  return {
    flags,
    intelligence,
  };
}