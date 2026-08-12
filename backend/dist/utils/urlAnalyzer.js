const shortenerDomains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "rebrand.ly",
    "goo.gl",
    "is.gd",
    "buff.ly",
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
];
function extractUrls(message) {
    const urlPattern = /https?:\/\/[^\s]+|www\.[^\s]+/gi;
    const matches = message.match(urlPattern);
    if (!matches) {
        return [];
    }
    return matches.map((url) => url.replace(/[),.!?]+$/, ""));
}
function normalizeUrl(rawUrl) {
    if (rawUrl.startsWith("www.")) {
        return `https://${rawUrl}`;
    }
    return rawUrl;
}
function isIpAddress(hostname) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}
export function analyzeUrls(message) {
    const urls = extractUrls(message);
    const flags = [];
    if (urls.length === 0) {
        return flags;
    }
    flags.push({
        category: "Link detected",
        description: "The message contains one or more links. Verify the destination before opening them.",
        points: 5,
    });
    let hasShortener = false;
    let hasIpAddress = false;
    let hasInsecureHttp = false;
    let hasSuspiciousTld = false;
    let hasLongSubdomainChain = false;
    for (const rawUrl of urls) {
        try {
            const normalizedUrl = normalizeUrl(rawUrl);
            const parsedUrl = new URL(normalizedUrl);
            const hostname = parsedUrl.hostname.toLowerCase();
            if (shortenerDomains.some((domain) => hostname === domain ||
                hostname.endsWith(`.${domain}`))) {
                hasShortener = true;
            }
            if (isIpAddress(hostname)) {
                hasIpAddress = true;
            }
            if (parsedUrl.protocol === "http:") {
                hasInsecureHttp = true;
            }
            if (suspiciousTlds.some((tld) => hostname.endsWith(tld))) {
                hasSuspiciousTld = true;
            }
            const hostnameParts = hostname.split(".");
            if (hostnameParts.length >= 5) {
                hasLongSubdomainChain = true;
            }
        }
        catch {
            flags.push({
                category: "Malformed link",
                description: "The message contains a link that could not be parsed correctly.",
                points: 15,
            });
        }
    }
    if (hasShortener) {
        flags.push({
            category: "Shortened link",
            description: "The message contains a shortened URL that hides the final destination.",
            points: 20,
        });
    }
    if (hasIpAddress) {
        flags.push({
            category: "IP-based link",
            description: "The link uses a raw IP address instead of a normal domain name.",
            points: 25,
        });
    }
    if (hasInsecureHttp) {
        flags.push({
            category: "Insecure link",
            description: "The message contains an HTTP link that does not use HTTPS encryption.",
            points: 10,
        });
    }
    if (hasSuspiciousTld) {
        flags.push({
            category: "Suspicious domain",
            description: "The link uses a domain ending that is commonly abused in phishing campaigns.",
            points: 15,
        });
    }
    if (hasLongSubdomainChain) {
        flags.push({
            category: "Misleading domain structure",
            description: "The link contains an unusually long chain of subdomains that may be designed to appear trustworthy.",
            points: 15,
        });
    }
    return flags;
}
//# sourceMappingURL=urlAnalyzer.js.map