const trustedDomains = {
    amazon: [
        "amazon.com",
        "amazon.co.uk",
        "amazon.ca",
        "amazon.de",
    ],
    microsoft: [
        "microsoft.com",
        "live.com",
        "outlook.com",
        "office.com",
    ],
    apple: [
        "apple.com",
        "icloud.com",
    ],
    google: [
        "google.com",
        "gmail.com",
        "youtube.com",
    ],
    paypal: [
        "paypal.com",
    ],
    facebook: [
        "facebook.com",
    ],
    instagram: [
        "instagram.com",
    ],
    netflix: [
        "netflix.com",
    ],
    chase: [
        "chase.com",
    ],
    bankofamerica: [
        "bankofamerica.com",
    ],
    wellsfargo: [
        "wellsfargo.com",
    ],
    coinbase: [
        "coinbase.com",
    ],
};
function normalizeHostname(hostname) {
    return hostname
        .trim()
        .toLowerCase()
        .replace(/\.$/, "");
}
function domainMatches(hostname, trustedDomain) {
    return (hostname ===
        trustedDomain ||
        hostname.endsWith(`.${trustedDomain}`));
}
export function checkTrustedDomain(hostname) {
    const normalizedHostname = normalizeHostname(hostname);
    for (const [brand, domains,] of Object.entries(trustedDomains)) {
        for (const domain of domains) {
            if (domainMatches(normalizedHostname, domain)) {
                return {
                    trusted: true,
                    brand,
                    matchedDomain: domain,
                };
            }
        }
    }
    return {
        trusted: false,
        brand: null,
        matchedDomain: null,
    };
}
export function isTrustedDomain(hostname) {
    return checkTrustedDomain(hostname).trusted;
}
//# sourceMappingURL=trustedDomains.js.map