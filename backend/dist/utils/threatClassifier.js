/*
 * Weak informational indicators should NOT
 * establish a threat classification by themselves.
 *
 * Example:
 * https://www.amazon.com/orders
 *
 * may produce "Link detected", but that alone
 * should not become "Phishing".
 */
const weakIndicators = new Set([
    "link detected",
]);
function normalize(value) {
    return value
        .trim()
        .toLowerCase();
}
function categoriesFromFlags(flags) {
    return flags.map((flag) => normalize(flag.category));
}
function hasCategory(categories, target) {
    const normalizedTarget = normalize(target);
    return categories.some((category) => category ===
        normalizedTarget ||
        category.includes(normalizedTarget));
}
function countTrue(values) {
    return values.filter(Boolean).length;
}
function clampConfidence(value) {
    return Math.max(0, Math.min(98, Math.round(value)));
}
export function classifyThreat(flags) {
    /*
     * Completely clean scan.
     */
    if (flags.length === 0) {
        return {
            threatCategory: "Unknown",
            confidence: 0,
            attackVector: "No dominant attack vector detected",
        };
    }
    const categories = categoriesFromFlags(flags);
    /*
     * Remove informational-only indicators
     * before attempting classification.
     */
    const meaningfulCategories = categories.filter((category) => !weakIndicators.has(category));
    /*
     * A URL merely existing in a message
     * is not enough evidence of phishing.
     */
    if (meaningfulCategories.length ===
        0) {
        return {
            threatCategory: "Unknown",
            confidence: 0,
            attackVector: "No dominant attack vector detected",
        };
    }
    /*
     * ---------------------------------------
     * SIGNAL GROUPS
     * ---------------------------------------
     */
    const urgency = hasCategory(categories, "urgency");
    const accountThreat = hasCategory(categories, "account threat");
    const sensitiveInformation = hasCategory(categories, "sensitive information");
    const suspiciousPayment = hasCategory(categories, "suspicious payment");
    const prizeReward = hasCategory(categories, "prize or reward");
    const investmentPromise = hasCategory(categories, "investment promise");
    const impersonation = hasCategory(categories, "impersonation") ||
        hasCategory(categories, "brand impersonation");
    const secrecy = hasCategory(categories, "secrecy request");
    const shortenedLink = hasCategory(categories, "shortened link");
    const insecureLink = hasCategory(categories, "insecure link");
    const suspiciousDomain = hasCategory(categories, "suspicious domain");
    const suspiciousPath = hasCategory(categories, "suspicious url path");
    const suspiciousQuery = hasCategory(categories, "suspicious query parameters");
    const nestedUrl = hasCategory(categories, "nested url");
    const punycode = hasCategory(categories, "punycode domain");
    const typosquatting = hasCategory(categories, "typosquatting");
    const ipBasedLink = hasCategory(categories, "ip-based link");
    const obfuscatedUrl = hasCategory(categories, "url obfuscation");
    const misleadingDomain = hasCategory(categories, "misleading domain structure");
    /*
     * A collection of URL signals that
     * represent actual suspicious behavior.
     *
     * Notice "Link detected" is NOT here.
     */
    const suspiciousUrlSignals = countTrue([
        shortenedLink,
        insecureLink,
        suspiciousDomain,
        suspiciousPath,
        suspiciousQuery,
        nestedUrl,
        punycode,
        typosquatting,
        ipBasedLink,
        obfuscatedUrl,
        misleadingDomain,
    ]);
    /*
     * ---------------------------------------
     * CREDENTIAL THEFT
     * ---------------------------------------
     *
     * Sensitive-information requests become
     * much more meaningful when combined with
     * account threats or suspicious URLs.
     */
    if (sensitiveInformation &&
        (accountThreat ||
            suspiciousUrlSignals >= 1)) {
        const evidence = countTrue([
            sensitiveInformation,
            accountThreat,
            urgency,
            impersonation,
        ]) +
            Math.min(suspiciousUrlSignals, 3);
        return {
            threatCategory: "Credential Theft",
            confidence: clampConfidence(58 +
                evidence * 7),
            attackVector: "Credential harvesting through deceptive account or security requests",
        };
    }
    /*
     * ---------------------------------------
     * FINANCIAL SCAM
     * ---------------------------------------
     */
    const financialSignals = countTrue([
        suspiciousPayment,
        prizeReward,
        investmentPromise,
    ]);
    if (financialSignals >= 1) {
        const supportingSignals = countTrue([
            urgency,
            secrecy,
            impersonation,
        ]);
        return {
            threatCategory: "Financial Scam",
            confidence: clampConfidence(58 +
                financialSignals *
                    12 +
                supportingSignals *
                    7),
            attackVector: "Financial manipulation or deceptive payment solicitation",
        };
    }
    /*
     * ---------------------------------------
     * IMPERSONATION
     * ---------------------------------------
     */
    if (impersonation &&
        (accountThreat ||
            urgency ||
            suspiciousUrlSignals >=
                1)) {
        const evidence = countTrue([
            impersonation,
            accountThreat,
            urgency,
        ]) +
            Math.min(suspiciousUrlSignals, 2);
        return {
            threatCategory: "Impersonation",
            confidence: clampConfidence(55 +
                evidence * 8),
            attackVector: "Brand or identity impersonation used to establish false trust",
        };
    }
    /*
     * ---------------------------------------
     * PHISHING
     * ---------------------------------------
     *
     * Require multiple phishing-related
     * signals. A plain link does not count.
     */
    const phishingSignals = countTrue([
        urgency,
        accountThreat,
        sensitiveInformation,
        impersonation,
    ]) +
        Math.min(suspiciousUrlSignals, 3);
    if (phishingSignals >= 2) {
        return {
            threatCategory: "Phishing",
            confidence: clampConfidence(48 +
                phishingSignals *
                    7),
            attackVector: suspiciousUrlSignals >
                0
                ? "Message deception combined with suspicious link delivery"
                : "Message-based deception intended to manipulate the recipient",
        };
    }
    /*
     * ---------------------------------------
     * MALICIOUS LINK
     * ---------------------------------------
     *
     * Require meaningful URL anomalies.
     * "Link detected" is intentionally ignored.
     */
    if (suspiciousUrlSignals >= 2) {
        return {
            threatCategory: "Malicious Link",
            confidence: clampConfidence(50 +
                suspiciousUrlSignals *
                    8),
            attackVector: "URL-based deception, obfuscation, or destination manipulation",
        };
    }
    /*
     * Certain individual URL indicators
     * are strong enough to warrant a
     * malicious-link classification.
     */
    if (typosquatting ||
        punycode ||
        obfuscatedUrl ||
        ipBasedLink) {
        return {
            threatCategory: "Malicious Link",
            confidence: 64,
            attackVector: "Suspicious URL structure designed to disguise or imitate a destination",
        };
    }
    /*
     * ---------------------------------------
     * SOCIAL ENGINEERING
     * ---------------------------------------
     */
    const socialSignals = countTrue([
        urgency,
        secrecy,
        impersonation,
        accountThreat,
    ]);
    if (socialSignals >= 2) {
        return {
            threatCategory: "Social Engineering",
            confidence: clampConfidence(50 +
                socialSignals * 8),
            attackVector: "Psychological pressure or trust manipulation",
        };
    }
    /*
     * ---------------------------------------
     * NO DOMINANT THREAT
     * ---------------------------------------
     *
     * We may still have one weak suspicious
     * indicator, but there isn't enough
     * evidence to confidently classify it.
     */
    return {
        threatCategory: "Unknown",
        confidence: 20,
        attackVector: "No dominant attack vector detected",
    };
}
//# sourceMappingURL=threatClassifier.js.map