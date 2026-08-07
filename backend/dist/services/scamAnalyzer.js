import { calculateRiskScore, determineRiskLevel, getRecommendation, } from "../utils/riskCalculator.js";
const scamRules = [
    {
        category: "Urgency",
        description: "The message uses pressure or urgent language.",
        points: 15,
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
        description: "The message threatens account suspension, closure, or restricted access.",
        points: 20,
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
        description: "The message requests private or security-related information.",
        points: 30,
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
        description: "The message requests an unusual or difficult-to-reverse payment.",
        points: 30,
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
        description: "The message claims the recipient won a prize, reward, or giveaway.",
        points: 20,
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
        category: "Suspicious link",
        description: "The message contains a link that should be verified before opening.",
        points: 25,
        patterns: [
            /https?:\/\/[^\s]+/i,
            /\bwww\.[^\s]+/i,
            /\bbit\.ly\/[^\s]+/i,
            /\btinyurl\.com\/[^\s]+/i,
            /\bt\.co\/[^\s]+/i,
            /\brebrand\.ly\/[^\s]+/i,
        ],
    },
    {
        category: "Investment promise",
        description: "The message promises unusually high, fast, or guaranteed investment returns.",
        points: 25,
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
        description: "The sender may be pretending to represent a trusted person or organization.",
        points: 20,
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
        description: "The message asks the recipient to keep the request secret.",
        points: 20,
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
export function analyzeMessage(message) {
    const flags = [];
    for (const rule of scamRules) {
        const matched = rule.patterns.some((pattern) => pattern.test(message));
        if (matched) {
            flags.push({
                category: rule.category,
                description: rule.description,
                points: rule.points,
            });
        }
    }
    const riskScore = calculateRiskScore(flags);
    const riskLevel = determineRiskLevel(riskScore);
    const summary = flags.length === 0
        ? "Sentri did not detect any common scam patterns in this message."
        : `Sentri detected ${flags.length} potential scam ${flags.length === 1 ? "indicator" : "indicators"}.`;
    return {
        riskScore,
        riskLevel,
        flags,
        summary,
        recommendation: getRecommendation(riskLevel),
    };
}
//# sourceMappingURL=scamAnalyzer.js.map