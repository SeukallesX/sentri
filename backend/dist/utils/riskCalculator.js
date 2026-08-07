export function calculateRiskScore(flags) {
    const totalScore = flags.reduce((total, flag) => {
        return total + flag.points;
    }, 0);
    return Math.min(totalScore, 100);
}
export function determineRiskLevel(score) {
    if (score >= 60) {
        return "High";
    }
    if (score >= 30) {
        return "Medium";
    }
    return "Low";
}
export function getRecommendation(level) {
    switch (level) {
        case "High":
            return "Do not reply, click links, send money, or provide personal information. Verify the sender through an official website or trusted phone number.";
        case "Medium":
            return "Treat this message cautiously. Verify the sender independently before clicking links or sharing information.";
        case "Low":
            return "No strong scam indicators were detected, but remain cautious with unexpected requests and unfamiliar links.";
    }
}
//# sourceMappingURL=riskCalculator.js.map