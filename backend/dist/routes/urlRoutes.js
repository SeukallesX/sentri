import { Router, } from "express";
import { analyzeUrlIntelligence, } from "../utils/urlAnalyzer.js";
import { calculateRiskScore, determineRiskLevel, getRecommendation, } from "../utils/riskCalculator.js";
import { classifyThreat, } from "../utils/threatClassifier.js";
import { correlateThreats, } from "../utils/threatCorrelation.js";
import { createSecurityEvent, } from "../services/securityEventService.js";
import { saveScan, } from "../services/scanService.js";
const router = Router();
router.post("/", (req, res) => {
    try {
        const url = typeof req.body?.url ===
            "string"
            ? req.body.url.trim()
            : "";
        if (!url) {
            return res
                .status(400)
                .json({
                error: "A URL is required for analysis.",
            });
        }
        if (url.length >
            2048) {
            return res
                .status(400)
                .json({
                error: "The URL is too long.",
            });
        }
        /*
         * ---------------------------------------
         * 1. CREATE SECURITY EVENT
         * ---------------------------------------
         */
        const securityEvent = createSecurityEvent({
            type: "url",
            content: url,
            metadata: {
                source: "user",
            },
        });
        /*
         * ---------------------------------------
         * 2. CREATE EVENT REFERENCE
         * ---------------------------------------
         */
        const eventReference = {
            id: securityEvent.id,
            type: securityEvent.type,
            timestamp: securityEvent
                .metadata
                .timestamp,
            source: securityEvent
                .metadata
                .source,
        };
        /*
         * ---------------------------------------
         * 3. URL INTELLIGENCE
         * ---------------------------------------
         */
        const analysis = analyzeUrlIntelligence(securityEvent.content);
        /*
         * ---------------------------------------
         * 4. RISK ANALYSIS
         * ---------------------------------------
         */
        const riskScore = calculateRiskScore(analysis.flags);
        const riskLevel = determineRiskLevel(riskScore);
        /*
         * ---------------------------------------
         * 5. THREAT CLASSIFICATION
         * ---------------------------------------
         */
        const classification = classifyThreat(analysis.flags);
        /*
         * ---------------------------------------
         * 6. THREAT CORRELATION
         * ---------------------------------------
         */
        const correlation = correlateThreats(analysis.flags);
        /*
         * ---------------------------------------
         * 7. SUMMARY
         * ---------------------------------------
         */
        const summary = analysis.flags.length ===
            0
            ? "Sentri did not detect any common suspicious URL indicators."
            : `Sentri detected ${analysis.flags.length} URL ${analysis.flags.length ===
                1
                ? "indicator"
                : "indicators"}.`;
        /*
         * ---------------------------------------
         * 8. COMPLETE RESULT
         * ---------------------------------------
         */
        const result = {
            riskScore,
            riskLevel,
            threatCategory: classification
                .threatCategory,
            confidence: classification
                .confidence,
            attackVector: classification
                .attackVector,
            correlatedThreat: correlation
                .correlatedThreat,
            correlationScore: correlation
                .correlationScore,
            matchedSignals: correlation
                .matchedSignals,
            correlationExplanation: correlation
                .explanation,
            flags: analysis.flags,
            summary,
            recommendation: getRecommendation(riskLevel),
            event: eventReference,
        };
        /*
         * ---------------------------------------
         * 9. SAVE SCAN
         * ---------------------------------------
         */
        saveScan("URL", analysis.intelligence
            ?.normalizedUrl ??
            securityEvent.content, result, eventReference);
        /*
         * ---------------------------------------
         * 10. API RESPONSE
         * ---------------------------------------
         */
        return res
            .status(200)
            .json({
            ...result,
            intelligence: analysis.intelligence,
        });
    }
    catch (error) {
        console.error("URL analysis failed:", error);
        return res
            .status(500)
            .json({
            error: "Unable to analyze the URL.",
        });
    }
});
export default router;
//# sourceMappingURL=urlRoutes.js.map