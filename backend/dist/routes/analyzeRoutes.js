import { Router } from "express";
import { analyzeMessage } from "../services/scamAnalyzer.js";
import { saveScan } from "../services/scanService.js";
const router = Router();
router.post("/", (request, response) => {
    const message = request.body?.message;
    if (typeof message !== "string" ||
        message.trim().length === 0) {
        return response.status(400).json({
            error: "Please provide a message to analyze.",
        });
    }
    if (message.length > 10_000) {
        return response.status(400).json({
            error: "The message must be fewer than 10,000 characters.",
        });
    }
    const cleanedMessage = message.trim();
    const result = analyzeMessage(cleanedMessage);
    saveScan("Message", cleanedMessage, result);
    return response.status(200).json(result);
});
export default router;
//# sourceMappingURL=analyzeRoutes.js.map