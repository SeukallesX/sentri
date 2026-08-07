import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import analyzeRoutes from "./routes/analyzeRoutes.js";
dotenv.config();
const app = express();
const port = Number(process.env.PORT) || 5000;
app.use(cors({
    origin: "http://localhost:5173",
}));
app.use(express.json({ limit: "20kb" }));
app.get("/", (_req, res) => {
    res.json({
        name: "Sentri API",
        version: "1.0.0",
        message: "Rule-based scam detection backend.",
    });
});
app.get("/api/health", (_req, res) => {
    res.json({
        status: "ok",
        message: "Sentri backend is running.",
    });
});
app.use("/api/analyze", analyzeRoutes);
app.use((_req, res) => {
    res.status(404).json({
        error: "Route not found.",
    });
});
app.use((err, _req, res, _next) => {
    console.error(err);
    res.status(500).json({
        error: "Internal Server Error",
    });
});
app.listen(port, () => {
    console.log(`🚀 Sentri backend running on http://localhost:${port}`);
});
//# sourceMappingURL=server.js.map