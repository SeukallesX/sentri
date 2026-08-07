import cors from "cors";
import dotenv from "dotenv";
import express, {
  NextFunction,
  Request,
  Response,
} from "express";

import analyzeRoutes from "./routes/analyzeRoutes.js";
import urlRoutes from "./routes/urlRoutes.js";

dotenv.config();

const app = express();

const port = Number(process.env.PORT) || 5000;

app.use(
  cors({
    origin: "http://localhost:5173",
  }),
);

app.use(
  express.json({
    limit: "20kb",
  }),
);

// Root route
app.get("/", (_req: Request, res: Response) => {
  res.json({
    name: "Sentri API",
    version: "1.0.0",
    message: "Rule-based scam detection backend.",
  });
});

// Health check
app.get("/api/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    message: "Sentri backend is running.",
  });
});

// Message analysis
app.use("/api/analyze", analyzeRoutes);

// URL analysis
app.use("/api/analyze-url", urlRoutes);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: "Route not found.",
  });
});

// Global error handler
app.use(
  (
    error: unknown,
    _req: Request,
    res: Response,
    _next: NextFunction,
  ) => {
    console.error("Sentri Server Error:", error);

    res.status(500).json({
      error: "An unexpected server error occurred.",
    });
  },
);

app.listen(port, () => {
  console.log("");
  console.log("======================================");
  console.log("        SENTRI SECURITY API");
  console.log("======================================");
  console.log(`Server:  http://localhost:${port}`);
  console.log(`Health:  http://localhost:${port}/api/health`);
  console.log(`Message: POST /api/analyze`);
  console.log(`URL:     POST /api/analyze-url`);
  console.log("======================================");
  console.log("");
});