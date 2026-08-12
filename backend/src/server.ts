import cors from "cors";
import dotenv from "dotenv";

import express, {
  NextFunction,
  Request,
  Response,
} from "express";

import analyzeRoutes from "./routes/analyzeRoutes.js";
import scanRoutes from "./routes/scanRoutes.js";
import statsRoutes from "./routes/statsRoutes.js";
import urlRoutes from "./routes/urlRoutes.js";

dotenv.config();

const app = express();

const port =
  Number(process.env.PORT) || 5000;

app.use(
  cors({
    origin:
      process.env.FRONTEND_URL ??
      "http://localhost:5173",
  }),
);

app.use(
  express.json({
    limit: "20kb",
  }),
);

app.get(
  "/",
  (_request: Request, response: Response) => {
    response.json({
      name: "Sentri API",
      version: "1.0.0",
      message:
        "Rule-based scam and suspicious-link detection backend.",
      endpoints: {
        health:
          "GET /api/health",
        analyzeMessage:
          "POST /api/analyze",
        analyzeUrl:
          "POST /api/analyze-url",
        scanHistory:
          "GET /api/scans",
        clearScanHistory:
          "DELETE /api/scans",
        dashboardStats:
          "GET /api/stats",
      },
    });
  },
);

app.get(
  "/api/health",
  (_request: Request, response: Response) => {
    response.json({
      status: "ok",
      service: "Sentri API",
      version: "1.0.0",
      message:
        "Sentri backend is running.",
    });
  },
);

app.use(
  "/api/analyze",
  analyzeRoutes,
);

app.use(
  "/api/analyze-url",
  urlRoutes,
);

app.use(
  "/api/scans",
  scanRoutes,
);

app.use(
  "/api/stats",
  statsRoutes,
);

app.use(
  (
    _request: Request,
    response: Response,
  ) => {
    response.status(404).json({
      error: "Route not found.",
    });
  },
);

app.use(
  (
    error: unknown,
    _request: Request,
    response: Response,
    _next: NextFunction,
  ) => {
    console.error(
      "Sentri Server Error:",
      error,
    );

    response.status(500).json({
      error:
        "An unexpected server error occurred.",
    });
  },
);

app.listen(port, () => {
  console.log("");
  console.log(
    "======================================",
  );
  console.log(
    "        SENTRI SECURITY API",
  );
  console.log(
    "======================================",
  );
  console.log(
    `Server:   http://localhost:${port}`,
  );
  console.log(
    `Health:   http://localhost:${port}/api/health`,
  );
  console.log(
    "Message:  POST /api/analyze",
  );
  console.log(
    "URL:      POST /api/analyze-url",
  );
  console.log(
    "History:  GET /api/scans",
  );
  console.log(
    "Clear:    DELETE /api/scans",
  );
  console.log(
    "Stats:    GET /api/stats",
  );
  console.log(
    "======================================",
  );
  console.log("");
});