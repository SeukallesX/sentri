import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
const currentFilePath = fileURLToPath(import.meta.url);
const currentDirectory = dirname(currentFilePath);
const dataDirectory = join(currentDirectory, "../../data");
mkdirSync(dataDirectory, {
    recursive: true,
});
const databasePath = join(dataDirectory, "sentri.db");
export const database = new DatabaseSync(databasePath);
database.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL
      CHECK(type IN ('Message', 'URL')),

    content TEXT NOT NULL,

    risk_score INTEGER NOT NULL,

    risk_level TEXT NOT NULL
      CHECK(risk_level IN ('Low', 'Medium', 'High')),

    summary TEXT NOT NULL,

    recommendation TEXT NOT NULL,

    flags_json TEXT NOT NULL,

    created_at TEXT NOT NULL
  );
`);
console.log(`Sentri database connected: ${databasePath}`);
//# sourceMappingURL=database.js.map