import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const currentFilePath =
  fileURLToPath(import.meta.url);

const currentDirectory =
  dirname(currentFilePath);

const dataDirectory =
  join(
    currentDirectory,
    "../../data",
  );

mkdirSync(
  dataDirectory,
  {
    recursive: true,
  },
);

const databasePath =
  join(
    dataDirectory,
    "sentri.db",
  );

export const database =
  new DatabaseSync(
    databasePath,
  );

/*
 * ---------------------------------------
 * HELPERS
 * ---------------------------------------
 */

interface TableColumn {
  cid: number;
  name: string;
  type: string;
  notnull: number;
  dflt_value: unknown;
  pk: number;
}

function getTableColumns(
  tableName: string,
): string[] {
  const statement =
    database.prepare(
      `PRAGMA table_info(${tableName})`,
    );

  const rows =
    statement.all() as unknown as TableColumn[];

  return rows.map(
    (row) => row.name,
  );
}

function addColumnIfMissing(
  tableName: string,
  columnName: string,
  definition: string,
): void {
  const columns =
    getTableColumns(
      tableName,
    );

  if (
    columns.includes(
      columnName,
    )
  ) {
    return;
  }

  database.exec(
    `
      ALTER TABLE ${tableName}
      ADD COLUMN ${columnName} ${definition};
    `,
  );

  console.log(
    `[SENTRI DB] Added column ${tableName}.${columnName}`,
  );
}

/*
 * ---------------------------------------
 * SECURITY EVENTS TABLE
 * ---------------------------------------
 */

database.exec(`
  CREATE TABLE IF NOT EXISTS security_events (
    id TEXT PRIMARY KEY,

    type TEXT NOT NULL,

    source TEXT NOT NULL,

    content TEXT NOT NULL,

    timestamp TEXT NOT NULL,

    metadata_json TEXT NOT NULL,

    created_at TEXT NOT NULL
  );
`);

/*
 * ---------------------------------------
 * SCANS TABLE
 * ---------------------------------------
 */

database.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,

    event_id TEXT,

    type TEXT NOT NULL
      CHECK(type IN ('Message', 'URL')),

    content TEXT NOT NULL,

    risk_score INTEGER NOT NULL,

    risk_level TEXT NOT NULL
      CHECK(risk_level IN ('Low', 'Medium', 'High')),

    threat_category TEXT,

    confidence INTEGER,

    attack_vector TEXT,

    correlated_threat TEXT,

    correlation_score INTEGER,

    matched_signals_json TEXT,

    correlation_explanation TEXT,

    summary TEXT NOT NULL,

    recommendation TEXT NOT NULL,

    flags_json TEXT NOT NULL,

    created_at TEXT NOT NULL,

    FOREIGN KEY(event_id)
      REFERENCES security_events(id)
      ON DELETE SET NULL
  );
`);

/*
 * ---------------------------------------
 * MIGRATE EXISTING SCANS TABLE
 * ---------------------------------------
 *
 * If Sentri already has an older scans
 * table, CREATE TABLE IF NOT EXISTS will
 * not add new columns.
 *
 * These checks safely add them without
 * deleting existing scan history.
 */

addColumnIfMissing(
  "scans",
  "event_id",
  "TEXT",
);

addColumnIfMissing(
  "scans",
  "threat_category",
  "TEXT",
);

addColumnIfMissing(
  "scans",
  "confidence",
  "INTEGER",
);

addColumnIfMissing(
  "scans",
  "attack_vector",
  "TEXT",
);

addColumnIfMissing(
  "scans",
  "correlated_threat",
  "TEXT",
);

addColumnIfMissing(
  "scans",
  "correlation_score",
  "INTEGER",
);

addColumnIfMissing(
  "scans",
  "matched_signals_json",
  "TEXT",
);

addColumnIfMissing(
  "scans",
  "correlation_explanation",
  "TEXT",
);

/*
 * ---------------------------------------
 * INDEXES
 * ---------------------------------------
 */

database.exec(`
  CREATE INDEX IF NOT EXISTS
    idx_scans_created_at
  ON scans(created_at);
`);

database.exec(`
  CREATE INDEX IF NOT EXISTS
    idx_scans_event_id
  ON scans(event_id);
`);

database.exec(`
  CREATE INDEX IF NOT EXISTS
    idx_security_events_timestamp
  ON security_events(timestamp);
`);

console.log(
  `Sentri database connected: ${databasePath}`,
);