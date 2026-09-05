// @ts-ignore Node.js type declarations are not available in this project.
import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";

// @ts-ignore Node.js type declarations are not available in this project.
import {
  dirname,
  join,
} from "node:path";

type StoredScan = Record<string, unknown>;

/*
 * ---------------------------------------
 * STORAGE LOCATION
 * ---------------------------------------
 */

const currentFile =
  decodeURIComponent(
    new URL(
      import.meta.url,
    ).pathname,
  ).replace(
    /^\/([A-Za-z]:)/,
    "$1",
  );

const currentDirectory =
  dirname(
    currentFile,
  );

const DATA_DIRECTORY =
  join(
    currentDirectory,
    "../../data",
  );

const SCAN_FILE =
  join(
    DATA_DIRECTORY,
    "scans.json",
  );

/*
 * ---------------------------------------
 * ENSURE STORAGE EXISTS
 * ---------------------------------------
 */

function ensureStorage():
  void {
  if (
    !existsSync(
      DATA_DIRECTORY,
    )
  ) {
    mkdirSync(
      DATA_DIRECTORY,
      {
        recursive: true,
      },
    );
  }

  if (
    !existsSync(
      SCAN_FILE,
    )
  ) {
    writeFileSync(
      SCAN_FILE,
      "[]",
      "utf-8",
    );
  }
}

/*
 * ---------------------------------------
 * LOAD SCANS
 * ---------------------------------------
 */

export function loadScans():
  StoredScan[] {
  try {
    ensureStorage();

    const rawData =
      readFileSync(
        SCAN_FILE,
        "utf-8",
      );

    const parsed =
      JSON.parse(
        rawData,
      );

    if (
      !Array.isArray(
        parsed,
      )
    ) {
      console.warn(
        "[SENTRI] Invalid scan storage format. Resetting archive.",
      );

      return [];
    }

    return parsed as StoredScan[];
  } catch (
    error
  ) {
    console.error(
      "[SENTRI] Unable to load scan archive:",
      error,
    );

    return [];
  }
}

/*
 * ---------------------------------------
 * WRITE SCANS
 * ---------------------------------------
 */

export function writeScans(
  scans: StoredScan[],
): void {
  try {
    ensureStorage();

    writeFileSync(
      SCAN_FILE,
      JSON.stringify(
        scans,
        null,
        2,
      ),
      "utf-8",
    );
  } catch (
    error
  ) {
    console.error(
      "[SENTRI] Unable to save scan archive:",
      error,
    );

    throw new Error(
      "Unable to persist scan archive.",
    );
  }
}