import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import type { Severity } from "./types.js";

export interface KnownBadEntry {
  match: string;
  matchType: "name" | "command" | "url-contains";
  severity: Severity;
  reason: string;
}

interface KnownBadFile {
  version: number;
  entries: KnownBadEntry[];
}

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Loads the bundled known-flagged-servers.json. Path resolution accounts
 * for running from dist/ (published package) vs src/ (via tsx in dev).
 */
export function loadKnownBadList(): KnownBadEntry[] {
  const candidates = [
    join(__dirname, "..", "data", "known-flagged-servers.json"),
    join(__dirname, "..", "..", "data", "known-flagged-servers.json"),
  ];

  for (const path of candidates) {
    try {
      const raw = readFileSync(path, "utf-8");
      const parsed = JSON.parse(raw) as KnownBadFile;
      return parsed.entries.filter((e) => e.match !== "example-flagged-server");
    } catch {
      continue;
    }
  }
  return [];
}
