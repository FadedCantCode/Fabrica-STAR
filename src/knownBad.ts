import { readFileSync, writeFileSync, mkdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
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

const REMOTE_URL =
  "https://raw.githubusercontent.com/FadedCantCode/Fabrica-STAR/main/data/known-flagged-servers.json";
const CACHE_DIR = join(homedir(), ".fabrica-star");
const CACHE_PATH = join(CACHE_DIR, "known-flagged-servers.json");
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

function parseEntries(raw: string): KnownBadEntry[] {
  const parsed = JSON.parse(raw) as unknown;

  // Validate top-level shape before trusting any fetched data.
  if (typeof parsed !== "object" || parsed === null) throw new Error("expected object");
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.version !== "number") throw new Error("missing version field");
  if (!Array.isArray(obj.entries)) throw new Error("missing entries array");

  return (obj.entries as unknown[]).filter((e): e is KnownBadEntry => {
    if (typeof e !== "object" || e === null) return false;
    const entry = e as Record<string, unknown>;
    return (
      typeof entry.match === "string" && entry.match.length > 0 &&
      typeof entry.severity === "string" &&
      ["info", "low", "medium", "high", "critical"].includes(entry.severity) &&
      typeof entry.reason === "string" &&
      entry.match !== "example-flagged-server"
    );
  });
}

function loadBundled(): KnownBadEntry[] {
  const candidates = [
    join(__dirname, "..", "data", "known-flagged-servers.json"),
    join(__dirname, "..", "..", "data", "known-flagged-servers.json"),
  ];
  for (const path of candidates) {
    try {
      return parseEntries(readFileSync(path, "utf-8"));
    } catch {
      continue;
    }
  }
  return [];
}

function loadCached(): KnownBadEntry[] | null {
  try {
    const stat = statSync(CACHE_PATH);
    const ageMs = Date.now() - stat.mtimeMs;
    if (ageMs > CACHE_TTL_MS) return null; // stale
    return parseEntries(readFileSync(CACHE_PATH, "utf-8"));
  } catch {
    return null;
  }
}

function isOffline() { return process.env.FABRICA_STAR_OFFLINE === "1"; }

async function fetchRemote(): Promise<KnownBadEntry[] | null> {
  try {
    const res = await fetch(REMOTE_URL, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) return null;
    const raw = await res.text();
    const entries = parseEntries(raw);
    // Persist to cache
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(CACHE_PATH, raw, "utf-8");
    return entries;
  } catch {
    return null;
  }
}

/**
 * Returns the known-bad list, preferring a fresh remote copy over the cache
 * and the cache over the bundled fallback. Network failures are silent — the
 * tool works offline, just without the latest additions.
 */
export async function loadKnownBadList(): Promise<KnownBadEntry[]> {
  if (isOffline()) return loadBundled();
  const cached = loadCached();
  if (cached) return cached;

  const remote = await fetchRemote();
  if (remote) return remote;

  return loadBundled();
}
