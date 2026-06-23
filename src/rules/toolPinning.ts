/**
 * Tool Pinning — Rug Pull Detection
 *
 * A "rug pull" is when a previously clean MCP server package is updated
 * with malicious code after gaining trust. The Postmark-mcp backdoor was
 * exactly this: clean for months, then v1.0.16 added a silent BCC to all emails.
 *
 * This module records the npm dist.shasum (cryptographic hash) of each package
 * at the time you first scan it. On subsequent scans, if the hash changes
 * without a corresponding version change in your config, it flags a rug pull.
 *
 * Storage: ~/.fabrica-star/pins.json
 * No live server connection required.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { Finding, McpServerEntry } from "../types.js";

const PINS_DIR = join(homedir(), ".fabrica-star");
const PINS_PATH = join(PINS_DIR, "pins.json");
const REGISTRY = "https://registry.npmjs.org";

interface PinEntry {
  name: string;
  version: string;
  shasum: string;
  pinnedAt: string;
  sourceFiles: string[];
}

interface PinStore {
  version: 1;
  pins: Record<string, PinEntry>; // key = "name@version"
}

interface NpmDist {
  shasum?: string;
  integrity?: string;
  tarball?: string;
}

interface NpmVersionInfo {
  dist?: NpmDist;
  version?: string;
}

interface NpmMeta {
  "dist-tags"?: { latest?: string };
  versions?: Record<string, NpmVersionInfo>;
}

function loadPins(): PinStore {
  try {
    const raw = readFileSync(PINS_PATH, "utf-8");
    const parsed = JSON.parse(raw) as PinStore;
    // Guard against malformed pins.json where pins is null/non-object
    if (!parsed || typeof parsed.pins !== "object" || parsed.pins === null) {
      return { version: 1, pins: {} };
    }
    return parsed;
  } catch {
    return { version: 1, pins: {} };
  }
}

function savePins(store: PinStore): void {
  try {
    mkdirSync(PINS_DIR, { recursive: true });
    writeFileSync(PINS_PATH, JSON.stringify(store, null, 2), "utf-8");
  } catch {
    // Non-fatal — pins are best-effort
  }
}

function isOffline(): boolean {
  return process.env.FABRICA_STAR_OFFLINE === "1";
}

function encodePackageName(name: string): string {
  return name.startsWith("@")
    ? "@" + encodeURIComponent(name.slice(1))
    : encodeURIComponent(name);
}

function extractPkgAndVersion(server: McpServerEntry): { name: string; version: string | null } | null {
  const RUNNERS = new Set(["npx", "bunx", "pnpm"]);
  if (!server.command || !RUNNERS.has(server.command)) return null;
  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return null;

  if (pkgArg.startsWith("@")) {
    const s = pkgArg.slice(1);
    const i = s.indexOf("@");
    return i > -1
      ? { name: "@" + s.slice(0, i), version: s.slice(i + 1) }
      : { name: pkgArg, version: null };
  }
  const i = pkgArg.indexOf("@");
  return i > 0
    ? { name: pkgArg.slice(0, i), version: pkgArg.slice(i + 1) }
    : { name: pkgArg, version: null };
}

const TRUSTED_SCOPES = new Set([
  "@modelcontextprotocol",
  "@anthropic-ai",
  "@openai",
  "@github",
  "@google",
  "@microsoft",
]);

function isTrustedScope(name: string): boolean {
  if (!name.startsWith("@")) return false;
  return TRUSTED_SCOPES.has(name.split("/")[0]);
}

async function fetchDistInfo(name: string, version: string): Promise<{ shasum: string; integrity: string } | null> {
  try {
    const res = await fetch(
      `${REGISTRY}/${encodePackageName(name)}/${encodeURIComponent(version)}`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as NpmVersionInfo;
    if (!data.dist?.shasum) return null;
    return {
      shasum: data.dist.shasum,
      integrity: data.dist.integrity ?? "",
    };
  } catch {
    return null;
  }
}

async function resolveLatestVersion(name: string): Promise<string | null> {
  try {
    const res = await fetch(
      `${REGISTRY}/${encodePackageName(name)}/latest`,
      { signal: AbortSignal.timeout(5000) }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as NpmVersionInfo;
    return data.version ?? null;
  } catch {
    return null;
  }
}

export async function checkToolPin(server: McpServerEntry): Promise<Finding[]> {
  if (isOffline()) return [];

  const pkg = extractPkgAndVersion(server);
  if (!pkg) return [];
  if (isTrustedScope(pkg.name)) return [];

  const store = loadPins();

  // Resolve version
  const resolvedVersion = pkg.version ?? await resolveLatestVersion(pkg.name);
  if (!resolvedVersion) return [];

  const pinKey = `${pkg.name}@${resolvedVersion}`;
  const dist = await fetchDistInfo(pkg.name, resolvedVersion);
  if (!dist) return [];

  const existing = store.pins[pinKey];

  if (!existing) {
    // First time seeing this package — record the pin
    store.pins[pinKey] = {
      name: pkg.name,
      version: resolvedVersion,
      shasum: dist.shasum,
      pinnedAt: new Date().toISOString(),
      sourceFiles: [],
    };
    savePins(store);

    return [
      {
        ruleId: "tool-pin-recorded",
        severity: "info",
        target: server.name,
        message: `"${pkg.name}@${resolvedVersion}" pinned. Shasum: ${dist.shasum.slice(0, 16)}... — future scans will detect if this package changes.`,
      },
    ];
  }

  // Check if shasum changed for the same version — this is a rug pull
  if (existing.shasum !== dist.shasum) {
    return [
      {
        ruleId: "tool-pin-mismatch",
        severity: "critical",
        target: server.name,
        message:
          `RUG PULL DETECTED: "${pkg.name}@${resolvedVersion}" shasum changed since last scan.\n` +
          `  Previously recorded: ${existing.shasum.slice(0, 16)}... (pinned ${existing.pinnedAt.slice(0, 10)})\n` +
          `  Current:             ${dist.shasum.slice(0, 16)}...\n` +
          `  The package content changed without a version bump. This is the exact pattern used in supply chain attacks like Postmark-mcp. Do NOT run this server until you have audited the source.`,
      },
    ];
  }

  // Shasum matches — still clean
  return [];
}

/**
 * CLI command: fabrica-star pin
 * Pins all packages in discovered configs. Run this after auditing servers you trust.
 */
export async function pinAllServers(servers: McpServerEntry[]): Promise<void> {
  const store = loadPins();
  let pinned = 0;
  let skipped = 0;

  for (const server of servers) {
    const pkg = extractPkgAndVersion(server);
    if (!pkg || isTrustedScope(pkg.name)) { skipped++; continue; }

    const resolvedVersion = pkg.version ?? await resolveLatestVersion(pkg.name);
    if (!resolvedVersion) { skipped++; continue; }

    const pinKey = `${pkg.name}@${resolvedVersion}`;
    if (store.pins[pinKey]) { skipped++; continue; }

    const dist = await fetchDistInfo(pkg.name, resolvedVersion);
    if (!dist) { skipped++; continue; }

    store.pins[pinKey] = {
      name: pkg.name,
      version: resolvedVersion,
      shasum: dist.shasum,
      pinnedAt: new Date().toISOString(),
      sourceFiles: [],
    };
    console.log(`  ✔ pinned ${pkg.name}@${resolvedVersion} (${dist.shasum.slice(0, 16)}...)`);
    pinned++;
  }

  savePins(store);
  console.log(`\nPinned ${pinned} package${pinned === 1 ? "" : "s"}, skipped ${skipped} (trusted scope or already pinned).`);
  console.log(`Pin store: ${PINS_PATH}`);
}

export function listPins(): PinEntry[] {
  return Object.values(loadPins().pins);
}

export function clearPin(pkgAtVersion: string): boolean {
  const store = loadPins();
  if (!store.pins[pkgAtVersion]) return false;
  delete store.pins[pkgAtVersion];
  savePins(store);
  return true;
}
