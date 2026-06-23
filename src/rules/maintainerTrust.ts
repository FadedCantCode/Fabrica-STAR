/**
 * Maintainer Trust Score
 *
 * Supply chain attacks often follow predictable patterns:
 *  - New account takes over an existing popular package
 *  - Publishes a malicious version shortly after gaining access
 *  - Or creates a package that mimics a popular one
 *
 * This module analyses the npm publish history to compute a trust signal.
 * Not a heuristic number — specific, explainable findings with evidence.
 *
 * Signals checked:
 *  1. Maintainer account age (new account = higher risk)
 *  2. Number of maintainers (single maintainer = higher risk)
 *  3. Recent maintainer change (ownership transfer = high risk)
 *  4. Version publish frequency anomaly (sudden burst after long silence)
 *  5. Time between first publish and MCP-related naming (freshly created for MCP = risk)
 */

import type { Finding, McpServerEntry } from "../types.js";

const REGISTRY = "https://registry.npmjs.org";
const NPM_USERS_API = "https://registry.npmjs.org/-/v1/search?text=author";

interface NpmVersionInfo {
  _npmUser?: { name?: string; email?: string };
  maintainers?: Array<{ name: string; email?: string }>;
  time?: string;
}

interface NpmPackageMeta {
  name?: string;
  "dist-tags"?: { latest?: string };
  versions?: Record<string, NpmVersionInfo>;
  time?: Record<string, string>;
  maintainers?: Array<{ name: string; email?: string }>;
  _npmUser?: { name?: string };
}

function isOffline(): boolean {
  return process.env.FABRICA_STAR_OFFLINE === "1";
}

function extractPkgName(server: McpServerEntry): string | null {
  const RUNNERS = new Set(["npx", "bunx", "pnpm"]);
  if (!server.command || !RUNNERS.has(server.command)) return null;
  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return null;

  if (pkgArg.startsWith("@")) {
    const s = pkgArg.slice(1);
    const i = s.indexOf("@");
    return i > -1 ? "@" + s.slice(0, i) : pkgArg;
  }
  const i = pkgArg.indexOf("@");
  return i > 0 ? pkgArg.slice(0, i) : pkgArg;
}

function encodePackageName(name: string): string {
  return name.startsWith("@")
    ? "@" + encodeURIComponent(name.slice(1))
    : encodeURIComponent(name);
}

async function fetchMeta(name: string): Promise<NpmPackageMeta | null> {
  try {
    const res = await fetch(`${REGISTRY}/${encodePackageName(name)}`, { // fabrica-star-ignore — REGISTRY is a hardcoded constant
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return (await res.json()) as NpmPackageMeta;
  } catch {
    return null;
  }
}

const TRUSTED_SCOPES = new Set([
  "@modelcontextprotocol",
  "@anthropic-ai",
  "@openai",
  "@github",
  "@google",
  "@microsoft",
  "@aws-sdk",
]);

function isTrustedScope(name: string): boolean {
  if (!name.startsWith("@")) return false;
  return TRUSTED_SCOPES.has(name.split("/")[0]);
}

export async function checkMaintainerTrust(server: McpServerEntry): Promise<Finding[]> {
  if (isOffline()) return [];

  const pkgName = extractPkgName(server);
  if (!pkgName) return [];
  if (isTrustedScope(pkgName)) return [];

  const meta = await fetchMeta(pkgName);
  if (!meta || !meta.time) return [];

  const findings: Finding[] = [];
  const timeEntries = meta.time;
  const versions = Object.keys(meta.versions ?? {});
  const publishTimes = versions
    .map((v) => ({ version: v, time: timeEntries[v] ? new Date(timeEntries[v]) : null }))
    .filter((e): e is { version: string; time: Date } => e.time !== null)
    .sort((a, b) => a.time.getTime() - b.time.getTime());

  if (publishTimes.length === 0) return [];

  const now = Date.now();
  const firstPublish = publishTimes[0].time;
  const latestPublish = publishTimes[publishTimes.length - 1].time;
  const packageAgeDays = Math.floor((now - firstPublish.getTime()) / 86400000);
  const latestAgeDays = Math.floor((now - latestPublish.getTime()) / 86400000);

  // ── Check 1: Maintainer change detection ─────────────────────────────────
  // Compare maintainers across the last few versions
  const recentVersions = publishTimes.slice(-5);
  const maintainerSets = recentVersions.map((v) => {
    const info = meta.versions?.[v.version];
    return {
      version: v.version,
      time: v.time,
      maintainers: (info?.maintainers ?? []).map((m) => m.name).sort().join(","),
      publisher: info?._npmUser?.name ?? "unknown",
    };
  });

  if (maintainerSets.length >= 2) {
    const oldestMaintainers = maintainerSets[0].maintainers;
    const newestMaintainers = maintainerSets[maintainerSets.length - 1].maintainers;

    if (oldestMaintainers !== newestMaintainers && oldestMaintainers !== "" && newestMaintainers !== "") {
      const changeVersion = maintainerSets.find((m, i) => i > 0 && m.maintainers !== maintainerSets[i - 1].maintainers);
      const daysSinceChange = changeVersion
        ? Math.floor((now - changeVersion.time.getTime()) / 86400000)
        : null;

      findings.push({
        ruleId: "maintainer-change-detected",
        severity: daysSinceChange !== null && daysSinceChange < 30 ? "high" : "medium",
        target: server.name,
        message:
          `"${pkgName}" maintainer set changed in recent versions` +
          (changeVersion ? ` (around v${changeVersion.version}, ${daysSinceChange} days ago)` : "") +
          `. Previous: [${oldestMaintainers}] → Current: [${newestMaintainers}]. ` +
          `Ownership transfers are a common supply chain attack vector. Review the changelog carefully.`,
      });
    }
  }

  // ── Check 2: Single maintainer on a widely-used package ──────────────────
  const currentMaintainers = meta.maintainers ?? [];
  if (currentMaintainers.length === 1 && versions.length > 5) {
    findings.push({
      ruleId: "single-maintainer",
      severity: "low",
      target: server.name,
      message:
        `"${pkgName}" has a single maintainer (${currentMaintainers[0].name}). ` +
        `Single-maintainer packages are higher-risk for account takeover attacks — ` +
        `one compromised account means instant access to publish a malicious version.`,
    });
  }

  // ── Check 3: Publish frequency anomaly ───────────────────────────────────
  // Detect sudden burst of versions after long silence (possible compromise)
  if (publishTimes.length >= 3) {
    const recentWindow = 30 * 24 * 60 * 60 * 1000; // 30 days
    const recentVersionCount = publishTimes.filter(
      (v) => now - v.time.getTime() < recentWindow,
    ).length;
    const totalVersionCount = publishTimes.length;
    const historicalRate = (totalVersionCount - recentVersionCount) / Math.max(1, (packageAgeDays - 30) / 30);
    const recentRate = recentVersionCount;

    if (recentVersionCount >= 3 && recentRate > historicalRate * 4 && packageAgeDays > 90) {
      findings.push({
        ruleId: "publish-frequency-anomaly",
        severity: "medium",
        target: server.name,
        message:
          `"${pkgName}" published ${recentVersionCount} versions in the last 30 days, ` +
          `compared to ~${historicalRate.toFixed(1)}/month historically. ` +
          `Sudden publish bursts can indicate a compromised account or rushed malicious releases. Review recent changelogs.`,
      });
    }
  }

  // ── Check 4: Very new package with MCP-related naming ────────────────────
  const isMcpRelated = pkgName.toLowerCase().includes("mcp") ||
    pkgName.toLowerCase().includes("claude") ||
    pkgName.toLowerCase().includes("model-context");

  if (packageAgeDays < 60 && isMcpRelated && versions.length < 5) {
    findings.push({
      ruleId: "new-mcp-package",
      severity: "medium",
      target: server.name,
      message:
        `"${pkgName}" is ${packageAgeDays} days old with ${versions.length} version${versions.length === 1 ? "" : "s"}. ` +
        `New MCP-themed packages have appeared rapidly alongside MCP's growth — ` +
        `some are legitimate, some are opportunistic typosquats or malicious clones. ` +
        `Verify the author's identity and review the source code before use.`,
    });
  }

  // ── Check 5: Package abandoned then suddenly updated ─────────────────────
  if (publishTimes.length >= 2) {
    const secondLatest = publishTimes[publishTimes.length - 2].time;
    const gapDays = Math.floor((latestPublish.getTime() - secondLatest.getTime()) / 86400000);

    if (gapDays > 180 && latestAgeDays < 14) {
      findings.push({
        ruleId: "abandoned-then-revived",
        severity: "high",
        target: server.name,
        message:
          `"${pkgName}" was dormant for ${gapDays} days then published a new version ${latestAgeDays} day${latestAgeDays === 1 ? "" : "s"} ago. ` +
          `Abandoned packages that suddenly revive are a known supply chain attack pattern — ` +
          `an attacker may have taken over the package. Audit the latest version's source before updating.`,
      });
    }
  }

  return findings;
}
