import type { Finding, McpServerEntry } from "../types.js";

const REGISTRY_URL = "https://registry.npmjs.org";

// Well-known MCP publishers whose packages should not be flagged for being new
const TRUSTED_SCOPES = new Set([
  "@modelcontextprotocol",
  "@anthropic-ai",
  "@openai",
  "@github",
  "@google",
  "@microsoft",
  "@aws-sdk",
]);

// Known-good package name prefixes — substring match, not exact
const TRUSTED_PREFIXES = ["@modelcontextprotocol/"];

// Popular MCP package names that typosquatters might clone
const POPULAR_NAMES = [
  "mcp-server-filesystem",
  "mcp-server-github",
  "mcp-server-fetch",
  "mcp-server-git",
  "mcp-server-slack",
  "mcp-remote",
  "server-filesystem",
  "server-github",
  "server-fetch",
];

interface NpmMeta {
  weeklyDownloads: number;
  publishedDaysAgo: number;
  isScoped: boolean;
  scope: string | null;
  packageName: string;
}

function isTrustedScope(pkg: string): boolean {
  if (TRUSTED_PREFIXES.some((p) => pkg.startsWith(p))) return true;
  if (!pkg.startsWith("@")) return false;
  const scope = pkg.split("/")[0];
  return TRUSTED_SCOPES.has(scope);
}

/** Levenshtein distance — used for typosquat detection */
function editDistance(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function looksLikeTyposquat(pkg: string): string | null {
  // Strip scope for comparison
  const bare = pkg.startsWith("@") ? pkg.split("/").slice(1).join("/") : pkg;
  for (const popular of POPULAR_NAMES) {
    const dist = editDistance(bare.toLowerCase(), popular.toLowerCase());
    if (dist > 0 && dist <= 2 && bare !== popular) {
      return popular;
    }
  }
  return null;
}

/** Validates that a string looks like a real npm package name before using it in a URL */
function isValidNpmPackageName(pkg: string): boolean {
  // npm package names: lowercase, alphanumeric, hyphens, dots, underscores, scoped (@scope/name)
  return /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(pkg) && pkg.length <= 214;
}

async function fetchNpmMeta(pkg: string): Promise<NpmMeta | null> {
  if (!isValidNpmPackageName(pkg)) return null; // refuse to build URLs from invalid names
  try {
    const encoded = pkg.startsWith("@") ? pkg.replace("/", "%2F") : pkg;
    const res = await fetch(`${REGISTRY_URL}/${encoded}`, { // fabrica-star-ignore — host is a hardcoded constant
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;

    const data = (await res.json()) as Record<string, unknown>;
    const times = data.time as Record<string, string> | undefined;
    const created = times?.created ? new Date(times.created) : null;
    const publishedDaysAgo = created
      ? Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24))
      : 9999;

    // Fetch weekly download count from the downloads API
    let weeklyDownloads = 0;
    try {
      const dlRes = await fetch(
        `https://api.npmjs.org/downloads/point/last-week/${encoded}`,
        { signal: AbortSignal.timeout(3000) }
      );
      if (dlRes.ok) {
        const dlData = (await dlRes.json()) as { downloads?: number };
        weeklyDownloads = dlData.downloads ?? 0;
      }
    } catch {
      // downloads API is best-effort
    }

    const isScoped = pkg.startsWith("@");
    const scope = isScoped ? pkg.split("/")[0] : null;

    return { weeklyDownloads, publishedDaysAgo, isScoped, scope, packageName: pkg };
  } catch {
    return null;
  }
}

function extractPackageName(server: McpServerEntry): string | null {
  const RUNNERS = new Set(["npx", "bunx", "pnpm", "uvx"]);
  if (!server.command || !RUNNERS.has(server.command)) return null;
  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return null;
  // Strip version pin for lookup
  if (pkgArg.startsWith("@")) {
    const withoutScope = pkgArg.slice(1);
    const atIdx = withoutScope.indexOf("@");
    return atIdx > -1 ? "@" + withoutScope.slice(0, atIdx) : pkgArg;
  }
  const atIdx = pkgArg.indexOf("@");
  return atIdx > 0 ? pkgArg.slice(0, atIdx) : pkgArg;
}

export async function checkNpmHeuristics(server: McpServerEntry): Promise<Finding[]> {
  const pkg = extractPackageName(server);
  if (!pkg) return [];

  const findings: Finding[] = [];

  // Typosquat check — local, no network needed, always runs
  const squatTarget = looksLikeTyposquat(pkg);
  if (squatTarget) {
    findings.push({
      ruleId: "npm-typosquat",
      severity: "high",
      target: server.name,
      message: `"${pkg}" is 1-2 characters away from the popular package "${squatTarget}". This is a common typosquatting pattern — verify this is the package you intended to install.`,
    });
  }

  // Skip network checks in offline mode
  if (process.env.FABRICA_STAR_OFFLINE === "1") return findings;

  // Network-based checks
  const meta = await fetchNpmMeta(pkg);
  if (!meta) return findings; // registry unreachable — skip silently

  const trusted = isTrustedScope(pkg);

  if (!trusted && meta.publishedDaysAgo < 30) {
    findings.push({
      ruleId: "npm-very-new-package",
      severity: "medium",
      target: server.name,
      message: `"${pkg}" was published to npm ${meta.publishedDaysAgo} day${meta.publishedDaysAgo === 1 ? "" : "s"} ago. Very new packages have had less community review time. Verify the publisher before running this with agent access.`,
    });
  }

  if (!trusted && meta.weeklyDownloads < 100 && meta.publishedDaysAgo > 14) {
    findings.push({
      ruleId: "npm-low-download-count",
      severity: "low",
      target: server.name,
      message: `"${pkg}" has fewer than 100 weekly downloads. Low-traffic packages receive less community scrutiny. This isn't a red flag on its own, but factor it into your trust assessment.`,
    });
  }

  return findings;
}
