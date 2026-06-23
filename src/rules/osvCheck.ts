/**
 * OSV (Open Source Vulnerabilities) checker.
 *
 * Queries https://api.osv.dev — a free, no-API-key database that aggregates
 * CVEs, GHSA advisories, and PYSEC entries across npm, PyPI, and more.
 * This runs network checks for known CVEs against packages in the config.
 */

import type { Finding, McpServerEntry } from "../types.js";

const OSV_API = "https://api.osv.dev/v1";

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type: string; score: string }>;
  aliases?: string[];
  affected?: Array<{
    ranges?: Array<{
      type: string;
      events?: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
}

interface OsvResponse {
  vulns?: OsvVuln[];
}

function extractPkgAndVersion(server: McpServerEntry): { name: string; version: string | null } | null {
  const RUNNERS = new Set(["npx", "bunx", "pnpm", "uvx", "pipx"]);
  if (!server.command || !RUNNERS.has(server.command)) return null;

  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return null;

  // npm: @scope/pkg@version or pkg@version
  if (server.command !== "uvx" && server.command !== "pipx") {
    if (pkgArg.startsWith("@")) {
      const withoutScope = pkgArg.slice(1);
      const atIdx = withoutScope.indexOf("@");
      if (atIdx > -1) {
        return { name: "@" + withoutScope.slice(0, atIdx), version: withoutScope.slice(atIdx + 1) };
      }
      return { name: pkgArg, version: null };
    }
    const atIdx = pkgArg.indexOf("@");
    if (atIdx > 0) {
      return { name: pkgArg.slice(0, atIdx), version: pkgArg.slice(atIdx + 1) };
    }
    return { name: pkgArg, version: null };
  }

  // Python: pkg==version or pkg>=version etc.
  const pyMatch = pkgArg.match(/^([A-Za-z0-9_.-]+)[=!<>~]+(.+)$/);
  if (pyMatch) return { name: pyMatch[1], version: pyMatch[2] };
  return { name: pkgArg, version: null };
}

function ecosystemFor(runner: string): string {
  return runner === "uvx" || runner === "pipx" ? "PyPI" : "npm";
}

async function queryOsv(name: string, version: string | null, ecosystem: string): Promise<OsvVuln[]> {
  const body: Record<string, unknown> = {
    package: { name, ecosystem },
  };
  if (version) body.version = version;

  try {
    const res = await fetch(`${OSV_API}/query`, { // fabrica-star-ignore — host is a hardcoded constant
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as OsvResponse;
    return data.vulns ?? [];
  } catch {
    return [];
  }
}

function highestCvss(vuln: OsvVuln): number {
  if (!vuln.severity) return 0;
  for (const s of vuln.severity) {
    if (s.type === "CVSS_V3") {
      const score = parseFloat(s.score);
      if (!isNaN(score)) return score;
    }
  }
  return 0;
}

function cvssToSeverity(score: number): Finding["severity"] {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

export async function checkOsvVulnerabilities(server: McpServerEntry): Promise<Finding[]> {
  if (process.env.FABRICA_STAR_OFFLINE === "1") return [];

  const pkg = extractPkgAndVersion(server);
  if (!pkg) return [];

  const ecosystem = ecosystemFor(server.command!);
  const vulns = await queryOsv(pkg.name, pkg.version, ecosystem);
  if (vulns.length === 0) return [];

  return vulns.slice(0, 5).map((vuln): Finding => {
    const cvss = highestCvss(vuln);
    const severity = cvss > 0 ? cvssToSeverity(cvss) : "high";
    const cveId = vuln.aliases?.find((a) => a.startsWith("CVE-")) ?? vuln.id;
    const scoreStr = cvss > 0 ? ` (CVSS ${cvss.toFixed(1)})` : "";
    return {
      ruleId: "osv-vulnerability",
      severity,
      target: server.name,
      message: `${pkg.name} has a known vulnerability: ${cveId}${scoreStr}. ${vuln.summary ?? "See OSV for details."}${pkg.version ? "" : " Pin a version to enable precise CVE matching."}`,
    };
  });
}
