import { readFileSync } from "node:fs";
import type { Finding, ScanResult, ServerReport } from "./types.js";
import { parseConfigFile } from "./configParser.js";
import { runConfigRules } from "./rules/configRules.js";
import { analyzeCompoundBlastRadius } from "./rules/compoundBlastRadius.js";
import { checkRootConfig } from "./rules/rootConfigChecks.js";
import { rollUpSeverity } from "./scorer.js";

export async function scanConfigFiles(filePaths: string[]): Promise<ScanResult> {
  const servers: ServerReport[] = [];
  const generalFindings: Finding[] = [];

  for (const filePath of filePaths) {
    // Parse raw JSON for root-level checks (hooks, trust flags, etc.)
    let rawConfig: unknown = null;
    try {
      rawConfig = JSON.parse(readFileSync(filePath, "utf-8"));
    } catch { /* handled below */ }

    // Root-level config checks (enableAllProjectMcpServers, hooks, trust flags)
    if (rawConfig !== null) {
      generalFindings.push(...checkRootConfig(rawConfig, filePath));
    }

    // Per-server checks
    let entries;
    try {
      entries = parseConfigFile(filePath);
    } catch (err) {
      generalFindings.push({
        ruleId: "unparseable-config",
        severity: "low",
        target: filePath,
        message: `Could not parse as JSON: ${err instanceof Error ? err.message : String(err)}`,
      });
      continue;
    }

    const results = await Promise.all(
      entries.map(async (server) => {
        const findings = await runConfigRules(server);
        return {
          server: server.name,
          sourceFile: filePath,
          findings,
          riskLevel: rollUpSeverity(findings),
        } satisfies ServerReport;
      })
    );
    servers.push(...results);

    // Cross-server compound blast radius analysis
    const compoundFindings = analyzeCompoundBlastRadius(entries, results);
    if (compoundFindings.length > 0) {
      generalFindings.push(...compoundFindings);
    }
  }

  return { servers, generalFindings };
}
