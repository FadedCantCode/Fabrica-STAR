import type { Finding, ScanResult, ServerReport } from "./types.js";
import { parseConfigFile } from "./configParser.js";
import { runConfigRules } from "./rules/configRules.js";
import { analyzeCompoundBlastRadius } from "./rules/compoundBlastRadius.js";
import { rollUpSeverity } from "./scorer.js";

/**
 * Scans a list of MCP client config files and returns a full report.
 * Network calls run concurrently to keep latency low.
 * After per-server analysis, runs cross-server compound blast radius analysis.
 */
export async function scanConfigFiles(filePaths: string[]): Promise<ScanResult> {
  const servers: ServerReport[] = [];
  const generalFindings: Finding[] = [];

  for (const filePath of filePaths) {
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

    // Run all per-server checks concurrently
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
    // Runs after all individual server results are available
    const compoundFindings = analyzeCompoundBlastRadius(entries, results);
    if (compoundFindings.length > 0) {
      generalFindings.push(...compoundFindings);
    }
  }

  return { servers, generalFindings };
}
