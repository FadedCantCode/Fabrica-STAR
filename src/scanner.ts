import type { Finding, ScanResult, ServerReport } from "./types.js";
import { parseConfigFile } from "./configParser.js";
import { runConfigRules } from "./rules/configRules.js";
import { rollUpSeverity } from "./scorer.js";

/**
 * Scans a list of MCP client config files and returns a full report.
 * Network calls (remote known-bad list fetch, npm registry checks) run
 * concurrently across all servers to keep total latency low.
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

    // Run all server checks concurrently within each config file
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
  }

  return { servers, generalFindings };
}
