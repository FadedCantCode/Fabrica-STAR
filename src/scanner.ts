import type { Finding, ScanResult, ServerReport } from "./types.js";
import { parseConfigFile } from "./configParser.js";
import { runConfigRules } from "./rules/configRules.js";
import { rollUpSeverity } from "./scorer.js";

/**
 * Scans a list of MCP client config files (already resolved to existing
 * paths) and returns a full report. A file that fails to parse produces a
 * general finding rather than aborting the whole scan, so one bad config
 * doesn't hide problems in the others.
 */
export function scanConfigFiles(filePaths: string[]): ScanResult {
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

    for (const server of entries) {
      const findings = runConfigRules(server);
      servers.push({
        server: server.name,
        sourceFile: filePath,
        findings,
        riskLevel: rollUpSeverity(findings),
      });
    }
  }

  return { servers, generalFindings };
}
