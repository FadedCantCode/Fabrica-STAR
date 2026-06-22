export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** A single MCP server entry as found in a client config file. */
export interface McpServerEntry {
  /** The key/name this server is registered under in the config. */
  name: string;
  /** "stdio" servers run a local command; "http" servers are remote URLs. */
  transport: "stdio" | "http" | "unknown";
  /** Shell command for stdio servers (e.g. "npx"). */
  command?: string;
  /** Arguments passed to the command. */
  args?: string[];
  /** Remote URL for http/sse servers. */
  url?: string;
  /** Environment variables configured for this server. */
  env?: Record<string, string>;
  /** Raw source file this entry was parsed from, for reporting. */
  sourceFile: string;
}

/** A single finding produced by a rule against one server or file. */
export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  /** Server name or file path this finding applies to. */
  target: string;
  /** Optional line number, for source-code findings. */
  line?: number;
}

/** Aggregated result for one server: all findings plus a rolled-up score. */
export interface ServerReport {
  server: string;
  sourceFile: string;
  findings: Finding[];
  riskLevel: Severity;
}

export interface ScanResult {
  servers: ServerReport[];
  /** Findings not tied to a specific server, e.g. malformed config file. */
  generalFindings: Finding[];
}
