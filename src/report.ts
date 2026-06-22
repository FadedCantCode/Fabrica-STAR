import type { ScanResult, ServerReport, Severity } from "./types.js";

const COLOR = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

const SEVERITY_COLOR: Record<Severity, string> = {
  info: COLOR.dim,
  low: COLOR.cyan,
  medium: COLOR.yellow,
  high: COLOR.red,
  critical: COLOR.magenta,
};

const SEVERITY_ICON: Record<Severity, string> = {
  info: "✔",
  low: "✔",
  medium: "⚠",
  high: "✖",
  critical: "✖",
};

function colorize(text: string, severity: Severity): string {
  return `${SEVERITY_COLOR[severity]}${text}${COLOR.reset}`;
}

function formatServerBlock(report: ServerReport): string {
  const lines: string[] = [];
  const icon = SEVERITY_ICON[report.riskLevel];
  const label = report.riskLevel === "info" ? "clean" : report.riskLevel.toUpperCase();

  lines.push(colorize(`${icon} ${report.server} [${label}]`, report.riskLevel));
  lines.push(`${COLOR.dim}   source: ${report.sourceFile}${COLOR.reset}`);

  for (const finding of report.findings) {
    const location = finding.line ? `${finding.target}:${finding.line}` : finding.target;
    lines.push(`   ${colorize(`- [${finding.ruleId}]`, finding.severity)} ${finding.message}`);
    if (finding.line) lines.push(`     ${COLOR.dim}at ${location}${COLOR.reset}`);
  }

  return lines.join("\n");
}

export function formatTextReport(result: ScanResult): string {
  const sections: string[] = [];
  sections.push(`${COLOR.bold}mcp-sentinel scan results${COLOR.reset}`);
  sections.push("");

  if (result.servers.length === 0 && result.generalFindings.length === 0) {
    sections.push("No MCP servers found to scan.");
    return sections.join("\n");
  }

  for (const server of result.servers) {
    sections.push(formatServerBlock(server));
    sections.push("");
  }

  if (result.generalFindings.length > 0) {
    sections.push(`${COLOR.bold}General${COLOR.reset}`);
    for (const finding of result.generalFindings) {
      sections.push(`   ${colorize(`- [${finding.ruleId}]`, finding.severity)} ${finding.message}`);
    }
    sections.push("");
  }

  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const server of result.servers) counts[server.riskLevel]++;
  const clean = counts.info + counts.low;
  const summaryParts = [`${result.servers.length} server${result.servers.length === 1 ? "" : "s"} scanned`];
  if (clean > 0) summaryParts.push(`${clean} clean`);
  if (counts.medium > 0) summaryParts.push(colorize(`${counts.medium} medium`, "medium"));
  if (counts.high > 0) summaryParts.push(colorize(`${counts.high} high`, "high"));
  if (counts.critical > 0) summaryParts.push(colorize(`${counts.critical} critical`, "critical"));

  sections.push(`${COLOR.bold}Summary:${COLOR.reset} ${summaryParts.join(" · ")}`);

  return sections.join("\n");
}

export function formatJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatSourceReport(findings: import("./types.js").Finding[], rootDir: string): string {
  const sections: string[] = [];
  sections.push(`${COLOR.bold}mcp-sentinel source scan: ${rootDir}${COLOR.reset}`);
  sections.push("");

  if (findings.length === 0) {
    sections.push(colorize("✔ No risky patterns found.", "info"));
    return sections.join("\n");
  }

  const byFile = new Map<string, typeof findings>();
  for (const f of findings) {
    const list = byFile.get(f.target) ?? [];
    list.push(f);
    byFile.set(f.target, list);
  }

  for (const [file, fileFindings] of byFile) {
    sections.push(`${COLOR.bold}${file}${COLOR.reset}`);
    for (const f of fileFindings) {
      sections.push(`   ${colorize(`[${f.severity.toUpperCase()}] line ${f.line}: [${f.ruleId}]`, f.severity)} ${f.message}`);
    }
    sections.push("");
  }

  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity]++;
  const summaryParts = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => colorize(`${n} ${sev}`, sev as Severity));
  sections.push(`${COLOR.bold}Summary:${COLOR.reset} ${findings.length} finding${findings.length === 1 ? "" : "s"} (${summaryParts.join(" · ")})`);

  return sections.join("\n");
}
