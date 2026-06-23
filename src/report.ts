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
  sections.push(`${COLOR.bold}fabrica-star scan results${COLOR.reset}`);
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
  sections.push(`${COLOR.bold}fabrica-star source scan: ${rootDir}${COLOR.reset}`);
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

// ── Permission Prompt format ───────────────────────────────────────────────

interface PermissionEntry {
  capability: string;
  detail: string;
  severity: Severity;
}

function buildPermissions(server: import("./types.js").ServerReport): PermissionEntry[] {
  const entries: PermissionEntry[] = [];
  for (const f of server.findings) {
    if (f.ruleId === "blast-radius-sensitive-files") {
      entries.push({ capability: "READ", detail: f.message.split("\n")[0].replace("This server has access to", "").trim(), severity: f.severity });
    } else if (f.ruleId === "unscoped-filesystem-access") {
      entries.push({ capability: "WRITE", detail: "full filesystem write access (root path configured)", severity: f.severity });
    } else if (f.ruleId === "insecure-transport" || f.ruleId === "insecure-transport-local") {
      const urlMatch = f.message.match(/\(([^)]{1,500})\)/);
      entries.push({ capability: "NETWORK", detail: urlMatch ? urlMatch[1] : "remote host", severity: f.severity });
    } else if (f.ruleId === "hardcoded-secret") {
      const keyMatch = f.message.match(/env var "([^"]{1,200})"/);
      entries.push({ capability: "EXPOSE", detail: keyMatch ? `${keyMatch[1]} (hardcoded credential)` : "hardcoded credential", severity: f.severity });
    } else if (f.ruleId === "osv-vulnerability") {
      entries.push({ capability: "CVE", detail: f.message.split(".")[0], severity: f.severity });
    } else if (f.ruleId === "known-flagged-server") {
      entries.push({ capability: "FLAGGED", detail: "matches known-malicious server list", severity: "critical" as Severity });
    } else if (f.ruleId === "prompt-injection-ignore" || f.ruleId === "prompt-injection-override" || f.ruleId === "tool-poisoning-must-call") {
      entries.push({ capability: "HIJACK", detail: "prompt injection pattern detected in source", severity: f.severity });
    }
  }
  return entries;
}

export function formatPermissionPromptReport(result: import("./types.js").ScanResult): string {
  const sections: string[] = [];
  sections.push(`${COLOR.bold}fabrica-star · permission audit${COLOR.reset}`);
  sections.push("");

  if (result.servers.length === 0) {
    sections.push("No MCP servers found.");
    return sections.join("\n");
  }

  for (const server of result.servers) {
    const icon = server.riskLevel === "info" ? "✔" : server.riskLevel === "medium" ? "⚠" : "✖";
    sections.push(colorize(`${icon} Compromise of "${server.server}" could:`, server.riskLevel));

    const perms = buildPermissions(server);
    if (perms.length === 0) {
      sections.push(`${COLOR.dim}   (no exploitable capabilities found)${COLOR.reset}`);
    } else {
      const maxCap = Math.max(...perms.map((p) => p.capability.length));
      for (const p of perms) {
        const pad = " ".repeat(maxCap - p.capability.length);
        sections.push(`   ${colorize(p.capability + pad, p.severity)}  ${p.detail}`);
      }
    }
    sections.push("");
  }

  return sections.join("\n");
}
