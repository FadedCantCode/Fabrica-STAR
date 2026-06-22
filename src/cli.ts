#!/usr/bin/env node
import { Command } from "commander";
import { existsSync } from "node:fs";
import { discoverConfigFiles } from "./discovery.js";
import { scanConfigFiles } from "./scanner.js";
import { scanSourceTree } from "./rules/sourceScanner.js";
import { formatTextReport, formatJsonReport, formatSourceReport } from "./report.js";
import { isAtLeast, rollUpSeverity } from "./scorer.js";
import type { Severity } from "./types.js";

const VALID_SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function parseFailOn(value: string): Severity {
  if (!VALID_SEVERITIES.includes(value as Severity)) {
    throw new Error(`--fail-on must be one of: ${VALID_SEVERITIES.join(", ")}`);
  }
  return value as Severity;
}

const program = new Command();

program
  .name("fabrica-star")
  .description("Security scanner for Model Context Protocol (MCP) servers and client configs.")
  .version("0.1.0");

program
  .command("scan")
  .description("Auto-discover known MCP client configs (Claude Desktop, Claude Code, Cursor) and scan every configured server.")
  .option("--json", "output machine-readable JSON instead of a formatted report")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action((opts: { json?: boolean; failOn: Severity }) => {
    const files = discoverConfigFiles();
    const result = scanConfigFiles(files);
    console.log(opts.json ? formatJsonReport(result) : formatTextReport(result));

    const worst = rollUpSeverity(result.servers.flatMap((s) => s.findings));
    process.exitCode = isAtLeast(worst, opts.failOn) ? 1 : 0;
  });

program
  .command("scan-config <path>")
  .description("Scan a specific MCP client config file.")
  .option("--json", "output machine-readable JSON instead of a formatted report")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action((path: string, opts: { json?: boolean; failOn: Severity }) => {
    if (!existsSync(path)) {
      console.error(`No such file: ${path}`);
      process.exitCode = 2;
      return;
    }
    const result = scanConfigFiles([path]);
    console.log(opts.json ? formatJsonReport(result) : formatTextReport(result));

    const worst = rollUpSeverity(result.servers.flatMap((s) => s.findings));
    process.exitCode = isAtLeast(worst, opts.failOn) ? 1 : 0;
  });

program
  .command("scan-source <path>")
  .description("Statically scan an MCP server's source code for risky patterns (eval, shell injection, hardcoded secrets, etc).")
  .option("--json", "output machine-readable JSON instead of a formatted report")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action((path: string, opts: { json?: boolean; failOn: Severity }) => {
    if (!existsSync(path)) {
      console.error(`No such file or directory: ${path}`);
      process.exitCode = 2;
      return;
    }
    const findings = scanSourceTree(path);
    console.log(opts.json ? JSON.stringify(findings, null, 2) : formatSourceReport(findings, path));

    const worst = rollUpSeverity(findings);
    process.exitCode = isAtLeast(worst, opts.failOn) ? 1 : 0;
  });

program.parse();
