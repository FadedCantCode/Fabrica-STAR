#!/usr/bin/env node
import { Command } from "commander";
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { discoverConfigFiles } from "./discovery.js";
import { scanConfigFiles } from "./scanner.js";
import { scanSourceTree } from "./rules/sourceScanner.js";
import { formatTextReport, formatJsonReport, formatSourceReport } from "./report.js";
import { isAtLeast, rollUpSeverity } from "./scorer.js";
import type { Severity } from "./types.js";

const REPO = "FadedCantCode/Fabrica-STAR";
const VALID_SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

function parseFailOn(value: string): Severity {
  if (!VALID_SEVERITIES.includes(value as Severity)) {
    throw new Error(`--fail-on must be one of: ${VALID_SEVERITIES.join(", ")}`);
  }
  return value as Severity;
}

function openBrowser(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "darwin" ? ["open", [url]] :
    process.platform === "win32"  ? ["cmd", ["/c", "start", "", url]] :
                                    ["xdg-open", [url]];
  execFile(cmd, args, { stdio: "ignore" } as never, () => {
    // Silently ignore errors — the URL is always printed below as a fallback.
  });
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
  .option("--offline", "skip remote known-bad list fetch and npm registry checks")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action(async (opts: { json?: boolean; offline?: boolean; failOn: Severity }) => {
    if (opts.offline) process.env.FABRICA_STAR_OFFLINE = "1";
    const files = discoverConfigFiles();
    const result = await scanConfigFiles(files);
    console.log(opts.json ? formatJsonReport(result) : formatTextReport(result));
    const worst = rollUpSeverity(result.servers.flatMap((s) => s.findings));
    process.exitCode = isAtLeast(worst, opts.failOn) ? 1 : 0;
  });

program
  .command("scan-config <path>")
  .description("Scan a specific MCP client config file.")
  .option("--json", "output machine-readable JSON instead of a formatted report")
  .option("--offline", "skip remote known-bad list fetch and npm registry checks")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action(async (path: string, opts: { json?: boolean; offline?: boolean; failOn: Severity }) => {
    if (!existsSync(path)) {
      console.error(`No such file: ${path}`);
      process.exitCode = 2;
      return;
    }
    if (opts.offline) process.env.FABRICA_STAR_OFFLINE = "1";
    const result = await scanConfigFiles([path]);
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

program
  .command("report <server-or-package>")
  .description("Open a pre-filled GitHub issue to flag a suspicious or malicious MCP server.")
  .option("--severity <severity>", "suggested severity (low, medium, high, critical)", "high")
  .action((target: string, opts: { severity: string }) => {
    const title = `Flag: ${target}`;
    const body = [
      `## Server / package`,
      `\`${target}\``,
      ``,
      `## Suggested severity`,
      opts.severity,
      ``,
      `## Why this should be flagged`,
      `<!-- Link to a CVE, security advisory, GitHub issue, or writeup. -->`,
      `<!-- Entries without a verifiable public source will be asked for one before merge. -->`,
      ``,
      `## Evidence / source`,
      ``,
      `## Steps to reproduce (optional)`,
      ``,
    ].join("\n");

    const url =
      `https://github.com/${REPO}/issues/new` +
      `?title=${encodeURIComponent(title)}` +
      `&body=${encodeURIComponent(body)}` +
      `&labels=flagged-server`;

    console.log(`\nOpening contribution form for "${target}"...`);
    console.log(`\nIf your browser did not open, paste this URL manually:\n${url}\n`);
    openBrowser(url);
  });

program.parseAsync();
