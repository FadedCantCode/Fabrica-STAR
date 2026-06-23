#!/usr/bin/env node
import { Command } from "commander";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { execFile } from "node:child_process";
import { join } from "node:path";
import { discoverConfigFiles } from "./discovery.js";
import { scanConfigFiles } from "./scanner.js";
import { scanSourceTree } from "./rules/sourceScanner.js";
import { formatTextReport, formatJsonReport, formatSourceReport, formatPermissionPromptReport } from "./report.js";
import { formatSarifReport } from "./sarif.js";
import { isAtLeast, rollUpSeverity } from "./scorer.js";
import { loadPolicy } from "./policy.js";
import type { Severity } from "./types.js";

const REPO = "FadedCantCode/Fabrica-STAR";
const VALID_SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];
const VALID_FORMATS = ["text", "json", "sarif", "permissions"] as const;
type OutputFormat = typeof VALID_FORMATS[number];

function parseFailOn(value: string): Severity {
  if (!VALID_SEVERITIES.includes(value as Severity)) {
    throw new Error(`--fail-on must be one of: ${VALID_SEVERITIES.join(", ")}`);
  }
  return value as Severity;
}

function parseFormat(value: string): OutputFormat {
  if (!VALID_FORMATS.includes(value as OutputFormat)) {
    throw new Error(`--format must be one of: ${VALID_FORMATS.join(", ")}`);
  }
  return value as OutputFormat;
}

function openBrowser(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "darwin" ? ["open", [url]] :
    process.platform === "win32"  ? ["cmd", ["/c", "start", "", url]] :
                                    ["xdg-open", [url]];
  execFile(cmd, args, { stdio: "ignore" } as never, () => {});
}

function formatOutput(result: import("./types.js").ScanResult, fmt: OutputFormat): string {
  if (fmt === "sarif") return formatSarifReport(result);
  if (fmt === "json") return formatJsonReport(result);
  if (fmt === "permissions") return formatPermissionPromptReport(result);
  return formatTextReport(result);
}

const program = new Command();

program
  .name("fabrica-star")
  .description("Security scanner for Model Context Protocol (MCP) servers and client configs.")
  .version("0.1.4");

// ── scan ──────────────────────────────────────────────────────────────────
program
  .command("scan")
  .description("Auto-discover MCP client configs (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Zed, Warp) and scan every configured server.")
  .option("--format <format>", "output format: text, json, sarif, permissions", parseFormat, "text" as OutputFormat)
  .option("--json", "shorthand for --format json")
  .option("--offline", "skip network checks (OSV, npm registry, remote blocklist)")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .option("--no-policy", "ignore .fabrica-star.yml policy file")
  .action(async (opts: { format: OutputFormat; json?: boolean; offline?: boolean; failOn: Severity; policy: boolean }) => {
    const policy = opts.policy ? loadPolicy() : null;
    if (opts.offline || policy?.offline) process.env.FABRICA_STAR_OFFLINE = "1";
    const fmt: OutputFormat = opts.json ? "json" : opts.format;
    const failOn: Severity = policy?.["fail-on"] ?? opts.failOn;
    const files = discoverConfigFiles();
    const result = await scanConfigFiles(files);
    console.log(formatOutput(result, fmt));
    const worst = rollUpSeverity(result.servers.flatMap((s) => s.findings));
    process.exitCode = isAtLeast(worst, failOn) ? 1 : 0;
  });

// ── scan-config ───────────────────────────────────────────────────────────
program
  .command("scan-config <path>")
  .description("Scan a specific MCP client config file.")
  .option("--format <format>", "output format: text, json, sarif, permissions", parseFormat, "text" as OutputFormat)
  .option("--json", "shorthand for --format json")
  .option("--offline", "skip network checks")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .option("--no-policy", "ignore .fabrica-star.yml policy file")
  .action(async (path: string, opts: { format: OutputFormat; json?: boolean; offline?: boolean; failOn: Severity; policy: boolean }) => {
    if (!existsSync(path)) { console.error(`No such file: ${path}`); process.exitCode = 2; return; }
    const policy = opts.policy ? loadPolicy() : null;
    if (opts.offline || policy?.offline) process.env.FABRICA_STAR_OFFLINE = "1";
    const fmt: OutputFormat = opts.json ? "json" : opts.format;
    const failOn: Severity = policy?.["fail-on"] ?? opts.failOn;
    const result = await scanConfigFiles([path]);
    console.log(formatOutput(result, fmt));
    const worst = rollUpSeverity(result.servers.flatMap((s) => s.findings));
    process.exitCode = isAtLeast(worst, failOn) ? 1 : 0;
  });

// ── scan-source ───────────────────────────────────────────────────────────
program
  .command("scan-source <path>")
  .description("Statically scan an MCP server's source code for risky patterns — eval, shell injection, prompt injection, tool poisoning, hardcoded secrets.")
  .option("--format <format>", "output format: text, json, sarif", parseFormat, "text" as OutputFormat)
  .option("--json", "shorthand for --format json")
  .option("--fail-on <severity>", "exit non-zero if any finding is at or above this severity", parseFailOn, "high" as Severity)
  .action((path: string, opts: { format: OutputFormat; json?: boolean; failOn: Severity }) => {
    if (!existsSync(path)) { console.error(`No such file or directory: ${path}`); process.exitCode = 2; return; }
    const fmt: OutputFormat = opts.json ? "json" : opts.format;
    const findings = scanSourceTree(path);
    if (fmt === "sarif") console.log(formatSarifReport({ servers: [], generalFindings: findings }));
    else if (fmt === "json") console.log(JSON.stringify(findings, null, 2));
    else console.log(formatSourceReport(findings, path));
    process.exitCode = isAtLeast(rollUpSeverity(findings), opts.failOn) ? 1 : 0;
  });

// ── report ────────────────────────────────────────────────────────────────
program
  .command("report <server-or-package>")
  .description("Open a pre-filled GitHub issue to flag a suspicious or malicious MCP server.")
  .option("--severity <severity>", "suggested severity (low, medium, high, critical)", "high")
  .action((target: string, opts: { severity: string }) => {
    const title = `Flag: ${target}`;
    const body = [
      `## Server / package`, `\`${target}\``, ``,
      `## Suggested severity`, opts.severity, ``,
      `## Why this should be flagged`,
      `<!-- Link to a CVE, security advisory, GitHub issue, or writeup. -->`,
      `<!-- Entries without a verifiable public source will be asked for one before merge. -->`,
      ``, `## Evidence / source`, ``, `## Steps to reproduce (optional)`, ``,
    ].join("\n");

    const url = `https://github.com/${REPO}/issues/new` +
      `?title=${encodeURIComponent(title)}&body=${encodeURIComponent(body)}&labels=flagged-server`;

    console.log(`\nOpening contribution form for "${target}"...`);
    console.log(`\nIf your browser did not open, paste this URL manually:\n${url}\n`);
    openBrowser(url);
  });

// ── install-hook ──────────────────────────────────────────────────────────
program
  .command("install-hook")
  .description("Install a git pre-commit hook that runs fabrica-star scan before every commit.")
  .option("--fail-on <severity>", "severity that blocks the commit", "high")
  .action((opts: { failOn: string }) => {
    // Validate before writing into a shell script — never trust CLI input in shell context
    if (!VALID_SEVERITIES.includes(opts.failOn as Severity)) {
      console.error(`Invalid --fail-on value: "${opts.failOn}". Must be one of: ${VALID_SEVERITIES.join(", ")}`);
      process.exitCode = 1;
      return;
    }
    const safeFailOn = opts.failOn as Severity;
    const hookDir = join(process.cwd(), ".git", "hooks");
    const hookPath = join(hookDir, "pre-commit");

    if (!existsSync(join(process.cwd(), ".git"))) {
      console.error("Not a git repository. Run from your project root.");
      process.exitCode = 1;
      return;
    }

    const hookContent = [
      "#!/bin/sh",
      "# Fabrica-STAR pre-commit hook — auto-installed by fabrica-star install-hook",
      `npx fabrica-star scan --offline --fail-on ${safeFailOn}`,
      "exit $?",
    ].join("\n") + "\n";

    mkdirSync(hookDir, { recursive: true });
    writeFileSync(hookPath, hookContent, { mode: 0o755 });
    console.log(`✔ Pre-commit hook installed at ${hookPath}`);
    console.log(`  Runs: fabrica-star scan --offline --fail-on ${safeFailOn} before every commit`);
    console.log(`  To uninstall: rm ${hookPath}`);
  });

// ── init ──────────────────────────────────────────────────────────────────
program
  .command("init")
  .description("Create a starter .fabrica-star.yml policy file in the current directory.")
  .action(() => {
    const policyPath = join(process.cwd(), ".fabrica-star.yml");
    if (existsSync(policyPath)) {
      console.log(".fabrica-star.yml already exists — skipping.");
      return;
    }
    const content = [
      "# Fabrica-STAR policy — committed alongside your code so the whole team shares the same rules.",
      "# Run: fabrica-star scan   (automatically picks this up)",
      "",
      "fail-on: high",
      "offline: false",
      "",
      "# Per-rule overrides: error | warn | info | off",
      "rules:",
      "  no-version-pin: error",
      "  npm-low-download-count: off",
      "",
      "# Scopes that bypass npm trust heuristics",
      "allow:",
      "  scopes:",
      "    - \"@modelcontextprotocol\"",
      "",
    ].join("\n");
    writeFileSync(policyPath, content, "utf-8");
    console.log(`✔ Created .fabrica-star.yml — commit this to share policy with your team.`);
  });

program.parseAsync();
