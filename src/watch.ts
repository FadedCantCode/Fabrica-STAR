/**
 * Watch mode — Continuous MCP config monitoring
 *
 * Monitors all discovered MCP client config files for changes.
 * On every change, re-scans and shows exactly what changed:
 *   - New servers added to the config
 *   - Existing servers modified
 *   - New findings on existing servers
 *   - Findings resolved
 *
 * Uses fs.watch (FSEvents on macOS, inotify on Linux, ReadDirectoryChangesW
 * on Windows) with a debounce to handle editors that write via temp file swap.
 */

import { watch, existsSync, statSync } from "node:fs";
import { basename } from "node:path";
import { scanConfigFiles } from "./scanner.js";
import { discoverConfigFiles } from "./discovery.js";
import type { ServerReport, ScanResult, Finding } from "./types.js";

const DEBOUNCE_MS = 600;
const COLOR = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
};

function c(color: keyof typeof COLOR, text: string): string {
  return `${COLOR[color]}${text}${COLOR.reset}`;
}

function timestamp(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

function log(msg: string): void {
  process.stdout.write(`${c("dim", timestamp())}  ${msg}\n`);
}

interface WatchDiff {
  newServers: ServerReport[];
  removedServers: string[];
  changedServers: Array<{
    name: string;
    newFindings: string[];
    resolvedFindings: string[];
    riskChanged: boolean;
    oldRisk: string;
    newRisk: string;
  }>;
  overallRiskChanged: boolean;
}

function diffResults(prev: ScanResult, next: ScanResult): WatchDiff {
  const prevMap = new Map<string, ServerReport>(prev.servers.map((s: ServerReport) => [s.server, s]));
  const nextMap = new Map<string, ServerReport>(next.servers.map((s: ServerReport) => [s.server, s]));

  const newServers = next.servers.filter((s: ServerReport) => !prevMap.has(s.server));
  const removedServers = prev.servers
    .filter((s: ServerReport) => !nextMap.has(s.server))
    .map((s: ServerReport) => s.server);

  const changedServers = next.servers
    .filter((s: ServerReport) => prevMap.has(s.server))
    .map((s: ServerReport) => {
      const old = prevMap.get(s.server)!;
      const prevRuleIds = new Set(old.findings.map((f: Finding) => f.ruleId));
      const nextRuleIds = new Set(s.findings.map((f: Finding) => f.ruleId));
      const newFindings = s.findings
        .filter((f: Finding) => !prevRuleIds.has(f.ruleId))
        .map((f: Finding) => f.ruleId);
      const resolvedFindings = old.findings
        .filter((f: Finding) => !nextRuleIds.has(f.ruleId))
        .map((f: Finding) => f.ruleId);
      return {
        name: s.server,
        newFindings,
        resolvedFindings,
        riskChanged: old.riskLevel !== s.riskLevel,
        oldRisk: old.riskLevel,
        newRisk: s.riskLevel,
      };
    })
    .filter(
      (s: { newFindings: string[]; resolvedFindings: string[]; riskChanged: boolean }) =>
        s.newFindings.length > 0 ||
        s.resolvedFindings.length > 0 ||
        s.riskChanged,
    );

  const prevWorst = prev.servers.reduce(
    (w: string, s: ServerReport) =>
      ["critical", "high", "medium", "low", "info"].indexOf(s.riskLevel) <
      ["critical", "high", "medium", "low", "info"].indexOf(w)
        ? s.riskLevel
        : w,
    "info",
  );
  const nextWorst = next.servers.reduce(
    (w: string, s: ServerReport) =>
      ["critical", "high", "medium", "low", "info"].indexOf(s.riskLevel) <
      ["critical", "high", "medium", "low", "info"].indexOf(w)
        ? s.riskLevel
        : w,
    "info",
  );

  return {
    newServers,
    removedServers,
    changedServers,
    overallRiskChanged: prevWorst !== nextWorst,
  };
}

function printDiff(diff: WatchDiff, filePath: string): void {
  const file = basename(filePath);
  const hasChanges =
    diff.newServers.length > 0 ||
    diff.removedServers.length > 0 ||
    diff.changedServers.length > 0;

  if (!hasChanges) {
    log(`${c("dim", file)} — config changed but no security impact`);
    return;
  }

  process.stdout.write(`\n${c("bold", "── Config changed:")} ${c("cyan", file)} ──────────────────\n\n`);

  // New servers — most important alert
  for (const s of diff.newServers) {
    const risk = s.riskLevel;
    const icon =
      risk === "critical" || risk === "high"
        ? c("red", "✖ NEW SERVER")
        : risk === "medium"
        ? c("yellow", "⚠ NEW SERVER")
        : c("green", "✔ NEW SERVER");

    process.stdout.write(`${icon}  ${c("bold", s.server)}  [${risk}]\n`);
    for (const f of s.findings) {
      process.stdout.write(
        `   ${c("dim", `[${f.ruleId}]`)}  ${f.message.split("\n")[0]}\n`,
      );
    }
    if (s.findings.length === 0) {
      process.stdout.write(`   ${c("dim", "no issues found")}\n`);
    }
    process.stdout.write("\n");
  }

  // Removed servers
  for (const name of diff.removedServers) {
    process.stdout.write(`${c("dim", "✖ REMOVED")}  ${c("bold", name)}\n\n`);
  }

  // Changed servers
  for (const s of diff.changedServers) {
    process.stdout.write(`${c("yellow", "⚠ CHANGED")}  ${c("bold", s.name)}`);
    if (s.riskChanged) {
      process.stdout.write(
        `  ${c("dim", s.oldRisk)} → ${c("bold", s.newRisk)}`,
      );
    }
    process.stdout.write("\n");

    for (const ruleId of s.newFindings) {
      process.stdout.write(`   ${c("red", "+")} ${ruleId}\n`);
    }
    for (const ruleId of s.resolvedFindings) {
      process.stdout.write(`   ${c("green", "−")} ${ruleId}\n`);
    }
    process.stdout.write("\n");
  }
}

function printInitialSummary(result: ScanResult, files: string[]): void {
  const total = result.servers.length;
  const byRisk = {
    critical: result.servers.filter((s: ServerReport) => s.riskLevel === "critical").length,
    high: result.servers.filter((s: ServerReport) => s.riskLevel === "high").length,
    medium: result.servers.filter((s: ServerReport) => s.riskLevel === "medium").length,
    clean: result.servers.filter((s: ServerReport) =>
      ["low", "info"].includes(s.riskLevel),
    ).length,
  };

  process.stdout.write(
    `\n${c("bold", "fabrica-star watch")} — monitoring ${files.length} config file${files.length === 1 ? "" : "s"}\n`,
  );
  process.stdout.write(
    `${c("dim", files.map((f) => basename(f)).join(", "))}\n\n`,
  );
  process.stdout.write(
    `Initial scan: ${total} server${total === 1 ? "" : "s"} · `,
  );

  const parts: string[] = [];
  if (byRisk.critical) parts.push(c("magenta", `${byRisk.critical} critical`));
  if (byRisk.high) parts.push(c("red", `${byRisk.high} high`));
  if (byRisk.medium) parts.push(c("yellow", `${byRisk.medium} medium`));
  if (byRisk.clean) parts.push(c("green", `${byRisk.clean} clean`));
  process.stdout.write(parts.join(" · ") + "\n\n");
  process.stdout.write(
    `${c("dim", "Watching for changes. Press Ctrl+C to stop.")}\n\n`,
  );
}

export async function startWatch(opts: {
  offline?: boolean;
  failOn?: string;
}): Promise<void> {
  if (opts.offline) process.env.FABRICA_STAR_OFFLINE = "1";

  const files = discoverConfigFiles();
  if (files.length === 0) {
    process.stdout.write(
      "No MCP config files found. Add a config and re-run.\n",
    );
    return;
  }

  // Initial scan
  let lastResult = await scanConfigFiles(files);
  printInitialSummary(lastResult, files);

  // Debounce timers per file
  const timers = new Map<string, ReturnType<typeof setTimeout>>();

  async function rescan(changedFile: string): Promise<void> {
    // File may have been deleted (editor temp-file swap) — wait for it
    let attempts = 0;
    while (!existsSync(changedFile) && attempts < 10) {
      await new Promise((r) => setTimeout(r, 100));
      attempts++;
    }
    if (!existsSync(changedFile)) {
      log(`${c("dim", basename(changedFile))} — deleted`);
      return;
    }

    try {
      const next = await scanConfigFiles(files);
      const diff = diffResults(lastResult, next);
      printDiff(diff, changedFile);
      lastResult = next;
    } catch {
      log(`${c("yellow", "⚠")} Could not parse ${basename(changedFile)} — skipping`);
    }
  }

  // Set up watchers
  for (const file of files) {
    try {
      watch(file, { persistent: true }, (event) => {
        // Debounce — editors often emit multiple events per save
        const existing = timers.get(file);
        if (existing) clearTimeout(existing);
        timers.set(
          file,
          setTimeout(() => {
            timers.delete(file);
            rescan(file);
          }, DEBOUNCE_MS),
        );
      });
    } catch {
      log(`${c("yellow", "⚠")} Cannot watch ${basename(file)} — skipping`);
    }
  }

  // Also watch parent directories for new config files appearing
  const watchedDirs = new Set(files.map((f: string) => f.replace(/\/[^/]+$/, "")));
  for (const dir of watchedDirs) {
    try {
      watch(dir as string, { persistent: true }, async () => {
        const newFiles = discoverConfigFiles();
        const addedFiles = newFiles.filter((f: string) => !files.includes(f));
        for (const added of addedFiles) {
          files.push(added);
          log(`${c("cyan", "+")} New config detected: ${basename(added)}`);
          await rescan(added);
          try {
            watch(added, { persistent: true }, () => {
              const existing = timers.get(added);
              if (existing) clearTimeout(existing);
              timers.set(
                added,
                setTimeout(() => {
                  timers.delete(added);
                  rescan(added);
                }, DEBOUNCE_MS),
              );
            });
          } catch { /* skip */ }
        }
      });
    } catch { /* skip — directory may not exist */ }
  }

  // Keep process alive
  process.on("SIGINT", () => {
    process.stdout.write(`\n${c("dim", "Watch stopped.")}\n`);
    process.exit(0);
  });
}
