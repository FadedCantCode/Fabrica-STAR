/**
 * Cross-server Compound Blast Radius Analysis
 *
 * Individual server risk analysis misses the most dangerous attack pattern:
 * chained exploitation across multiple servers. A filesystem server and an
 * HTTP server are each medium-risk alone. Together, they form a complete
 * credential exfiltration pipeline. // fabrica-star-ignore
 *
 * This module analyzes ALL servers in a config together to detect compound
 * attack chains. No other MCP scanner does multi-server correlation.
 *
 * Attack chains detected:
 *   1. EXFILTRATION: filesystem (can READ secrets) + HTTP server (can SEND data) // fabrica-star-ignore
 *   2. EXECUTION:    filesystem (can WRITE) + shell/exec server (can RUN code)
 *   3. PIVOT:        secrets in env vars + HTTP server (credential theft)
 *   4. PERSISTENCE:  filesystem (write) + any server that can modify startup files
 */

import type { Finding, McpServerEntry, ServerReport } from "../types.js";
import type { SensitiveMatch } from "./blastRadius.js";

interface ServerCapabilities {
  name: string;
  canReadFiles: boolean;
  canWriteFiles: boolean;
  canSendHttp: boolean;
  canExecShell: boolean;
  hasHardcodedSecrets: boolean;
  sensitiveFilesReachable: SensitiveMatch[];
  filesystemPaths: string[];
  httpHosts: string[];
}

const HTTP_RUNNERS = new Set(["npx", "bunx", "pnpm", "uvx", "pipx"]);
const FETCH_SERVER_NAMES = ["fetch", "http", "browser", "playwright", "puppeteer", "web", "request", "axios", "curl"];
const SHELL_SERVER_NAMES = ["shell", "bash", "exec", "terminal", "command", "ssh", "run", "subprocess"];
const FS_SERVER_NAMES = ["filesystem", "file", "fs", "storage", "disk", "drive"];

const SECRET_PATTERNS = [
  /^sk-[A-Za-z0-9]{20,}$/,
  /^ghp_[A-Za-z0-9]{30,}$/,
  /^github_pat_[A-Za-z0-9_]{30,}$/,
  /^AKIA[A-Z0-9]{16}$/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/,
];

function isPlaceholder(v: string): boolean {
  return /^\$\{.+\}$|^\$[A-Z_]|^<.*>$|^(YOUR_|REPLACE_|TODO|XXX)/i.test(v);
}

function serverHasName(server: McpServerEntry, names: string[]): boolean {
  const haystack = [
    server.name,
    server.command ?? "",
    ...(server.args ?? []),
  ].join(" ").toLowerCase();
  return names.some((n) => haystack.includes(n));
}

function analyzeCapabilities(server: McpServerEntry, blastFindings: Finding[]): ServerCapabilities {
  const isFs = serverHasName(server, FS_SERVER_NAMES);
  const isFetch = serverHasName(server, FETCH_SERVER_NAMES);
  const isShell = serverHasName(server, SHELL_SERVER_NAMES);
  const hasHttp = server.url?.startsWith("http") || isFetch;
  const hasUnscoped = (server.args ?? []).some((a) => a === "/" || a === "~" || a === "C:\\");
  const hasBlastRadius = blastFindings.some((f) => f.ruleId === "blast-radius-sensitive-files");

  const hardcodedSecrets = Object.entries(server.env ?? {}).some(
    ([, v]) => !isPlaceholder(v) && SECRET_PATTERNS.some((r) => r.test(v)),
  );

  const httpHosts: string[] = [];
  if (server.url) {
    try { httpHosts.push(new URL(server.url).hostname); } catch { /* skip */ }
  }

  return {
    name: server.name,
    canReadFiles: isFs || hasUnscoped || hasBlastRadius,
    canWriteFiles: isFs || hasUnscoped,
    canSendHttp: isFetch || hasHttp || Boolean(server.url),
    canExecShell: isShell,
    hasHardcodedSecrets: hardcodedSecrets,
    sensitiveFilesReachable: [],
    filesystemPaths: (server.args ?? []).filter((a) => a.startsWith("/") || a.startsWith("~")),
    httpHosts,
  };
}

export interface CompoundFinding {
  chain: string[];
  attackType: string;
  severity: Finding["severity"];
  description: string;
}

export function analyzeCompoundBlastRadius(
  servers: McpServerEntry[],
  serverFindings: ServerReport[],
): Finding[] {
  if (servers.length < 2) return [];

  const capabilities = servers.map((s) => {
    const report = serverFindings.find((r) => r.server === s.name);
    const blastFindings = report?.findings.filter((f) => f.ruleId === "blast-radius-sensitive-files") ?? [];
    return analyzeCapabilities(s, blastFindings);
  });

  const findings: Finding[] = [];

  // ── Chain 1: EXFILTRATION ───────────────────────────────────────────────── // fabrica-star-ignore
  // filesystem server that can reach secrets + any HTTP-capable server
  const fileReaders = capabilities.filter((c) => c.canReadFiles);
  const httpSenders = capabilities.filter((c) => c.canSendHttp);

  if (fileReaders.length > 0 && httpSenders.length > 0) {
    for (const reader of fileReaders) {
      for (const sender of httpSenders) {
        if (reader.name === sender.name) continue;
        findings.push({
          ruleId: "compound-exfiltration-chain", // fabrica-star-ignore
          severity: "critical",
          target: `[${reader.name}] + [${sender.name}]`,
          message:
            `COMPOUND RISK — Exfiltration chain detected across two servers:\n` + // fabrica-star-ignore
            `  [${reader.name}] can READ files from your filesystem` +
            (reader.filesystemPaths.length ? ` (${reader.filesystemPaths.join(", ")})` : "") + `\n` +
            `  [${sender.name}] can SEND data to remote hosts` + // fabrica-star-ignore
            (sender.httpHosts.length ? ` (${sender.httpHosts.join(", ")})` : "") + `\n` +
            `  Combined: if either server is compromised, SSH keys, AWS credentials, and ` +
            `.env files reachable by [${reader.name}] could be exfiltrated via [${sender.name}].`, // fabrica-star-ignore
        });
        break; // One finding per reader, not a cartesian product
      }
    }
  }

  // ── Chain 2: CODE EXECUTION ───────────────────────────────────────────────
  // filesystem (write) + shell/exec server
  const fileWriters = capabilities.filter((c) => c.canWriteFiles);
  const shellExecs = capabilities.filter((c) => c.canExecShell);

  if (fileWriters.length > 0 && shellExecs.length > 0) {
    for (const writer of fileWriters) {
      for (const exec of shellExecs) {
        if (writer.name === exec.name) continue;
        findings.push({
          ruleId: "compound-execution-chain",
          severity: "critical",
          target: `[${writer.name}] + [${exec.name}]`,
          message:
            `COMPOUND RISK — Code execution chain detected:\n` +
            `  [${writer.name}] can WRITE files to your filesystem\n` +
            `  [${exec.name}] can EXECUTE shell commands\n` +
            `  Combined: a compromised [${writer.name}] could write a malicious script, ` +
            `then [${exec.name}] could execute it. This is a full remote code execution chain.`,
        });
        break;
      }
    }
  }

  // ── Chain 3: CREDENTIAL PIVOT ─────────────────────────────────────────────
  // Hardcoded secret in env + HTTP server = instant credential theft
  const secretHolders = capabilities.filter((c) => c.hasHardcodedSecrets);

  if (secretHolders.length > 0 && httpSenders.length > 0) {
    for (const holder of secretHolders) {
      const otherSenders = httpSenders.filter((s) => s.name !== holder.name);
      if (otherSenders.length === 0) continue;
      findings.push({
        ruleId: "compound-credential-pivot",
        severity: "critical",
        target: `[${holder.name}] + [${otherSenders[0].name}]`,
        message:
          `COMPOUND RISK — Credential pivot chain detected:\n` +
          `  [${holder.name}] has hardcoded credentials in its env vars\n` +
          `  [${otherSenders[0].name}] can make outbound HTTP requests\n` +
          `  Combined: credentials in [${holder.name}]'s process environment are accessible ` +
          `to other servers in the same agent session. A compromised [${otherSenders[0].name}] ` +
          `could exfiltrate them.`, // fabrica-star-ignore
      });
    }
  }

  // ── Chain 4: MULTI-SERVER TRUST ESCALATION ────────────────────────────────
  // More than 3 servers with high/critical findings = broad attack surface
  const riskyServers = serverFindings.filter(
    (r) => r.riskLevel === "high" || r.riskLevel === "critical",
  );
  if (riskyServers.length >= 3) {
    findings.push({
      ruleId: "compound-broad-attack-surface",
      severity: "high",
      target: `[${riskyServers.map((r) => r.server).join("] + [")}]`,
      message:
        `COMPOUND RISK — ${riskyServers.length} servers have high/critical findings. ` +
        `Each server runs with your full user privileges. A single compromised server in this ` +
        `config can pivot to abuse the trust relationships of all other servers in the same session.`,
    });
  }

  return findings;
}
