import { readdirSync, statSync } from "node:fs";
import { join, basename, extname, resolve } from "node:path";
import { homedir } from "node:os";
import type { Finding, McpServerEntry } from "../types.js";

export interface SensitiveMatch {
  path: string;
  reason: string;
  severity: "medium" | "high" | "critical";
}

/** Paths that are system-level and should never be flagged as sensitive user data */
function isSystemPath(filePath: string): boolean {
  return (
    filePath.startsWith("/etc/") ||
    filePath.startsWith("/usr/") ||
    filePath.startsWith("/lib/") ||
    filePath.startsWith("/opt/") ||
    filePath.startsWith("/var/") ||
    filePath.startsWith("/snap/") ||
    filePath.includes("/etc/skel/")
  );
}

/** Known sensitive file/directory patterns and what they mean */
const SENSITIVE_PATTERNS: Array<{
  test: (filePath: string, name: string, ext: string) => boolean;
  reason: string;
  severity: "medium" | "high" | "critical";
}> = [
  // SSH keys
  {
    test: (p) => p.includes("/.ssh/") && !p.endsWith(".pub"),
    reason: "SSH private key",
    severity: "critical",
  },
  // AWS credentials
  {
    test: (p) => p.includes("/.aws/credentials") || p.includes("/.aws/config"),
    reason: "AWS credentials",
    severity: "critical",
  },
  // GCP credentials
  {
    test: (p, n) => n === "application_default_credentials.json" || p.includes("/.config/gcloud/"),
    reason: "GCP credentials",
    severity: "critical",
  },
  // .env files
  {
    test: (_, n) => n === ".env" || n.startsWith(".env.") && !n.endsWith(".example") && !n.endsWith(".sample"),
    reason: ".env file (may contain secrets)",
    severity: "high",
  },
  // Private key files — only flag user-space files, not system CA bundles
  {
    test: (p, _, ext) =>
      !isSystemPath(p) &&
      (ext === ".pem" || ext === ".key" || ext === ".p12" || ext === ".pfx"),
    reason: "private key or certificate file",
    severity: "critical",
  },
  // Kubernetes config
  {
    test: (p, n) => (p.includes("/.kube/") && n === "config") || n === "kubeconfig",
    reason: "Kubernetes credentials",
    severity: "critical",
  },
  // npmrc with tokens — skip system/skel copies
  {
    test: (p, n) => !isSystemPath(p) && (n === ".npmrc" || n === ".yarnrc"),
    reason: "npm/yarn config (may contain registry tokens)",
    severity: "high",
  },
  // Netrc
  {
    test: (_, n) => n === ".netrc",
    reason: ".netrc (stores plaintext credentials for servers)",
    severity: "critical",
  },
  // Browser profiles
  {
    test: (p) =>
      p.includes("/Library/Application Support/Google/Chrome") ||
      p.includes("/Library/Application Support/Firefox") ||
      p.includes("/.mozilla/firefox") ||
      p.includes("/AppData/Local/Google/Chrome"),
    reason: "browser profile (cookies, saved passwords)",
    severity: "high",
  },
  // Docker config
  {
    test: (p, n) => p.includes("/.docker/") && n === "config.json",
    reason: "Docker registry credentials",
    severity: "high",
  },
  // Git credentials
  {
    test: (_, n) => n === ".git-credentials",
    reason: "git credential store (plaintext passwords)",
    severity: "critical",
  },
  // History files (can contain secrets typed in terminal)
  {
    test: (_, n) => n === ".bash_history" || n === ".zsh_history" || n === ".fish_history",
    reason: "shell history (may contain secrets typed on command line)",
    severity: "medium",
  },
  // Terraform state (can contain secrets)
  {
    test: (_, n) => n === "terraform.tfstate" || n === "terraform.tfstate.backup",
    reason: "Terraform state file (may contain secrets and infrastructure details)",
    severity: "high",
  },
  // 1Password / Bitwarden local vaults
  {
    test: (p) => p.includes("/1Password") || p.includes("bitwarden"),
    reason: "password manager data",
    severity: "critical",
  },
];

const MAX_DEPTH = 4;
const MAX_MATCHES = 20; // Stop after finding this many to avoid huge reports
const EXCLUDED_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__"]);

function scanForSensitiveFiles(
  rootDir: string,
  depth: number = 0,
  matches: SensitiveMatch[] = [],
): SensitiveMatch[] {
  if (depth > MAX_DEPTH || matches.length >= MAX_MATCHES) return matches;

  let entries;
  try {
    entries = readdirSync(rootDir, { withFileTypes: true });
  } catch {
    return matches;
  }

  for (const entry of entries) {
    if (matches.length >= MAX_MATCHES) break;

    const fullPath = join(rootDir, entry.name);
    const name = entry.name;
    const ext = extname(name).toLowerCase();

    if (entry.isDirectory()) {
      if (EXCLUDED_DIRS.has(name)) continue;
      // Always recurse into hidden dirs like .ssh, .aws, .kube
      scanForSensitiveFiles(fullPath, depth + 1, matches);
    } else if (entry.isFile()) {
      for (const pattern of SENSITIVE_PATTERNS) {
        if (pattern.test(fullPath, name, ext)) {
          // Replace home dir with ~ for cleaner output
          const displayPath = fullPath.replace(homedir(), "~");
          matches.push({ path: displayPath, reason: pattern.reason, severity: pattern.severity });
          break; // Only match one pattern per file
        }
      }
    }
  }

  return matches;
}

function extractFilesystemPaths(server: McpServerEntry): string[] {
  const FS_SERVER_NAMES = ["filesystem", "server-filesystem", "mcp-server-filesystem"];
  const isFilesystemServer =
    FS_SERVER_NAMES.some((n) => server.name.toLowerCase().includes(n) || (server.args ?? []).some((a) => a.includes(n)));
  if (!isFilesystemServer) return [];

  const args = server.args ?? [];
  return args
    .filter((a) => !a.startsWith("-") && !a.includes("/") === false && (a.startsWith("/") || a.startsWith("~") || a === "."))
    .map((a) => (a === "~" ? homedir() : a.startsWith("~") ? join(homedir(), a.slice(2)) : resolve(a)));
}

export function checkBlastRadius(server: McpServerEntry): Finding[] {
  const paths = extractFilesystemPaths(server);
  if (paths.length === 0) return [];

  const findings: Finding[] = [];

  for (const scanPath of paths) {
    let stat;
    try {
      stat = statSync(scanPath);
    } catch {
      continue; // path doesn't exist on this machine
    }

    if (!stat.isDirectory()) continue;

    const matches = scanForSensitiveFiles(scanPath);
    if (matches.length === 0) continue;

    const critical = matches.filter((m) => m.severity === "critical");
    const high = matches.filter((m) => m.severity === "high");
    const medium = matches.filter((m) => m.severity === "medium");

    const rolledUpSeverity = critical.length > 0 ? "critical" : high.length > 0 ? "high" : "medium";
    const matchList = matches
      .slice(0, 8)
      .map((m) => `\n      ${m.path}  (${m.reason})`)
      .join("");
    const moreCount = matches.length > 8 ? ` and ${matches.length - 8} more` : "";

    findings.push({
      ruleId: "blast-radius-sensitive-files",
      severity: rolledUpSeverity,
      target: server.name,
      message:
        `This server has access to ${scanPath.replace(homedir(), "~")} which contains ` +
        `${matches.length} sensitive file${matches.length === 1 ? "" : "s"}${moreCount}:` +
        matchList +
        (moreCount ? `\n      ...${moreCount}` : ""),
    });
  }

  return findings;
}
