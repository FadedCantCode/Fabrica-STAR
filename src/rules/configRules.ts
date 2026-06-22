import type { Finding, McpServerEntry } from "../types.js";
import { loadKnownBadList } from "../knownBad.js";

const RUNNERS_NEEDING_VERSION_PIN = new Set(["npx", "bunx", "pnpm", "uvx", "pipx"]);

// Patterns that strongly suggest a literal secret was pasted into a config
// file instead of being referenced via ${ENV_VAR} substitution.
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /^sk-[A-Za-z0-9]{20,}$/, // OpenAI/Anthropic-style API keys
  /^ghp_[A-Za-z0-9]{30,}$/, // GitHub personal access token
  /^github_pat_[A-Za-z0-9_]{30,}$/,
  /^AKIA[A-Z0-9]{16}$/, // AWS access key id
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/, // Slack tokens
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, // JWT
];

function looksLikePlaceholder(value: string): boolean {
  return /^\$\{.+\}$|^\$[A-Z_][A-Z0-9_]*$|^<.*>$|^(YOUR_|REPLACE_|TODO|XXX)/i.test(value);
}

function isLocalhost(url: string): boolean {
  try {
    const { hostname } = new URL(url);
    return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
  } catch {
    return false;
  }
}

function hasVersionPin(arg: string): boolean {
  // Strip a leading scope ("@scope/pkg") before checking for an "@version" suffix.
  const withoutScope = arg.startsWith("@") ? arg.slice(1) : arg;
  return withoutScope.includes("@");
}

export function checkVersionPin(server: McpServerEntry): Finding[] {
  if (!server.command || !RUNNERS_NEEDING_VERSION_PIN.has(server.command)) return [];
  const pkgArg = (server.args ?? []).find((a) => !a.startsWith("-"));
  if (!pkgArg) return [];
  if (hasVersionPin(pkgArg)) return [];

  return [
    {
      ruleId: "no-version-pin",
      severity: "medium",
      target: server.name,
      message: `"${server.command} ${pkgArg}" has no version pin, so it will silently run whatever is published as "latest" on every launch. Pin a version (e.g. "${pkgArg}@1.2.3") to avoid an unreviewed update changing behavior under you.`,
    },
  ];
}

export function checkHardcodedSecrets(server: McpServerEntry): Finding[] {
  if (!server.env) return [];
  const findings: Finding[] = [];
  for (const [key, value] of Object.entries(server.env)) {
    if (looksLikePlaceholder(value)) continue;
    if (SECRET_VALUE_PATTERNS.some((re) => re.test(value))) {
      findings.push({
        ruleId: "hardcoded-secret",
        severity: "high",
        target: server.name,
        message: `env var "${key}" appears to contain a literal credential rather than a $\{VAR\} reference. If this config file is ever committed or shared, the credential leaks with it.`,
      });
    }
  }
  return findings;
}

export function checkInsecureTransport(server: McpServerEntry): Finding[] {
  if (server.transport !== "http" || !server.url) return [];
  if (!server.url.startsWith("http://")) return [];
  if (isLocalhost(server.url)) {
    return [
      {
        ruleId: "insecure-transport-local",
        severity: "info",
        target: server.name,
        message: `"${server.name}" connects over plain HTTP, but only to localhost, so this is low-risk.`,
      },
    ];
  }
  return [
    {
      ruleId: "insecure-transport",
      severity: "high",
      target: server.name,
      message: `"${server.name}" connects over plain HTTP to a non-local host (${server.url}). Traffic, including any auth tokens, can be intercepted in transit. Use an https:// endpoint.`,
    },
  ];
}

export function checkUnscopedFilesystemAccess(server: McpServerEntry): Finding[] {
  const args = server.args ?? [];
  const hasRootArg = args.some((a) => a === "/" || a === "C:\\" || a === "~");
  if (!hasRootArg) return [];
  return [
    {
      ruleId: "unscoped-filesystem-access",
      severity: "medium",
      target: server.name,
      message: `"${server.name}" is configured with a filesystem root ("${args.find((a) => a === "/" || a === "C:\\" || a === "~")}") instead of a scoped subdirectory. Scope it to the narrowest directory the server actually needs.`,
    },
  ];
}

export function checkKnownFlagged(server: McpServerEntry): Finding[] {
  const knownBad = loadKnownBadList();
  if (knownBad.length === 0) return [];

  const haystacks = [server.name, server.command, ...(server.args ?? []), server.url]
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.toLowerCase());

  const findings: Finding[] = [];
  for (const entry of knownBad) {
    const needle = entry.match.toLowerCase();
    if (haystacks.some((h) => h.includes(needle))) {
      findings.push({
        ruleId: "known-flagged-server",
        severity: entry.severity,
        target: server.name,
        message: `Matches known-flagged entry "${entry.match}": ${entry.reason}`,
      });
    }
  }
  return findings;
}

export const CONFIG_RULES = [
  checkVersionPin,
  checkHardcodedSecrets,
  checkInsecureTransport,
  checkUnscopedFilesystemAccess,
  checkKnownFlagged,
];

export function runConfigRules(server: McpServerEntry): Finding[] {
  return CONFIG_RULES.flatMap((rule) => rule(server));
}
