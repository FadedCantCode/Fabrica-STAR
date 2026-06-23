/**
 * Root-level MCP config checks
 *
 * Checks that operate on the full config object (not per-server),
 * catching settings that affect trust boundaries across all servers:
 *
 *  - enableAllProjectMcpServers (Claude Code) — CVE-2026-40068
 *  - dangerouslyAllowShell (Claude Code)
 *  - Hook injection across all MCP clients (Claude, Cursor, VS Code, Windsurf)
 *  - Wildcard permissions / trust escalation flags
 */

import type { Finding } from "../types.js";

// Shell metacharacters that indicate injection risk
const SHELL_META = /[;&|`$(){}[\]<>\\]/;

// Network tools that should never appear in hooks
const NETWORK_TOOLS = /\b(curl|wget|nc|netcat|ncat|ssh|scp|rsync|telnet|ftp)\b/;

// Credential-harvesting patterns in hook commands
const CRED_PATTERNS = /(\$HOME|\$USER|\.ssh|\.aws|\.env|\.npmrc|keychain|secrets)/i;

function hookFindings(command: string, hookType: string, sourceFile: string): Finding[] {
  const findings: Finding[] = [];

  if (SHELL_META.test(command)) {
    findings.push({
      ruleId: "hook-shell-injection",
      severity: "critical",
      target: sourceFile,
      message:
        `Hook "${hookType}" runs a command containing shell metacharacters: "${command}". ` +
        `If any tool output or argument flows into this command, it is a shell injection (RCE) path. ` +
        `Use a script file with no shell interpolation, or an allowlist of safe values.`,
    });
  }

  if (NETWORK_TOOLS.test(command)) {
    findings.push({
      ruleId: "hook-network-capability",
      severity: "high",
      target: sourceFile,
      message:
        `Hook "${hookType}" uses a network tool (${command.match(NETWORK_TOOLS)?.[0]}). ` +
        `A compromised or malicious hook with network access can exfiltrate data from every tool call. ` + // fabrica-star-ignore
        `Review whether this hook needs network access.`,
    });
  }

  if (CRED_PATTERNS.test(command)) {
    findings.push({
      ruleId: "hook-credential-access", // fabrica-star-ignore
      severity: "high",
      target: sourceFile,
      message:
        `Hook "${hookType}" accesses credential or home-directory paths (${command.match(CRED_PATTERNS)?.[0]}). ` +
        `Hooks run on every tool call — credential access in hooks creates a persistent exfiltration surface.`, // fabrica-star-ignore
    });
  }

  return findings;
}

function extractHookCommands(obj: unknown, path: string): Array<{ command: string; path: string }> {
  if (typeof obj !== "object" || obj === null) return [];
  const results: Array<{ command: string; path: string }> = [];

  if (Array.isArray(obj)) {
    obj.forEach((item, i) => results.push(...extractHookCommands(item, `${path}[${i}]`)));
    return results;
  }

  const record = obj as Record<string, unknown>;

  // Claude Code hook format: { "command": "..." } or { "type": "command", "command": "..." }
  if (typeof record.command === "string" && record.command.length > 0) {
    results.push({ command: record.command, path });
  }

  // VS Code / generic hook format: { "run": "..." } // fabrica-star-ignore
  if (typeof record.run === "string" && record.run.length > 0) {
    results.push({ command: record.run, path });
  }

  // Cursor format: { "script": "..." } // fabrica-star-ignore
  if (typeof record.script === "string" && record.script.length > 0) {
    results.push({ command: record.script, path });
  }

  // Recurse into nested objects
  for (const [key, val] of Object.entries(record)) {
    if (key === "command" || key === "run" || key === "script") continue;
    results.push(...extractHookCommands(val, `${path}.${key}`));
  }

  return results;
}

export function checkRootConfig(raw: unknown, sourceFile: string): Finding[] {
  if (typeof raw !== "object" || raw === null) return [];
  const config = raw as Record<string, unknown>;
  const findings: Finding[] = [];

  // ── Claude Code: enableAllProjectMcpServers ──────────────────────────────
  if (config.enableAllProjectMcpServers === true) {
    findings.push({
      ruleId: "enable-all-project-mcp-servers",
      severity: "high",
      target: sourceFile,
      message:
        `"enableAllProjectMcpServers": true automatically trusts every MCP server defined in ` +
        `any project you open, without prompting for confirmation. ` +
        `CVE-2026-40068 demonstrates folder-trust bypass via this flag. ` +
        `Remove this flag and approve servers individually.`,
    });
  }

  // ── Claude Code: dangerouslyAllowShell ───────────────────────────────────
  if (config.dangerouslyAllowShell === true) {
    findings.push({
      ruleId: "dangerously-allow-shell",
      severity: "critical",
      target: sourceFile,
      message:
        `"dangerouslyAllowShell": true grants MCP servers direct shell execution capability. ` +
        `This bypasses all sandboxing and allows arbitrary command execution on your system. ` +
        `Remove this flag unless you have an explicit security justification.`,
    });
  }

  // ── Generic: allowAllTools / wildcard trust flags ─────────────────────────
  const wildcardFlags = ["allowAllTools", "trustAllServers", "skipVerification", "disableSecurity"];
  for (const flag of wildcardFlags) {
    if (config[flag] === true) {
      findings.push({
        ruleId: "wildcard-trust-flag",
        severity: "high",
        target: sourceFile,
        message:
          `"${flag}": true disables trust boundary enforcement for MCP servers. ` +
          `This flag bypasses security checks designed to limit what servers can do. ` +
          `Remove it and configure explicit allowlists instead.`,
      });
    }
  }

  // ── Hook injection — all agent formats ────────────────────────────────────
  // Claude Code: { hooks: { PreToolUse: [...], PostToolUse: [...] } } // fabrica-star-ignore
  // Cursor:      { onToolCall: { ... } } // fabrica-star-ignore
  // VS Code:     { mcpHooks: [...] } // fabrica-star-ignore
  // Windsurf:    { hooks: [...] } // fabrica-star-ignore
  // Generic:     any key containing "hook" with nested commands // fabrica-star-ignore
  const hookRoots: Array<{ obj: unknown; name: string }> = []; // fabrica-star-ignore
 // fabrica-star-ignore
  if (config.hooks) hookRoots.push({ obj: config.hooks, name: "hooks" });
  if (config.onToolCall) hookRoots.push({ obj: config.onToolCall, name: "onToolCall" });
  if (config.mcpHooks) hookRoots.push({ obj: config.mcpHooks, name: "mcpHooks" });
  if (config.preToolHooks) hookRoots.push({ obj: config.preToolHooks, name: "preToolHooks" });
  if (config.postToolHooks) hookRoots.push({ obj: config.postToolHooks, name: "postToolHooks" });

  // Also search all keys that contain "hook"
  for (const [key, val] of Object.entries(config)) {
    if (key.toLowerCase().includes("hook") && !hookRoots.some((r) => r.name === key)) {
      hookRoots.push({ obj: val, name: key });
    }
  }

  for (const { obj, name } of hookRoots) {
    const commands = extractHookCommands(obj, name);
    for (const { command, path } of commands) {
      findings.push(...hookFindings(command, path, sourceFile));
    }
  }

  // ── Wildcard hook matchers ────────────────────────────────────────────────
  // { hooks: { PreToolUse: [{ matcher: ".*", hooks: [...] }] } } // fabrica-star-ignore
  if (typeof config.hooks === "object" && config.hooks !== null) {
    const hooks = config.hooks as Record<string, unknown>;
    for (const [hookType, hookList] of Object.entries(hooks)) {
      if (!Array.isArray(hookList)) continue;
      for (const entry of hookList) {
        if (typeof entry === "object" && entry !== null) {
          const e = entry as Record<string, unknown>;
          if (e.matcher === ".*" || e.matcher === "*") { // fabrica-star-ignore
            findings.push({
              ruleId: "hook-wildcard-matcher",
              severity: "medium",
              target: sourceFile,
              message:
                `Hook "${hookType}" uses a wildcard matcher ("${e.matcher}"), meaning it runs on ` +
                `every single tool call regardless of which tool is invoked. ` +
                `Scope hooks to specific tools to reduce attack surface.`,
            });
          }
        }
      }
    }
  }

  return findings;
}
