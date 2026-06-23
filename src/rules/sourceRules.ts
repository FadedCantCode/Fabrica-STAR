export interface SourcePattern {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  extensions?: string[];
  regex: RegExp;
  message: string;
}

export const SOURCE_PATTERNS: SourcePattern[] = [
  // ── JavaScript / TypeScript ──────────────────────────────────────────────
  {
    id: "js-eval",
    severity: "high",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /\beval\s*\(/, // fabrica-star-ignore
    message: "eval() executes arbitrary strings as code. If any part of the input can reach this, it is a code-injection path.",
  },
  {
    id: "js-new-function",
    severity: "high",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /new\s+Function\s*\(/, // fabrica-star-ignore
    message: "new Function() compiles a string into executable code, same risk class as eval().",
  },
  {
    id: "js-exec-shell-string",
    severity: "high",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /\bexec\s*\([^)]*(\$\{|\+)/,
    message: "child_process.exec() called with a dynamically-built command string risks shell/command injection. Prefer execFile()/spawn() with an argument array.",
  },
  {
    id: "js-spawn-shell-true",
    severity: "medium",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /\{\s*shell\s*:\s*true/,
    message: "shell:true re-enables shell interpretation of arguments, reopening the injection risk execFile()/spawn() normally avoid.",
  },
  {
    id: "js-dynamic-fetch-url",
    severity: "medium",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /\bfetch\s*\(\s*[`][^`]*\$\{/,
    message: "fetch() called with an interpolated URL. If any part of that URL is attacker- or model-controlled, this is a potential SSRF path.",
  },

  // ── Python ───────────────────────────────────────────────────────────────
  {
    id: "py-os-system",
    severity: "high",
    extensions: ["py"],
    regex: /\bos\.system\s*\(/,
    message: "os.system() runs a string through the shell. Prefer subprocess.run([...]) with a list of arguments and shell=False.",
  },
  {
    id: "py-subprocess-shell-true",
    severity: "high",
    extensions: ["py"],
    regex: /shell\s*=\s*True/,
    message: "subprocess call with shell=True interprets the command through the shell, risking injection if any part is dynamically built.",
  },

  // ── Hardcoded credentials ─────────────────────────────────────────────────
  {
    id: "hardcoded-api-key",
    severity: "critical",
    regex: /(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})/,
    message: "Looks like a literal API key/credential committed in source rather than read from the environment.",
  },

  // ── Prompt injection & tool poisoning ────────────────────────────────────
  {
    id: "prompt-injection-ignore",
    severity: "critical",
    regex: /ignore\s+(previous|all\s+previous|prior|earlier)\s+(instructions?|context|prompts?)/i, // fabrica-star-ignore
    message: "Possible prompt injection: 'ignore previous instructions' pattern detected. This is a classic injection string used to hijack LLM behavior.",
  },
  {
    id: "prompt-injection-override",
    severity: "critical",
    regex: /disregard\s+(your|all|any)\s+(previous|prior|earlier|system|instructions?)/i,
    message: "Possible prompt injection: instruction override pattern detected in source.",
  },
  {
    id: "tool-poisoning-must-call",
    severity: "high",
    regex: /you\s+(must|shall|have\s+to)\s+(always\s+)?(first\s+)?(call|invoke|use|run)\s+(this|the)/i,
    message: "Possible tool poisoning: coercive 'you must call this' pattern in tool description or source. Malicious servers use this to force tool invocations.",
  },
  {
    id: "prompt-injection-system-delimiter",
    severity: "high",
    regex: /\[SYSTEM\]|<system>|###\s*system\s*###/i, // fabrica-star-ignore
    message: "Possible prompt injection: fake system prompt delimiter detected. Attackers use these to inject instructions into LLM context.",
  },
  {
    id: "exfiltration-pattern",
    severity: "critical",

    regex: /\b(exfiltrat|send\s+.{0,30}\s+to\s+remote|upload\s+.{0,30}\s+(secret|key|credential|token))/i, // fabrica-star-ignore
    message: "Possible data exfiltration pattern detected. Review carefully before running this server.", // fabrica-star-ignore
  },

  // ── Hook injection (all MCP agents) ──────────────────────────────────────
  // Detects risky patterns in hook handler registrations across Claude Code,
  // Cursor, VS Code, Windsurf, and generic MCP hook implementations.
  {
    id: "hook-wildcard-matcher",
    severity: "medium",
    regex: /matcher\s*:\s*["']\.\*["']|matcher\s*:\s*["']\*["']/,
    message: "Hook registered with wildcard matcher ('.*' or '*') runs on every tool call, maximizing attack surface. Scope to specific tools.",
  },
  {
    id: "hook-broad-permission",
    severity: "medium",
    regex: /(PreToolUse|PostToolUse|onToolCall|mcpHook|hookHandler)\s*[=:]/,
    message: "MCP hook handler registration detected. Ensure no unsanitized tool output flows into exec() or subprocess calls within hook handlers (CVE-2025-59536 class RCE).",
  },
];
