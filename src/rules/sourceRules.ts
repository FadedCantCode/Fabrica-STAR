export interface SourcePattern {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  /** File extensions this pattern applies to (without the dot). Omit to apply to all scanned files. */
  extensions?: string[];
  regex: RegExp;
  message: string;
}

// Each pattern is intentionally a simple per-line regex, not a full AST
// analysis. That keeps the tool dependency-free and fast, at the cost of
// false positives on cleverly-written code. Findings are signals to review,
// not proof of a vulnerability.
export const SOURCE_PATTERNS: SourcePattern[] = [
  {
    id: "js-eval",
    severity: "high",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /\beval\s*\(/,
    message: "eval() executes arbitrary strings as code. If any part of the input can reach this, it's a code-injection path.",
  },
  {
    id: "js-new-function",
    severity: "high",
    extensions: ["js", "ts", "jsx", "tsx", "mjs", "cjs"],
    regex: /new\s+Function\s*\(/,
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
    message: "fetch() called with an interpolated URL. If any part of that URL is attacker- or model-controlled, this is a potential SSRF path — verify the value is constrained to an expected host.",
  },
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
  {
    id: "hardcoded-api-key",
    severity: "critical",
    regex: /(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})/,
    message: "Looks like a literal API key/credential committed in source rather than read from the environment.",
  },
];
