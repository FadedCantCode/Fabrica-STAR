import { readFileSync, readdirSync, statSync, type Dirent } from "node:fs";
import { extname, join, basename } from "node:path";
import type { Finding } from "../types.js";
import { SOURCE_PATTERNS } from "./sourceRules.js";

const SCANNED_EXTENSIONS = new Set(["js", "ts", "jsx", "tsx", "mjs", "cjs", "py", "json", "env"]);
const EXCLUDED_DIRS = new Set(["node_modules", ".git", "dist", "build", "venv", ".venv", "__pycache__", "out"]);
const MAX_FILE_BYTES = 1_000_000; // skip anything bigger than ~1MB; not source we expect to hand-review anyway

function extensionOf(filePath: string): string {
  if (basename(filePath) === ".env") return "env";
  return extname(filePath).slice(1).toLowerCase();
}

function listFiles(rootDir: string): string[] {
  const results: string[] = [];

  function walk(dir: string) {
    let entries: Dirent[];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return; // unreadable directory; skip rather than fail the whole scan
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!EXCLUDED_DIRS.has(entry.name)) walk(join(dir, entry.name));
        continue;
      }
      if (!entry.isFile()) continue;
      const fullPath = join(dir, entry.name);
      if (!SCANNED_EXTENSIONS.has(extensionOf(fullPath))) continue;
      results.push(fullPath);
    }
  }

  const rootStat = statSync(rootDir);
  if (rootStat.isFile()) return [rootDir];
  walk(rootDir);
  return results;
}

export function scanSourceTree(rootDir: string): Finding[] {
  const findings: Finding[] = [];

  for (const filePath of listFiles(rootDir)) {
    let content: string;
    try {
      if (statSync(filePath).size > MAX_FILE_BYTES) continue;
      content = readFileSync(filePath, "utf-8");
    } catch {
      continue; // unreadable or binary; skip
    }

    const ext = extensionOf(filePath);
    const lines = content.split("\n");
    const applicablePatterns = SOURCE_PATTERNS.filter((p) => !p.extensions || p.extensions.includes(ext));

    for (const pattern of applicablePatterns) {
      lines.forEach((line, idx) => {
        if (pattern.regex.test(line)) {
          findings.push({
            ruleId: pattern.id,
            severity: pattern.severity,
            target: filePath,
            line: idx + 1,
            message: pattern.message,
          });
        }
      });
    }
  }

  return findings;
}
