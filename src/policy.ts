/**
 * Policy-as-code support for Fabrica-STAR.
 *
 * If a `.fabrica-star.yml` file exists in the current directory (or any
 * parent), its settings override the CLI defaults. This lets teams commit
 * a shared security policy alongside their code.
 *
 * Example policy file:
 *
 *   fail-on: high
 *   offline: false
 *   rules:
 *     no-version-pin: error    # promote to error
 *     npm-low-download-count: off  # silence this check
 *   allow:
 *     scopes:
 *       - "@modelcontextprotocol"
 *       - "@mycompany"
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import type { Severity } from "./types.js";

export type RuleLevel = "error" | "warn" | "info" | "off";

export interface FabricaPolicy {
  /** Minimum severity that causes a non-zero exit. */
  "fail-on"?: Severity;
  /** Skip network calls. */
  offline?: boolean;
  /** Per-rule overrides: "error" | "warn" | "info" | "off" */
  rules?: Record<string, RuleLevel>;
  /** Scopes / package prefixes that bypass npm trust checks. */
  allow?: {
    scopes?: string[];
    packages?: string[];
  };
}

const POLICY_FILE = ".fabrica-star.yml";

/**
 * Walks up from `startDir` looking for a `.fabrica-star.yml` file.
 * Returns the first one found, or null.
 */
function findPolicyFile(startDir: string): string | null {
  let dir = resolve(startDir);
  while (true) {
    const candidate = join(dir, POLICY_FILE);
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) return null; // filesystem root
    dir = parent;
  }
}

/** Minimal YAML parser — supports only the flat subset used by our policy file. */
function parseMinimalYaml(raw: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  let currentKey: string | null = null;
  let currentObj: Record<string, string> | null = null;
  let currentList: string[] | null = null;
  let parentKey: string | null = null;

  for (const rawLine of raw.split("\n")) {
    const line = rawLine.replace(/#.*$/, ""); // strip comments
    if (!line.trim()) continue;

    const indent = line.length - line.trimStart().length;

    if (indent === 0) {
      // Save previous collection
      if (currentKey && currentObj) result[currentKey] = currentObj;
      if (currentKey && currentList) {
        if (parentKey) {
          (result[parentKey] as Record<string, unknown>)[currentKey] = currentList;
        } else {
          result[currentKey] = currentList;
        }
      }
      currentObj = null;
      currentList = null;
      parentKey = null;

      const [rawK, ...vParts] = line.split(":");
      const k = rawK.trim();
      const v = vParts.join(":").trim();
      if (v) {
        result[k] = v === "true" ? true : v === "false" ? false : v;
      } else {
        currentKey = k;
        currentObj = {};
        result[k] = currentObj;
      }
    } else if (indent === 2) {
      const trimmed = line.trim();
      if (trimmed.startsWith("- ")) {
        // list item at depth 2
        if (!currentList) {
          currentList = [];
          if (currentKey) {
            if (parentKey) {
              (result[parentKey] as Record<string, unknown>)[currentKey] = currentList;
            } else {
              result[currentKey] = currentList;
            }
          }
        }
        currentList.push(trimmed.slice(2).trim());
      } else {
        // key: value at depth 2
        const [rawK, ...vParts] = trimmed.split(":");
        const k = rawK.trim();
        const v = vParts.join(":").trim();
        if (currentObj) currentObj[k] = v;
      }
    } else if (indent === 4) {
      // list item at depth 4 (nested under depth-2 key)
      const trimmed = line.trim();
      if (trimmed.startsWith("- ")) {
        if (!currentList) {
          currentList = [];
        }
        currentList.push(trimmed.slice(2).trim());
      }
    }
  }

  return result;
}

export function loadPolicy(cwd: string = process.cwd()): FabricaPolicy | null {
  const policyPath = findPolicyFile(cwd);
  if (!policyPath) return null;

  try {
    const raw = readFileSync(policyPath, "utf-8");
    const parsed = parseMinimalYaml(raw) as FabricaPolicy;
    return parsed;
  } catch {
    return null;
  }
}

/** Apply policy rule overrides to a finding's severity. */
export function applyPolicyToSeverity(
  ruleId: string,
  severity: Severity,
  policy: FabricaPolicy | null,
): Severity | null {
  if (!policy?.rules) return severity;
  const override = policy.rules[ruleId];
  if (!override) return severity;
  if (override === "off") return null; // suppress this finding
  if (override === "error") return "high"; // promote
  if (override === "warn") return "medium";
  if (override === "info") return "low";
  return severity;
}

export function isPolicyAllowedScope(pkg: string, policy: FabricaPolicy | null): boolean {
  if (!policy?.allow?.scopes) return false;
  return policy.allow.scopes.some((scope) => pkg.startsWith(scope));
}
