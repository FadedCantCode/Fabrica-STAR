import type { Finding, Severity } from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Highest severity among the given findings, or "info" if there are none. */
export function rollUpSeverity(findings: Finding[]): Severity {
  if (findings.length === 0) return "info";
  return findings.reduce<Severity>((worst, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[worst] ? f.severity : worst), "info");
}

export function isAtLeast(severity: Severity, threshold: Severity): boolean {
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold];
}

export { SEVERITY_RANK };
