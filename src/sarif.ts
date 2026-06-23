/**
 * SARIF 2.1.0 formatter for Fabrica-STAR scan results.
 *
 * SARIF (Static Analysis Results Interchange Format) is the standard format
 * consumed by GitHub Code Scanning, VS Code, and most enterprise security
 * pipelines. Outputting SARIF lets findings appear directly in GitHub PR
 * reviews as code scanning alerts.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { ScanResult, Finding, Severity } from "./types.js";

const TOOL_VERSION = "0.1.2";
const REPO_URL = "https://github.com/FadedCantCode/Fabrica-STAR";
const RULES_URL = `${REPO_URL}#severity-levels`;

// Map our severity levels to SARIF levels
const SEVERITY_TO_SARIF: Record<Severity, "error" | "warning" | "note" | "none"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

// Map our severity levels to SARIF security-severity scores (CVSS-like 0-10)
const SEVERITY_TO_SCORE: Record<Severity, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 2.5,
  info: 0.0,
};

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri: string;
  properties: {
    tags: string[];
    "security-severity": string;
  };
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region?: { startLine: number };
    };
  }>;
  properties: { severity: string };
}

// Collect unique rules from all findings so SARIF has a complete rule registry
function collectRules(findings: Finding[]): Map<string, SarifRule> {
  const rules = new Map<string, SarifRule>();
  for (const finding of findings) {
    if (rules.has(finding.ruleId)) continue;
    rules.set(finding.ruleId, {
      id: finding.ruleId,
      name: ruleIdToName(finding.ruleId),
      shortDescription: { text: shortDesc(finding.ruleId) },
      fullDescription: { text: finding.message },
      helpUri: `${RULES_URL}`,
      properties: {
        tags: ["security", "mcp"],
        "security-severity": String(SEVERITY_TO_SCORE[finding.severity]),
      },
      defaultConfiguration: {
        level: SEVERITY_TO_SARIF[finding.severity],
      },
    });
  }
  return rules;
}

function ruleIdToName(ruleId: string): string {
  return ruleId
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("");
}

function shortDesc(ruleId: string): string {
  const descriptions: Record<string, string> = {
    "no-version-pin": "MCP server package has no version pin",
    "hardcoded-secret": "Hardcoded credential in MCP config",
    "insecure-transport": "MCP server uses plain HTTP transport",
    "insecure-transport-local": "MCP server uses plain HTTP to localhost",
    "unscoped-filesystem-access": "MCP server has overly broad filesystem access",
    "known-flagged-server": "MCP server matches known-malicious entry",
    "npm-typosquat": "MCP server package name resembles a popular package",
    "npm-very-new-package": "MCP server package was recently published",
    "npm-low-download-count": "MCP server package has very few downloads",
    "blast-radius-sensitive-files": "MCP server can reach sensitive files",
    "unparseable-config": "MCP config file could not be parsed",
    "js-eval": "Source uses eval()", // fabrica-star-ignore
    "js-new-function": "Source uses new Function()", // fabrica-star-ignore
    "js-exec-shell-string": "Source uses exec() with dynamic string",
    "js-spawn-shell-true": "Source uses spawn() with shell:true",
    "js-dynamic-fetch-url": "Source uses fetch() with interpolated URL",
    "py-os-system": "Python source uses os.system()",
    "py-subprocess-shell-true": "Python source uses subprocess with shell=True",
    "hardcoded-api-key": "Hardcoded API key in source code",
  };
  return descriptions[ruleId] ?? ruleId;
}

function findingToSarifResult(finding: Finding): SarifResult {
  const uri = finding.target.startsWith("/")
    ? finding.target
    : finding.target;

  return {
    ruleId: finding.ruleId,
    level: SEVERITY_TO_SARIF[finding.severity],
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: uri.replace(/^\//, ""),
            uriBaseId: "%SRCROOT%",
          },
          ...(finding.line ? { region: { startLine: finding.line } } : {}),
        },
      },
    ],
    properties: { severity: finding.severity },
  };
}

export function formatSarifReport(result: ScanResult): string {
  const allFindings: Finding[] = [
    ...result.servers.flatMap((s) => s.findings),
    ...result.generalFindings,
  ];

  const rules = collectRules(allFindings);
  const sarifResults = allFindings.map(findingToSarifResult);

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Fabrica-STAR",
            version: TOOL_VERSION,
            informationUri: REPO_URL,
            rules: Array.from(rules.values()),
          },
        },
        results: sarifResults,
        artifacts: [
          ...new Set(allFindings.map((f) => f.target)),
        ].map((uri) => ({
          location: {
            uri: uri.replace(/^\//, ""),
            uriBaseId: "%SRCROOT%",
          },
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
