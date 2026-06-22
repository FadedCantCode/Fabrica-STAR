import { describe, it, expect } from "vitest";
import { formatSarifReport } from "../src/sarif.js";
import type { ScanResult } from "../src/types.js";

const SAMPLE_RESULT: ScanResult = {
  servers: [
    {
      server: "github",
      sourceFile: "test.json",
      riskLevel: "high",
      findings: [
        {
          ruleId: "hardcoded-secret",
          severity: "high",
          target: "github",
          message: "env var GITHUB_TOKEN contains a literal credential.",
        },
        {
          ruleId: "no-version-pin",
          severity: "medium",
          target: "github",
          message: "npx @scope/pkg has no version pin.",
        },
      ],
    },
  ],
  generalFindings: [],
};

describe("formatSarifReport", () => {
  const output = formatSarifReport(SAMPLE_RESULT);
  let parsed: ReturnType<typeof JSON.parse>;

  it("produces valid JSON", () => {
    expect(() => { parsed = JSON.parse(output); }).not.toThrow();
    parsed = JSON.parse(output);
  });

  it("uses SARIF 2.1.0 schema", () => {
    const sarif = JSON.parse(output);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0");
  });

  it("includes the tool driver with correct name", () => {
    const sarif = JSON.parse(output);
    expect(sarif.runs[0].tool.driver.name).toBe("Fabrica-STAR");
  });

  it("maps findings to SARIF results", () => {
    const sarif = JSON.parse(output);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("maps high severity to error level", () => {
    const sarif = JSON.parse(output);
    const errorResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === "hardcoded-secret");
    expect(errorResult.level).toBe("error");
  });

  it("maps medium severity to warning level", () => {
    const sarif = JSON.parse(output);
    const warnResult = sarif.runs[0].results.find((r: { ruleId: string }) => r.ruleId === "no-version-pin");
    expect(warnResult.level).toBe("warning");
  });

  it("includes rule definitions", () => {
    const sarif = JSON.parse(output);
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain("hardcoded-secret");
    expect(ruleIds).toContain("no-version-pin");
  });

  it("returns empty results for an empty scan", () => {
    const empty = formatSarifReport({ servers: [], generalFindings: [] });
    const sarif = JSON.parse(empty);
    expect(sarif.runs[0].results).toHaveLength(0);
  });
});
