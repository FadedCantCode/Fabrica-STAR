import { describe, it, expect } from "vitest";
import { calculateScore } from "../src/htmlReport.js";
import type { ScanResult } from "../src/types.js";

function result(findings: Array<{ severity: "critical" | "high" | "medium" | "low" | "info" }>): ScanResult {
  return {
    servers: [
      {
        server: "test",
        sourceFile: "test.json",
        riskLevel: "high",
        findings: findings.map((f, i) => ({
          ruleId: `rule-${i}`,
          severity: f.severity,
          target: "test",
          message: "test finding",
        })),
      },
    ],
    generalFindings: [],
  };
}

describe("calculateScore", () => {
  it("gives A grade for a clean config", () => {
    const scored = calculateScore({ servers: [{ server: "x", sourceFile: "f", riskLevel: "info", findings: [] }], generalFindings: [] });
    expect(scored.grade).toBe("A");
    expect(scored.score).toBe(100);
  });

  it("drops to F for multiple critical findings", () => {
    const scored = calculateScore(result([
      { severity: "critical" },
      { severity: "critical" },
      { severity: "critical" },
    ]));
    expect(scored.grade).toBe("F");
  });

  it("never goes below 0", () => {
    const many = Array.from({ length: 20 }, () => ({ severity: "critical" as const }));
    const scored = calculateScore(result(many));
    expect(scored.score).toBeGreaterThanOrEqual(0);
  });

  it("assigns correct grade boundaries", () => {
    // One high finding = 15 penalty = 85 = B
    const scored = calculateScore(result([{ severity: "high" }]));
    expect(scored.grade).toBe("B");
    expect(scored.score).toBe(85);
  });

  it("info findings do not affect score", () => {
    const scored = calculateScore(result([{ severity: "info" }, { severity: "info" }]));
    expect(scored.score).toBe(100);
    expect(scored.grade).toBe("A");
  });
});
