import { describe, it, expect } from "vitest";
import { rollUpSeverity, isAtLeast } from "../src/scorer.js";
import type { Finding } from "../src/types.js";

function finding(severity: Finding["severity"]): Finding {
  return { ruleId: "x", severity, target: "t", message: "m" };
}

describe("rollUpSeverity", () => {
  it("returns info for no findings", () => {
    expect(rollUpSeverity([])).toBe("info");
  });

  it("returns the highest severity present", () => {
    expect(rollUpSeverity([finding("low"), finding("critical"), finding("medium")])).toBe("critical");
  });

  it("is not affected by ordering", () => {
    expect(rollUpSeverity([finding("high"), finding("low")])).toBe("high");
  });
});

describe("isAtLeast", () => {
  it("compares severities by rank", () => {
    expect(isAtLeast("high", "medium")).toBe(true);
    expect(isAtLeast("low", "medium")).toBe(false);
    expect(isAtLeast("medium", "medium")).toBe(true);
  });
});
