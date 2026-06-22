import { describe, it, expect } from "vitest";
import { scanSourceTree } from "../src/rules/sourceScanner.js";

const FIXTURE_DIR = new URL("./fixtures/sample-server", import.meta.url).pathname;

describe("scanSourceTree", () => {
  const findings = scanSourceTree(FIXTURE_DIR);
  const ruleIds = findings.map((f) => f.ruleId);

  it("detects command injection via exec() with concatenation", () => {
    expect(ruleIds).toContain("js-exec-shell-string");
  });

  it("detects shell:true on spawn", () => {
    expect(ruleIds).toContain("js-spawn-shell-true");
  });

  it("detects eval()", () => {
    expect(ruleIds).toContain("js-eval");
  });

  it("detects a dynamically interpolated fetch URL", () => {
    expect(ruleIds).toContain("js-dynamic-fetch-url");
  });

  it("detects a hardcoded API key", () => {
    expect(ruleIds).toContain("hardcoded-api-key");
  });

  it("reports correct line numbers", () => {
    const evalFinding = findings.find((f) => f.ruleId === "js-eval");
    expect(evalFinding?.line).toBeGreaterThan(0);
  });

  it("ignores node_modules", () => {
    expect(findings.every((f) => !f.target.includes("node_modules"))).toBe(true);
  });
});
