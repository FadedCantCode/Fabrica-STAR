import { describe, it, expect, beforeAll } from "vitest";
import { checkNpmHeuristics } from "../src/rules/npmHeuristics.js";
import type { McpServerEntry } from "../src/types.js";

// Run in offline mode — no real npm registry calls during tests
beforeAll(() => { process.env.FABRICA_STAR_OFFLINE = "1"; });

function makeServer(overrides: Partial<McpServerEntry>): McpServerEntry {
  return { name: "test-server", transport: "stdio", sourceFile: "test.json", ...overrides };
}

describe("checkNpmHeuristics — typosquat detection (offline)", () => {
  it("flags a package 1 edit away from a popular name", async () => {
    // "mcp-server-githb" is 1 deletion away from "mcp-server-github"
    const findings = await checkNpmHeuristics(
      makeServer({ command: "npx", args: ["mcp-server-githb"] })
    );
    expect(findings.some((f) => f.ruleId === "npm-typosquat")).toBe(true);
  });

  it("does not flag a well-known scoped package", async () => {
    const findings = await checkNpmHeuristics(
      makeServer({ command: "npx", args: ["@modelcontextprotocol/server-github"] })
    );
    expect(findings.some((f) => f.ruleId === "npm-typosquat")).toBe(false);
  });

  it("does not flag a package with an unrelated name", async () => {
    const findings = await checkNpmHeuristics(
      makeServer({ command: "npx", args: ["my-totally-different-tool"] })
    );
    expect(findings.some((f) => f.ruleId === "npm-typosquat")).toBe(false);
  });

  it("returns no findings for non-npm commands", async () => {
    const findings = await checkNpmHeuristics(
      makeServer({ command: "/usr/local/bin/custom-server", args: [] })
    );
    expect(findings).toHaveLength(0);
  });
});
