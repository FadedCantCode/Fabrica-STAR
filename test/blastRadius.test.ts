import { describe, it, expect } from "vitest";
import { checkBlastRadius } from "../src/rules/blastRadius.js";
import type { McpServerEntry } from "../src/types.js";

function makeServer(overrides: Partial<McpServerEntry>): McpServerEntry {
  return { name: "test-server", transport: "stdio", sourceFile: "test.json", ...overrides };
}

describe("checkBlastRadius", () => {
  it("returns no findings for non-filesystem servers", () => {
    const findings = checkBlastRadius(
      makeServer({ name: "github", command: "npx", args: ["@modelcontextprotocol/server-github"] })
    );
    expect(findings).toHaveLength(0);
  });

  it("returns no findings for filesystem server with non-existent path", () => {
    const findings = checkBlastRadius(
      makeServer({
        name: "filesystem",
        command: "npx",
        args: ["@modelcontextprotocol/server-filesystem", "/nonexistent/path/that/does/not/exist"],
      })
    );
    expect(findings).toHaveLength(0);
  });

  it("returns no findings for filesystem server with no path args", () => {
    const findings = checkBlastRadius(
      makeServer({ name: "filesystem", command: "npx", args: ["@modelcontextprotocol/server-filesystem"] })
    );
    expect(findings).toHaveLength(0);
  });

  it("finding ruleId is blast-radius-sensitive-files when triggered", () => {
    // Scan the test directory itself — it contains .ts files but no secrets,
    // so this verifies the scanner runs without crashing
    const findings = checkBlastRadius(
      makeServer({
        name: "filesystem",
        command: "npx",
        args: ["@modelcontextprotocol/server-filesystem", process.cwd()],
      })
    );
    // Either 0 findings (no secrets in this dir) or valid findings if there are any
    for (const f of findings) {
      expect(f.ruleId).toBe("blast-radius-sensitive-files");
      expect(["medium", "high", "critical"]).toContain(f.severity);
    }
  });
});
