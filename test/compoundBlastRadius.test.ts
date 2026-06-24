import { describe, it, expect } from "vitest";
import { analyzeCompoundBlastRadius } from "../src/rules/compoundBlastRadius.js";
import type { McpServerEntry, ServerReport } from "../src/types.js";

function server(overrides: Partial<McpServerEntry>): McpServerEntry {
  return { name: "s", transport: "stdio", sourceFile: "test.json", ...overrides };
}

function report(name: string, riskLevel: ServerReport["riskLevel"] = "medium"): ServerReport {
  return { server: name, sourceFile: "test.json", findings: [], riskLevel };
}

describe("analyzeCompoundBlastRadius", () => {
  it("returns nothing for a single server", () => {
    const servers = [server({ name: "filesystem", command: "npx", args: ["server-filesystem", "/"] })];
    const findings = analyzeCompoundBlastRadius(servers, [report("filesystem")]);
    expect(findings).toHaveLength(0);
  });

  it("detects exfiltration chain: filesystem + http server", () => {
    const servers = [
      server({ name: "filesystem", command: "npx", args: ["server-filesystem", "/"] }),
      server({ name: "fetch", command: "npx", args: ["server-fetch"] }),
    ];
    const reports = [report("filesystem", "high"), report("fetch", "medium")];
    const findings = analyzeCompoundBlastRadius(servers, reports);
    expect(findings.some((f) => f.ruleId === "compound-exfiltration-chain")).toBe(true);
  });

  it("detects credential pivot: hardcoded secret + http server", () => {
    const servers = [
      server({ name: "github", command: "npx", args: ["server-github"], env: { TOKEN: "ghp_" + "a".repeat(36) } }),
      server({ name: "fetch", command: "npx", args: ["server-fetch"] }),
    ];
    const reports = [report("github", "high"), report("fetch", "medium")];
    const findings = analyzeCompoundBlastRadius(servers, reports);
    expect(findings.some((f) => f.ruleId === "compound-credential-pivot")).toBe(true);
  });

  it("detects broad attack surface with 3+ risky servers", () => {
    const servers = [
      server({ name: "a", command: "npx", args: ["a"] }),
      server({ name: "b", command: "npx", args: ["b"] }),
      server({ name: "c", command: "npx", args: ["c"] }),
    ];
    const reports = [report("a", "high"), report("b", "high"), report("c", "critical")];
    const findings = analyzeCompoundBlastRadius(servers, reports);
    expect(findings.some((f) => f.ruleId === "compound-broad-attack-surface")).toBe(true);
  });

  it("does not flag two unrelated clean servers", () => {
    const servers = [
      server({ name: "time", command: "npx", args: ["server-time"] }),
      server({ name: "memory", command: "npx", args: ["server-memory"] }),
    ];
    const reports = [report("time", "info"), report("memory", "info")];
    const findings = analyzeCompoundBlastRadius(servers, reports);
    expect(findings).toHaveLength(0);
  });
});
