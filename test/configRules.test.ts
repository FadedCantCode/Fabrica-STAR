import { describe, it, expect } from "vitest";
import {
  checkVersionPin,
  checkHardcodedSecrets,
  checkInsecureTransport,
  checkUnscopedFilesystemAccess,
} from "../src/rules/configRules.js";
import type { McpServerEntry } from "../src/types.js";

// Run all network-dependent rules in offline mode during tests
process.env.FABRICA_STAR_OFFLINE = "1";

function makeServer(overrides: Partial<McpServerEntry>): McpServerEntry {
  return { name: "test-server", transport: "stdio", sourceFile: "test.json", ...overrides };
}

describe("checkVersionPin", () => {
  it("flags npx without a version pin", () => {
    const findings = checkVersionPin(makeServer({ command: "npx", args: ["@scope/pkg"] }));
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe("no-version-pin");
  });

  it("does not flag a pinned version", () => {
    const findings = checkVersionPin(makeServer({ command: "npx", args: ["@scope/pkg@1.2.3"] }));
    expect(findings).toHaveLength(0);
  });

  it("ignores commands that are not package runners", () => {
    const findings = checkVersionPin(makeServer({ command: "/usr/local/bin/my-server", args: [] }));
    expect(findings).toHaveLength(0);
  });

  it("skips flag-only args to find the actual package arg", () => {
    const findings = checkVersionPin(makeServer({ command: "npx", args: ["-y", "@scope/pkg@2.0.0"] }));
    expect(findings).toHaveLength(0);
  });
});

describe("checkHardcodedSecrets", () => {
  it("flags an env var that looks like a literal API key", () => {
    const findings = checkHardcodedSecrets(makeServer({ env: { OPENAI_API_KEY: "sk-" + "a".repeat(40) } }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("does not flag a ${VAR} placeholder", () => {
    const findings = checkHardcodedSecrets(makeServer({ env: { OPENAI_API_KEY: "${OPENAI_API_KEY}" } }));
    expect(findings).toHaveLength(0);
  });

  it("does not flag ordinary non-secret-shaped values", () => {
    const findings = checkHardcodedSecrets(makeServer({ env: { LOG_LEVEL: "debug" } }));
    expect(findings).toHaveLength(0);
  });
});

describe("checkInsecureTransport", () => {
  it("flags http:// to a remote host as high severity", () => {
    const findings = checkInsecureTransport(makeServer({ transport: "http", url: "http://example.com/mcp" }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
  });

  it("downgrades http://localhost to info", () => {
    const findings = checkInsecureTransport(makeServer({ transport: "http", url: "http://localhost:3000/mcp" }));
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("info");
  });

  it("does not flag https://", () => {
    const findings = checkInsecureTransport(makeServer({ transport: "http", url: "https://example.com/mcp" }));
    expect(findings).toHaveLength(0);
  });
});

describe("checkUnscopedFilesystemAccess", () => {
  it("flags a bare root path argument", () => {
    const findings = checkUnscopedFilesystemAccess(makeServer({ command: "npx", args: ["server-filesystem", "/"] }));
    expect(findings).toHaveLength(1);
  });

  it("does not flag a scoped subdirectory", () => {
    const findings = checkUnscopedFilesystemAccess(makeServer({ command: "npx", args: ["server-filesystem", "/home/user/projects"] }));
    expect(findings).toHaveLength(0);
  });
});
