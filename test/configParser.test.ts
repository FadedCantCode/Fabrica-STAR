import { describe, it, expect } from "vitest";
import { parseConfigObject } from "../src/configParser.js";

describe("parseConfigObject", () => {
  it("returns an empty array when there is no mcpServers key", () => {
    expect(parseConfigObject({}, "test.json")).toEqual([]);
    expect(parseConfigObject(null, "test.json")).toEqual([]);
    expect(parseConfigObject("not an object", "test.json")).toEqual([]);
  });

  it("parses a stdio server entry", () => {
    const result = parseConfigObject(
      {
        mcpServers: {
          github: { command: "npx", args: ["-y", "@modelcontextprotocol/server-github"], env: { TOKEN: "abc" } },
        },
      },
      "test.json",
    );

    expect(result).toEqual([
      {
        name: "github",
        transport: "stdio",
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github"],
        url: undefined,
        env: { TOKEN: "abc" },
        sourceFile: "test.json",
      },
    ]);
  });

  it("parses an http server entry", () => {
    const result = parseConfigObject(
      { mcpServers: { remote: { url: "https://example.com/mcp" } } },
      "test.json",
    );

    expect(result[0].transport).toBe("http");
    expect(result[0].url).toBe("https://example.com/mcp");
  });

  it("skips non-object server entries instead of throwing", () => {
    const result = parseConfigObject({ mcpServers: { broken: "not-an-object", ok: { command: "npx" } } }, "test.json");
    expect(result).toHaveLength(1);
    expect(result[0].name).toBe("ok");
  });
});
