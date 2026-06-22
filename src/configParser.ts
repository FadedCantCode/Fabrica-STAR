import { readFileSync } from "node:fs";
import type { McpServerEntry } from "./types.js";

/**
 * Claude Desktop, Claude Code, and Cursor all use a near-identical config
 * shape: a top-level "mcpServers" object keyed by server name. This parser
 * normalizes that shared shape into McpServerEntry[].
 *
 * Throws if the file is not valid JSON. Returns an empty array (rather than
 * throwing) if the file is valid JSON but has no "mcpServers" key, since
 * that's a normal state for an unconfigured client.
 */
export function parseConfigFile(filePath: string): McpServerEntry[] {
  const raw = readFileSync(filePath, "utf-8");
  const data = JSON.parse(raw) as unknown;
  return parseConfigObject(data, filePath);
}

export function parseConfigObject(data: unknown, sourceFile: string): McpServerEntry[] {
  if (typeof data !== "object" || data === null) return [];
  const servers = (data as Record<string, unknown>).mcpServers;
  if (typeof servers !== "object" || servers === null) return [];

  const entries: McpServerEntry[] = [];
  for (const [name, rawEntry] of Object.entries(servers as Record<string, unknown>)) {
    if (typeof rawEntry !== "object" || rawEntry === null) continue;
    const entry = rawEntry as Record<string, unknown>;

    const url = typeof entry.url === "string" ? entry.url : undefined;
    const command = typeof entry.command === "string" ? entry.command : undefined;
    const args = Array.isArray(entry.args) ? entry.args.filter((a): a is string => typeof a === "string") : undefined;
    const env =
      typeof entry.env === "object" && entry.env !== null
        ? Object.fromEntries(
            Object.entries(entry.env as Record<string, unknown>).filter(
              (pair): pair is [string, string] => typeof pair[1] === "string",
            ),
          )
        : undefined;

    const transport: McpServerEntry["transport"] = url ? "http" : command ? "stdio" : "unknown";

    entries.push({ name, transport, command, args, url, env, sourceFile });
  }
  return entries;
}
