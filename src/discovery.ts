import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Returns candidate paths for known MCP client configs, filtered to ones
 * that actually exist on disk. Covers Claude Desktop, Claude Code, and
 * Cursor, since those three account for the bulk of MCP client usage.
 */
export function discoverConfigFiles(cwd: string = process.cwd()): string[] {
  const home = homedir();
  const candidates: string[] = [];

  // Claude Desktop
  if (process.platform === "darwin") {
    candidates.push(join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"));
  } else if (process.platform === "win32") {
    const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");
    candidates.push(join(appData, "Claude", "claude_desktop_config.json"));
  } else {
    candidates.push(join(home, ".config", "Claude", "claude_desktop_config.json"));
  }

  // Claude Code: project-level and user-level
  candidates.push(join(cwd, ".mcp.json"));
  candidates.push(join(home, ".claude.json"));

  // Cursor: project-level and user-level
  candidates.push(join(cwd, ".cursor", "mcp.json"));
  candidates.push(join(home, ".cursor", "mcp.json"));

  return [...new Set(candidates)].filter((path) => existsSync(path));
}
