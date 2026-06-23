import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Returns candidate paths for known MCP client configs, filtered to ones
 * that actually exist on disk. Covers Claude Desktop, Claude Code, Cursor,
 * VS Code, Windsurf, Zed, and Warp.
 */
export function discoverConfigFiles(cwd: string = process.cwd()): string[] {
  const home = homedir();
  const candidates: string[] = [];

  // ── Claude Desktop ──────────────────────────────────────────────────────
  if (process.platform === "darwin") {
    candidates.push(join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"));
  } else if (process.platform === "win32") {
    const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");
    candidates.push(join(appData, "Claude", "claude_desktop_config.json"));
  } else {
    candidates.push(join(home, ".config", "Claude", "claude_desktop_config.json"));
  }

  // ── Claude Code ──────────────────────────────────────────────────────────
  candidates.push(join(cwd, ".mcp.json"));
  candidates.push(join(home, ".claude.json"));

  // ── Cursor ───────────────────────────────────────────────────────────────
  candidates.push(join(cwd, ".cursor", "mcp.json"));
  candidates.push(join(home, ".cursor", "mcp.json"));

  // ── VS Code (GitHub Copilot / Continue) ──────────────────────────────────
  candidates.push(join(cwd, ".vscode", "mcp.json"));
  if (process.platform === "darwin") {
    candidates.push(join(home, "Library", "Application Support", "Code", "User", "mcp.json"));
  } else if (process.platform === "win32") {
    const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");
    candidates.push(join(appData, "Code", "User", "mcp.json"));
  } else {
    candidates.push(join(home, ".config", "Code", "User", "mcp.json"));
  }

  // ── Windsurf (Codeium) ───────────────────────────────────────────────────
  candidates.push(join(home, ".codeium", "windsurf", "mcp_config.json"));
  candidates.push(join(cwd, ".windsurf", "mcp.json"));

  // ── Zed ──────────────────────────────────────────────────────────────────
  if (process.platform === "darwin") {
    candidates.push(join(home, "Library", "Application Support", "Zed", "mcp.json"));
  } else {
    candidates.push(join(home, ".config", "zed", "mcp.json"));
  }

  // ── Warp ─────────────────────────────────────────────────────────────────
  candidates.push(join(home, ".warp", "mcp_config.json"));

  // ── Cline / Roo (VSCode extension) ───────────────────────────────────────
  candidates.push(join(cwd, ".roo", "mcp.json"));
  candidates.push(join(cwd, ".cline", "mcp.json"));

  return [...new Set(candidates)].filter((path) => existsSync(path));
}
