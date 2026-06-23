# Fabrica-STAR

**Know what you're installing before you `npx` it.**

A lightweight, zero-config security scanner for [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers — the things Claude Desktop, Claude Code, Cursor, and friends connect to when you give an AI agent tools.

[![CI](https://github.com/FadedCantCode/Fabrica-STAR/actions/workflows/ci.yml/badge.svg)](https://github.com/FadedCantCode/Fabrica-STAR/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/fabrica-star.svg)](https://www.npmjs.com/package/fabrica-star)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](package.json)

**[Try the web playground →](https://fadedcantcode.github.io/Fabrica-STAR)**

---

## Why this exists

MCP exploded from a niche protocol into the default way AI agents reach external tools — and the ecosystem grew faster than the tooling to vet it. Independent research auditing thousands of public MCP servers has found that a large share ship with no authentication at all and are vulnerable to common issues like SSRF, with only a small minority using OAuth (see [BlueRock Security's 2026 analysis](https://www.mcpbundles.com/blog/best-mcp-servers)). Most of the security tooling that has shown up to address this targets enterprise procurement — SOC 2 audits, SSO, compliance dashboards.

If you're an individual developer who just typed `npx some-mcp-server` into your config, none of that helps you. **Fabrica-STAR is the five-second gut check for the rest of us:** point it at your config or a server's source, get a plain-English report, move on.

## What it does

- **`scan`** — auto-discovers MCP configs for Claude Desktop, Claude Code, and Cursor, and flags risky setups: hardcoded credentials, plaintext HTTP to remote hosts, unpinned package versions, overly broad filesystem access, and matches against a community-maintained known-bad list.
- **`scan-config <path>`** — same checks against a specific config file (useful in CI, or for configs in non-default locations).
- **`scan-source <path>`** — static analysis of an MCP server's own source code for risky patterns: `eval`, shell injection via `exec`/`os.system`, `shell: true`, dynamically-interpolated fetch URLs, and hardcoded API keys.

No telemetry, no network calls, no account. It reads files on your disk and prints a report.

## Install

```bash
npx fabrica-star scan
```

or install it globally:

```bash
npm install -g fabrica-star
fabrica-star scan
```

## Example

```
$ fabrica-star scan-config examples/sample-claude-config.json

fabrica-star scan results

⚠ filesystem [MEDIUM]
   source: examples/sample-claude-config.json
   - [no-version-pin] "npx @modelcontextprotocol/server-filesystem" has no version pin, so it
     will silently run whatever is published as "latest" on every launch. Pin a version
     (e.g. "@modelcontextprotocol/server-filesystem@1.2.3") to avoid an unreviewed update
     changing behavior under you.
   - [unscoped-filesystem-access] "filesystem" is configured with a filesystem root ("/")
     instead of a scoped subdirectory. Scope it to the narrowest directory the server
     actually needs.

✖ github [HIGH]
   source: examples/sample-claude-config.json
   - [no-version-pin] ...
   - [hardcoded-secret] env var "GITHUB_TOKEN" appears to contain a literal credential
     rather than a ${VAR} reference. If this config file is ever committed or shared,
     the credential leaks with it.

✖ internal-api [HIGH]
   source: examples/sample-claude-config.json
   - [insecure-transport] "internal-api" connects over plain HTTP to a non-local host
     (http://internal.example.com/mcp). Traffic, including any auth tokens, can be
     intercepted in transit. Use an https:// endpoint.

✔ well-configured [clean]
   source: examples/sample-claude-config.json

Summary: 4 servers scanned · 1 clean · 1 medium · 2 high
```

Try it yourself against the bundled example:

```bash
git clone https://github.com/FadedCantCode/Fabrica-STAR.git
cd Fabrica-STAR && npm install && npm run build
node dist/cli.js scan-config examples/sample-claude-config.json
```

## CLI reference

```
fabrica-star scan                       Auto-discover and scan known client configs
fabrica-star scan-config <path>         Scan a specific config file
fabrica-star scan-source <path>         Static-scan a server's source for risky code patterns
fabrica-star report <server-or-pkg>     Open a pre-filled GitHub issue to flag a suspicious server

Options (scan commands):
  --json                Machine-readable output, for piping into other tools
  --offline             Skip remote known-bad list fetch and npm registry checks
  --fail-on <severity>  Exit non-zero at or above this severity (default: high)
                         One of: info, low, medium, high, critical
```

The non-zero exit code on findings means you can drop it straight into CI:

```yaml
- run: npx fabrica-star scan-config .mcp.json --fail-on high
```

Or use the official GitHub Action:

```yaml
- name: Scan MCP servers
  uses: FadedCantCode/Fabrica-STAR@v0.1.0
  with:
    config-path: .mcp.json
    fail-on: high
```

The action annotates findings directly on your PR as code scanning alerts.

## Severity levels

| Severity | Meaning |
|---|---|
| `critical` | Near-certain exploit path (e.g. a literal API key in a file) |
| `high` | Real, common attack surface (plaintext credentials reference, HTTP to a remote host, shell injection) |
| `medium` | Hygiene issue worth fixing, not proof of a vulnerability (unpinned version, overly broad scope) |
| `low` / `info` | Worth knowing, low practical risk (e.g. plaintext HTTP to localhost) |

## What this is *not*

- Not a guarantee of safety. It's pattern matching, not a formal audit — a clean report means "nothing obvious," not "definitely safe."
- Not an enterprise gateway. If you need SSO, RBAC, and compliance attestations across a fleet of agents, look at the MCP gateway products built for that; this tool is intentionally scoped to the "single developer, thirty seconds" use case.
- Not a replacement for reading the source of anything you give filesystem or shell access to.

## Contributing

PRs welcome — new rules, new known-bad entries (with a source), bug reports on false positives. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
