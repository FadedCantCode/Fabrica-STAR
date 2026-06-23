# Fabrica-STAR

**Know what you're installing before you `npx` it.**

A security scanner for [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers — the things Claude Desktop, Claude Code, Cursor, and friends connect to when you give an AI agent tools.

[![CI](https://github.com/FadedCantCode/Fabrica-STAR/actions/workflows/ci.yml/badge.svg)](https://github.com/FadedCantCode/Fabrica-STAR/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/fabrica-star.svg)](https://www.npmjs.com/package/fabrica-star)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)

**[Try the web playground →](https://fadedcantcode.github.io/Fabrica-STAR)**

---

## Why this exists

MCP exploded from a niche protocol into the default way AI agents reach external tools — and the ecosystem grew faster than the tooling to vet it. Over 40 CVEs were filed against MCP implementations in the first four months of 2026 alone. The postmark-mcp backdoor silently BCC'd emails from ~300 organizations before anyone noticed. Most security tooling that has shown up targets enterprise procurement: SOC 2 audits, SSO, compliance dashboards, API keys required.

If you're an individual developer who just typed `npx some-mcp-server` into your config, none of that helps you. **Fabrica-STAR is the five-second gut check for the rest of us.**

## Philosophy

Most MCP security tooling is enterprise-first: accounts, dashboards, pricing tiers. Fabrica-STAR is the opposite. One command. No account. Works offline. MIT license. Top of the line security tooling, available to everyone.

---

## Install

```bash
npx fabrica-star scan
```

or install globally:

```bash
npm install -g fabrica-star
fabrica-star scan
```

---

## What it checks

Every server in your config goes through all of these:

| Check | What it catches |
|---|---|
| Hardcoded secrets | API keys, tokens, JWTs literal in env vars |
| Unpinned versions | Silent `latest` installs — supply chain entry point |
| Insecure transport | Plain HTTP to remote hosts |
| Unscoped filesystem | Root `/` or `~` access |
| Known-malicious servers | 19 confirmed CVEs (postmark-mcp, mcp-remote, gemini-mcp-tool, and more) |
| Typosquat detection | Levenshtein distance vs popular MCP packages |
| OSV / CVE audit | Live vulnerability check via api.osv.dev — no API key |
| npm Provenance | Sigstore attestation — cryptographic proof of build origin |
| Maintainer trust | Ownership transfers, publish anomalies, abandoned-then-revived packages |
| Blast radius | Sensitive files reachable from filesystem servers (SSH keys, AWS creds, .env) |
| **Compound blast radius** | **Cross-server attack chains: filesystem + HTTP = complete exfiltration pipeline** |
| **Tool pinning** | **Shasum rug pull detection — alerts if a package changes without a version bump** |

No account required. Network checks (OSV, npm registry, provenance) are opt-out via `--offline`.

---

## Example output

```
$ fabrica-star scan-config examples/sample-claude-config.json --offline

fabrica-star scan results

✖ filesystem [HIGH]
   source: examples/sample-claude-config.json
   - [no-version-pin] "npx @modelcontextprotocol/server-filesystem" has no version
     pin — will silently run "latest" on every launch.
   - [unscoped-filesystem-access] root "/" configured. Scope to the narrowest
     directory the server actually needs.
   - [blast-radius-sensitive-files] This server has access to / which contains
     sensitive files:
       ~/.ssh/id_rsa          (SSH private key)
       ~/.aws/credentials     (AWS credentials)
       ~/projects/.env        (env file)

✖ github [HIGH]
   source: examples/sample-claude-config.json
   - [no-version-pin] "npx @modelcontextprotocol/server-github" has no version pin.
   - [hardcoded-secret] env var "GITHUB_TOKEN" contains a literal credential.
     If this config is committed or shared, the credential leaks with it.

✖ internal-api [HIGH]
   source: examples/sample-claude-config.json
   - [insecure-transport] plain HTTP to internal.example.com. Use https://.

✔ well-configured [clean]

General
   - [compound-exfiltration-chain] COMPOUND RISK
     [filesystem] can READ files from your filesystem (/)
     [internal-api] can SEND data to remote hosts (internal.example.com)
     Combined: if either server is compromised, credentials reachable by
     [filesystem] could be exfiltrated via [internal-api].

   - [compound-credential-pivot] COMPOUND RISK
     [github] has hardcoded credentials in its env vars
     [internal-api] can make outbound HTTP requests
     Combined: a compromised [internal-api] could exfiltrate [github]'s credentials.

Summary: 4 servers scanned · 1 clean · 3 high
```

---

## Permission prompt format

```bash
fabrica-star scan-config .mcp.json --format permissions
```

```
fabrica-star · permission audit

✖ Compromise of "filesystem" could:
   WRITE    full filesystem write access (root path configured)
   READ     / — SSH keys, AWS credentials, .env files reachable

✖ Compromise of "github" could:
   EXPOSE   GITHUB_TOKEN (hardcoded credential)

✖ Compromise of "internal-api" could:
   NETWORK  http://internal.example.com/mcp

✔ Compromise of "well-configured" could:
   (no exploitable capabilities found)
```

---

## Rug pull detection (tool pinning)

Pin the current shasum of every package in your config. Future scans alert if a package changes without a version bump — the exact pattern used in the postmark-mcp backdoor.

```bash
# Record current shasums
fabrica-star pin

# Found 3 servers across 1 config file.
#   ✔ pinned @modelcontextprotocol/server-github@1.4.0 (a3f8c2d1...)
#   ✔ pinned @modelcontextprotocol/server-fetch@1.2.1  (b9e4f7a2...)

# Subsequent scans automatically check pins
fabrica-star scan
# ✖ [tool-pin-mismatch] RUG PULL DETECTED: "some-mcp@1.2.3" shasum changed!
#   Previously: a3f8c2d1...  (pinned 2026-06-23)
#   Current:    ff00dead...
#   Do NOT run this server until you have audited the source.

# List all pinned packages
fabrica-star pin --list

# Remove a specific pin
fabrica-star pin --clear some-mcp@1.2.3
```

---

## Watch mode

```bash
fabrica-star watch
```

Monitors all discovered MCP config files in real time. On every save, shows exactly what changed:

```
08:59:36  fabrica-star watch — monitoring 2 config files
          claude_desktop_config.json, .mcp.json

Initial scan: 4 servers · 1 critical · 2 high · 1 clean

Watching for changes. Press Ctrl+C to stop.

── Config changed: claude_desktop_config.json ──────────────

✖ NEW SERVER  evil-mcp  [critical]
   [known-flagged-server]  matches known-malicious list
   [hardcoded-secret]  OPENAI_KEY contains a literal credential

⚠ CHANGED  github
   + hardcoded-secret
   − no-version-pin
```

Detects new servers the moment they are added, shows new and resolved findings as a diff, and handles editor temp-file swaps gracefully. Use `--offline` to skip network checks on each rescan.

---

## Source scanning

```bash
fabrica-star scan-source ./path/to/mcp-server/src
```

Detects: `eval()`, `new Function()`, shell injection via `exec`/`os.system`, `shell: true`, dynamically-interpolated fetch URLs, hardcoded API keys, prompt injection strings (`ignore previous instructions`), and tool poisoning coercion patterns (`you must call this`).

---

## CI integration

Non-zero exit on findings — drop it into any pipeline:

```yaml
- run: npx fabrica-star scan-config .mcp.json --fail-on high
```

SARIF output for GitHub Security tab:

```yaml
- run: npx fabrica-star scan --format sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

Official GitHub Action:

```yaml
- name: Scan MCP servers
  uses: FadedCantCode/Fabrica-STAR@v0.1.7
  with:
    config-path: .mcp.json
    fail-on: high
```

---

## Policy as code

Commit a `.fabrica-star.yml` so the whole team shares the same rules:

```yaml
fail-on: high
offline: false
rules:
  no-version-pin: error
  npm-low-download-count: off
allow:
  scopes:
    - "@modelcontextprotocol"
    - "@mycompany"
```

Generate a starter file: `fabrica-star init`

---

## CLI reference

```
fabrica-star scan                       Auto-discover configs across 9 IDEs
                                        (Claude Desktop, Claude Code, Cursor, VS Code,
                                         Windsurf, Zed, Warp, Cline, Roo)
fabrica-star scan-config <path>         Scan a specific config file
fabrica-star scan-source <path>         Static-scan server source code
fabrica-star watch                      Continuously monitor config files for changes
fabrica-star pin                        Record package shasums for rug pull detection
fabrica-star pin --list                 List all pinned packages
fabrica-star pin --clear <pkg@version>  Remove a specific pin
fabrica-star report <server-or-pkg>     Open a pre-filled GitHub issue to flag a server
fabrica-star install-hook               Install a git pre-commit hook
fabrica-star init                       Create a starter .fabrica-star.yml policy file

Options (scan commands):
  --format <format>     Output format: text, json, sarif, permissions (default: text)
  --json                Shorthand for --format json
  --offline             Skip all network checks (OSV, npm registry, provenance, blocklist)
  --fail-on <severity>  Exit non-zero at or above this severity (default: high)
                         One of: info, low, medium, high, critical
  --no-policy           Ignore .fabrica-star.yml policy file
```

---

## Severity levels

| Severity | Meaning |
|---|---|
| `critical` | Near-certain exploit path — known CVE, rug pull detected, backdoor match |
| `high` | Real attack surface — hardcoded secrets, plain HTTP, shell injection, compound risk |
| `medium` | Hygiene issue — unpinned version, no provenance attestation |
| `low` / `info` | Worth knowing, low practical risk |

---

## What this is *not*

- Not a guarantee of safety. Pattern matching is not a formal audit — a clean report means "nothing obvious," not "definitely safe."
- Not an enterprise gateway. If you need SSO, RBAC, and compliance attestations across a fleet of agents, look at the gateway products built for that.
- Not a replacement for reading the source of anything you give filesystem or shell access to.

---

## Contributing

PRs welcome — new rules, new known-bad entries (with a verifiable source link), bug reports on false positives. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
