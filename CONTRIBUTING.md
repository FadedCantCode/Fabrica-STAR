# Contributing to mcp-sentinel

Thanks for considering a contribution. This project stays useful only if its
rules and known-bad list are accurate, so the bar for new entries is
**evidence, not suspicion**.

## Development setup

```bash
git clone https://github.com/<your-fork>/mcp-sentinel.git
cd mcp-sentinel
npm install
npm run build
npm test
```

Use `npm run dev -- scan` to run the CLI directly from source via `tsx`,
without building first.

## Adding a config or source rule

Rules live in `src/rules/configRules.ts` (checks against parsed MCP client
config entries) and `src/rules/sourceRules.ts` (regex-based static checks
against server source code).

A good rule:

- Has a unique `ruleId` in `kebab-case`.
- Picks the lowest severity that's still honest. Reserve `critical` for
  things that are close to certainly exploitable (e.g. a literal credential
  in plaintext), and `medium`/`low` for hygiene issues that are worth
  surfacing but aren't proof of a vulnerability.
- Ships with tests covering both a triggering case and a non-triggering case
  (see `test/configRules.test.ts` and `test/sourceScanner.test.ts` for the
  pattern).
- Explains *why* in its `message`, not just *what*. The person reading the
  output should be able to act on it without opening an issue to ask what it
  means.

## Adding to the known-flagged-servers list

Edit `data/known-flagged-servers.json`. Every entry must include a `reason`
that links to or names a public source (a security advisory, a GitHub issue,
a writeup) — not "I heard this was sketchy." PRs that add entries without a
verifiable source will be asked for one before merge.

## Reporting a false positive

Open an issue with the config or source snippet that triggered the finding
(redact real credentials/URLs first). If a rule is too aggressive, the fix is
usually to narrow its regex/condition, not to remove it outright — false
negatives are worse than false positives for a security tool, so we lean
toward over-flagging, but real false positives are still bugs.

## Code style

- TypeScript, strict mode. No `any` unless there's a comment explaining why.
- Keep functions small and named after what they check (`checkX`, not
  `validate` or `process`).
- No new runtime dependencies without discussion in an issue first — part of
  this tool's value is that it has a tiny, auditable dependency tree.
