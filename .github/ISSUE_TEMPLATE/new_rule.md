---
name: New rule or known-bad entry
about: Suggest a security check or flag a specific MCP server
labels: enhancement
---

**What should be checked / flagged?**

<!-- Describe the pattern, config issue, or specific server -->

**Why is this a security concern?**

<!-- Link to a public advisory, CVE, writeup, or GitHub issue. 
     Entries without a verifiable public source will be asked for one before merge. -->

**Example that should trigger the check**

```json
{
  "mcpServers": {
    "example": { }
  }
}
```

**Example that should NOT trigger (to avoid false positives)**

```json

```

**Suggested severity** (`low` / `medium` / `high` / `critical`)

<!-- See README for severity definitions -->
