# Security Policy

## Supported Versions
We currently provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.7   | :white_check_mark: |

### 🟢 Not a Vulnerability (Report via Public Issue)
Fabrica-STAR relies on pattern matching and heuristics rather than formal auditing. The following scenarios are considered **rule improvements or bugs**, not security vulnerabilities:
* **False Negatives:** The scanner fails to flag a dangerous MCP server or a risky configuration.
* **False Positives:** The scanner incorrectly flags safe code or local `mcp.json` settings.
* **Bypass:** A user finds a way to write an MCP server that bypasses the current `scan-source` detection rules[cite: 1].

*For these, please open a standard GitHub Issue or submit a PR.*

### 🔴 Is a Vulnerability (Report Privately)
A true vulnerability occurs if a maliciously crafted configuration file or server source code compromises the machine running Fabrica-STAR. Examples include:
* **Arbitrary Code Execution (RCE):** Running `fabrica-star scan` or `scan-source` triggers malicious shell commands.
* **Path Traversal:** The scanner can be tricked into reading or exposing sensitive files outside the intended directories during analysis.
* **Credential Leakage:** The CLI accidentally logs or transmits environment variables or API keys from the host machine.

## Reporting a Vulnerability

If you discover a legitimate security vulnerability in Fabrica-STAR itself, **please do not open a public issue.**

Instead, please report it using one of the following methods:
1. **GitHub Private Vulnerability Reporting:** Go to the "Security" tab of this repository and click "Report a vulnerability".
2. **THREADS:** Send a detailed report to **@fabrica_tw** on Threads.

### What to include in your report:
* A detailed description of the vulnerability and its potential impact.
* Step-by-step instructions to reproduce the issue.
* A sample malicious config file or code snippet (if applicable).
* Your environment details (OS, Node.js version, and Fabrica-STAR version).

### What to expect:
1. We will acknowledge receipt of your vulnerability report within **48 hours**.
2. We will investigate the issue and confirm whether it is a valid security flaw.
3. If valid, we will develop a patch, issue a CVE/Security Advisory if necessary, and release an update.
