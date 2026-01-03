# A/B Validation Testbed Setup Guide

**Status**: Production Ready
**Version**: 1.0
**Last Updated**: 2026-01-03

---

## Overview

The A/B validation testbed proves behavior-based detection by testing **identical tool names** against two servers with different implementations:

| Server             | Port  | Implementation                         | Expected Result      |
| ------------------ | ----- | -------------------------------------- | -------------------- |
| **vulnerable-mcp** | 10900 | Exploitable code                       | 176+ vulnerabilities |
| **hardened-mcp**   | 10901 | Safe implementations (SAME tool names) | 0 vulnerabilities    |

**Key Insight**: Both servers expose the same 29 tools (e.g., `vulnerable_calculator_tool`, `safe_storage_tool_mcp`). The Inspector detects vulnerabilities based on **actual behavior**, not tool names.

---

## Testbed Location

```
/home/bryan/mcp-servers/mcp-vulnerable-testbed/
├── src/                    # Vulnerable server source
│   ├── server.py          # Main MCP server (27,249 lines)
│   ├── vulnerable_tools.py # 13 vulnerable tools
│   └── safe_tools.py      # 6 safe control tools
├── src-hardened/          # Hardened server source
├── docker-compose.yml     # Container configuration
├── test-both-servers.sh   # Validation script
└── expected_results.json  # Baseline results
```

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
# 1. Start both servers
cd /home/bryan/mcp-servers/mcp-vulnerable-testbed
docker compose up -d

# 2. Verify servers are running
docker ps --filter "name=testbed"
# Should show: mcp-vulnerable-testbed, mcp-hardened-testbed

# 3. Test connectivity
curl -s -X POST http://localhost:10900/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq '.result.tools | length'
# Expected: 29

curl -s -X POST http://localhost:10901/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq '.result.tools | length'
# Expected: 29
```

### Option 2: Direct Python (Without Docker)

```bash
# Terminal 1: Start vulnerable server
cd /home/bryan/mcp-servers/mcp-vulnerable-testbed
source .venv/bin/activate
SERVER_PORT=10900 TRANSPORT=http python3 src/server.py &

# Terminal 2: Start hardened server
cd /home/bryan/mcp-servers/mcp-vulnerable-testbed
source .venv/bin/activate
SERVER_PORT=10901 TRANSPORT=http python3 src-hardened/server.py &
```

---

## Configuration Files

### Vulnerable Server Config

Create `/tmp/vulnerable-mcp-config.json`:

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

### Hardened Server Config

Create `/tmp/hardened-mcp-config.json`:

```json
{
  "transport": "http",
  "url": "http://localhost:10901/mcp"
}
```

### Create Both Configs (One Command)

```bash
echo '{"transport": "http", "url": "http://localhost:10900/mcp"}' > /tmp/vulnerable-mcp-config.json
echo '{"transport": "http", "url": "http://localhost:10901/mcp"}' > /tmp/hardened-mcp-config.json
```

---

## Validation Workflow

### Step 1: Run Against Vulnerable Server

```bash
cd /home/bryan/inspector
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json
```

**Expected Output**:

- 176+ vulnerabilities detected
- Security score: ~53%
- Risk level: CRITICAL
- 29 tools discovered

### Step 2: Run Against Hardened Server

```bash
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json
```

**Expected Output**:

- 0 vulnerabilities detected
- Security score: 100%
- Risk level: LOW/MEDIUM
- 29 tools discovered (SAME tool names!)

### Step 3: Verify Zero False Positives

Both servers have 6 `safe_*` tools that should NEVER be flagged:

```bash
# Check vulnerable server results
cat /tmp/inspector-assessment-vulnerable-mcp.json | \
  jq '[.security.promptInjectionTests[] |
      select(.toolName | startswith("safe_")) |
      select(.vulnerable == true)] | length'
# Expected: 0

# Check hardened server results
cat /tmp/inspector-assessment-hardened-mcp.json | \
  jq '[.security.promptInjectionTests[] |
      select(.toolName | startswith("safe_")) |
      select(.vulnerable == true)] | length'
# Expected: 0
```

---

## Tool Breakdown

### Vulnerable Tools (13)

| Tool                              | Vulnerability Type       | Risk   |
| --------------------------------- | ------------------------ | ------ |
| vulnerable_calculator_tool        | Command Injection        | HIGH   |
| vulnerable_system_exec_tool       | System Command Execution | HIGH   |
| vulnerable_data_leak_tool         | Data Exfiltration        | HIGH   |
| vulnerable_tool_override_tool     | Tool Shadowing           | HIGH   |
| vulnerable_config_modifier_tool   | Configuration Drift      | HIGH   |
| vulnerable_fetcher_tool           | SSRF                     | HIGH   |
| vulnerable_deserializer_tool      | Insecure Deserialization | HIGH   |
| vulnerable_template_tool          | SSTI                     | HIGH   |
| vulnerable_file_reader_tool       | Path Traversal           | HIGH   |
| vulnerable_unicode_processor_tool | Unicode Bypass           | MEDIUM |
| vulnerable_nested_parser_tool     | Nested Injection         | MEDIUM |
| vulnerable_package_installer_tool | Typosquatting            | MEDIUM |
| vulnerable_rug_pull_tool          | Temporal/Rug Pull        | MEDIUM |

### Safe Control Tools (6)

| Tool                   | Purpose                                  |
| ---------------------- | ---------------------------------------- |
| safe_storage_tool_mcp  | Stores data without execution            |
| safe_search_tool_mcp   | Searches without executing queries       |
| safe_list_tool_mcp     | Lists resources with safe errors         |
| safe_info_tool_mcp     | Gets info with safe error reflection     |
| safe_echo_tool_mcp     | Echoes data without execution            |
| safe_validate_tool_mcp | Validates and rejects malicious patterns |

### Utility Tools (2)

| Tool                | Purpose                  |
| ------------------- | ------------------------ |
| get_testbed_info    | Returns server metadata  |
| reset_testbed_state | Clears stateful tracking |

---

## Acceptance Criteria for Inspector Changes

Before merging any changes to MCP Inspector detection logic:

| Criterion            | Requirement          | Verification                               |
| -------------------- | -------------------- | ------------------------------------------ |
| Vulnerable Detection | ≥176 vulnerabilities | `jq '.security.vulnerabilities \| length'` |
| Hardened Detection   | 0 vulnerabilities    | Same tool names, 0 flagged                 |
| Zero False Positives | 0 on safe\_\* tools  | Both servers                               |
| Test Suite           | All ~1000 tests pass | `npm test`                                 |

### Quick Verification Script

```bash
#!/bin/bash
# save as: verify-testbed.sh

echo "Running vulnerable-mcp assessment..."
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json

echo "Running hardened-mcp assessment..."
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json

echo ""
echo "=== RESULTS ==="
VULN_COUNT=$(cat /tmp/inspector-assessment-vulnerable-mcp.json | jq '.security.vulnerabilities | length')
HARD_COUNT=$(cat /tmp/inspector-assessment-hardened-mcp.json | jq '.security.vulnerabilities | length')
SAFE_FP_VULN=$(cat /tmp/inspector-assessment-vulnerable-mcp.json | jq '[.security.promptInjectionTests[] | select(.toolName | startswith("safe_")) | select(.vulnerable == true)] | length')
SAFE_FP_HARD=$(cat /tmp/inspector-assessment-hardened-mcp.json | jq '[.security.promptInjectionTests[] | select(.toolName | startswith("safe_")) | select(.vulnerable == true)] | length')

echo "Vulnerable server: $VULN_COUNT vulnerabilities (expected: ≥176)"
echo "Hardened server: $HARD_COUNT vulnerabilities (expected: 0)"
echo "False positives (vulnerable): $SAFE_FP_VULN (expected: 0)"
echo "False positives (hardened): $SAFE_FP_HARD (expected: 0)"

if [ "$HARD_COUNT" -eq 0 ] && [ "$SAFE_FP_VULN" -eq 0 ] && [ "$SAFE_FP_HARD" -eq 0 ]; then
  echo ""
  echo "✅ PASS: Zero false positives, behavior-based detection working"
else
  echo ""
  echo "❌ FAIL: Check detection logic"
  exit 1
fi
```

---

## Regression Testing Procedure

### 1. Save Baseline (Before Changes)

```bash
mkdir -p /tmp/baseline
cp /tmp/inspector-assessment-vulnerable-mcp.json /tmp/baseline/
cp /tmp/inspector-assessment-hardened-mcp.json /tmp/baseline/
```

### 2. Make Code Changes

Edit Inspector detection logic as needed.

### 3. Run Both Servers

```bash
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json
```

### 4. Compare Results

```bash
# Compare vulnerability counts
echo "Baseline vulnerable: $(jq '.security.vulnerabilities | length' /tmp/baseline/inspector-assessment-vulnerable-mcp.json)"
echo "Current vulnerable: $(jq '.security.vulnerabilities | length' /tmp/inspector-assessment-vulnerable-mcp.json)"

echo "Baseline hardened: $(jq '.security.vulnerabilities | length' /tmp/baseline/inspector-assessment-hardened-mcp.json)"
echo "Current hardened: $(jq '.security.vulnerabilities | length' /tmp/inspector-assessment-hardened-mcp.json)"
```

### 5. Verify Gap Unchanged or Improved

- Vulnerable count should stay the same or increase
- Hardened count should stay at 0
- No new false positives on safe\_\* tools

---

## Troubleshooting

| Issue                         | Cause                             | Fix                                                                               |
| ----------------------------- | --------------------------------- | --------------------------------------------------------------------------------- |
| Port already in use           | Previous server still running     | `docker compose down` or `kill $(lsof -t -i:10900)`                               |
| Connection refused            | Server not running                | Check with `docker ps` or `ps aux \| grep python`                                 |
| Different vulnerability count | Code changes or test data changed | Compare tool list with baseline                                                   |
| Docker not starting           | Missing dependencies              | Run `docker compose build` first                                                  |
| Python venv issues            | Missing venv                      | `cd testbed && uv venv .venv && source .venv/bin/activate && uv pip install -e .` |

### Check Server Health

```bash
# Docker health
docker inspect mcp-vulnerable-testbed --format='{{.State.Health.Status}}'

# Direct HTTP test
curl -s http://localhost:10900/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' | jq '.result.tools[0].name'
```

---

## Architecture Diagram

```
┌────────────────────────────────────────────────────────────────┐
│                    A/B VALIDATION TESTBED                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ┌──────────────────┐         ┌──────────────────┐           │
│  │  VULNERABLE-MCP  │         │   HARDENED-MCP   │           │
│  │  Port: 10900     │         │   Port: 10901    │           │
│  │                  │         │                  │           │
│  │  Same 29 tools:  │         │  Same 29 tools:  │           │
│  │  - calculator    │         │  - calculator    │           │
│  │  - system_exec   │         │  - system_exec   │           │
│  │  - data_leak     │         │  - data_leak     │           │
│  │  - ...           │         │  - ...           │           │
│  │                  │         │                  │           │
│  │  EXECUTES        │         │  REFLECTS/LOGS   │           │
│  │  malicious       │         │  malicious       │           │
│  │  payloads        │         │  payloads        │           │
│  └────────┬─────────┘         └────────┬─────────┘           │
│           │                            │                      │
│           ▼                            ▼                      │
│  ┌──────────────────┐         ┌──────────────────┐           │
│  │  RESULT: 176+    │         │  RESULT: 0       │           │
│  │  vulnerabilities │         │  vulnerabilities │           │
│  │  CRITICAL risk   │         │  LOW risk        │           │
│  └──────────────────┘         └──────────────────┘           │
│                                                                │
│  ════════════════════════════════════════════════════════     │
│  PROOF: Behavior-based detection, not name-based heuristics   │
│  ════════════════════════════════════════════════════════     │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Related Documentation

- [Vulnerability Testbed Details](mcp_vulnerability_testbed.md) - Full validation results
- [Security Assessment Guide](ASSESSMENT_CATALOG.md) - Security module reference
- [CLAUDE.md](../CLAUDE.md) - Project conventions and testbed usage

---

## Version History

| Version | Date       | Changes         |
| ------- | ---------- | --------------- |
| 1.0     | 2026-01-03 | Initial release |
