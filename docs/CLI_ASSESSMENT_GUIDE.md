# MCP Inspector CLI Assessment Guide

**Version**: 1.23.1
**Status**: Stable
**Target Audience**: MCP developers, CI/CD engineers, automated testing systems

---

## Quick Start

### Installation

```bash
# Install globally
npm install -g @bryan-thompson/inspector-assessment

# Or use with npx (no install needed)
npx @bryan-thompson/inspector-assessment --help
```

### 30-Second Example

```bash
# Run full assessment on an MCP server
mcp-assess-full --server memory-mcp --config /tmp/config.json

# Output: Results saved to /tmp/inspector-full-assessment-memory-mcp.json
```

---

## Table of Contents

1. [Three Assessment Modes](#three-assessment-modes)
2. [Configuration Files](#configuration-files)
3. [Logging & Diagnostics](#logging--diagnostics)
4. [Output & Results](#output--results)
5. [Common Use Cases](#common-use-cases)
6. [JSONL Event Streaming](#jsonl-event-streaming)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Options](#advanced-options)

---

## Three Assessment Modes

The MCP Inspector provides three distinct CLI modes for different workflows:

### Mode 1: Local Development Script

**Purpose**: Development, testing, quick iterations
**Command**: `npm run assess:full`
**Location**: `/home/bryan/inspector/cli/src/assess-full.ts` (unified CLI)
**Available**: When running from source code (requires `npm run build-cli` first)

```bash
# Runs full assessment with all assessment modules
npm run assess:full -- --server <server-name>

# With config file
npm run assess:full -- --server my-server --config /tmp/config.json

# Output goes to /tmp/inspector-full-assessment-my-server.json
```

**Key Characteristics:**

- Uses the same CLI binary as the published npm package
- All features available (resource/prompt assessment, comparison mode, etc.)
- Requires `npm run build-cli` after code changes
- Fastest iteration cycle for testing CLI features
- Requires Node.js and npm install

> **Migration Note**: The legacy script (`scripts/run-full-assessment.ts`) is deprecated
> and available via `npm run assess:full:legacy` during the transition period.
> See [GitHub Issue #19](https://github.com/triepod-ai/inspector-assessment/issues/19).

**Command Signature:**

```
npm run assess:full -- [options] [server-name]

Options:
  --server, -s <name>     Server name (required or positional)
  --config, -c <path>     Server config JSON file
  --output, -o <path>     Output JSON path
  --source <path>         Source code path for AUP/portability analysis
  --pattern-config <path> Custom annotation patterns
  --claude-enabled        Enable Claude Code integration
  --full                  Enable all modules (default)
  --skip-modules <list>   Skip specific modules (comma-separated)
  --only-modules <list>   Run only specific modules (comma-separated)
  --json                  Output only JSON path (no console summary)
  --verbose, -v           Enable verbose logging
  --help, -h              Show help
```

### Mode 2: Published npm Binary

**Purpose**: Production assessments, CI/CD pipelines, external integrations
**Command**: `mcp-assess-full`
**Location**: Published on npm as `@bryan-thompson/inspector-assessment`
**Available**: After `npm install -g` or via `npx`

```bash
# Global install
npm install -g @bryan-thompson/inspector-assessment

# Run assessment
mcp-assess-full --server my-server --config config.json

# Or without installing globally
npx @bryan-thompson/inspector-assessment my-server
```

**Key Characteristics:**

- Published npm binary (precompiled)
- Works on any machine with Node.js installed
- Includes additional features like:
  - `--format markdown` - Output as markdown report
  - `--include-policy` - Include policy compliance mapping
  - `--preflight` - Quick validation before full assessment
  - `--compare` - Baseline comparison mode
  - `--resume` / `--no-resume` - Resumable assessments
- Perfect for CI/CD integration
- No source code required

**Command Signature:**

```
mcp-assess-full [options] [server-name]

All local script options, plus:
  --format, -f <type>         json (default) or markdown
  --include-policy            Add 30-requirement policy compliance mapping
  --preflight                 Run quick validation only (30 seconds)
  --compare <path>            Baseline JSON for comparison
  --diff-only                 Show only the diff, not full assessment
  --resume                    Resume interrupted assessment
  --no-resume                 Force fresh start
  --temporal-invocations <n>  Rug pull detection invocations (default: 25)
  --skip-temporal             Skip temporal/rug pull testing
  --skip-modules <list>       Skip specific modules (comma-separated)
  --only-modules <list>       Run only specific modules (comma-separated)
```

### Mode 3: Security-Only Assessment

**Purpose**: Quick security scanning, vulnerability detection only
**Command**: `npm run assess` (local) or `mcp-assess-security` (npm binary)
**Modules**: Security only (no functionality, documentation, etc.)

```bash
# Local development
npm run assess -- --server my-server --config config.json

# From npm binary
mcp-assess-security --server my-server --config config.json

# Output: Focuses on vulnerabilities and injection attacks
```

**Key Characteristics:**

- Fastest assessment mode
- Tests security patterns only
- No functionality validation
- Ideal for rapid security audits
- Perfect for automated security gates

---

## Configuration Files

All three modes require a server configuration file specifying how to connect to your MCP server.

### Configuration Format

The config JSON file specifies the transport type and connection details:

#### STDIO Transport (Local Commands)

Use this when your MCP server is a locally executable command:

```json
{
  "transport": "stdio",
  "command": "python3",
  "args": ["server.py"],
  "env": {
    "API_KEY": "your-secret-key",
    "DEBUG": "false"
  }
}
```

**Fields:**

| Field       | Type   | Required | Description                           |
| ----------- | ------ | -------- | ------------------------------------- |
| `transport` | string | Yes      | Must be `"stdio"`                     |
| `command`   | string | Yes      | Executable name (python3, node, etc.) |
| `args`      | array  | No       | Arguments to pass to the command      |
| `env`       | object | No       | Environment variables for subprocess  |
| `cwd`       | string | No       | Working directory for subprocess      |

**Example - Python Server:**

```json
{
  "command": "/usr/bin/python3",
  "args": ["/home/user/mcp-servers/memory-mcp/src/memory.py"],
  "env": {
    "PYTHONPATH": "/home/user/mcp-servers/memory-mcp"
  }
}
```

**Example - Node Server:**

```json
{
  "command": "node",
  "args": ["--loader", "tsx", "server.ts"],
  "cwd": "/home/user/my-mcp-server"
}
```

#### HTTP Transport (Remote Servers)

Use this for servers running on localhost or remote HTTP endpoints:

```json
{
  "transport": "http",
  "url": "http://localhost:3000/mcp"
}
```

**Fields:**

| Field       | Type   | Required | Description              |
| ----------- | ------ | -------- | ------------------------ |
| `transport` | string | Yes      | Must be `"http"`         |
| `url`       | string | Yes      | Full URL to MCP endpoint |

**Examples:**

```json
// Local development server
{
  "transport": "http",
  "url": "http://localhost:8000/mcp"
}

// Remote HTTP server
{
  "transport": "http",
  "url": "https://api.example.com/mcp/endpoint"
}
```

#### SSE Transport (Server-Sent Events)

Use this for servers supporting SSE streaming:

```json
{
  "transport": "sse",
  "url": "http://localhost:9000/sse"
}
```

**Fields:** Same as HTTP transport

**Example:**

```json
{
  "transport": "sse",
  "url": "http://vulnerable-mcp.local:10900/sse"
}
```

### Configuration File Examples

**Simple HTTP Config:**

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

Save to `/tmp/config.json`, then use:

```bash
mcp-assess-full --server my-server --config /tmp/config.json
```

**Complex STDIO Config with Environment:**

```json
{
  "command": "/home/user/.venv/bin/python",
  "args": ["/home/user/servers/complex-mcp/src/main.py"],
  "env": {
    "OPENAI_API_KEY": "sk-...",
    "LOG_LEVEL": "DEBUG",
    "PYTHONUNBUFFERED": "1"
  },
  "cwd": "/home/user/servers/complex-mcp"
}
```

### Loading Configuration from Claude Desktop

If your MCP servers are configured in Claude Desktop, the inspector can load them automatically:

```bash
# Reads from ~/.config/claude/claude_desktop_config.json
mcp-assess-full --server memory-mcp
```

If Claude Desktop config exists, you don't need `--config` flag.

### Configuration Resolution Order

The inspector looks for server config in this order:

1. **Explicit `--config` argument** - `mcp-assess-full --config /path/to/config.json`
2. **Individual server config** - `~/.config/mcp/servers/<server-name>.json`
3. **Claude Desktop config** - `~/.config/claude/claude_desktop_config.json`

First match wins. If no config found, error is thrown with attempted paths.

---

## Logging & Diagnostics

The inspector provides structured logging with configurable verbosity levels for development, debugging, and production use.

### Log Levels

| Level    | Description                      | Use Case                          |
| -------- | -------------------------------- | --------------------------------- |
| `silent` | No diagnostic output             | CI/CD pipelines, batch processing |
| `error`  | Critical errors only             | Production monitoring             |
| `warn`   | Warnings and errors              | Normal production use             |
| `info`   | Standard progress info (default) | Development, manual runs          |
| `debug`  | Detailed diagnostic output       | Troubleshooting, debugging        |

### CLI Flags

```bash
# Enable verbose/debug logging
mcp-assess-full --server my-server --verbose
mcp-assess-full --server my-server -v

# Suppress all diagnostic output
mcp-assess-full --server my-server --silent

# Set specific log level
mcp-assess-full --server my-server --log-level debug
mcp-assess-full --server my-server --log-level warn
```

### Environment Variable

You can also set the log level via environment variable:

```bash
# Set via environment
LOG_LEVEL=debug mcp-assess-full --server my-server

# In CI/CD pipelines
export LOG_LEVEL=silent
mcp-assess-full --server my-server
```

### Precedence Order

When multiple logging configurations are provided:

1. **CLI flags** (highest priority): `--verbose`, `--silent`, `--log-level`
2. **Environment variable**: `LOG_LEVEL`
3. **Default**: `info`

```bash
# CLI flag wins over environment variable
LOG_LEVEL=debug mcp-assess-full --server my-server --silent
# Result: silent (CLI flag takes precedence)
```

### Output Examples

**Default (info level):**

```
🔍 Starting full assessment for: my-server
✅ Server config loaded
✅ Connected to MCP server
🔧 Found 12 tools
🏃 Running assessment with 18 modules...
```

**Verbose (debug level):**

```
🔍 Starting full assessment for: my-server
✅ Server config loaded
✅ Connected to MCP server
🔧 Found 12 tools
🏃 Running assessment with 18 modules...
[TemporalAssessor] Starting temporal assessment with 25 invocations per tool
[TemporalAssessor] Testing add_memory with 25 invocations
[TemporalAssessor] Testing get_memory with 25 invocations
[FunctionalityAssessor] Testing tool: add_memory with params: {"key":"test","value":"hello"}
[SecurityAssessor] Testing add_memory with all attack patterns
[SecurityAssessor] Pattern: Command Injection - testing 8 payloads
```

**Silent mode:**

```
/tmp/inspector-full-assessment-my-server.json
```

Only the output file path is displayed (when combined with `--json`).

### Logging vs JSONL Events

The inspector has two distinct output streams:

| Stream           | Destination | Purpose                    | Control                    |
| ---------------- | ----------- | -------------------------- | -------------------------- |
| **Logger**       | stdout      | Human-readable diagnostics | `--verbose`, `--silent`    |
| **JSONL Events** | stderr      | Machine-parseable progress | Always emitted (see below) |

**JSONL events** (`{"event":"module_started",...}`) are always emitted to stderr regardless of log level. This ensures automated tools can parse assessment progress even when diagnostic logging is suppressed.

```bash
# Capture JSONL events while suppressing diagnostic logs
mcp-assess-full --server my-server --silent 2>events.jsonl

# View only JSONL events (filter out logger output)
mcp-assess-full --server my-server 2>&1 | grep '{"event"'
```

### Common Logging Scenarios

**Development/Debugging:**

```bash
# Maximum verbosity for troubleshooting
mcp-assess-full --server my-server --verbose
```

**CI/CD Pipeline:**

```bash
# Minimal output, capture JSONL for monitoring
mcp-assess-full --server my-server --silent --json 2>events.jsonl
```

**Production Assessment:**

```bash
# Standard output with warnings
mcp-assess-full --server my-server --log-level warn
```

**Batch Processing:**

```bash
# Silent with JSON output path only
for server in server1 server2 server3; do
  output=$(mcp-assess-full --server $server --silent --json)
  echo "$server: $output"
done
```

---

## Output & Results

### Default Output Locations

All assessment results are saved to JSON by default:

```bash
# Assessment result saved to:
/tmp/inspector-full-assessment-<server-name>.json

# Custom output path:
mcp-assess-full --server my-server --output ./results.json
```

### JSON Output Schema

The JSON output file contains comprehensive assessment results:

```json
{
  "timestamp": "2025-01-03T15:30:45.123Z",
  "assessmentType": "full",
  "serverName": "memory-mcp",
  "overallStatus": "PASS",
  "summary": "Server passed all 18 assessment modules...",
  "totalTestsRun": 1440,
  "executionTime": 47823,
  "recommendations": [
    "Consider adding more detailed tool descriptions",
    "Add readOnlyHint annotations to query tools"
  ],

  "functionality": {
    "status": "PASS",
    "workingTools": 12,
    "brokenTools": [],
    "coveragePercentage": 100,
    "enhancedResults": [
      {
        "toolName": "add_memory",
        "overallStatus": "PASS",
        "testScenarios": [...]
      }
    ]
  },

  "security": {
    "status": "PASS",
    "vulnerabilities": [],
    "testPatterns": [
      {
        "pattern": "Prompt Injection",
        "tested": true,
        "detected": false
      }
    ]
  },

  "documentation": {
    "status": "PASS",
    "readmePresent": true,
    "completeness": "comprehensive"
  },

  "errorHandling": {
    "status": "PASS",
    "metrics": {
      "mcpComplianceScore": 95,
      "invalidResponseRate": 0
    }
  },

  "aupCompliance": {
    "status": "PASS",
    "violations": []
  },

  "toolAnnotations": {
    "status": "PASS",
    "annotatedCount": 12,
    "missingAnnotationsCount": 0,
    "misalignedAnnotationsCount": 0
  },

  "portability": {
    "status": "PASS",
    "supportedPlatforms": ["linux", "macos", "windows"],
    "issues": []
  }
}
```

### Console Output Summary

When not using `--json` flag, the inspector displays a console summary:

```
======================================================================
FULL ASSESSMENT RESULTS
======================================================================
Server: memory-mcp
Overall Status: PASS
Total Tests Run: 1440
Execution Time: 47823ms
----------------------------------------------------------------------

📊 MODULE STATUS:
   ✅ Functionality: PASS
   ✅ Security: PASS
   ✅ Documentation: PASS
   ✅ Error Handling: PASS
   ✅ Usability: PASS
   ✅ MCP Spec Compliance: PASS
   ✅ AUP Compliance: PASS
   ✅ Tool Annotations: PASS
   ✅ Prohibited Libraries: PASS
   ✅ Manifest Validation: PASS
   ✅ Portability: PASS

📋 KEY FINDINGS:
   Server passed all assessment criteria with flying colors.

💡 RECOMMENDATIONS:
   • Consider adding more detailed tool descriptions
   • Add readOnlyHint annotations to destructive tools

📄 Results saved to: /tmp/inspector-full-assessment-memory-mcp.json
```

### Exit Codes

The CLI returns specific exit codes for scripting:

```bash
mcp-assess-full --server my-server

echo $?  # Exit code:
        # 0 = PASS (all modules passed)
        # 1 = FAIL (vulnerabilities or failures found)
```

Use in bash scripts:

```bash
#!/bin/bash
mcp-assess-full --server my-server || {
  echo "Assessment failed!"
  exit 1
}
echo "All checks passed!"
```

---

## Common Use Cases

### Use Case 1: Quick Security Audit

**Goal**: Check for security vulnerabilities quickly (< 2 minutes)

```bash
# Security-only assessment
mcp-assess-security --server my-server --config config.json

# Or local development mode
npm run assess -- --server my-server --config config.json
```

**Output**: Focuses on vulnerabilities, injection patterns, risky behaviors
**Duration**: 30-60 seconds
**Typical Issues Detected**: Command injection, SQL injection, prompt injection

---

### Use Case 2: Pre-Flight Validation

**Goal**: Verify server is reachable and functional before full assessment

```bash
mcp-assess-full --server my-server --config config.json --preflight
```

**What It Checks:**

- Server is reachable
- Tools exist and are discoverable
- manifest.json is valid (if --source provided)
- First tool responds successfully

**Output**:

```json
{
  "passed": true,
  "toolCount": 12,
  "manifestValid": true,
  "serverResponsive": true,
  "errors": []
}
```

**Duration**: 10-30 seconds
**Use**: Perfect before launching full assessments in CI/CD

---

### Use Case 3: Full Assessment with Report Export

**Goal**: Complete assessment with markdown report for documentation

```bash
mcp-assess-full \
  --server my-server \
  --config config.json \
  --format markdown \
  --include-policy \
  --output ./assessment-report.md
```

**Output Files:**

- `assessment-report.md` - Formatted markdown report
- JSON also available via `outputPath` in assessment event

**Features:**

- Human-readable markdown formatting
- Policy compliance mapping (30 requirements)
- Can be committed to version control
- Suitable for executive reviews

---

### Use Case 4: CI/CD Pipeline Integration

**Goal**: Automated testing on every commit

```bash
#!/bin/bash
# .github/workflows/mcp-assessment.yml equivalent

# Create config for HTTP server
cat > /tmp/config.json <<EOF
{
  "transport": "http",
  "url": "http://localhost:8000/mcp"
}
EOF

# Start test server (your deployment)
./scripts/start-server.sh &
SERVER_PID=$!
sleep 5  # Wait for startup

# Run assessment
npx @bryan-thompson/inspector-assessment \
  my-server \
  --config /tmp/config.json \
  --output ./assessment-results.json

RESULT=$?

# Cleanup
kill $SERVER_PID

# Fail CI if vulnerabilities found
exit $RESULT
```

**In GitHub Actions:**

```yaml
name: MCP Assessment
on: [push, pull_request]

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Install dependencies
        run: npm install

      - name: Start MCP server
        run: npm run start &

      - name: Wait for server
        run: sleep 5

      - name: Run assessment
        run: |
          npx @bryan-thompson/inspector-assessment \
            my-server \
            --config /tmp/config.json \
            --output ./results.json

      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: assessment-results
          path: results.json
```

---

### Use Case 5: Baseline Comparison

**Goal**: Track assessment changes over time, detect regressions

```bash
# Create baseline (v1.0.0)
mcp-assess-full \
  --server my-server \
  --config config.json \
  --output baseline-v1.0.0.json

# Later, after updates (v1.1.0)
mcp-assess-full \
  --server my-server \
  --config config.json \
  --compare ./baseline-v1.0.0.json \
  --format markdown \
  --output comparison-v1.1.0.md
```

**Comparison Output Shows:**

- Module status changes (improved/regressed)
- New vulnerabilities detected
- Fixed vulnerabilities
- New/broken tools
- Version information

**Sample Output:**

```
======================================================================
VERSION COMPARISON
======================================================================
Baseline: 1.0.0 (2025-01-01T10:00:00Z)
Current:  1.1.0 (2025-01-03T15:30:00Z)
Overall Change: IMPROVED
Modules Improved: 2
Modules Regressed: 0

⚠️  NEW VULNERABILITIES: 0
✅ FIXED VULNERABILITIES: 1
✅ FIXED TOOLS: 2
```

---

### Use Case 6: Batch Testing Multiple Servers

**Goal**: Assess multiple MCP servers, aggregate results

```bash
#!/bin/bash
# assess-all-servers.sh

servers=("memory-mcp" "filesystem-mcp" "web-mcp")

for server in "${servers[@]}"; do
  echo "Assessing $server..."

  mcp-assess-full \
    --server "$server" \
    --config "/tmp/${server}-config.json" \
    --output "./results/${server}-assessment.json" \
    --json  # Suppress console output for batch processing
done

# Aggregate results
echo "Assessment complete. Results in ./results/"
ls -lh ./results/
```

---

## JSONL Event Streaming

The inspector emits real-time JSONL (JSON Lines) events to stderr for monitoring progress during long assessments.

### Capturing Events

```bash
# Capture events while running assessment
mcp-assess-full --server my-server --config config.json 2>events.jsonl

# Monitor events in real-time
mcp-assess-full --server my-server --config config.json 2>&1 | \
  grep '{"event"' | \
  jq '.'
```

### Event Types

13 distinct event types are emitted in sequence:

| Event Type                      | When                   | Purpose                      |
| ------------------------------- | ---------------------- | ---------------------------- |
| `server_connected`              | Connection established | Server is reachable          |
| `tool_discovered`               | Each tool found        | Tool metadata (name, params) |
| `tools_discovery_complete`      | After all tools        | Total tool count             |
| `modules_configured`            | Before modules run     | Enabled/skipped modules      |
| `module_started`                | Before each module     | Test count estimate          |
| `test_batch`                    | During execution       | Real-time progress           |
| `vulnerability_found`           | Security detections    | Security alerts              |
| `annotation_missing`            | Tool lacks hints       | Missing annotations          |
| `annotation_misaligned`         | Hint conflicts         | Annotation conflicts         |
| `annotation_aligned`            | Annotations match      | Proper annotations confirmed |
| `annotation_review_recommended` | Ambiguous patterns     | Manual review suggested      |
| `module_complete`               | Module finishes        | Module result + score        |
| `assessment_complete`           | End of assessment      | Final summary                |

### Event Examples

**Server Connected:**

```json
{
  "event": "server_connected",
  "serverName": "memory-mcp",
  "transport": "http",
  "version": "1.21.4"
}
```

**Test Batch (Progress):**

```json
{
  "event": "test_batch",
  "module": "security",
  "completed": 45,
  "total": 240,
  "batchSize": 10,
  "elapsed": 2450,
  "version": "1.21.4"
}
```

**Vulnerability Found:**

```json
{
  "event": "vulnerability_found",
  "tool": "system_exec",
  "pattern": "Command Injection",
  "confidence": "high",
  "evidence": "Tool executes arbitrary shell commands",
  "riskLevel": "HIGH",
  "requiresReview": true,
  "payload": "'; rm -rf / #",
  "version": "1.21.4"
}
```

**Module Complete:**

```json
{
  "event": "module_complete",
  "module": "security",
  "status": "FAIL",
  "score": 80,
  "testsRun": 240,
  "duration": 5234,
  "version": "1.21.4"
}
```

### Consuming Events in Real-Time

**Bash Script:**

```bash
#!/bin/bash
mcp-assess-full --server my-server --config config.json 2>&1 | \
  while IFS= read -r line; do
    [[ $line =~ ^"{\"event\" ]] || continue

    event=$(echo "$line" | jq -r '.event')

    case "$event" in
      server_connected)
        echo "Connected!"
        ;;
      test_batch)
        progress=$(echo "$line" | jq -r '.completed / .total * 100 | floor')
        echo "Progress: $progress%"
        ;;
      vulnerability_found)
        tool=$(echo "$line" | jq -r '.tool')
        pattern=$(echo "$line" | jq -r '.pattern')
        echo "SECURITY: [$tool] $pattern"
        ;;
      assessment_complete)
        status=$(echo "$line" | jq -r '.overallStatus')
        echo "Done: $status"
        ;;
    esac
  done
```

**Python Script:**

```python
import subprocess
import json
import sys

proc = subprocess.Popen(
    ["mcp-assess-full", "--server", "my-server", "--config", "config.json"],
    stderr=subprocess.PIPE,
    text=True
)

for line in proc.stderr:
    line = line.strip()
    if not line.startswith("{"):
        continue

    try:
        event = json.loads(line)

        if event["event"] == "vulnerability_found":
            print(f"[{event['riskLevel']}] {event['tool']}: {event['pattern']}")
        elif event["event"] == "test_batch":
            pct = (event["completed"] / event["total"]) * 100
            print(f"{event['module']}: {pct:.1f}%")
        elif event["event"] == "assessment_complete":
            print(f"Done: {event['overallStatus']}")
    except json.JSONDecodeError:
        pass
```

**JavaScript/Node.js:**

```javascript
const { spawn } = require("child_process");

const proc = spawn("mcp-assess-full", [
  "--server",
  "my-server",
  "--config",
  "config.json",
]);

let buffer = "";

proc.stderr.on("data", (data) => {
  buffer += data.toString();
  const lines = buffer.split("\n");
  buffer = lines.pop() || "";

  for (const line of lines) {
    if (!line.startsWith("{")) continue;

    try {
      const event = JSON.parse(line);

      if (event.event === "vulnerability_found") {
        console.log(`[${event.riskLevel}] ${event.tool}: ${event.pattern}`);
      } else if (event.event === "test_batch") {
        const pct = ((event.completed / event.total) * 100).toFixed(1);
        console.log(`${event.module}: ${pct}%`);
      } else if (event.event === "assessment_complete") {
        console.log(`Done: ${event.overallStatus}`);
      }
    } catch (e) {
      // Invalid JSON, skip
    }
  }
});
```

### Complete Event Reference

For comprehensive JSONL documentation, see:
**[JSONL_EVENTS_API.md](./JSONL_EVENTS_API.md)**

This document provides:

- Complete schema for each event type
- TypeScript interfaces
- Integration examples
- Error handling patterns
- Performance metrics

---

## Troubleshooting

### Issue: "Server config not found"

**Error:**

```
Error: Server config not found for: my-server
Tried: /tmp/config.json, ~/.config/mcp/servers/my-server.json, ~/.config/claude/claude_desktop_config.json
```

**Solution:**

Create a config file and pass it:

```bash
# Create config
cat > /tmp/config.json <<EOF
{
  "transport": "http",
  "url": "http://localhost:8000/mcp"
}
EOF

# Use it
mcp-assess-full --server my-server --config /tmp/config.json
```

Or add to Claude Desktop config:

```json
{
  "mcpServers": {
    "my-server": {
      "transport": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

---

### Issue: "Failed to connect to MCP server"

**Error:**

```
Error: Failed to connect to MCP server: ECONNREFUSED 127.0.0.1:8000

Server stderr:
ModuleNotFoundError: No module named 'mcp'
```

**Solution:**

1. **Verify server is running:**

   ```bash
   curl http://localhost:8000/mcp  # For HTTP servers
   ```

2. **For STDIO servers, ensure dependencies are installed:**

   ```bash
   cd /path/to/server
   pip install -r requirements.txt
   ```

3. **Check environment variables:**

   ```bash
   # Verify API keys are set
   export OPENAI_API_KEY="sk-..."
   mcp-assess-full --server my-server --config config.json
   ```

4. **For Python servers, specify full path to interpreter:**

   ```json
   {
     "command": "/home/user/.venv/bin/python",
     "args": ["server.py"]
   }
   ```

---

### Issue: "Test timeout - tool not responding"

**Error:**

```
Tool 'fetch_url' timed out after 30000ms
```

**Solution:**

The default timeout is 30 seconds. For slow servers:

1. **Increase timeout in config:**

   ```json
   {
     "timeout": 60000,
     "transport": "http",
     "url": "http://localhost:8000/mcp"
   }
   ```

2. **Or skip specific slow tools** (if supported by your assessment version)

3. **Run security-only assessment** (faster, fewer tests):

   ```bash
   mcp-assess-security --server my-server --config config.json
   ```

---

### Issue: "Manifest validation failed"

**Error:**

```
Error: Invalid manifest.json (JSON parse error)
```

**Solution:**

Verify manifest.json is valid JSON:

```bash
# Check JSON syntax
node -e "console.log(JSON.parse(require('fs').readFileSync('manifest.json', 'utf-8')))"

# Or use jq
cat manifest.json | jq '.'
```

Fix any syntax errors (missing commas, quotes, etc.)

---

### Issue: "Module assessment incomplete"

**Error:**

```
Assessment interrupted: Module 'security' did not complete
```

**Solution:**

1. **Resume from checkpoint:**

   ```bash
   mcp-assess-full --server my-server --config config.json --resume
   ```

   This continues from where it left off.

2. **Start fresh:**

   ```bash
   mcp-assess-full --server my-server --config config.json --no-resume
   ```

3. **Check server logs for errors:**

   ```bash
   # For STDIO servers
   tail -f /var/log/mcp-server.log

   # For HTTP servers
   curl -v http://localhost:8000/health
   ```

---

### Issue: "No tools found"

**Error:**

```
❌ No tools discovered from server
```

**Solution:**

1. **Verify server's listTools works:**

   ```bash
   # For HTTP servers
   curl http://localhost:8000/mcp/tools | jq '.tools | length'

   # For STDIO, check server output
   ```

2. **Check server is advertising tools properly:**

   The MCP spec requires servers to implement `listTools` endpoint/RPC.

3. **Verify MCP protocol support:**

   ```bash
   # Run preflight check
   mcp-assess-full --server my-server --config config.json --preflight
   ```

---

### Issue: "Invalid format option"

**Error:**

```
Invalid format: invalid. Valid options: json, markdown
```

**Solution:**

Use only supported formats:

```bash
# JSON (default)
mcp-assess-full --server my-server --format json

# Markdown
mcp-assess-full --server my-server --format markdown
```

---

## Advanced Options

### Option: Claude Code Integration

**Purpose**: Enable Claude Code to analyze source code for intelligent test generation

**Command:**

```bash
mcp-assess-full \
  --server my-server \
  --config config.json \
  --source /path/to/source \
  --claude-enabled
```

**Requirements:**

- Claude Code must be available (check: `which claude`)
- Source code path must exist
- Additional timeout (60s vs 30s default)

**Benefits:**

- Intelligent test payload generation
- AUP semantic analysis
- Annotation inference from code
- Documentation quality assessment

---

### Option: Custom Annotation Patterns

**Purpose**: Define custom security patterns for your domain

**Command:**

```bash
mcp-assess-full \
  --server my-server \
  --config config.json \
  --pattern-config /path/to/patterns.json
```

**Pattern File Format:**

```json
{
  "customPatterns": [
    {
      "name": "AWS_API_KEY_LEAK",
      "description": "Detects AWS API key exposure",
      "regex": "AKIA[0-9A-Z]{16}",
      "severity": "HIGH",
      "testPayloads": ["export AWS_KEY=AKIA1234567890ABCDEF"]
    }
  ]
}
```

---

### Option: Temporal/Rug Pull Detection

**Purpose**: Detect tools that change behavior over multiple invocations

**Command:**

```bash
# Custom invocation count
mcp-assess-full \
  --server my-server \
  --config config.json \
  --temporal-invocations 50

# Disable temporal testing (faster)
mcp-assess-full \
  --server my-server \
  --config config.json \
  --skip-temporal
```

**Explanation:**

Temporal testing invokes each tool multiple times and compares responses to detect:

- Response changes (rug pull)
- State mutations (side effects)
- Non-deterministic behavior

**Default**: 25 invocations per tool
**Tradeoff**: More invocations = slower but more thorough

---

### Option: Security Test Timeout

**Purpose**: Optimize security testing speed by setting a shorter timeout specifically for payload-based security tests.

**Configuration**:

Add `securityTestTimeout` to your assessment configuration:

```json
{
  "transport": "http",
  "url": "http://localhost:8000/mcp",
  "testTimeout": 30000,
  "securityTestTimeout": 5000
}
```

**Parameters**:

| Parameter             | Type   | Default | Description                                                     |
| --------------------- | ------ | ------- | --------------------------------------------------------------- |
| `testTimeout`         | number | 30000   | General test timeout (applies to functionality tests)           |
| `securityTestTimeout` | number | 5000    | Security-specific timeout for faster payload testing (optional) |

**Explanation**:

The SecurityAssessor tests multiple attack patterns and payloads against each tool. By setting a lower `securityTestTimeout` than the general `testTimeout`, you can:

- Speed up security assessments (each payload test is limited to 5 seconds vs 30)
- Maintain longer timeouts for functionality tests (30 seconds)
- Improve overall assessment performance without sacrificing coverage

**Performance Impact**:

A security assessment with 12 tools and 23 patterns:

- Without `securityTestTimeout`: 12 tools × 23 patterns × 30s = 8280s (~2.3 hours max)
- With `securityTestTimeout: 5000`: 12 tools × 23 patterns × 5s = 1380s (~23 minutes max)

**When to Use**:

- Production assessments where speed is critical
- CI/CD pipelines with time constraints
- Large MCP servers with many tools
- When tools are slow to respond but you want quick security validation

**Default Behavior**:

If `securityTestTimeout` is not specified, the SecurityAssessor uses `5000ms` as the default timeout for security tests.

---

### Option: Output-Only JSON

**Purpose**: Suppress console output, only output JSON file path

**Command:**

```bash
output_path=$(mcp-assess-full \
  --server my-server \
  --config config.json \
  --json)

# Use output path
echo "Results: $output_path"
cat "$output_path" | jq '.security.vulnerabilities'
```

**Use Cases:**

- Piping to other tools
- Batch processing
- Automated parsing
- CI/CD integration

---

### Option: Verbose Logging

**Purpose**: Enable detailed debug output

**Command:**

```bash
mcp-assess-full \
  --server my-server \
  --config config.json \
  --verbose
```

**Output Includes:**

- Each tool invocation
- Test payloads sent
- Response details
- Timing information
- Module progress details

---

## Assessment Modules Reference

The inspector runs assessment modules covering different aspects:

| Module               | Tests  | Time | Purpose                            |
| -------------------- | ------ | ---- | ---------------------------------- |
| **Functionality**    | 20-100 | 30s  | Tool invocation, response handling |
| **Security**         | 240+   | 60s  | Injection attacks, vulnerabilities |
| **Documentation**    | 10     | 5s   | README completeness, descriptions  |
| **Error Handling**   | 50+    | 20s  | MCP protocol compliance            |
| **Usability**        | 30     | 10s  | Parameter clarity, naming          |
| **MCP Spec**         | 40     | 15s  | MCP specification compliance       |
| **AUP Compliance**   | 15     | 30s  | Acceptable Use Policy violations   |
| **Tool Annotations** | 20     | 10s  | readOnlyHint/destructiveHint       |
| **Prohibited Libs**  | 100+   | 20s  | Dependency security                |
| **Manifest**         | 20     | 5s   | manifest.json validation           |
| **Portability**      | 50+    | 15s  | Cross-platform compatibility       |

**Total**: ~500-600 tests across all modules
**Typical Duration**: 4-5 minutes for full assessment

### Selective Module Testing

You can run specific modules or skip modules using the `--skip-modules` and `--only-modules` flags.

**Skip specific modules (blacklist mode):**

```bash
# Skip security and AUP modules for faster iteration
mcp-assess-full --server my-server --config config.json \
  --skip-modules security,aupCompliance

# Skip temporal testing (also available via --skip-temporal)
mcp-assess-full --server my-server --config config.json \
  --skip-modules temporal
```

**Run only specific modules (whitelist mode):**

```bash
# Run only functionality and tool annotations checks
mcp-assess-full --server my-server --config config.json \
  --only-modules functionality,toolAnnotations

# Quick security-only scan
mcp-assess-full --server my-server --config config.json \
  --only-modules security
```

**Valid module names (18 total):**

| Category         | Module Names                                                                                                                                                                                                                                                                     |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core (16)**    | `functionality`, `security`, `documentation`, `errorHandling`, `usability`, `mcpSpecCompliance`, `aupCompliance`, `toolAnnotations`, `prohibitedLibraries`, `externalAPIScanner`, `authentication`, `temporal`, `resources`, `prompts`, `crossCapability`, `protocolConformance` |
| **Optional (2)** | `manifestValidation`, `portability`                                                                                                                                                                                                                                              |

**Note:** `externalAPIScanner` only runs when `--source` path is provided

**Important notes:**

- `--skip-modules` and `--only-modules` are **mutually exclusive** - use one or the other
- Invalid module names will produce an error with the list of valid names
- Module names are case-sensitive

---

## Summary

| Task                 | Command                                                                   |
| -------------------- | ------------------------------------------------------------------------- |
| Quick security audit | `npm run assess -- --server S`                                            |
| Full assessment      | `mcp-assess-full --server S --config C`                                   |
| Pre-flight check     | `mcp-assess-full --server S --config C --preflight`                       |
| Markdown report      | `mcp-assess-full --server S --config C --format markdown`                 |
| Baseline comparison  | `mcp-assess-full --server S --config C --compare baseline.json`           |
| Skip modules         | `mcp-assess-full --server S --skip-modules security,aupCompliance`        |
| Run specific modules | `mcp-assess-full --server S --only-modules functionality,toolAnnotations` |
| CI/CD integration    | Exit code: 0=PASS, 1=FAIL                                                 |
| Real-time progress   | Capture stderr, parse JSONL events                                        |
| Resume assessment    | `mcp-assess-full --server S --resume`                                     |

---

## Additional Resources

- **JSONL Events**: [JSONL_EVENTS_API.md](./JSONL_EVENTS_API.md) - Complete event reference
- **Assessment Catalog**: [ASSESSMENT_CATALOG.md](./ASSESSMENT_CATALOG.md) - Module details
- **Source Code**:
  - CLI binary: `/home/bryan/inspector/cli/src/assess-full.ts` (unified for local and npm)
  - Legacy script: `/home/bryan/inspector/scripts/run-full-assessment.ts` (deprecated)
- **npm Package**: https://www.npmjs.com/package/@bryan-thompson/inspector-assessment

---

**Version**: 1.23.1
**Last Updated**: 2026-01-04
**Status**: Stable
**Maintainer**: Bryan Thompson (triepod-ai)
