# MCP Inspector CLI Assessment Guide

**Version**: 1.35.0
**Status**: Stable
**Last Updated**: 2026-01-12
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

1. [Four Assessment Modes](#four-assessment-modes)
2. [Configuration Files](#configuration-files)
3. [Logging & Diagnostics](#logging--diagnostics)
4. [Output & Results](#output--results)
5. [Tiered Output for LLM Consumption](#tiered-output-for-llm-consumption)
6. [Common Use Cases](#common-use-cases)
7. [JSONL Event Streaming](#jsonl-event-streaming)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Options](#advanced-options)

---

## Four Assessment Modes

The MCP Inspector provides four distinct CLI modes for different workflows:

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

# Quick HTTP/SSE testing (no config file needed) - Issue #183
npm run assess:full -- --server my-server --http http://localhost:10900/mcp
npm run assess:full -- --server my-server --sse http://localhost:9002/sse

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
  --server, -s <name>        Server name (required or positional)
  --config, -c <path>        Server config JSON file
  --http <url>               Quick HTTP transport (no config file needed)
  --sse <url>                Quick SSE transport (no config file needed)
  --output, -o <path>        Output JSON path
  --source <path>            Source code path for AUP/portability analysis
  --pattern-config <path>    Custom annotation patterns
  --performance-config <path> Performance tuning parameters (Issue #37)
  --claude-enabled           Enable Claude Code integration
  --full                     Enable all modules (default)
  --skip-modules <list>      Skip specific modules (comma-separated)
  --only-modules <list>      Run only specific modules (comma-separated)
  --module, -m <name>        Run single module directly (Issue #184)
  --json                     Output only JSON path (no console summary)
  --verbose, -v              Enable verbose logging
  --help, -h                 Show help
```

**Transport Options (Issue #183):**

- `--http <url>` - Quick HTTP transport testing without config file
- `--sse <url>` - Quick SSE transport testing without config file
- `--config <path>` - Load from JSON config file (required for STDIO)

**Note**: `--http`, `--sse`, and `--config` are mutually exclusive. Use `--http` or `--sse` for rapid testing, or `--config` for complex setups (STDIO, environment variables, custom timeouts).

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
  --format, -f <type>          json (default) or markdown
  --include-policy             Add 30-requirement policy compliance mapping
  --preflight                  Run quick validation only (30 seconds)
  --compare <path>             Baseline JSON for comparison
  --diff-only                  Show only the diff, not full assessment
  --resume                     Resume interrupted assessment
  --no-resume                  Force fresh start
  --temporal-invocations <n>   Rug pull detection invocations (default: 3)
  --skip-temporal              Skip temporal/rug pull testing
  --skip-modules <list>        Skip specific modules (comma-separated)
  --only-modules <list>        Run only specific modules (comma-separated)
  --performance-config <path>  Performance tuning config (batch sizes, timeouts)
```

### Mode 3: Security-Only Assessment

**Purpose**: Quick security scanning, vulnerability detection only
**Command**: `npm run assess` (local) or `mcp-assess-security` (npm binary)
**Modules**: Security only (no functionality, documentation, etc.)

```bash
# Local development
npm run assess -- --server my-server --config config.json

# Quick HTTP/SSE testing (no config file) - Issue #183
npm run assess -- --server my-server --http http://localhost:10900/mcp
npm run assess -- --server my-server --sse http://localhost:9002/sse

# From npm binary
mcp-assess-security --server my-server --config config.json

# With Claude semantic analysis (reduces false positives)
npm run assess -- --server my-server --config config.json --claude

# With custom mcp-auditor URL
npm run assess -- --server my-server --config config.json --claude --mcp-auditor-url http://custom:8085
```

**Key Characteristics:**

- Fastest assessment mode
- Tests security patterns only
- No functionality validation
- Ideal for rapid security audits
- Perfect for automated security gates
- Optional Claude semantic analysis for reduced false positives

**Claude Semantic Analysis Options:**

Use `--claude` to enable Claude-based semantic analysis via mcp-auditor:

```bash
# Enable Claude (uses default mcp-auditor at http://localhost:8085)
npm run assess -- --server my-server --config config.json --claude

# Specify custom mcp-auditor URL
npm run assess -- --server my-server --config config.json --claude --mcp-auditor-url http://auditor.example.com:8085

# Enable verbose Stage B enrichment for detailed evidence (Issue #137)
npm run assess -- --server my-server --config config.json --claude --stage-b-verbose

# Via environment variables (useful for CI/CD)
export INSPECTOR_CLAUDE=true
export INSPECTOR_MCP_AUDITOR_URL=http://custom:8085
npm run assess -- --server my-server --config config.json
```

**Stage B Enrichment (Issue #137):**

The `--stage-b-verbose` flag enhances Claude semantic analysis with additional evidence details:

- **Evidence samples**: Includes actual tool responses that triggered detections
- **Payload correlations**: Maps attack payloads to their detection patterns
- **Confidence breakdowns**: Shows per-test confidence scores and reasoning

**How Claude Reduces False Positives:** Pattern-based detection runs first for speed. Claude semantic analysis then validates medium/low confidence findings by examining tool behavior, reducing false positives while maintaining detection accuracy.

---

### Mode 4: Single-Module Execution (Issue #184)

**Purpose**: Run individual assessment modules for rapid validation, CI/CD checks, or debugging
**Command**: Use `--module <name>` flag with any assessment command
**Performance**: Fastest execution - bypasses orchestrator overhead

```bash
# Local development
npm run assess:full -- --server my-server --http http://localhost:10900/mcp --module toolAnnotations
npm run assess:full -- --server my-server --config config.json --module functionality

# Published npm package
mcp-assess-full --server my-server --sse http://localhost:9002/sse --module security

# Quick transport testing + single module
npm run assess:full -- --server my-server --http http://localhost:10900/mcp --module protocolCompliance
```

**Key Characteristics:**

- **Fastest execution**: Bypasses AssessmentOrchestrator for minimal overhead
- **Targeted testing**: Run only the module you need (e.g., toolAnnotations during development)
- **Simple output**: Results saved to `/tmp/inspector-{module}-{server}.json`
- **CI/CD friendly**: Perfect for automated module-specific checks

**Valid Module Names:**

All 19 assessment modules can be run individually:

| Tier           | Module Names                                                                                    |
| -------------- | ----------------------------------------------------------------------------------------------- |
| **Tier 1 (6)** | `functionality`, `security`, `errorHandling`, `protocolCompliance`, `temporal`, `aupCompliance` |
| **Tier 2 (4)** | `toolAnnotations`, `prohibitedLibraries`, `manifestValidation`, `authentication`                |
| **Tier 3 (3)** | `resources`, `prompts`, `crossCapability`                                                       |
| **Tier 4 (3)** | `developerExperience`, `portability`, `externalAPIScanner`                                      |
| **Tier 5 (2)** | `fileModularization`, `conformance`                                                             |

**Mutual Exclusivity:**

`--module` cannot be used with:

- `--profile` (use single module OR profile, not both)
- `--skip-modules` (single module execution doesn't need skipping)
- `--only-modules` (single module is more direct than whitelist)

```bash
# ❌ Invalid - conflicting flags
npm run assess:full -- --server my-server --module security --profile quick

# ✅ Valid - single module execution
npm run assess:full -- --server my-server --module security

# ✅ Valid - orchestrated profile execution
npm run assess:full -- --server my-server --profile quick
```

**Output Format:**

```
/tmp/inspector-{module}-{server}.json

Examples:
  /tmp/inspector-functionality-my-server.json
  /tmp/inspector-toolAnnotations-my-server.json
  /tmp/inspector-security-my-server.json
```

**Use Cases:**

1. **Development iteration**: Test annotation changes without full assessment

   ```bash
   npm run assess:full -- --server my-server --http http://localhost:10900/mcp --module toolAnnotations
   ```

2. **CI/CD gates**: Run specific checks in pipeline stages

   ```bash
   # Stage 1: Functionality validation
   mcp-assess-full --server my-server --config config.json --module functionality

   # Stage 2: Security scan
   mcp-assess-full --server my-server --config config.json --module security
   ```

3. **Debugging**: Isolate module issues

   ```bash
   npm run assess:full -- --server my-server --config config.json --module protocolCompliance --verbose
   ```

4. **Quick validation**: Verify single aspect after code changes
   ```bash
   npm run assess:full -- --server my-server --http http://localhost:10900/mcp --module manifestValidation
   ```

---

## Assessment Profiles (v1.25.0+)

The inspector provides 4 pre-configured assessment profiles optimized for different use cases. Use the `--profile` flag to quickly select module combinations without manual configuration.

### Profile Overview

| Profile      | Modules                    | Time     | Use Case                                    |
| ------------ | -------------------------- | -------- | ------------------------------------------- |
| `quick`      | 2 modules (Tier 1 partial) | ~30 sec  | Pre-commit hooks, CI validation             |
| `security`   | 6 modules (Tier 1)         | ~2-3 min | Security-focused audits, vulnerability scan |
| `compliance` | 10 modules (Tier 1 + 2)    | ~5 min   | MCP Directory submission validation         |
| `full`       | 16 modules (all tiers)     | ~10-15   | Comprehensive audits, initial server review |

### Using Profiles

```bash
# Quick validation (fastest)
mcp-assess-full --server my-server --config config.json --profile quick

# Security-focused
mcp-assess-full --server my-server --config config.json --profile security

# Pre-submission compliance check
mcp-assess-full --server my-server --config config.json --profile compliance

# Comprehensive audit (default)
mcp-assess-full --server my-server --config config.json --profile full
```

### Profile Definitions

#### Quick Profile (2 modules, ~30 seconds)

**Modules**: functionality, security

**Best for:**

- Pre-commit hooks
- Pull request validation
- Quick CI checks
- Development iteration

**Example:**

```bash
# Fast check during development
mcp-assess-full --server my-server --config config.json --profile quick
```

#### Security Profile (6 modules, ~2-3 minutes)

**Modules**: functionality, security, temporal, errorHandling, protocolCompliance, aupCompliance

**Tier 1 Core Security modules**

**Best for:**

- Security-focused audits
- Vulnerability scanning
- Third-party server assessment
- Security gate enforcement

**Example:**

```bash
# Comprehensive security audit
mcp-assess-full --server my-server --config config.json --profile security
```

#### Compliance Profile (10 modules, ~5 minutes)

**Modules**:

- Tier 1: functionality, security, temporal, errorHandling, protocolCompliance, aupCompliance
- Tier 2: toolAnnotations, prohibitedLibraries, manifestValidation, authentication

**Best for:**

- MCP Directory submission prep
- Compliance validation
- Production readiness checks
- Directory listing qualification

**Example:**

```bash
# Pre-submission validation
mcp-assess-full --server my-server --config config.json --profile compliance
```

#### Full Profile (16 modules, ~10-15 minutes)

**Modules**: All assessment modules including Tiers 1-4

**Includes:**

- All Tier 1 core security modules
- All Tier 2 compliance modules
- All Tier 3 capability-based modules
- All Tier 4 extended modules

**Best for:**

- Initial comprehensive audit
- Detailed server review
- Complete documentation
- Executive reporting

**Example:**

```bash
# Complete assessment with all modules
mcp-assess-full --server my-server --config config.json --profile full
```

### Module Tier Organization

Understanding module tiers helps you choose the right profile:

**Tier 1 (Core Security)** - Always Recommended

- functionality, security, temporal, errorHandling, protocolCompliance, aupCompliance
- Essential for any MCP server assessment
- ~60% of assessment time

**Tier 2 (Compliance)** - MCP Directory

- toolAnnotations, prohibitedLibraries, manifestValidation, authentication
- Required for MCP Directory submission
- ~25% of assessment time

**Tier 3 (Capability-Based)** - Conditional

- resources, prompts, crossCapability
- Only relevant if server has these capabilities
- ~10% of assessment time

**Tier 4 (Extended)** - Optional

- developerExperience, portability, externalAPIScanner
- For comprehensive audits and detailed analysis
- ~5% of assessment time

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
[TemporalAssessor] Starting temporal assessment with 3 invocations per tool
[TemporalAssessor] Testing add_memory with 3 invocations
[TemporalAssessor] Testing get_memory with 3 invocations
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

## Tiered Output for LLM Consumption

**Version**: 1.35.0+
**Issue**: [#136](https://github.com/triepod-ai/inspector-assessment/issues/136)

Assessment outputs can exceed LLM context windows for real-world MCP servers:

- Single tool: ~34K tokens (166KB)
- 57 tools: ~2.4M tokens (~9.5MB) - 12x over Claude's 200K limit

The tiered output strategy splits results into manageable chunks optimized for LLM consumption.

### Output Formats

Three output formats are available via `--output-format`:

| Format         | Description                     | Token Size      | Use Case                     |
| -------------- | ------------------------------- | --------------- | ---------------------------- |
| `full`         | Complete JSON (default)         | Full size       | Programmatic processing      |
| `tiered`       | Directory with split files      | ~5K + on-demand | LLM analysis, chat workflows |
| `summary-only` | Executive + tool summaries only | ~5K-15K tokens  | Quick overview, monitoring   |

### Usage

```bash
# Full output (default)
mcp-assess-full --server my-server --config config.json

# Tiered output for LLM consumption
mcp-assess-full --server my-server --config config.json --output-format tiered

# Summary-only (smallest output)
mcp-assess-full --server my-server --config config.json --output-format summary-only

# Auto-tier: Automatically switch to tiered when results exceed 100K tokens
mcp-assess-full --server my-server --config config.json --auto-tier
```

### Tiered Output Directory Structure

When using `--output-format tiered`, results are saved to a directory:

```
/tmp/inspector-full-assessment-{server}/
├── index.json                 # Metadata and paths
├── executive-summary.json     # Tier 1: ~5K tokens
├── tool-summaries.json        # Tier 2: ~500 tokens per tool
└── tools/                     # Tier 3: Full detail per tool
    ├── vulnerable_calculator_tool.json
    ├── vulnerable_system_exec_tool.json
    └── ...
```

### Tier 1: Executive Summary (~5K tokens)

High-level overview always fits in context:

```json
{
  "serverName": "my-server",
  "overallStatus": "PASS",
  "overallScore": 85,
  "toolCount": 12,
  "testCount": 1440,
  "executionTime": 47823,
  "criticalFindings": {
    "securityVulnerabilities": 2,
    "aupViolations": 0,
    "brokenTools": 1,
    "missingAnnotations": 3
  },
  "toolRiskDistribution": {
    "high": 1,
    "medium": 2,
    "low": 3,
    "safe": 6
  },
  "modulesSummary": {
    "functionality": { "status": "PASS", "score": 100 },
    "security": { "status": "FAIL", "score": 75 }
  },
  "recommendations": [
    "Fix command injection vulnerability in system_exec tool",
    "Add readOnlyHint annotations to query tools"
  ],
  "estimatedTokens": 4800,
  "generatedAt": "2026-01-12T15:30:45.123Z"
}
```

### Tier 2: Tool Summaries (~500 tokens/tool)

Per-tool digest for risk assessment without full test details:

```json
{
  "totalTools": 12,
  "aggregate": {
    "totalVulnerabilities": 3,
    "misalignedAnnotations": 2,
    "averagePassRate": 87
  },
  "tools": [
    {
      "toolName": "system_exec",
      "riskLevel": "HIGH",
      "vulnerabilityCount": 2,
      "topPatterns": ["command_injection", "shell_escape"],
      "testCount": 120,
      "passRate": 65,
      "hasAnnotations": false,
      "annotationStatus": "MISSING",
      "recommendations": ["Add input validation", "Implement allowlist"]
    },
    {
      "toolName": "get_data",
      "riskLevel": "SAFE",
      "vulnerabilityCount": 0,
      "topPatterns": [],
      "testCount": 120,
      "passRate": 100,
      "hasAnnotations": true,
      "annotationStatus": "ALIGNED"
    }
  ],
  "estimatedTokens": 6000
}
```

### Tier 3: Per-Tool Details (Full Data)

Complete test results for deep-dive analysis. Access on-demand:

```bash
# Read specific tool detail
cat /tmp/inspector-full-assessment-my-server/tools/system_exec.json | jq
```

### Using Tiered Output with LLMs

**Recommended Workflow:**

1. **Start with executive summary** - Always fits in context

   ```bash
   cat /tmp/inspector-full-assessment-my-server/executive-summary.json
   ```

2. **Review tool summaries** - Identify high-risk tools

   ```bash
   cat /tmp/inspector-full-assessment-my-server/tool-summaries.json | \
     jq '.tools[] | select(.riskLevel == "HIGH")'
   ```

3. **Deep-dive specific tools** - Load details as needed

   ```bash
   cat /tmp/inspector-full-assessment-my-server/tools/system_exec.json
   ```

**Token Budget Planning:**

| Server Size | Executive | Tool Summaries | Total (Tiers 1+2) |
| ----------- | --------- | -------------- | ----------------- |
| 5 tools     | ~5K       | ~2.5K          | ~7.5K             |
| 20 tools    | ~5K       | ~10K           | ~15K              |
| 50 tools    | ~5K       | ~25K           | ~30K              |
| 100 tools   | ~5K       | ~50K           | ~55K              |

### Auto-Tier Mode

The `--auto-tier` flag automatically switches to tiered output when results exceed 100K tokens:

```bash
# Automatically tier large assessments
mcp-assess-full --server large-server --config config.json --auto-tier

# Output message when auto-tiering activates:
# 📊 Auto-tiering enabled: 245,000 tokens (tiered output recommended)
```

### JSONL Event for Tiered Output

When tiered output is generated, a JSONL event is emitted:

```json
{
  "event": "tiered_output_generated",
  "outputDir": "/tmp/inspector-full-assessment-my-server",
  "outputFormat": "tiered",
  "tiers": {
    "executiveSummary": {
      "path": "/tmp/inspector-full-assessment-my-server/executive-summary.json",
      "estimatedTokens": 4800
    },
    "toolSummaries": {
      "path": "/tmp/inspector-full-assessment-my-server/tool-summaries.json",
      "estimatedTokens": 6000,
      "toolCount": 12
    },
    "toolDetails": {
      "directory": "/tmp/inspector-full-assessment-my-server/tools",
      "fileCount": 12,
      "totalEstimatedTokens": 150000
    }
  }
}
```

### Combining with Other Options

Tiered output works with all other CLI options:

```bash
# Tiered output with policy compliance
mcp-assess-full --server my-server --config config.json \
  --output-format tiered --include-policy

# Summary-only for quick CI checks
mcp-assess-full --server my-server --config config.json \
  --output-format summary-only --json

# Auto-tier with custom output directory
mcp-assess-full --server my-server --config config.json \
  --auto-tier --output ./results/my-server
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

### Use Case 7: Reduce False Positives with Claude Semantic Analysis

**Goal**: Enhance security assessment with AI-driven semantic analysis to validate findings

Requires: mcp-auditor running at http://localhost:8085 (or custom URL)

```bash
# Enable Claude for the security assessment
npm run assess -- --server my-server --config config.json --claude

# With custom mcp-auditor URL
npm run assess -- --server my-server --config config.json --claude --mcp-auditor-url http://auditor.example.com:8085

# In CI/CD environment
export INSPECTOR_CLAUDE=true
export INSPECTOR_MCP_AUDITOR_URL=http://auditor.example.com:8085
npm run assess -- --server my-server --config config.json
```

**How It Works:**

1. Pattern-based detection runs first (fast, reliable)
2. Medium/low confidence findings are marked for semantic review
3. Claude analyzes tool behavior and descriptions
4. False positives are filtered; true positives confirmed
5. Results include semantic analysis confidence scores

**Benefits:**

- Fewer false positives than pattern-based detection alone
- Maintains high true positive rate
- Semantic understanding of tool behavior
- Suitable for gated security checks in CI/CD

**Requirements:**

- mcp-auditor service running (see mcp-auditor docs for setup)
- Network connectivity to mcp-auditor endpoint
- Additional ~30-60 seconds assessment time

**Output Enhancements:**

The assessment results include:

- `semantic_confidence` score for each finding
- `claude_analysis` details explaining the decision
- `validation_method` showing if pattern-based or semantic

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

### Issue: "Invalid server config" (Config Validation Errors)

**Error:**

```
Error: Invalid server config in /tmp/config.json:
url: url must be a valid URL
```

Or for union validation failures:

```
Error: Invalid server config in /tmp/config.json:
url: url must be a valid URL
command: command is required for stdio transport
transport: Invalid enum value. Expected 'http' | 'sse' | 'stdio', received 'ws'
```

**Cause:**

The config file format is invalid. As of v1.32.1, server configurations are validated with Zod schemas for runtime type safety (Issue #84). Error messages now show ALL validation failures to help diagnose configuration issues quickly.

**Solution:**

Check the error message for specific validation failures. Common issues:

1. **Invalid URL (HTTP/SSE configs):**

   ```json
   {
     "transport": "http",
     "url": "invalid-url" // ❌ Must be a valid URL
   }
   ```

   **Fix:**

   ```json
   {
     "transport": "http",
     "url": "http://localhost:8000/mcp" // ✅ Valid URL
   }
   ```

2. **Missing required fields (stdio configs):**

   ```json
   {
     "transport": "stdio"
     // ❌ Missing "command" field
   }
   ```

   **Fix:**

   ```json
   {
     "transport": "stdio",
     "command": "python3",
     "args": ["server.py"]
   }
   ```

3. **Invalid transport type:**

   ```json
   {
     "transport": "websocket", // ❌ Not supported
     "url": "ws://localhost:8000"
   }
   ```

   **Fix:** Use `"http"`, `"sse"`, or `"stdio"` only.

4. **Union validation errors** (mixed config format):

   When you see multiple error messages from different transport types, it means the config doesn't match any valid transport format. Check which transport you intend to use and ensure all required fields are present.

**Valid Config Examples:**

```json
// HTTP config
{
  "transport": "http",
  "url": "http://localhost:8000/mcp"
}

// SSE config
{
  "transport": "sse",
  "url": "http://localhost:9000/sse"
}

// STDIO config
{
  "transport": "stdio",
  "command": "python3",
  "args": ["server.py"],
  "env": { "API_KEY": "..." }
}
```

See [Configuration Files](#configuration-files) section for complete reference.

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

### Issue: "Task queue depth exceeds threshold" (Issue #37)

**Warning:**

```
Warning: Task queue depth exceeds threshold (10000)
```

**Causes:**

- Server has many tools (50+ tools)
- Security assessment generating many payloads
- Large batch sizes creating backlog

**Solutions:**

1. **Increase queue threshold:**

   ```bash
   echo '{"queueWarningThreshold": 50000}' > /tmp/perf.json
   mcp-assess-full --server my-server --config config.json --performance-config /tmp/perf.json
   ```

2. **Use fast preset with larger batches:**

   ```bash
   echo '{"functionalityBatchSize": 10, "securityBatchSize": 20}' > /tmp/fast.json
   mcp-assess-full --server my-server --config config.json --performance-config /tmp/fast.json
   ```

3. **Run security assessment on tool subsets:**

   ```bash
   mcp-assess-full --server my-server --only-modules functionality
   ```

See [PERFORMANCE_TUNING_GUIDE.md](PERFORMANCE_TUNING_GUIDE.md) for detailed guidance.

---

### Issue: "MaxListenersExceededWarning"

**Warning:**

```
MaxListenersExceededWarning: Possible EventEmitter memory leak detected
```

**Causes:**

- Assessment creates many event listeners
- Multiple concurrent assessments
- Default listener limit exceeded

**Solutions:**

1. **Increase EventEmitter max listeners:**

   ```bash
   echo '{"eventEmitterMaxListeners": 200}' > /tmp/perf.json
   mcp-assess-full --server my-server --config config.json --performance-config /tmp/perf.json
   ```

2. **Note:** This is a warning, not an error - assessment continues normally.

See [PERFORMANCE_TUNING_GUIDE.md](PERFORMANCE_TUNING_GUIDE.md#troubleshooting) for details.

---

### Issue: Server Not Providing serverInfo (v1.24.2+)

**Warning:**

```
⚠️  Server did not provide serverInfo during initialization
```

**What This Means:**

Some MCP servers may not fully populate `serverInfo` or `serverCapabilities` during the initialization handshake. This is handled gracefully:

1. Assessment continues with available data
2. Protocol Conformance checks receive "medium" or "low" confidence
3. Other assessments (functionality, security) are unaffected

**Example Output (when serverInfo missing):**

```json
{
  "protocolConformance": {
    "checks": {
      "initializationHandshake": {
        "passed": false,
        "confidence": "low",
        "evidence": "1/4 initialization checks passed",
        "warnings": [
          "Server should provide version for better compatibility tracking",
          "Server should declare capabilities for feature negotiation"
        ]
      }
    }
  }
}
```

**Assessment Impact:**

| Aspect               | Impact                           |
| -------------------- | -------------------------------- |
| Functionality        | None - tests run normally        |
| Security             | None - tests run normally        |
| Protocol Conformance | Degraded confidence              |
| Overall Score        | Slightly lower conformance score |

**Solutions:**

1. **If you control the server:** Update it to return proper `serverInfo`:

   ```json
   {
     "name": "my-server",
     "version": "1.0.0"
   }
   ```

2. **If you can't modify the server:** Accept the warning - assessment still provides value for other modules.

3. **To suppress for known limitation:** Focus on other module results:

   ```bash
   mcp-assess-full --server my-server --skip-modules protocolConformance
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

### Option: MCP Protocol Version Configuration (v1.24.2+)

**Purpose**: Validate against a specific MCP specification version

The Protocol Conformance Assessor can validate against different MCP specification versions. Configure this in your server config file:

**Config File Example:**

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp",
  "mcpProtocolVersion": "2025-06-18"
}
```

**How it works**: The assessor generates specification reference URLs dynamically based on this version for compliance reporting.

**Default**: `2025-06` if not specified.

**Generated URLs**:

- Base: `https://modelcontextprotocol.io/specification/{version}`
- Lifecycle: `https://modelcontextprotocol.io/specification/{version}/basic/lifecycle`
- Tools: `https://modelcontextprotocol.io/specification/{version}/server/tools`

See [PROTOCOL_CONFORMANCE_ASSESSOR_GUIDE.md](PROTOCOL_CONFORMANCE_ASSESSOR_GUIDE.md) for detailed configuration options.

---

### Option: Server Info Capture (v1.24.2+)

**Purpose**: Automatic capture of server metadata for Protocol Conformance validation

The CLI automatically captures `serverInfo` and `serverCapabilities` from the MCP server during connection. This information is used by the Protocol Conformance Assessor for validation checks.

**Behavior**:

- If the server provides `serverInfo`, it's used for validation
- If the server doesn't provide this information, warnings are logged but assessment continues with defaults
- The `initializationHandshake` check validates completeness of server metadata

**Example Warning** (when server omits info):

```
WARN: Server did not provide serverInfo, using defaults for Protocol Conformance
```

**No configuration required** - this feature works automatically.

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

**Default**: 3 invocations per tool
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

### Option: Performance Configuration (Issue #37)

**Purpose**: Tune assessment execution parameters for different environments

**Command:**

```bash
# Use custom performance config
mcp-assess-full \
  --server my-server \
  --config config.json \
  --performance-config /path/to/perf.json

# Quick inline config
echo '{"functionalityBatchSize": 10, "securityBatchSize": 20}' > /tmp/fast.json
mcp-assess-full --server my-server --config config.json --performance-config /tmp/fast.json
```

**Configuration File Format:**

```json
{
  "batchFlushIntervalMs": 500,
  "functionalityBatchSize": 5,
  "securityBatchSize": 10,
  "testTimeoutMs": 5000,
  "securityTestTimeoutMs": 5000,
  "queueWarningThreshold": 10000,
  "eventEmitterMaxListeners": 50
}
```

**Available Parameters:**

| Parameter                  | Default | Range       | Description                    |
| -------------------------- | ------- | ----------- | ------------------------------ |
| `batchFlushIntervalMs`     | 500     | 50-10000    | Progress event batch interval  |
| `functionalityBatchSize`   | 5       | 1-100       | Functionality test batch size  |
| `securityBatchSize`        | 10      | 1-100       | Security test batch size       |
| `testTimeoutMs`            | 5000    | 100-300000  | Functionality test timeout     |
| `securityTestTimeoutMs`    | 5000    | 100-300000  | Security test timeout          |
| `queueWarningThreshold`    | 10000   | 100-1000000 | Task queue depth warning level |
| `eventEmitterMaxListeners` | 50      | 10-1000     | Max EventEmitter listeners     |

**Built-in Presets:**

```bash
# Fast preset (larger batches for speed)
echo '{"functionalityBatchSize": 10, "securityBatchSize": 20}' > /tmp/fast.json

# Resource-constrained preset (smaller batches, lower thresholds)
echo '{"functionalityBatchSize": 3, "securityBatchSize": 5, "queueWarningThreshold": 5000}' > /tmp/constrained.json

# High-latency network preset (longer timeouts)
echo '{"testTimeoutMs": 30000, "securityTestTimeoutMs": 30000, "batchFlushIntervalMs": 2000}' > /tmp/slow-network.json
```

**When to Use:**

- **CI/CD pipelines**: Use larger batch sizes for speed
- **Slow MCP servers**: Increase `testTimeoutMs` and `securityTestTimeoutMs`
- **Large tool sets (100+ tools)**: Increase `queueWarningThreshold`
- **Resource-constrained environments**: Decrease batch sizes

**Complete Documentation:** See [PERFORMANCE_TUNING_GUIDE.md](PERFORMANCE_TUNING_GUIDE.md) for:

- Detailed parameter explanations
- Example configurations for various scenarios
- Troubleshooting performance issues
- API reference for programmatic usage

---

## Assessment Modules Reference (v1.25.0+)

The inspector runs 16 assessment modules organized into 4 tiers. Each module can be configured independently via `--skip-modules` and `--only-modules` flags.

### Tier 1: Core Security (6 modules)

Always recommended for any MCP server assessment.

| Module                  | Tests  | Time | Purpose                                       |
| ----------------------- | ------ | ---- | --------------------------------------------- |
| **Functionality**       | 20-100 | 30s  | Tool invocation, response handling            |
| **Security**            | 240+   | 60s  | Injection attacks, vulnerability detection    |
| **Error Handling**      | 50+    | 20s  | MCP error protocol compliance                 |
| **Protocol Compliance** | 40     | 15s  | MCP specification validation (NEW in v1.25.0) |
| **Temporal**            | 25×N   | 30s  | Rug pull detection                            |
| **AUP Compliance**      | 15     | 30s  | Acceptable Use Policy violations              |

**Subtotal**: ~410-460 tests, ~3-4 minutes

### Tier 2: Compliance (4 modules)

Required for MCP Directory submission.

| Module                  | Tests | Time | Purpose                      |
| ----------------------- | ----- | ---- | ---------------------------- |
| **Tool Annotations**    | 20    | 10s  | readOnlyHint/destructiveHint |
| **Prohibited Libs**     | 100+  | 20s  | Dependency security          |
| **Manifest Validation** | 20    | 5s   | manifest.json validation     |
| **Authentication**      | 15    | 10s  | OAuth appropriateness        |

**Subtotal**: ~155-160 tests, ~45 seconds

### Tier 3: Capability-Based (3 modules)

Conditional - only if server has corresponding capabilities.

| Module               | Tests | Time | Purpose                      |
| -------------------- | ----- | ---- | ---------------------------- |
| **Resources**        | 20+   | 10s  | Resource security assessment |
| **Prompts**          | 20+   | 10s  | Prompt AUP compliance        |
| **Cross-Capability** | 15    | 10s  | Cross-capability attacks     |

**Subtotal**: ~55-65 tests, ~30 seconds

### Tier 4: Extended (3 modules)

Optional for comprehensive audits.

| Module                   | Tests | Time | Purpose                                    |
| ------------------------ | ----- | ---- | ------------------------------------------ |
| **Developer Experience** | 40    | 15s  | Documentation + usability (NEW in v1.25.0) |
| **Portability**          | 50+   | 15s  | Cross-platform compatibility               |
| **External API Scanner** | 20    | 10s  | External API detection (requires source)   |

**Subtotal**: ~110 tests, ~40 seconds

**Grand Total**: ~630-695 tests across all 16 modules
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

**Valid module names (18 total, v1.40.0+):**

| Tier           | Module Names                                                                                    |
| -------------- | ----------------------------------------------------------------------------------------------- |
| **Tier 1 (6)** | `functionality`, `security`, `errorHandling`, `protocolCompliance`, `temporal`, `aupCompliance` |
| **Tier 2 (4)** | `toolAnnotations`, `prohibitedLibraries`, `manifestValidation`, `authentication`                |
| **Tier 3 (3)** | `resources`, `prompts`, `crossCapability`                                                       |
| **Tier 4 (3)** | `developerExperience`, `portability`, `externalAPIScanner`                                      |
| **Tier 5 (2)** | `fileModularization`, `conformance`                                                             |

**Deprecated module names** (still supported with warnings):

- `documentation` → use `developerExperience`
- `usability` → use `developerExperience`
- `mcpSpecCompliance` → use `protocolCompliance`
- `protocolConformance` → use `protocolCompliance`

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
| Quick HTTP testing   | `mcp-assess-full --server S --http http://localhost:10900/mcp`            |
| Quick SSE testing    | `mcp-assess-full --server S --sse http://localhost:9002/sse`              |
| Single module run    | `mcp-assess-full --server S --http URL --module toolAnnotations`          |
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
- **Performance Tuning**: [PERFORMANCE_TUNING_GUIDE.md](./PERFORMANCE_TUNING_GUIDE.md) - Batch sizes, timeouts, presets
- **Architecture Detection**: [ARCHITECTURE_DETECTION_GUIDE.md](./ARCHITECTURE_DETECTION_GUIDE.md) - Server infrastructure analysis
- **Behavior Inference**: [BEHAVIOR_INFERENCE_GUIDE.md](./BEHAVIOR_INFERENCE_GUIDE.md) - Tool behavior classification
- **Source Code**:
  - CLI binary: `/home/bryan/inspector/cli/src/assess-full.ts` (unified for local and npm)
  - Legacy script: `/home/bryan/inspector/scripts/run-full-assessment.ts` (deprecated)
- **npm Package**: https://www.npmjs.com/package/@bryan-thompson/inspector-assessment

---

**Version**: 1.35.0
**Last Updated**: 2026-01-12
**Status**: Stable
**Maintainer**: Bryan Thompson (triepod-ai)
