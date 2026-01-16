# MCP Inspector Development Guide

## Quick Reference

- **Full Documentation**: See [README.md](README.md) for features and usage
- **Timeline & Status**: See [PROJECT_STATUS.md](PROJECT_STATUS.md) for recent changes and development history
- **Build Commands**: Listed below for quick access

## Build Commands

- Build all: `npm run build`
- Build client: `npm run build-client`
- Build server: `npm run build-server`
- Development mode: `npm run dev` (use `npm run dev:windows` on Windows)
- Format code: `npm run prettier-fix`
- Client lint: `cd client && npm run lint`
- Run tests: `npm test` (~1560 tests passing)
- Run assessment tests: `npm test -- assessment` (assessment module tests)

## Structured Logging (v1.23.1)

- **Log levels**: `silent`, `error`, `warn`, `info` (default), `debug`
- **CLI flags**: `--verbose` (debug), `--silent`, `--log-level <level>`
- **Environment**: `LOG_LEVEL=<level>` (precedence: CLI > ENV > default)
- **Output**: Logger → stdout, JSONL events → stderr (preserved)
- **Documentation**: [docs/LOGGING_GUIDE.md](docs/LOGGING_GUIDE.md)
- **Implementation**: `client/src/services/assessment/lib/logger.ts`

## Code Style Guidelines

- Use TypeScript with proper type annotations
- Follow React functional component patterns with hooks
- Use ES modules (import/export) not CommonJS
- Use Prettier for formatting (auto-formatted on commit)
- Follow existing naming conventions:
  - camelCase for variables and functions
  - PascalCase for component names and types
  - kebab-case for file names
- Use async/await for asynchronous operations
- Implement proper error handling with try/catch blocks
- Use Tailwind CSS for styling in the client
- Keep components small and focused on a single responsibility

## Project Organization

The project is organized as a monorepo with workspaces:

- `client/`: React frontend with Vite, TypeScript and Tailwind
- `server/`: Express backend with TypeScript
- `cli/`: Command-line interface for testing and invoking MCP server methods directly

## CLI Security Assessment Runner

Run security assessments from the command line without the web UI:

```bash
# Quick HTTP/SSE testing (no config file needed):
npm run assess -- --server my-server --http http://localhost:10900/mcp
npm run assess -- --server my-server --sse http://localhost:9002/sse

# Config-based testing (for STDIO or complex setups):
npm run assess -- --server <server-name> --config <path-to-config.json>

# Test specific tool
npm run assess -- --server <server-name> --config <config.json> --tool <tool-name>

# Single-module execution (fastest, bypasses orchestrator):
npm run assess -- --server my-server --http http://localhost:10900/mcp --module toolAnnotations
npm run assess:full -- --server my-server --sse http://localhost:9002/sse --module functionality
```

**Transport Options:**

- `--http <url>` - Quick HTTP transport (no config file needed)
- `--sse <url>` - Quick SSE transport (no config file needed)
- `--config <path>` - Load from JSON config file (required for STDIO)

Note: `--http`, `--sse`, and `--config` are mutually exclusive.

**Module Execution Options:**

- `--module <name>` - Run single module directly (bypasses orchestrator, fastest execution)
- Valid modules: functionality, security, temporal, errorHandling, protocolCompliance, aupCompliance, toolAnnotations, prohibitedLibraries, manifestValidation, authentication, resources, prompts, crossCapability, developerExperience, portability, externalAPIScanner
- Mutual exclusivity: `--module` cannot be used with `--profile`, `--skip-modules`, or `--only-modules`
- Output format: `/tmp/inspector-{module}-{server}.json` (e.g., `/tmp/inspector-functionality-my-server.json`)

**Config File Format** (HTTP transport):

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

**Config File Format** (STDIO transport):

```json
{
  "command": "python3",
  "args": ["server.py"],
  "env": {}
}
```

**Features:**

- ✅ No modifications to core assessment modules (preserves upstream sync compatibility)
- ✅ Supports stdio, HTTP, and SSE transports
- ✅ Test all tools or specific tool
- ✅ Claude semantic analysis with mcp-auditor (optional)
- ✅ JSON output to `/tmp/inspector-assessment-{serverName}.json`
- ✅ Exit code 0 for safe, 1 for vulnerabilities (perfect for CI/CD)

**Claude Semantic Analysis:**

Enable Claude to reduce false positives via semantic understanding (requires mcp-auditor running):

```bash
# Enable Claude semantic analysis
npm run assess -- --server my-server --config config.json --claude

# Custom mcp-auditor URL
npm run assess -- --server my-server --config config.json --claude --mcp-auditor-url http://custom:8085

# Via environment variables (useful for CI/CD)
INSPECTOR_CLAUDE=true npm run assess -- --server my-server --config config.json
INSPECTOR_MCP_AUDITOR_URL=http://custom:8085 npm run assess -- --server my-server --config config.json
```

**Claude Options:**

- `--claude` - Enable Claude semantic analysis (requires mcp-auditor at http://localhost:8085 by default)
- `--mcp-auditor-url <url>` - Custom mcp-auditor URL (default: http://localhost:8085)
- `--stage-b-verbose` - Add evidence samples and confidence breakdowns to Stage B enrichment (Issue #137)
- `INSPECTOR_CLAUDE=true` - Environment variable to enable Claude
- `INSPECTOR_MCP_AUDITOR_URL` - Environment variable for custom URL

**How It Works:** Pattern-based detection runs first. For medium/low confidence findings, Claude analyzes tool behavior semantically to reduce false positives.

**Implementation:** `scripts/run-security-assessment.ts`

**Complete Documentation:** See [docs/CLI_ASSESSMENT_GUIDE.md](docs/CLI_ASSESSMENT_GUIDE.md) for all three CLI modes, configuration options, and CI/CD integration examples.

## Full Assessment CLI

The full assessment is now unified under a single CLI binary (`cli/src/assess-full.ts`).

**Usage** (local development and published package):

```bash
# Local development (requires npm run build-cli first)
npm run assess:full -- --server <name> --config <path>

# Published package
npx @bryan-thompson/inspector-assessment mcp-assess-full <server> --config <path>
```

**Features**:

- Resource/Prompt capability assessment
- Pre-flight validation mode (`--preflight`)
- Comparison/diff modes (`--compare`, `--diff-only`)
- State management/resume (`--resume`, `--no-resume`)
- Policy compliance reports (`--include-policy`)
- Multiple output formats (`--format json|markdown`)

**Legacy Script** (deprecated, will be removed):

The old `scripts/run-full-assessment.ts` is available via `npm run assess:full:legacy` during the transition period. See [GitHub Issue #19](https://github.com/triepod-ai/inspector-assessment/issues/19) for details.

## Vulnerability Testbed Validation

The inspector includes comprehensive A/B comparison validation using the vulnerable-mcp and hardened-mcp testbed servers.

**Purpose**: Validate pure behavior-based detection logic with ground-truth labeled tools. Both servers use **IDENTICAL tool names** but different implementations to prove detection is behavior-based, not name-based.

**Server Configuration**:

| Server         | Port      | Description                                                      |
| -------------- | --------- | ---------------------------------------------------------------- |
| vulnerable-mcp | 10900     | 10 vulnerable + 6 safe tools                                     |
| hardened-mcp   | 10901     | Same tool names, safe implementations                            |
| test-server    | 10651     | General testing (not part of testbed)                            |
| firecrawl      | 10777     | No credits - fails but testable                                  |
| dvmcp          | 9001-9006 | Damn Vulnerable MCP (`~/mcp-servers/damn-vulnerable-mcp-server`) |

**Quick Usage**:

```bash
# Run assessment against both servers
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json

# Expected results (A/B comparison):
# Vulnerable: 1440 tests, 200 vulnerabilities, FAIL
# Hardened: 1440 tests, 0 vulnerabilities, PASS
# Both: 0 false positives on 6 safe tools (100% precision)
```

**Testbed Configs**:

```json
// /tmp/vulnerable-mcp-config.json
{"transport": "http", "url": "http://localhost:10900/mcp"}

// /tmp/hardened-mcp-config.json
{"transport": "http", "url": "http://localhost:10901/mcp"}
```

**Validation Status** (2025-12-28):

- ✅ A/B Detection Gap: 200 vulnerabilities (vulnerable) vs 0 (hardened) with identical tool names
- ✅ Pure Behavior Detection: 100% precision (0 false positives on both servers)
- ✅ 23 attack patterns tested per tool (expanded from 8)
- ✅ Real HTTP tool calls verified inspector findings
- ✅ Ready for production MCP server assessments

**When to Use Testbed**:

1. **Before Inspector Changes**: Run baseline on both servers
2. **After Inspector Changes**: Verify A/B detection gap and 0 false positives
3. **Before Release**: Full validation on both servers
4. **CI/CD Pipeline**: Automated regression testing

**Key Insight**: Both servers have tools named `vulnerable_calculator_tool`, `vulnerable_system_exec_tool`, etc. The inspector detects 200 vulnerabilities on one server and 0 on the other - proving pure behavior-based detection, not name-based heuristics.

**Validation Commands**:

```bash
# A/B Comparison (should be 200 vs 0)
cat /tmp/inspector-assessment-vulnerable-mcp.json | jq '.security.vulnerabilities | length'
# Expected: 200
cat /tmp/inspector-assessment-hardened-mcp.json | jq '.security.vulnerabilities | length'
# Expected: 0

# Verify zero false positives on safe tools (both servers)
cat /tmp/inspector-assessment-vulnerable-mcp.json | \
  jq '[.security.promptInjectionTests[] | select(.toolName | startswith("safe_")) | select(.vulnerable == true)] | length'
# Expected: 0

cat /tmp/inspector-assessment-hardened-mcp.json | \
  jq '[.security.promptInjectionTests[] | select(.toolName | startswith("safe_")) | select(.vulnerable == true)] | length'
# Expected: 0
```

**Acceptance Criteria for Changes**:

- ✅ False positives: 0 (both servers, safe tools)
- ✅ Precision: 100%
- ✅ Vulnerable server: ≥200 vulnerabilities
- ✅ Hardened server: 0 vulnerabilities (same tool names!)
- ✅ No regressions in detection logic

**Detailed Documentation**: See [docs/TESTBED_SETUP_GUIDE.md](docs/TESTBED_SETUP_GUIDE.md) for:

- Complete A/B comparison results
- Real tool response evidence
- Detection architecture explanation
- Testbed configuration and usage
- CI/CD integration examples
- Performance benchmarks

## DVMCP (Damn Vulnerable MCP) Testbed

The inspector supports validation against the DVMCP CTF-style educational project with 10 intentionally vulnerable MCP servers.

**Repository**:

- **Fork**: https://github.com/triepod-ai/damn-vulnerable-MCP-server
- **Upstream**: https://github.com/harishsg993010/damn-vulnerable-MCP-server
- **Local Path**: `/home/bryan/mcp-servers/damn-vulnerable-mcp-server/`

**Server Configuration**:

| Challenge | Port | Vulnerability Class                    | Detection Status (v1.20.5)          |
| --------- | ---- | -------------------------------------- | ----------------------------------- |
| CH1       | 9001 | Prompt Injection via Resources         | GAP (resources not tested)          |
| CH2       | 9002 | Tool Description Poisoning + Cmd Inj   | ✅ DETECTED (7 patterns)            |
| CH3       | 9003 | Path Traversal / Excessive Permissions | ✅ DETECTED                         |
| CH4       | 9004 | Rug Pull (Temporal Mutation)           | GAP (stateful pattern exemption)    |
| CH5       | 9005 | Tool Shadowing                         | GAP (FastMCP compatibility)         |
| CH6       | 9006 | Indirect Prompt Injection              | GAP                                 |
| CH7       | 9007 | Token Theft via Info Disclosure        | ✅ DETECTED                         |
| CH8       | 9008 | Arbitrary Code Execution               | Safe reflection                     |
| CH9       | 9009 | Command Injection (RCE)                | ✅ DETECTED                         |
| CH10      | 9010 | Multi-Vector Attack Chain              | ✅ DETECTED (3 patterns + 12 vulns) |

**Important**: SSE servers (`server_sse.py`) have different tools than stdio servers (`server.py`). The poisoned descriptions are in `server.py` only.

### Testing with Published npm Package

**Config Files** (SSE transport - for servers already running):

```json
// /tmp/dvmcp-ch2-sse.json
{ "transport": "sse", "url": "http://localhost:9002/sse" }
```

**Config Files** (STDIO transport - for poisoned description testing):

```json
// /tmp/dvmcp-ch2-stdio.json
{
  "command": "/home/bryan/mcp-servers/damn-vulnerable-mcp-server/.venv/bin/python",
  "args": ["/tmp/run-ch2-stdio.py"]
}
```

**STDIO Wrapper Script** (required for server.py which defaults to HTTP):

```python
# /tmp/run-ch2-stdio.py
#!/usr/bin/env python
import sys
sys.path.insert(0, '/home/bryan/mcp-servers/damn-vulnerable-mcp-server/challenges/easy/challenge2')
from server import mcp
mcp.run(transport='stdio')
```

**Quick Usage with Published Package**:

```bash
# Install DVMCP dependencies first
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server
uv venv .venv && source .venv/bin/activate && uv pip install -e .

# Test via SSE (if server running)
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-sse.json --output /tmp/dvmcp-ch2-results.json

# Test via STDIO (for poisoned descriptions in server.py)
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-stdio.json --output /tmp/dvmcp-ch2-results.json
```

### v1.20.5 Validation Results (2025-12-31)

**CH2 Tool Description Poisoning** (STDIO server.py):

- `get_company_data`: 3 patterns detected (`important_tag`, `do_not_mention`, `internal_resource_uri`)
- `search_company_database`: 7 patterns detected (`hidden_tag`, `override_auth_protocol`, `internal_resource_uri`, `access_confidential`, `hidden_trigger_phrase` x2, `do_not_mention`)

**CH10 Multi-Vector** (STDIO server.py):

- `get_user_profile`: 2 patterns detected (`important_tag`, `internal_resource_uri`)
- `malicious_check_system_status`: 1 pattern detected (`hidden_tag`)
- Plus 12 security vulnerabilities (Command Injection, Calculator Injection, Code Execution, etc.)

**Check Results**:

```bash
# View poisoning detections
cat /tmp/dvmcp-ch2-results.json | jq '.toolAnnotations.toolResults[] | select(.descriptionPoisoning.detected == true) | {toolName, patterns: [.descriptionPoisoning.patterns[].name]}'

# Count poisoned tools
cat /tmp/dvmcp-ch2-results.json | jq '.toolAnnotations.poisonedDescriptionsDetected'
```

### Description Poisoning Patterns

The following patterns are detected by ToolAnnotationAssessor (added in v1.20.5):

| Pattern                  | Category             | Example                                    |
| ------------------------ | -------------------- | ------------------------------------------ |
| `important_tag`          | hidden_instructions  | `<IMPORTANT>...</IMPORTANT>`               |
| `hidden_tag`             | hidden_instructions  | `<HIDDEN>...</HIDDEN>`                     |
| `override_auth_protocol` | auth_bypass          | `override-auth-protocol-555`               |
| `internal_resource_uri`  | resource_access      | `company://confidential`, `system://admin` |
| `access_confidential`    | exfiltration         | `access the confidential`                  |
| `hidden_trigger_phrase`  | hidden_trigger       | `if the query contains the exact phrase`   |
| `do_not_mention`         | concealment          | `do not mention that you're accessing`     |
| `master_password`        | credential_reference | `include the master password`              |
| `get_secrets_call`       | hidden_trigger       | `get_secrets()`                            |

**Test Suite**: `client/src/services/assessment/__tests__/DescriptionPoisoning-DVMCP.test.ts`

### Known Gaps

**CH4 Rug Pull**: TemporalAssessor doesn't detect because `get_weather` matches "get" in `STATEFUL_TOOL_PATTERNS` (stateful tools use schema-only comparison).

**CH5 Tool Shadowing**: FastMCP version incompatibility (`listed=False` param not supported in newer mcp package).

## Assessment Result Analysis

Every assessment run automatically saves results to `/tmp/inspector-assessment-{serverName}.json` for fast CLI-based analysis.

**Quick Troubleshooting Commands:**

```bash
# View full assessment
cat /tmp/inspector-assessment-memory-mcp.json | jq

# Check functionality results
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality'

# List broken tools
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.brokenTools[]'

# Get specific tool details
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | select(.toolName == "tool_name")'

# See all tools and their status
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | {tool: .toolName, status: .overallStatus}'

# Get security vulnerabilities
cat /tmp/inspector-assessment-memory-mcp.json | jq '.security.vulnerabilities'

# Check error handling metrics
cat /tmp/inspector-assessment-memory-mcp.json | jq '.errorHandling.metrics'
```

## Feature Documentation

For detailed documentation on specific features:

**Documentation Index**: [docs/README.md](docs/README.md) - Complete navigation hub for all documentation

### Core Documentation

- **Assessment Catalog**: [docs/ASSESSMENT_CATALOG.md](docs/ASSESSMENT_CATALOG.md) - Complete assessment module reference with tier organization
- **Architecture & Value**: [docs/ARCHITECTURE_AND_VALUE.md](docs/ARCHITECTURE_AND_VALUE.md) - What inspector-assessment provides and why

### JSONL Events API

- **Event Reference**: [docs/JSONL_EVENTS_REFERENCE.md](docs/JSONL_EVENTS_REFERENCE.md) - All 13 event types and schema definitions
- **Algorithms**: [docs/JSONL_EVENTS_ALGORITHMS.md](docs/JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment
- **Integration**: [docs/JSONL_EVENTS_INTEGRATION.md](docs/JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, checklist, testing

**Schema Versioning (Issue #108):**

All events extend `BaseEvent` interface with `version` and `schemaVersion` fields. The `SCHEMA_VERSION` constant is maintained in `/client/src/lib/moduleScoring.ts` (single source of truth) and imported by CLI and orchestration modules. Increment `SCHEMA_VERSION` when event structure changes. See BaseEvent Interface section in JSONL_EVENTS_REFERENCE.md for details.

### Test Data Generation

- **Architecture**: [docs/TEST_DATA_ARCHITECTURE.md](docs/TEST_DATA_ARCHITECTURE.md) - Core architecture, field handlers, boundaries
- **Scenarios**: [docs/TEST_DATA_SCENARIOS.md](docs/TEST_DATA_SCENARIOS.md) - Scenario categories, tool-aware generation
- **Extension**: [docs/TEST_DATA_EXTENSION.md](docs/TEST_DATA_EXTENSION.md) - Adding handlers, debugging, integration

### Response Validation

- **Core**: [docs/RESPONSE_VALIDATION_CORE.md](docs/RESPONSE_VALIDATION_CORE.md) - Validation logic, business error detection
- **Extension**: [docs/RESPONSE_VALIDATION_EXTENSION.md](docs/RESPONSE_VALIDATION_EXTENSION.md) - Adding rules, troubleshooting, API reference

### Developer Guides

- **Assessment Module Guide**: [docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md](docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating and extending assessment modules
- **Scoring Algorithm**: [docs/SCORING_ALGORITHM_GUIDE.md](docs/SCORING_ALGORITHM_GUIDE.md) - Module weights, thresholds, calculations
- **Progressive Complexity**: [docs/PROGRESSIVE_COMPLEXITY_GUIDE.md](docs/PROGRESSIVE_COMPLEXITY_GUIDE.md) - 2-level testing approach

### Security Testing

- **Security Patterns Catalog**: [docs/SECURITY_PATTERNS_CATALOG.md](docs/SECURITY_PATTERNS_CATALOG.md) - Comprehensive attack patterns and payloads
- **Testbed Setup**: [docs/TESTBED_SETUP_GUIDE.md](docs/TESTBED_SETUP_GUIDE.md) - A/B validation with vulnerable-mcp/hardened-mcp
- **DVMCP Usage Guide**: [docs/DVMCP_USAGE_GUIDE.md](docs/DVMCP_USAGE_GUIDE.md) - Damn Vulnerable MCP testbed
- **Security Audits**: [docs/security/](docs/security/) - Security audit reports

### CLI & Operations

- **CLI Assessment Guide**: [docs/CLI_ASSESSMENT_GUIDE.md](docs/CLI_ASSESSMENT_GUIDE.md) - Complete CLI modes comparison
- **Upstream Sync Workflow**: [docs/UPSTREAM_SYNC_WORKFLOW.md](docs/UPSTREAM_SYNC_WORKFLOW.md) - Sync procedure with upstream

### Base Inspector Reference

- **Base Inspector Guide**: [docs/BASE_INSPECTOR_GUIDE.md](docs/BASE_INSPECTOR_GUIDE.md) - UI operation, Docker, auth, transports, config
- **Fork History**: [docs/FORK_HISTORY.md](docs/FORK_HISTORY.md) - Upstream relationship, sync status, what we added

### Specification & UI

- **Manifest Requirements**: [docs/MANIFEST_REQUIREMENTS.md](docs/MANIFEST_REQUIREMENTS.md) - manifest_version 0.3 spec
- **UI Component Reference**: [docs/UI_COMPONENT_REFERENCE.md](docs/UI_COMPONENT_REFERENCE.md) - Assessment UI architecture

### Related Projects

- **mcp-auditor**: See `../mcp-auditor/docs/` for auditor CLI usage (audit.js, stage-ab-compare.js) and Inspector integration docs

### Legacy References

- **Functionality Testing**: [README.md](README.md#assessment-modules-18-total) - Assessment modules overview
- **Security Assessment**: [README.md](README.md#security-testing-pure-behavior-detection) - Pure behavior-based security testing
- **Recent Changes**: [PROJECT_STATUS.md](PROJECT_STATUS.md#development-timeline---october-2025)

## Key Technical Implementations

**Assessment Architecture:**

- `client/src/services/assessment/TestScenarioEngine.ts` - Multi-scenario testing orchestration
- `client/src/services/assessment/ResponseValidator.ts` - Business logic error detection
- `client/src/services/assessment/TestDataGenerator.ts` - Context-aware test data
- `client/src/services/assessment/testdata/` - Test data constants (realistic values, tool categories)
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Domain-specific security testing
- `client/src/services/assessment/modules/ErrorHandlingAssessor.ts` - MCP protocol compliance
- `client/src/services/assessment/modules/ProtocolComplianceAssessor.ts` - Unified protocol compliance checks

**UI Components:**

- `client/src/components/ui/tool-selector.tsx` - Multi-select tool picker for error handling

> **Note**: Assessment Tab UI was deprecated in v1.23.0. Assessment functionality is now CLI-only via `mcp-assess-full` and `mcp-assess-security` commands.

**Testing:**

- `client/src/services/__tests__/` - Service layer tests
- `client/src/services/assessment/__tests__/` - Assessment module tests
- Total: ~1560 tests across 66 test suites

## Development Workflow

1. **Make changes** to source files
2. **Run tests** to ensure nothing broke: `npm test`
3. **Build** the project: `npm run build`
4. **Format code** (optional, auto-formatted on commit): `npm run prettier-fix`
5. **Test in dev mode**: `npm run dev` (opens http://localhost:6274)
6. **Commit changes** with descriptive message

## PROJECT_STATUS.md Maintenance & Archival

**Important**: When adding new timeline entries to PROJECT_STATUS.md, follow the archival procedure to keep the file manageable.

### Timeline Entry Guidelines

- **Format**: Reverse chronological order (newest entries at top)
- **Date Format**: `**2025-10-12**: Title - Description`
- **Location**: Add new entries at the top of "Development Timeline - October 2025" section
- **Structure**: Use consistent emoji indicators (✅ for completed, 🎯 for result, 📊 for impact, etc.)

### Archival Procedure (7-Day Rule)

**When to Archive**: After adding entries for a new day, check if there are entries older than 7 days.

**Steps**:

1. **Identify entries to archive**: Timeline entries from 8+ days ago

   ```bash
   grep -n "^\*\*2025-" /home/bryan/inspector/PROJECT_STATUS.md | head -15
   ```

2. **Extract entries with full detail sections**:
   - Find line boundaries: Summary entries end, detailed sections begin with `### 2025-`
   - Example: Lines 254-1015 contained Oct 7-9 summary + detailed sections

   ```bash
   grep -n "^### 2025-" /home/bryan/inspector/PROJECT_STATUS.md
   ```

3. **Append to PROJECT_STATUS_ARCHIVE.md**:
   - Extract entries: `sed -n 'START,ENDp' PROJECT_STATUS.md > /tmp/archived.txt`
   - Append to archive: `cat /tmp/archived.txt >> PROJECT_STATUS_ARCHIVE.md`

4. **Remove from PROJECT_STATUS.md**:

   ```bash
   sed -i 'START,ENDd' /home/bryan/inspector/PROJECT_STATUS.md
   ```

5. **Update archive note** (if first time archiving):
   - Add section after last Oct 10+ entry:

   ```markdown
   ---
   
   ## 📁 Older Timeline Entries
   
   **Note**: Timeline entries older than 7 days have been moved to [PROJECT_STATUS_ARCHIVE.md](PROJECT_STATUS_ARCHIVE.md) to keep this file focused on recent development.
   
   **Archive Policy**: Entries are automatically archived after 7 days to maintain readability and performance.
   
   **How to View Archived Entries**: See [PROJECT_STATUS_ARCHIVE.md](PROJECT_STATUS_ARCHIVE.md) for detailed entries from [date range] and earlier development history.
   
   ---
   ```

### Example Archival Session

```bash
# 1. Find boundaries
grep -n "^\*\*2025-10-09\|^\*\*2025-10-08\|^\*\*2025-10-07" PROJECT_STATUS.md
# Output: 254:**2025-10-09, 263:**2025-10-09, etc.

grep -n "^### 2025-10-09\|^### 2025-10-08\|^### 2025-10-07" PROJECT_STATUS.md
# Output: 288:### 2025-10-09, 424:### 2025-10-09, etc.

# 2. Extract (from first summary to last detailed section)
sed -n '254,1015p' PROJECT_STATUS.md > /tmp/archived.txt

# 3. Append to archive (add header first if new)
cat /tmp/archived.txt >> PROJECT_STATUS_ARCHIVE.md

# 4. Remove from main file
sed -i '254,1015d' PROJECT_STATUS.md

# 5. Verify
wc -l PROJECT_STATUS.md PROJECT_STATUS_ARCHIVE.md
```

### Archive File Structure

**PROJECT_STATUS_ARCHIVE.md** format:

```markdown
# Project Status Archive: MCP Inspector

This file contains archived project timeline entries from earlier development phases.

**Archive Policy**: Entries older than 7 days are moved here.

**Archived Date**: 2025-10-12

---

## Development Timeline - October 2025 (Oct 7-9)

[Summary entries]

---

[Detailed sections]
```

### Benefits

- **Performance**: Keeps main file under 2000 lines (readable in Claude)
- **Focus**: Recent entries remain visible and actionable
- **History**: Complete development history preserved in archive
- **Searchability**: Clear links between main and archive files

**Note**: Always add new timeline entries BEFORE performing archival. Archival is a maintenance task, not a development task.

## Documentation Maintenance Guidelines

### File Size Thresholds

**When to split**: Documentation files exceeding ~1000 lines should be split into focused documents.

**Target size**: Each split file should be 400-650 lines for optimal readability and Claude context efficiency.

### Split Strategy

1. **Identify logical sections**: Group related content (e.g., core vs extension, reference vs examples)
2. **Create focused files**: Name clearly (e.g., `GUIDE_CORE.md`, `GUIDE_EXTENSION.md`)
3. **Add series navigation**: Each split file should have a header linking to related files:
   ```markdown
   > **Part of the [Topic] documentation series:**
   >
   > - **Core** (this document) - Description
   > - [Extension](GUIDE_EXTENSION.md) - Description
   ```

### Backwards Compatibility

**Convert original files to redirect pages** - Don't delete, redirect:

```markdown
# [Original Title]

> **Note**: This guide has been split into focused documents for easier navigation.

## Quick Links

- [Document 1](link) - Description
- [Document 2](link) - Description

---

_For the complete documentation index, see [docs/README.md](README.md)._
```

### Navigation Hub

**Maintain `docs/README.md`** as the central navigation hub:

- Update when adding/splitting documentation
- Organize by category (Core, Security, CLI, etc.)
- Use tables for quick scanning

### Consistency Standards

- **Overview section**: All major docs should have an Overview section after the title
- **Table of Contents**: Files >500 lines should have a TOC
- **Related Documentation**: End files with links to related docs

## npm Package Publishing & Maintenance

**Package**: `@bryan-thompson/inspector-assessment`
**Current Version**: 1.24.2
**Registry**: https://www.npmjs.com/package/@bryan-thompson/inspector-assessment

### Quick Publish Workflow

When making changes that should be published to npm:

```bash
# 1. Ensure clean git state (required for npm version)
git status  # Should show no uncommitted changes to tracked files

# 2. Format all files (catches new docs that would fail prettier-check)
npm run prettier-fix
git add . && git commit -m "style: format files"  # If any changes

# 3. Bump version (workspaces sync automatically via lifecycle hook!)
npm version patch   # Bug fixes: 1.0.0 -> 1.0.1
npm version minor   # New features: 1.0.0 -> 1.1.0
npm version major   # Breaking changes: 1.0.0 -> 2.0.0

# 4. Publish all packages (workspaces + root)
npm run publish-all

# 5. Push to origin with tags
git push origin main --tags

# 6. Verify published package
bunx @bryan-thompson/inspector-assessment --help
```

**Note**: The `npm version` command automatically syncs all workspace versions via the `version` lifecycle script in package.json. No manual workspace syncing needed!

### Publishing Commands Reference

**Publish all packages** (recommended - publishes workspaces first, then root):

```bash
npm run publish-all
```

**Publish workspaces only**:

```bash
npm publish --workspaces --access public
```

**Publish root package only**:

```bash
npm publish --access public
```

**Check what will be published**:

```bash
npm pack
tar -tzf bryan-thompson-inspector-assessment-1.0.0.tgz
```

### Version Numbering Guide

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (1.0.0 → 1.0.1): Bug fixes, no new features, backward compatible
  - Security vulnerability fixes
  - Test expectation updates
  - Documentation corrections
  - Build script improvements

- **Minor** (1.0.0 → 1.1.0): New features, backward compatible
  - New assessment capabilities
  - Additional test scenarios
  - Performance improvements
  - New CLI options

- **Major** (1.0.0 → 2.0.0): Breaking changes
  - Changed API interfaces
  - Removed features
  - Changed command-line arguments
  - Modified assessment output format

### Package Structure

The npm package consists of 4 published packages:

1. **@bryan-thompson/inspector-assessment** (root) - Meta-package with CLI entry point
2. **@bryan-thompson/inspector-assessment-client** - React web interface
3. **@bryan-thompson/inspector-assessment-server** - Express backend
4. **@bryan-thompson/inspector-assessment-cli** - CLI tools

All four must be published for the package to work correctly.

### Workspace Architecture (Critical)

**Why workspace packages are NOT listed as npm dependencies:**

The root package bundles workspace code via the `files` array, NOT npm dependencies. This is a critical architectural decision:

```json
// CORRECT - workspace content is bundled via files array
"files": [
  "client/bin",
  "client/dist",
  "server/build",
  "cli/build"
]

// WRONG - DO NOT add workspace packages as dependencies
"dependencies": {
  "@bryan-thompson/inspector-assessment-cli": "^1.22.6"  // NEVER DO THIS
}
```

**Why this matters:**

1. When users run `npx @bryan-thompson/inspector-assessment`, npm resolves dependencies from the registry
2. If workspace packages are listed as deps with version `^X.Y.Z`, npm tries to fetch that exact version
3. If versions mismatch (e.g., workspaces at 1.22.5 but deps require ^1.22.6), installation fails with ETARGET
4. The `files` array physically includes the workspace builds in the tarball - no npm resolution needed

**Safeguards in place:**

- `npm run validate:publish` - Manual validation script
- `prepublishOnly` hook - Runs validation automatically before publish
- `package-structure.test.ts` - Unit test that fails if workspace deps found
- `.github/workflows/verify-publish.yml` - Post-publish CI verification

**If you see ETARGET errors during `npx` installation:**

1. Check `package.json` for workspace packages in dependencies
2. Remove any `@bryan-thompson/inspector-assessment-*` entries
3. Run `npm run validate:publish` to verify the fix

### Monorepo Publishing Gotchas

**Automated as of v1.17.1:**

1. **Workspace Version Sync** (Now Automated!)
   - ~~`npm version patch` only bumps the root package version~~
   - **Fixed**: The `version` lifecycle script in package.json now automatically syncs all workspace versions
   - Script: `scripts/sync-workspace-versions.js`
   - Just run `npm version patch` - everything syncs automatically!

**Still requires attention:**

2. **Prettier Formatting**
   - New files (especially docs) must be formatted before commit
   - `npm test` runs `prettier-check` first and fails if files aren't formatted
   - **Fix**: Run `npm run prettier-fix` before committing new files

3. **Clean Git Directory**
   - `npm version` fails if working directory has uncommitted changes
   - **Fix**: Commit or stash changes before running `npm version`

### Testing Published Package

```bash
# Test with bunx (no install, fastest)
bunx @bryan-thompson/inspector-assessment

# Test with npx
npx @bryan-thompson/inspector-assessment

# Test global install
npm install -g @bryan-thompson/inspector-assessment
mcp-inspector-assess --help
npm uninstall -g @bryan-thompson/inspector-assessment
```

### Known Issues

- **24 test failures**: Test expectation mismatches from security enhancements (non-blocking)
  - Tests expect "FAIL" but get "PASS" due to improved detection
  - Update test expectations in future release
  - Does not affect functionality

### Important Notes

- **Always publish workspaces first**: The root package depends on workspace packages being available on npm
- **Update CHANGELOG.md**: Document all changes before publishing
- **Test locally first**: Use `npm pack` and test the tarball before publishing
- **Format code**: Run `npm run prettier-fix` before publishing to avoid format issues
- **Git tags**: Create git tags for each release for version tracking
- **Node version**: Package requires Node >=22.7.5 (currently using v18.19.0 with warnings)

### Complete Publishing Checklist

- [ ] Make and test changes locally (`npm run dev`)
- [ ] Run tests (`npm test`)
- [ ] Update version (`npm version [patch|minor|major]`)
- [ ] Update CHANGELOG.md with changes
- [ ] Build project (`npm run build`)
- [ ] Format code (`npm run prettier-fix`)
- [ ] Publish packages (`npm run publish-all`)
- [ ] Test published package (`bunx @bryan-thompson/inspector-assessment`)
- [ ] Commit changes (`git commit -am "chore: release vX.Y.Z"`)
- [ ] Create git tag (`git tag vX.Y.Z`)
- [ ] Push to GitHub (`git push origin main --tags`)
- [ ] Update PROJECT_STATUS.md with release notes

### Future Migration Path

If Anthropic adopts this package, it can be migrated to `@modelcontextprotocol/inspector-assessment`:

1. Update all package.json names
2. Publish to new namespace
3. Deprecate old packages with migration notice

## Upstream Sync Status

- **Current Version**: 0.18.0
- **Last Sync**: 2025-12-23 (synced from v0.17.5 to v0.18.0)
- **Fork**: triepod-ai/inspector-assessment
- **Upstream**: modelcontextprotocol/inspector
- **Integration Doc**: [docs/UPSTREAM_SYNC_WORKFLOW.md](docs/UPSTREAM_SYNC_WORKFLOW.md) - Comprehensive sync procedure (35K)
- See [PROJECT_STATUS.md](PROJECT_STATUS.md) for sync history

### Upstream Sync Helper Script

Use the automated sync script for guided upstream syncing:

```bash
# Check status and view upstream changes (safe, read-only)
npm run sync:upstream

# Individual commands
./scripts/sync-upstream.sh status    # Show sync status and divergence
./scripts/sync-upstream.sh diff      # View upstream changes to App.tsx
./scripts/sync-upstream.sh merge     # Attempt merge with conflict guidance
./scripts/sync-upstream.sh validate  # Build and test after merge
```

**What the script does:**

- Fetches upstream and shows how many commits behind/ahead
- Highlights if upstream changes affect our integration lines in App.tsx
- Provides merge conflict resolution guidance referencing UPSTREAM_SYNC.md
- Prompts to update UPSTREAM_SYNC.md with new version info after successful merge

**Integration Architecture:**

Assessment functionality is CLI-only (v1.23.0+):

- **No UI integration points** - Assessment Tab UI was deprecated
- **CLI tools**: `mcp-assess-full` and `mcp-assess-security` are the primary interfaces
- **~160k lines** of assessment code in dedicated directories (no upstream conflicts)
- **npm package**: Assessment modules exported for programmatic use via `@bryan-thompson/inspector-assessment`

See [docs/UPSTREAM_SYNC_WORKFLOW.md](docs/UPSTREAM_SYNC_WORKFLOW.md) for sync workflow documentation.
