# MCP Inspector Assessment

[![npm version](https://badge.fury.io/js/@bryan-thompson%2Finspector-assessment.svg)](https://www.npmjs.com/package/@bryan-thompson/inspector-assessment)
[![npm downloads](https://img.shields.io/npm/dm/@bryan-thompson/inspector-assessment.svg)](https://www.npmjs.com/package/@bryan-thompson/inspector-assessment)

**Comprehensive MCP server validation with 18 automated assessment modules.**
Test functionality, security, documentation, and policy compliance from the command line.

![MCP Inspector Screenshot](./mcp-inspector.png)

---

## Installation

```bash
# Install globally
npm install -g @bryan-thompson/inspector-assessment

# Or use directly with bunx (no installation)
bunx @bryan-thompson/inspector-assessment
```

---

## Quick Start: Assess an MCP Server

Run a full assessment on any MCP server:

```bash
# Create a config file
cat > /tmp/config.json << 'EOF'
{
  "transport": "http",
  "url": "http://localhost:8000/mcp"
}
EOF

# Run full assessment
mcp-assess-full --server my-server --config /tmp/config.json

# Results saved to /tmp/inspector-full-assessment-my-server.json
```

For STDIO servers (local commands):

```bash
cat > /tmp/config.json << 'EOF'
{
  "command": "python3",
  "args": ["server.py"],
  "env": {}
}
EOF

mcp-assess-full --server my-server --config /tmp/config.json
```

---

## CLI Commands

The inspector provides three CLI commands for different workflows:

| Command                | Purpose                       | Use Case                     |
| ---------------------- | ----------------------------- | ---------------------------- |
| `mcp-assess-full`      | Complete 18-module assessment | Full validation, CI/CD gates |
| `mcp-assess-security`  | Security-only testing         | Quick vulnerability scan     |
| `mcp-inspector-assess` | Interactive web UI            | Debugging, exploration       |

### Common Options

```bash
# Full assessment with all modules
mcp-assess-full --server <name> --config <path>

# Security-only (faster)
mcp-assess-security --server <name> --config <path>

# Skip slow modules for CI/CD
mcp-assess-full --server <name> --skip-modules temporal,security

# Run only specific modules
mcp-assess-full --server <name> --only-modules functionality,toolAnnotations

# Generate markdown report
mcp-assess-full --server <name> --format markdown --output report.md

# Pre-flight validation (quick check)
mcp-assess-full --server <name> --preflight
```

For complete CLI documentation, see [CLI Assessment Guide](docs/CLI_ASSESSMENT_GUIDE.md).

---

## Assessment Modules (18 Total)

### Core Modules (16)

| Module                   | Purpose                      | Key Features                                        |
| ------------------------ | ---------------------------- | --------------------------------------------------- |
| **Functionality**        | Tool execution validation    | Multi-scenario testing, business logic detection    |
| **Security**             | Vulnerability detection      | Comprehensive attack patterns, zero false positives |
| **Documentation**        | README/description quality   | Completeness scoring, example validation            |
| **Error Handling**       | MCP protocol compliance      | Error code validation, response quality             |
| **Usability**            | Developer experience         | Naming conventions, schema completeness             |
| **MCP Spec Compliance**  | Protocol adherence           | JSON-RPC 2.0, MCP message formats                   |
| **AUP Compliance**       | Policy violation detection   | 14 AUP categories (A-N)                             |
| **Tool Annotations**     | readOnlyHint/destructiveHint | Policy #17 compliance                               |
| **Prohibited Libraries** | Dependency security          | Blocked packages (Stripe, FFmpeg, etc.)             |
| **External API Scanner** | External service detection   | API URLs, affiliation warnings                      |
| **Authentication**       | OAuth/auth evaluation        | Auth pattern validation, deployment context         |
| **Temporal**             | Rug pull detection           | Behavior changes over invocations                   |
| **Resources**            | Resource capability          | Discovery, read success, errors                     |
| **Prompts**              | Prompt capability            | Execution, multimodal support                       |
| **Cross-Capability**     | Chained vulnerabilities      | Multi-tool attack patterns                          |
| **Protocol Conformance** | Protocol-level validation    | Error format, content types, initialization         |

### Optional Modules (2) - MCPB Bundles

| Module                  | Purpose                      | Policy Alignment                        |
| ----------------------- | ---------------------------- | --------------------------------------- |
| **Manifest Validation** | MCPB manifest.json           | manifest_version 0.3 spec               |
| **Portability**         | Cross-platform compatibility | Hardcoded paths, platform-specific code |

For detailed module documentation, see [Assessment Catalog](docs/ASSESSMENT_CATALOG.md).

---

## Security Testing: Pure Behavior Detection

The inspector uses **pure behavior-based detection** for security assessment, analyzing tool responses to identify actual code execution vs safe data handling.

### How It Works

```bash
# Run security assessment
mcp-assess-security --server my-server --config config.json
```

**Detection Strategy:**

1. **Reflection Detection**: Identifies when tools safely echo malicious input as data
   - `"Stored query: ../../../etc/passwd"` → SAFE (reflection)
   - `"Query results for: ..."` → SAFE (search results)

2. **Execution Evidence**: Detects actual code execution
   - Response contains `"root:x:0:0"` → VULNERABLE (file accessed)
   - Response contains `"total 42 drwx"` → VULNERABLE (directory listed)

3. **Category Classification**: Distinguishes safe tool types
   - Search/retrieval tools return data, not code execution
   - CRUD operations create resources, not execute code

### Supported Attack Patterns

- Command Injection, SQL Injection, Path Traversal, XXE, NoSQL Injection
- Calculator Injection, Code Execution (Python/JS)
- Data Exfiltration, Token Theft, Permission Scope
- Unicode Bypass, Nested Injection, Package Squatting
- DoS/Resource Exhaustion, Insecure Deserialization
- Configuration Drift, Tool Shadowing

See [Security Patterns Catalog](docs/SECURITY_PATTERNS_CATALOG.md) for complete pattern documentation.

---

## Testbed Validation

The inspector is validated against purpose-built testbed servers with ground-truth labeled tools:

```bash
# Test against vulnerable-mcp testbed (10 vulnerable + 6 safe tools)
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json
# Results: 200 vulnerabilities detected, 0 false positives (100% precision)

# Test against hardened-mcp testbed (same tool names, safe implementations)
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json
# Results: 0 vulnerabilities (proves behavior-based detection, not name-based)
```

**Key Insight**: Both servers have tools named `vulnerable_calculator_tool`, `vulnerable_system_exec_tool`, etc. The inspector detects 200 vulnerabilities on one server and 0 on the other - proving pure behavior-based detection, not name-based heuristics.

See [Testbed Setup Guide](docs/TESTBED_SETUP_GUIDE.md) for detailed validation results.

---

## Assessment Output

### JSON Results

Every assessment saves results to JSON:

```bash
# Default location
/tmp/inspector-full-assessment-<server-name>.json

# Custom output
mcp-assess-full --server my-server --output ./results.json
```

**Quick Analysis:**

```bash
# View overall status
cat /tmp/inspector-full-assessment-my-server.json | jq '.overallStatus'

# List security vulnerabilities
cat /tmp/inspector-full-assessment-my-server.json | jq '.security.vulnerabilities'

# Check broken tools
cat /tmp/inspector-full-assessment-my-server.json | jq '.functionality.brokenTools'

# Get module scores
cat /tmp/inspector-full-assessment-my-server.json | jq '.moduleSummary'
```

### Exit Codes

```bash
mcp-assess-full --server my-server
echo $?
# 0 = PASS (all modules passed)
# 1 = FAIL (vulnerabilities or failures found)
```

---

## Quality Metrics

- **Test Coverage**: ~1560 tests passing across 66 test suites
- **Assessment Module Tests**: 291+ tests validating assessment enhancements
- **Code Quality**: Production TypeScript types, proper error handling
- **Upstream Sync**: Up-to-date with v0.18.0

**Run tests:**

```bash
npm test                         # All ~1560 tests
npm test -- assessment           # Assessment module tests
npm test -- SecurityAssessor     # Security tests
```

---

## Documentation

### Quick Start

| Document                                               | Purpose                        |
| ------------------------------------------------------ | ------------------------------ |
| [CLI Assessment Guide](docs/CLI_ASSESSMENT_GUIDE.md)   | Complete CLI modes and options |
| [Architecture & Value](docs/ARCHITECTURE_AND_VALUE.md) | What this provides and why     |

### API & Integration

| Document                                                 | Purpose                      |
| -------------------------------------------------------- | ---------------------------- |
| [Programmatic API Guide](docs/PROGRAMMATIC_API_GUIDE.md) | AssessmentOrchestrator usage |
| [API Reference](docs/API_REFERENCE.md)                   | Complete API documentation   |
| [Integration Guide](docs/INTEGRATION_GUIDE.md)           | CI/CD, multi-server patterns |

### Assessment Details

| Document                                                       | Purpose                              |
| -------------------------------------------------------------- | ------------------------------------ |
| [Assessment Catalog](docs/ASSESSMENT_CATALOG.md)               | Complete assessment module reference |
| [Security Patterns Catalog](docs/SECURITY_PATTERNS_CATALOG.md) | Comprehensive attack patterns        |
| [Testbed Setup Guide](docs/TESTBED_SETUP_GUIDE.md)             | A/B validation                       |

For complete documentation, see [docs/README.md](docs/README.md).

---

## Evidence & Validation

All performance claims are backed by implementation analysis.

| Claim                             | Evidence                                                                          |
| --------------------------------- | --------------------------------------------------------------------------------- |
| Progressive complexity (2 levels) | [TestScenarioEngine.ts](client/src/services/assessment/TestScenarioEngine.ts)     |
| Comprehensive security patterns   | [securityPatterns.ts](client/src/lib/securityPatterns.ts)                         |
| Zero false positives              | [SecurityAssessor.ts](client/src/services/assessment/modules/SecurityAssessor.ts) |

---

## Contributing

We welcome contributions! See [PROJECT_STATUS.md](PROJECT_STATUS.md) for current development status.

**Areas of interest:**

- Additional security patterns
- Performance optimizations
- CI/CD integration examples
- New assessment modules

**Repository**: https://github.com/triepod-ai/inspector-assessment

---

## Links

- **npm Package**: https://www.npmjs.com/package/@bryan-thompson/inspector-assessment
- **GitHub Repository**: https://github.com/triepod-ai/inspector-assessment
- **Issues**: https://github.com/triepod-ai/inspector-assessment/issues
- **MCP Documentation**: https://modelcontextprotocol.io
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

## License

This project is licensed under the MIT License—see the [LICENSE](LICENSE) file for details.

---

<a id="about-this-fork"></a>

## Appendix: Fork History & Acknowledgments

This is an enhanced fork of [Anthropic's MCP Inspector](https://github.com/modelcontextprotocol/inspector) with significantly expanded assessment capabilities.

| Repository    | URL                                                |
| ------------- | -------------------------------------------------- |
| **Original**  | https://github.com/modelcontextprotocol/inspector  |
| **This Fork** | https://github.com/triepod-ai/inspector-assessment |

**Note**: If you want the official Anthropic inspector without assessment features, use:

```bash
npx @modelcontextprotocol/inspector
```

### What We Added

We built a comprehensive assessment framework on top of the original inspector, transforming it from a debugging tool into a full validation suite. Key additions:

- **17 Assessment Modules** covering functionality, security, compliance
- **Pure Behavior-Based Detection** analyzing responses, not tool names
- **Zero False Positives** through context-aware reflection detection
- **CLI-First Workflow** with three specialized commands

### Base Inspector Features

For documentation on the underlying inspector UI and operational features (Docker, authentication, configuration, transports), see:

- [Base Inspector Guide](docs/BASE_INSPECTOR_GUIDE.md)
- [Fork History](docs/FORK_HISTORY.md)
- [Upstream Sync Workflow](docs/UPSTREAM_SYNC_WORKFLOW.md)

### Acknowledgments

This project builds upon the excellent foundation provided by Anthropic's MCP Inspector team. We're grateful for their work on the original inspector and the MCP protocol specification.
