# Inspector-Assessment: Architecture & Value Proposition

## Overview

This document explains what inspector-assessment provides, how it integrates with mcp-auditor, and why behavioral testing matters compared to Claude-only reasoning. It covers architecture, component breakdown, and the value of behavioral testing vs static analysis.

**Key Topics:**

- Architecture overview and component breakdown
- Comparison with original MCP Inspector
- Why behavioral testing matters (behavioral proof vs speculation)
- The 16 assessment modules
- Integration with mcp-auditor

---

## Executive Summary

**inspector-assessment** is a fork of Anthropic's MCP Inspector that adds:

1. **Programmatic CLI access** - Test any MCP server from command line
2. **16 automated assessment modules** - Security, functionality, documentation, and more
3. **Behavioral security testing** - Actually calls tools with attack payloads
4. **CI/CD integration** - Exit codes, JSON output, JSONL progress events

**The key innovation is "pipe through"** - the ability to connect to arbitrary MCP servers via config file and run comprehensive automated assessment without code changes.

### Related Documentation

For detailed implementation guides, see:

- **[ASSESSMENT_MODULE_DEVELOPER_GUIDE.md](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md)** - Creating and extending assessment modules
- **[SCORING_ALGORITHM_GUIDE.md](SCORING_ALGORITHM_GUIDE.md)** - Module weights, thresholds, calculations
- **[SECURITY_PATTERNS_CATALOG.md](SECURITY_PATTERNS_CATALOG.md)** - Comprehensive attack patterns and payloads
- **[CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md)** - Three CLI modes comparison
- **[JSONL_EVENTS_API.md](JSONL_EVENTS_API.md)** - Real-time event streaming reference

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            mcp-auditor                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │  audit-worker.js                                                     │    │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐            │    │
│  │  │ GitHub Audit  │  │  HTTP Audit   │  │  Local Audit  │            │    │
│  │  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘            │    │
│  │          │                  │                  │                     │    │
│  │          ▼                  ▼                  ▼                     │    │
│  │  ┌─────────────────────────────────────────────────────────────┐    │    │
│  │  │              npx mcp-assess-full                             │    │    │
│  │  │              (spawned as child process)                      │    │    │
│  │  └─────────────────────────┬───────────────────────────────────┘    │    │
│  │                            │                                         │    │
│  │                    JSONL to stderr ──────► Real-time WebSocket      │    │
│  │                    JSON to file ─────────► Result parsing           │    │
│  └────────────────────────────┼─────────────────────────────────────────┘    │
└───────────────────────────────┼──────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      inspector-assessment (our mod)                          │
│                                                                              │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │  "Pipe Through" - The Key Innovation                              │      │
│   │                                                                   │      │
│   │   Config File ──► Transport Auto-Detection ──► MCP Server        │      │
│   │       │                    │                        │             │      │
│   │       │            ┌───────┴───────┐               │             │      │
│   │       │            │               │               │             │      │
│   │       │         STDIO          HTTP/SSE           │             │      │
│   │       │            │               │               │             │      │
│   │       ▼            ▼               ▼               ▼             │      │
│   │   ┌─────────────────────────────────────────────────────────────┐       │
│   │   │           Unified MCP Client Interface                      │       │
│   │   │   - listTools() → discover all tools                        │       │
│   │   │   - callTool(name, params) → test any tool                  │       │
│   │   └─────────────────────────────────────────────────────────────┘       │
│   └──────────────────────────────────────────────────────────────────┘      │
│                                    │                                         │
│                                    ▼                                         │
│   ┌──────────────────────────────────────────────────────────────────┐      │
│   │                    16 Assessment Modules                          │      │
│   │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐     │      │
│   │  │Functionality│ │  Security  │ │   Docs     │ │Error Handle│     │      │
│   │  └────────────┘ └────────────┘ └────────────┘ └────────────┘     │      │
│   │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐     │      │
│   │  │MCP Spec    │ │    AUP     │ │Tool Annot. │ │Prohibited  │     │      │
│   │  └────────────┘ └────────────┘ └────────────┘ └────────────┘     │      │
│   │  ┌────────────┐ ┌────────────┐ ┌────────────┐                    │      │
│   │  │ Manifest   │ │Portability │ │ Usability  │                    │      │
│   │  └────────────┘ └────────────┘ └────────────┘                    │      │
│   └──────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component              | Location                                  | Purpose                               |
| ---------------------- | ----------------------------------------- | ------------------------------------- |
| **CLI Entry Points**   | `cli/src/*.ts`                            | Command-line interface (primary)      |
| **Transport Layer**    | `cli/src/transport.ts`                    | STDIO/HTTP/SSE connection abstraction |
| **Assessment Modules** | `client/src/services/assessment/modules/` | 16 specialized assessors              |
| **JSONL Events**       | `scripts/lib/jsonl-events.ts`             | Real-time progress streaming          |
| **Legacy Scripts**     | `scripts/run-*.ts`                        | Deprecated fallback runners (v1 only) |

---

## Comparison: Original Inspector vs Our Fork

| Capability                   | Original Inspector        | inspector-assessment                      |
| ---------------------------- | ------------------------- | ----------------------------------------- |
| **Interface**                | Web UI only               | Web UI + CLI + npm package                |
| **Server Connection**        | Manual browser navigation | Config-based auto-connect                 |
| **Transport Support**        | Interactive only          | Programmatic STDIO/HTTP/SSE               |
| **Assessment**               | None (debugging tool)     | 16 automated modules                      |
| **Security Testing**         | Manual click-testing      | Comprehensive attack patterns, behavioral |
| **CI/CD Ready**              | No                        | Exit codes, JSON output                   |
| **Real-time Progress**       | No                        | JSONL events to stderr                    |
| **Arbitrary Server Testing** | Requires code changes     | Config file only                          |

### The "Pipe Through" Innovation

The original inspector required:

1. Start web server manually
2. Navigate browser to UI
3. Configure server connection in browser
4. Click through tools one by one

Our fork enables:

```bash
# Single command to assess any MCP server
npm run assess -- --server my-server --config /path/to/config.json
```

No code changes needed. Just add a config file:

```json
{
  "transport": "stdio",
  "command": "python3",
  "args": ["server.py"]
}
```

---

## Why Behavioral Testing Matters

### The Core Problem

Claude can reason about tool safety from:

- Tool names and descriptions
- Parameter schemas
- Source code (if available)

**But this is like a security auditor reading API documentation and guessing if there are vulnerabilities, vs actually sending attack payloads and observing responses.**

### Concrete Example: Path Traversal

**What inspector-assessment does (behavioral proof):**

```
Tool: file_reader
Input: {"path": "../../../etc/passwd"}
Response: "root:x:0:0:root:/root:/bin/bash..."
Result: VULNERABLE (path traversal confirmed)
```

**What Claude reasoning would do (speculation):**

```
Tool: file_reader
Description: "Reads files from the filesystem"
Claude: "This MIGHT be vulnerable to path traversal..."
Result: UNCERTAIN (no behavioral confirmation)
```

### Implications

| Aspect              | Behavioral Testing                      | Claude Reasoning Only                |
| ------------------- | --------------------------------------- | ------------------------------------ |
| **False Positives** | Near-zero (tests actual behavior)       | Higher (safe tools flagged as risky) |
| **False Negatives** | Low (actually exploits vulnerabilities) | Higher (vulnerabilities missed)      |
| **Confidence**      | Proof                                   | Speculation                          |
| **Reproducibility** | Same tests every time                   | Varies by prompt/context             |

---

## The 16 Assessment Modules

### Behavioral Testing Modules

| Module                  | What It Tests             | Attack Patterns                                                  |
| ----------------------- | ------------------------- | ---------------------------------------------------------------- |
| **Security**            | Injection vulnerabilities | Comprehensive patterns (command, SQL, path traversal, XSS, etc.) |
| **Functionality**       | Tools actually work       | Progressive complexity, edge cases, stress tests                 |
| **Error Handling**      | Graceful failure          | Invalid inputs, timeouts, malformed data                         |
| **MCP Spec Compliance** | Protocol correctness      | Error formats, content types, required fields                    |

### Static Analysis Modules

These catch things behavioral testing cannot:

| Module                   | What It Checks                    | Why It Matters                                  |
| ------------------------ | --------------------------------- | ----------------------------------------------- |
| **Documentation**        | Tool/param descriptions           | LLM usability - can Claude understand the tool? |
| **Tool Annotations**     | `readOnlyHint`, `destructiveHint` | Safety metadata for LLM decision-making         |
| **AUP Compliance**       | Prohibited categories             | Policy compliance (CSAM, weapons, etc.)         |
| **Prohibited Libraries** | Dangerous dependencies            | Supply chain security                           |
| **Portability**          | Platform-specific code            | Deployment flexibility                          |
| **Manifest Validation**  | package.json, pyproject.toml      | Bundle compatibility                            |
| **Usability**            | Parameter clarity, naming         | Developer experience                            |

**Key insight:** A tool might work perfectly (pass functionality) but have a malicious dependency (fail prohibited libraries) or violate AUP. Static checks complement behavioral tests.

---

## Integration with mcp-auditor

### How mcp-auditor Invokes Inspector

```javascript
// audit-worker.js spawns inspector as child process
spawn(
  "npx",
  [
    "-p",
    "@bryan-thompson/inspector-assessment",
    "mcp-assess-full",
    "--server",
    serverName,
    "--config",
    configPath,
    "--output",
    outputPath,
    "--json",
    "--full",
  ],
  { env: getNode22Env() },
);
```

### Real-Time Progress (JSONL)

Inspector emits structured events to stderr:

```json
{"event":"server_connected","serverName":"my-server","transport":"stdio"}
{"event":"tool_discovered","name":"calc","description":"Calculator tool"}
{"event":"module_started","module":"security","estimatedTests":39}
{"event":"test_batch","module":"security","completed":10,"total":39}
{"event":"assessment_complete","overallStatus":"PASS","totalTests":39}
```

mcp-auditor parses these for live WebSocket updates to the frontend.

### Score Mapping

Inspector's 16 modules are mapped to mcp-auditor's 5 categories:

- **Functionality** = functionality + mcpSpecCompliance
- **Security** = security + aupCompliance + prohibitedLibraries
- **Documentation** = documentation
- **Error Handling** = errorHandling
- **Usability** = usability + toolAnnotations + portability

---

## What You'd Lose Without Inspector-Assessment

### Fallback Behavior

mcp-auditor gracefully degrades if inspector fails:

```javascript
function generateFallbackResults() {
  return {
    scores: {
      functionality: 50, // Neutral
      security: 50,
      documentation: 50,
      errorHandling: 50,
      usability: 50,
    },
    recommendations: ["Manual review recommended"],
  };
}
```

### Comparison Table

| Aspect                  | With Inspector                     | Without Inspector                           |
| ----------------------- | ---------------------------------- | ------------------------------------------- |
| **Audit Quality**       | 16 automated modules, quantitative | Fallback 50% scores, "manual review needed" |
| **Security Confidence** | Behavioral proof                   | Claude speculation                          |
| **CI/CD Integration**   | Pass/Fail automation               | Always "VERIFY" level                       |
| **Tool Discovery**      | Auto-enumerated                    | Manual listing required                     |
| **Real-time Progress**  | JSONL streaming                    | No progress visibility                      |
| **Reproducibility**     | Same tests every run               | Varies by Claude session                    |
| **Cost**                | One-time assessment                | Token cost per analysis                     |

---

## Conclusion

**inspector-assessment provides three things Claude alone cannot:**

1. **Behavioral Ground Truth** - Actually calls tools with attack payloads and observes real responses. Claude can only reason about descriptions.

2. **Systematic Coverage** - Comprehensive security patterns x all tools x multiple payloads = thorough testing. Claude would need extensive prompting to achieve similar coverage.

3. **Quantitative, Reproducible Metrics** - Same tests, same scoring, every time. Enables comparison, trending, CI/CD automation.

### The Ideal Architecture

```
inspector-assessment (behavioral testing, quantitative data)
         +
Claude (interpretation, recommendations, nuanced analysis)
         =
Comprehensive MCP server audit
```

You could audit servers with Claude alone, but you'd lose the **behavioral proof** that a tool is actually vulnerable vs just looking suspicious.

---

## Related Documentation

- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete 16-module reference
- [REAL_TIME_PROGRESS_OUTPUT.md](REAL_TIME_PROGRESS_OUTPUT.md) - JSONL event format
- [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) - CLI modes and options
