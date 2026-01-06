# Integration Guide

Practical patterns for integrating `@bryan-thompson/inspector-assessment` into your projects.

> **Related Documentation:**
>
> - [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Getting started with AssessmentOrchestrator
> - [API Reference](API_REFERENCE.md) - Complete API documentation
> - [Type Reference](TYPE_REFERENCE.md) - TypeScript type definitions

---

## Table of Contents

- [Overview](#overview)
- [Basic Integration Pattern](#basic-integration-pattern)
- [Transport Connections](#transport-connections)
  - [STDIO Transport](#stdio-transport)
  - [HTTP Transport](#http-transport)
  - [SSE Transport](#sse-transport)
- [Multi-Server Assessment](#multi-server-assessment)
- [Progressive Assessment](#progressive-assessment)
- [Result Processing](#result-processing)
- [Error Recovery](#error-recovery)
- [CI/CD Integration](#cicd-integration)
- [Advanced Features](#advanced-features)
  - [Source Code Analysis](#source-code-analysis)
  - [Claude Code Integration](#claude-code-integration)
  - [Custom Pattern Configuration](#custom-pattern-configuration)
- [Performance Optimization](#performance-optimization)
- [Testing Your Integration](#testing-your-integration)
- [Troubleshooting](#troubleshooting)
- [Complete Example](#complete-example)

---

## Overview

This guide covers common integration patterns for using the inspector-assessment package programmatically. Whether you're building a CI/CD pipeline, an audit tool, or a custom MCP management system, these patterns provide a foundation for your implementation.

**Key Integration Points:**

1. **Transport Setup** - Connect to MCP servers via stdio, HTTP, or SSE
2. **Context Building** - Construct the AssessmentContext with all metadata
3. **Orchestration** - Run assessments with appropriate configuration
4. **Result Processing** - Extract and act on assessment findings

---

## Basic Integration Pattern

The fundamental pattern for any integration:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  AssessmentOrchestrator,
  type AssessmentContext,
} from "@bryan-thompson/inspector-assessment";
import { DEFAULT_ASSESSMENT_CONFIG } from "@bryan-thompson/inspector-assessment/config";

async function assessServer(serverConfig: { command: string; args: string[] }) {
  // 1. Create transport and client
  const transport = new StdioClientTransport({
    command: serverConfig.command,
    args: serverConfig.args,
    stderr: "pipe",
  });

  const client = new Client(
    { name: "my-assessor", version: "1.0.0" },
    { capabilities: {} },
  );

  await client.connect(transport);

  // 2. Discover capabilities
  const { tools } = await client.listTools();

  // 3. Build assessment context
  const orchestrator = new AssessmentOrchestrator();
  const context: AssessmentContext = {
    serverName: "my-server",
    tools,
    callTool: async (name, params) => {
      const response = await client.callTool({ name, arguments: params });
      return {
        content: response.content,
        isError: response.isError || false,
      };
    },
    config: orchestrator.getConfig(),
  };

  // 4. Run assessment
  const results = await orchestrator.runFullAssessment(context);

  // 5. Cleanup
  await client.close();

  return results;
}
```

---

## Transport Connections

### STDIO Transport

For servers launched as child processes:

```typescript
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "npx",
  args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
  env: {
    ...process.env,
    NODE_ENV: "production",
  },
  stderr: "pipe", // Capture stderr for error reporting
});

// Capture stderr before connecting
let stderrOutput = "";
if (transport.stderr) {
  transport.stderr.on("data", (data: Buffer) => {
    stderrOutput += data.toString();
  });
}

try {
  await client.connect(transport);
} catch (error) {
  console.error("Connection failed:", error);
  if (stderrOutput) {
    console.error("Server stderr:", stderrOutput);
  }
  throw error;
}
```

### HTTP Transport

For HTTP-based MCP servers:

```typescript
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("http://localhost:3000/mcp"),
);

await client.connect(transport);

// Include transport info in context for security assessment
const context: AssessmentContext = {
  // ... other fields
  transportConfig: {
    type: "streamable-http",
    url: "http://localhost:3000/mcp",
    usesTLS: false,
    oauthEnabled: false,
  },
};
```

### SSE Transport

For Server-Sent Events transport (legacy):

```typescript
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";

const transport = new SSEClientTransport(new URL("http://localhost:3000/sse"));

await client.connect(transport);
```

---

## Multi-Server Assessment

Assess multiple servers in parallel:

```typescript
interface ServerConfig {
  name: string;
  command: string;
  args: string[];
}

async function assessMultipleServers(servers: ServerConfig[]) {
  const orchestrator = new AssessmentOrchestrator({
    parallelTesting: true,
    testTimeout: 30000,
  });

  const results = await Promise.allSettled(
    servers.map(async (server) => {
      const transport = new StdioClientTransport({
        command: server.command,
        args: server.args,
        stderr: "pipe",
      });

      const client = new Client(
        { name: "multi-assessor", version: "1.0.0" },
        { capabilities: {} },
      );

      try {
        await client.connect(transport);
        const { tools } = await client.listTools();

        const context: AssessmentContext = {
          serverName: server.name,
          tools,
          callTool: async (name, params) => {
            const response = await client.callTool({ name, arguments: params });
            return {
              content: response.content,
              isError: response.isError || false,
            };
          },
          config: orchestrator.getConfig(),
        };

        const result = await orchestrator.runFullAssessment(context);
        await client.close();

        return { server: server.name, result };
      } catch (error) {
        await client.close().catch(() => {});
        throw { server: server.name, error };
      }
    }),
  );

  // Process results
  const successful = results
    .filter(
      (r): r is PromiseFulfilledResult<{ server: string; result: any }> =>
        r.status === "fulfilled",
    )
    .map((r) => r.value);

  const failed = results
    .filter((r): r is PromiseRejectedResult => r.status === "rejected")
    .map((r) => r.reason);

  return { successful, failed };
}
```

---

## Progressive Assessment

Run assessments in stages with early exit on failures:

```typescript
import {
  AssessmentOrchestrator,
  type AssessmentContext,
} from "@bryan-thompson/inspector-assessment";
import {
  REVIEWER_MODE_CONFIG,
  AUDIT_MODE_CONFIG,
} from "@bryan-thompson/inspector-assessment/config";

async function progressiveAssessment(context: AssessmentContext) {
  // Stage 1: Quick screening (fast)
  const quickOrchestrator = new AssessmentOrchestrator({
    ...REVIEWER_MODE_CONFIG,
    assessmentCategories: {
      functionality: true,
      security: true,
      documentation: false,
      errorHandling: false,
      usability: false,
    },
  });

  console.log("Stage 1: Quick screening...");
  const quickResults = await quickOrchestrator.runFullAssessment(context);

  if (quickResults.overallStatus === "FAIL") {
    console.log("Failed quick screening, stopping early");
    return { stage: 1, results: quickResults, passed: false };
  }

  // Stage 2: Full assessment (comprehensive)
  console.log("Stage 2: Full assessment...");
  const fullOrchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);
  const fullResults = await fullOrchestrator.runFullAssessment(context);

  return {
    stage: 2,
    results: fullResults,
    passed: fullResults.overallStatus === "PASS",
  };
}
```

---

## Result Processing

### Extracting Key Findings

```typescript
function extractFindings(results: MCPDirectoryAssessment) {
  const findings = {
    critical: [] as string[],
    warnings: [] as string[],
    passed: [] as string[],
  };

  // Security vulnerabilities
  if (results.security.vulnerabilities.length > 0) {
    findings.critical.push(
      ...results.security.vulnerabilities.map((v) => `[Security] ${v}`),
    );
  }

  // AUP violations
  if (results.aupCompliance?.violations) {
    const critical = results.aupCompliance.violations.filter(
      (v) => v.severity === "CRITICAL",
    );
    findings.critical.push(
      ...critical.map((v) => `[AUP] ${v.categoryName}: ${v.matchedText}`),
    );
  }

  // Broken tools
  if (results.functionality.brokenTools.length > 0) {
    findings.warnings.push(
      ...results.functionality.brokenTools.map(
        (t) => `[Functionality] Broken: ${t}`,
      ),
    );
  }

  // Missing annotations
  if (results.toolAnnotations?.missingAnnotationsCount > 0) {
    findings.warnings.push(
      `[Annotations] ${results.toolAnnotations.missingAnnotationsCount} tools missing annotations`,
    );
  }

  // Passed categories
  const modules = [
    { name: "Functionality", result: results.functionality },
    { name: "Security", result: results.security },
    { name: "Documentation", result: results.documentation },
    { name: "Error Handling", result: results.errorHandling },
    { name: "Usability", result: results.usability },
  ];

  for (const { name, result } of modules) {
    if (result.status === "PASS") {
      findings.passed.push(name);
    }
  }

  return findings;
}
```

### Generating Reports

```typescript
function generateReport(results: MCPDirectoryAssessment): string {
  const lines: string[] = [
    `# Assessment Report: ${results.serverName}`,
    ``,
    `**Date**: ${results.assessmentDate}`,
    `**Status**: ${results.overallStatus}`,
    `**Tests Run**: ${results.totalTestsRun}`,
    `**Execution Time**: ${results.executionTime}ms`,
    ``,
    `## Summary`,
    ``,
    results.summary,
    ``,
    `## Module Results`,
    ``,
  ];

  const modules = [
    { name: "Functionality", result: results.functionality },
    { name: "Security", result: results.security },
    { name: "Documentation", result: results.documentation },
    { name: "Error Handling", result: results.errorHandling },
    { name: "Usability", result: results.usability },
  ];

  for (const { name, result } of modules) {
    const icon =
      result.status === "PASS" ? "✅" : result.status === "FAIL" ? "❌" : "⚠️";
    lines.push(`- ${icon} **${name}**: ${result.status}`);
  }

  if (results.recommendations.length > 0) {
    lines.push(``, `## Recommendations`, ``);
    for (const rec of results.recommendations) {
      lines.push(`- ${rec}`);
    }
  }

  return lines.join("\n");
}
```

---

## Error Recovery

Handle failures gracefully with retry logic:

```typescript
interface RetryOptions {
  maxRetries: number;
  delayMs: number;
  backoffMultiplier: number;
}

async function assessWithRetry(
  context: AssessmentContext,
  orchestrator: AssessmentOrchestrator,
  options: RetryOptions = {
    maxRetries: 3,
    delayMs: 1000,
    backoffMultiplier: 2,
  },
): Promise<MCPDirectoryAssessment> {
  let lastError: Error | undefined;
  let delay = options.delayMs;

  for (let attempt = 1; attempt <= options.maxRetries; attempt++) {
    try {
      console.log(`Attempt ${attempt}/${options.maxRetries}...`);
      return await orchestrator.runFullAssessment(context);
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      console.warn(`Attempt ${attempt} failed: ${lastError.message}`);

      if (attempt < options.maxRetries) {
        console.log(`Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
        delay *= options.backoffMultiplier;
      }
    }
  }

  throw new Error(
    `Assessment failed after ${options.maxRetries} attempts: ${lastError?.message}`,
  );
}
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: MCP Server Assessment

on:
  push:
    branches: [main]
  pull_request:

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: "22"

      - name: Install dependencies
        run: npm ci

      - name: Run Assessment
        run: |
          npx @bryan-thompson/inspector-assessment mcp-assess-full \
            my-server \
            --config ./server-config.json \
            --output ./assessment-results.json \
            --format json

      - name: Check Results
        run: |
          STATUS=$(jq -r '.overallStatus' ./assessment-results.json)
          if [ "$STATUS" = "FAIL" ]; then
            echo "Assessment failed!"
            jq '.security.vulnerabilities' ./assessment-results.json
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: assessment-results
          path: ./assessment-results.json
```

### Programmatic CI Check

```typescript
import { writeFileSync } from "fs";

async function ciAssessment() {
  const results = await runAssessment();

  // Write results for artifact upload
  writeFileSync("./assessment-results.json", JSON.stringify(results, null, 2));

  // Generate summary for GitHub
  const summary = [
    `## Assessment Results: ${results.serverName}`,
    ``,
    `| Module | Status |`,
    `|--------|--------|`,
    `| Functionality | ${results.functionality.status} |`,
    `| Security | ${results.security.status} |`,
    `| Documentation | ${results.documentation.status} |`,
    `| Error Handling | ${results.errorHandling.status} |`,
    `| Usability | ${results.usability.status} |`,
  ].join("\n");

  // Write to GitHub step summary if available
  if (process.env.GITHUB_STEP_SUMMARY) {
    writeFileSync(process.env.GITHUB_STEP_SUMMARY, summary);
  }

  // Exit with appropriate code
  process.exit(results.overallStatus === "FAIL" ? 1 : 0);
}
```

---

## Advanced Features

### Source Code Analysis

Enable deep analysis with source code access:

```typescript
import { readFileSync, readdirSync, statSync } from "fs";
import { join, extname } from "path";

function loadSourceFiles(
  sourcePath: string,
  extensions = [".ts", ".js", ".py", ".go"],
): Map<string, string> {
  const files = new Map<string, string>();

  function walk(dir: string, prefix = "") {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;

      const fullPath = join(dir, entry.name);
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;

      if (entry.isDirectory()) {
        walk(fullPath, relativePath);
      } else if (extensions.includes(extname(entry.name))) {
        try {
          const content = readFileSync(fullPath, "utf-8");
          if (content.length < 100000) {
            files.set(relativePath, content);
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  walk(sourcePath);
  return files;
}

// Usage
const context: AssessmentContext = {
  // ... other fields
  sourceCodePath: "./my-server",
  sourceCodeFiles: loadSourceFiles("./my-server"),
};

const orchestrator = new AssessmentOrchestrator({
  enableSourceCodeAnalysis: true,
  assessmentCategories: {
    // ... core modules
    aupCompliance: true, // Benefits from source analysis
    prohibitedLibraries: true, // Checks package.json
    portability: true, // Detects hardcoded paths
  },
});
```

### Claude Code Integration

Enable AI-enhanced analysis:

```typescript
const orchestrator = new AssessmentOrchestrator();

// Enable Claude Code features
orchestrator.enableClaudeCode({
  features: {
    intelligentTestGeneration: true, // Better test parameters
    aupSemanticAnalysis: true, // Reduce false positives
    annotationInference: true, // Detect annotation misalignments
    documentationQuality: true, // Assess docs semantically
  },
  timeout: 90000, // 90s per Claude call
  maxRetries: 2,
});

// Check if enabled
if (orchestrator.isClaudeEnabled()) {
  console.log("Claude Code integration active");
}
```

### Custom Pattern Configuration

Load custom annotation patterns:

```typescript
// custom-patterns.json
{
  "includeBuiltin": true,
  "customPatterns": [
    {
      "name": "internal_api_call",
      "pattern": "internal://",
      "flags": "i",
      "severity": "HIGH",
      "category": "hidden_instructions"
    }
  ]
}

// Usage
const orchestrator = new AssessmentOrchestrator({
  patternConfigPath: "./custom-patterns.json",
  assessmentCategories: {
    // ... other modules
    toolAnnotations: true,
  },
});
```

---

## Performance Optimization

### Parallel Testing

```typescript
const orchestrator = new AssessmentOrchestrator({
  parallelTesting: true,
  maxParallelTests: 10, // Adjust based on server capacity
  testTimeout: 30000,
});
```

### Selective Module Execution

Run only specific modules for faster assessments:

```typescript
// Fast security-only check
const securityOrchestrator = new AssessmentOrchestrator({
  assessmentCategories: {
    functionality: false,
    security: true,
    documentation: false,
    errorHandling: false,
    usability: false,
  },
});

// Annotation-focused review
const annotationOrchestrator = new AssessmentOrchestrator({
  enableExtendedAssessment: true,
  assessmentCategories: {
    functionality: true, // Need to discover tools
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
    toolAnnotations: true, // Focus on annotations
  },
});
```

### Caching Connections

Reuse client connections for multiple assessments:

```typescript
class AssessmentRunner {
  private client: Client | null = null;
  private orchestrator: AssessmentOrchestrator;

  constructor(config?: Partial<AssessmentConfiguration>) {
    this.orchestrator = new AssessmentOrchestrator(config);
  }

  async connect(transport: Transport) {
    this.client = new Client(
      { name: "cached-runner", version: "1.0.0" },
      { capabilities: {} },
    );
    await this.client.connect(transport);
  }

  async assess(serverName: string): Promise<MCPDirectoryAssessment> {
    if (!this.client) throw new Error("Not connected");

    const { tools } = await this.client.listTools();

    const context: AssessmentContext = {
      serverName,
      tools,
      callTool: async (name, params) => {
        const response = await this.client!.callTool({
          name,
          arguments: params,
        });
        return {
          content: response.content,
          isError: response.isError || false,
        };
      },
      config: this.orchestrator.getConfig(),
    };

    return this.orchestrator.runFullAssessment(context);
  }

  async disconnect() {
    if (this.client) {
      await this.client.close();
      this.client = null;
    }
  }
}
```

---

## Testing Your Integration

### Unit Test Pattern

```typescript
import { describe, it, expect, vi } from "vitest";

describe("Assessment Integration", () => {
  it("should assess a mock server", async () => {
    const mockTools = [
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: { type: "object", properties: {} },
      },
    ];

    const mockCallTool = vi.fn().mockResolvedValue({
      content: [{ type: "text", text: "Success" }],
      isError: false,
    });

    const orchestrator = new AssessmentOrchestrator({
      testTimeout: 5000,
      assessmentCategories: {
        functionality: true,
        security: false,
        documentation: false,
        errorHandling: false,
        usability: false,
      },
    });

    const context: AssessmentContext = {
      serverName: "test-server",
      tools: mockTools,
      callTool: mockCallTool,
      config: orchestrator.getConfig(),
    };

    const results = await orchestrator.runFullAssessment(context);

    expect(results.serverName).toBe("test-server");
    expect(results.functionality.status).toBeDefined();
    expect(mockCallTool).toHaveBeenCalled();
  });
});
```

---

## Troubleshooting

### Common Issues

| Issue              | Cause                      | Solution                                     |
| ------------------ | -------------------------- | -------------------------------------------- |
| Connection timeout | Server not responding      | Increase `testTimeout`, check server health  |
| Empty tool list    | Server not returning tools | Verify server implementation of `tools/list` |
| All tests failing  | callTool wrapper issue     | Check error handling in callTool wrapper     |
| Missing results    | Module disabled            | Check `assessmentCategories` configuration   |

### Debug Logging

```typescript
const orchestrator = new AssessmentOrchestrator({
  logging: { level: "debug" },
});

// Or enable via environment
process.env.LOG_LEVEL = "debug";
```

### Capturing JSONL Events

```typescript
// Events are emitted to stderr
process.stderr.on("data", (data) => {
  const lines = data.toString().split("\n").filter(Boolean);
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      console.log(`Event: ${event.event}`, event);
    } catch {
      // Not JSON, regular log output
    }
  }
});
```

---

## Complete Example

A full working example combining all patterns:

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";
import type {
  AssessmentContext,
  MCPDirectoryAssessment,
} from "@bryan-thompson/inspector-assessment/types";
import { AUDIT_MODE_CONFIG } from "@bryan-thompson/inspector-assessment/config";
import { writeFileSync, readFileSync, existsSync } from "fs";

interface ServerConfig {
  name: string;
  command: string;
  args: string[];
  sourcePath?: string;
}

async function runComprehensiveAssessment(
  config: ServerConfig,
): Promise<MCPDirectoryAssessment> {
  // 1. Setup transport with error capture
  const transport = new StdioClientTransport({
    command: config.command,
    args: config.args,
    stderr: "pipe",
  });

  let stderrOutput = "";
  if (transport.stderr) {
    transport.stderr.on("data", (data: Buffer) => {
      stderrOutput += data.toString();
    });
  }

  // 2. Connect to server
  const client = new Client(
    { name: "comprehensive-assessor", version: "1.0.0" },
    { capabilities: {} },
  );

  try {
    await client.connect(transport);
    console.log(`Connected to ${config.name}`);
  } catch (error) {
    console.error("Connection failed:", error);
    if (stderrOutput) {
      console.error("Server stderr:", stderrOutput);
    }
    throw error;
  }

  // 3. Discover capabilities
  const { tools } = await client.listTools();
  console.log(`Discovered ${tools.length} tools`);

  let resources: any[] = [];
  let prompts: any[] = [];

  try {
    const resourcesResponse = await client.listResources();
    resources = resourcesResponse.resources || [];
  } catch {
    console.log("Server does not support resources");
  }

  try {
    const promptsResponse = await client.listPrompts();
    prompts = promptsResponse.prompts || [];
  } catch {
    console.log("Server does not support prompts");
  }

  // 4. Load source files if available
  let sourceCodeFiles: Map<string, string> | undefined;
  let readmeContent: string | undefined;
  let packageJson: unknown;

  if (config.sourcePath && existsSync(config.sourcePath)) {
    sourceCodeFiles = new Map();
    // Load files (simplified - use the full implementation from earlier)

    const readmePath = `${config.sourcePath}/README.md`;
    if (existsSync(readmePath)) {
      readmeContent = readFileSync(readmePath, "utf-8");
    }

    const pkgPath = `${config.sourcePath}/package.json`;
    if (existsSync(pkgPath)) {
      packageJson = JSON.parse(readFileSync(pkgPath, "utf-8"));
    }
  }

  // 5. Configure orchestrator
  const orchestrator = new AssessmentOrchestrator({
    ...AUDIT_MODE_CONFIG,
    enableSourceCodeAnalysis: !!config.sourcePath,
    logging: { level: "info" },
  });

  // 6. Build assessment context
  const context: AssessmentContext = {
    serverName: config.name,
    tools,
    callTool: async (name, params) => {
      const response = await client.callTool({ name, arguments: params });
      return {
        content: response.content,
        isError: response.isError || false,
      };
    },
    config: orchestrator.getConfig(),
    readmeContent,
    packageJson,
    sourceCodePath: config.sourcePath,
    sourceCodeFiles,
    resources: resources.map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description,
    })),
    prompts: prompts.map((p) => ({
      name: p.name,
      description: p.description,
      arguments: p.arguments,
    })),
    listTools: async () => {
      const response = await client.listTools();
      return response.tools;
    },
  };

  // 7. Run assessment
  console.log("Starting assessment...");
  const results = await orchestrator.runFullAssessment(context);

  // 8. Cleanup
  await client.close();

  // 9. Save results
  const outputPath = `/tmp/assessment-${config.name}.json`;
  writeFileSync(outputPath, JSON.stringify(results, null, 2));
  console.log(`Results saved to ${outputPath}`);

  // 10. Report summary
  console.log("\n=== Assessment Summary ===");
  console.log(`Server: ${results.serverName}`);
  console.log(`Status: ${results.overallStatus}`);
  console.log(`Tests: ${results.totalTestsRun}`);
  console.log(`Time: ${results.executionTime}ms`);

  if (results.security.vulnerabilities.length > 0) {
    console.log(
      `\nVulnerabilities: ${results.security.vulnerabilities.length}`,
    );
  }

  if (results.recommendations.length > 0) {
    console.log("\nTop Recommendations:");
    for (const rec of results.recommendations.slice(0, 3)) {
      console.log(`  - ${rec}`);
    }
  }

  return results;
}

// Run the assessment
runComprehensiveAssessment({
  name: "my-mcp-server",
  command: "node",
  args: ["./server.js"],
  sourcePath: "./src",
}).catch(console.error);
```

---

## See Also

- [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - Getting started
- [API Reference](API_REFERENCE.md) - Complete API documentation
- [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md) - Command-line usage
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - Event stream format

---

**Version**: 1.23.5+
**Last Updated**: 2026-01-06
