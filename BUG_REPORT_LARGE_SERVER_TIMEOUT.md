# Bug Report: Inspector Assessment Timeout on Large Servers

## Summary

The inspector-assessment CLI times out when auditing MCP servers with 30+ tools, even with a 10-minute timeout. The mcp-playwright server (33 tools) consistently fails to complete the inspector assessment.

## Environment

- **Inspector Version**: @bryan-thompson/inspector-assessment v1.7.1
- **Node Version**: v22.21.1
- **Platform**: Linux (WSL2)
- **Date**: 2025-12-23

## Steps to Reproduce

1. Run the audit CLI on mcp-playwright:
   ```bash
   node cli/audit.js --github https://github.com/executeautomation/mcp-playwright --verbose
   ```
2. Wait for inspector assessment phase
3. Observe timeout after 10 minutes

## Expected Behavior

Inspector should complete assessment within reasonable time or provide progress updates.

## Actual Behavior

```
[Inspector] Running: /home/bryan/.nvm/versions/node/v22.21.1/bin/node /home/bryan/inspector/cli/build/assess-full.js --server mcp-playwright --config ... --json --full --source ...
[Inspector] Warning: Inspector failed - Inspector assessment timed out after 600000ms
```

## Root Cause Analysis

### Sequential Tool Testing (Primary Bottleneck)

The `FunctionalityAssessor` tests each tool sequentially:

```typescript
// FunctionalityAssessor.ts:63
for (const tool of toolsToTest) {
  const result = await this.testTool(tool, context.callTool);
  // ...
}
```

With 33 tools and a 30-second per-tool timeout:

- Worst case: 33 × 30s = 990 seconds (16.5 minutes) **just for functionality**
- Multiple modules test all tools (Functionality, Security, ErrorHandling)
- Total worst case could exceed 30+ minutes

### Sequential Module Execution

The orchestrator runs modules sequentially when `parallelTesting` is false:

```typescript
// AssessmentOrchestrator.ts:326-362
assessmentResults.functionality =
  await this.functionalityAssessor.assess(context);
assessmentResults.security = await this.securityAssessor.assess(context);
// ... 11 modules total
```

### No Overall Orchestrator Timeout

The orchestrator has no maximum execution time limit - it will run until all modules complete or an external timeout kills it.

## Affected Modules

All modules that iterate over tools:

1. **FunctionalityAssessor** - Tests each tool with parameters
2. **SecurityAssessor** - Tests each tool for injection patterns
3. **ErrorHandlingAssessor** - Tests each tool with invalid inputs
4. **UsabilityAssessor** - May analyze each tool

## Proposed Solutions

### Option 1: Parallel Tool Testing (Quick Win)

Enable parallel tool testing within modules:

```typescript
// FunctionalityAssessor.ts
const results = await Promise.all(
  toolsToTest.map((tool) => this.testTool(tool, context.callTool)),
);
```

- **Pros**: Dramatic speedup (33 tools in ~30s vs 16+ minutes)
- **Cons**: May overwhelm server, need connection pooling

### Option 2: Tool Sampling for Large Servers

For servers with >20 tools, test a representative sample:

```typescript
const MAX_TOOLS_TO_TEST = 20;
const toolsToTest =
  tools.length > MAX_TOOLS_TO_TEST
    ? this.selectRepresentativeSample(tools, MAX_TOOLS_TO_TEST)
    : tools;
```

- **Pros**: Consistent execution time regardless of tool count
- **Cons**: May miss issues in untested tools

### Option 3: Orchestrator Timeout with Early Exit

Add overall orchestrator timeout with graceful degradation:

```typescript
class AssessmentOrchestrator {
  private maxExecutionTime: number = 300000; // 5 minutes

  async runFullAssessment(context: AssessmentContext) {
    const deadline = Date.now() + this.maxExecutionTime;

    for (const assessor of this.assessors) {
      if (Date.now() > deadline) {
        return this.generatePartialResults();
      }
      await assessor.assess(context);
    }
  }
}
```

- **Pros**: Guaranteed completion time, partial results still useful
- **Cons**: May skip important modules

### Option 4: Progress Reporting (UX Improvement)

Add real-time progress output for CLI:

```typescript
console.log(`[Progress] Testing tool ${i + 1}/${tools.length}: ${tool.name}`);
```

- **Pros**: Better UX, easier debugging
- **Cons**: Doesn't solve timeout issue

## Recommended Fix

Implement **Option 1 (Parallel Tool Testing)** with a concurrency limit:

```typescript
import pLimit from "p-limit";

const limit = pLimit(5); // Max 5 concurrent tool tests

const results = await Promise.all(
  toolsToTest.map((tool) => limit(() => this.testTool(tool, context.callTool))),
);
```

This provides:

- ~6x speedup for 33 tools (parallel batches of 5)
- Controlled resource usage
- No server overwhelming

## Test Case

```json
{
  "server": "mcp-playwright",
  "github": "https://github.com/executeautomation/mcp-playwright",
  "tools": 33,
  "expected_time": "< 2 minutes",
  "actual_time": "> 10 minutes (timeout)"
}
```

## Related Files

- `/client/src/services/assessment/AssessmentOrchestrator.ts`
- `/client/src/services/assessment/modules/FunctionalityAssessor.ts`
- `/client/src/services/assessment/modules/SecurityAssessor.ts`
- `/client/src/services/assessment/modules/ErrorHandlingAssessor.ts`
- `/cli/src/assess-full.ts`

## Priority

**High** - Affects usability for any MCP server with >20 tools

## Labels

- bug
- performance
- cli
- timeout
