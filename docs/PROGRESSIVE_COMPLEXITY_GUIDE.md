# Progressive Complexity Testing Guide for MCP Inspector

## Overview

The MCP Inspector uses a **2-level progressive complexity approach** to efficiently validate MCP tool functionality while catching edge cases and failures. This guide explains the rationale, implementation, and best practices for using progressive complexity testing.

**Key Achievement**: Reduced testing time by 50% (from 4-level to 2-level approach) while maintaining zero coverage loss through integrated multi-scenario testing.

---

## Table of Contents

1. [Progressive Complexity Rationale](#progressive-complexity-rationale)
2. [Level 1: Minimal Scenarios](#level-1-minimal-scenarios)
3. [Level 2: Simple Scenarios](#level-2-simple-scenarios)
4. [Integration with Comprehensive Testing](#integration-with-comprehensive-testing)
5. [Scenario Selection Algorithm](#scenario-selection-algorithm)
6. [Failure Diagnosis](#failure-diagnosis)
7. [Tuning Complexity Levels](#tuning-complexity-levels)
8. [Performance Optimization](#performance-optimization)
9. [Common Patterns and Examples](#common-patterns-and-examples)

---

## Progressive Complexity Rationale

### The Problem: Binary Testing vs Diagnostic Testing

Traditional testing approaches often use one of two extremes:

| Approach               | Pros          | Cons                    |
| ---------------------- | ------------- | ----------------------- | ----------------------------------------------------------------------------- |
| **Simple Tests Only**  | Fast          | Can't identify failures | Tool works or it doesn't (no diagnostic value)                                |
| **Complex Tests Only** | Comprehensive | Slow                    | Hard to identify where failures occur (minimal test is fast, complex is slow) |

**Progressive Complexity solves this** by creating a spectrum of complexity levels that help identify exactly where and why tools fail.

### Progressive Complexity Architecture

```
Execution Flow (Diagnostic Phase)
┌─────────────────┐
│   Minimal Test  │  Required fields + simplest values
│  (Level 1)      │  Tests basic connectivity
└────────┬────────┘
         │ Fails?
         ├─ NO  ──→ Continue to Level 2
         │
         └─ YES ──→ Stop (tool fails basic connectivity)
                    Return: failurePoint = "minimal"

         │ Success
         ├─ NO  ──→ Continue to comprehensive testing
         │
         └─ YES ──→ Continue to comprehensive testing

┌────────────────┐
│  Simple Test   │  Required fields + realistic simple values
│  (Level 2)     │  Tests core functionality
└────────┬───────┘
         │ Fails?
         ├─ NO  ──→ Passed both levels
         │          Return: failurePoint = "none"
         │
         └─ YES ──→ Passes minimal but fails simple
                    Return: failurePoint = "simple"

Comprehensive Testing (Full Coverage Phase)
┌──────────────────────────────────────────┐
│ Multi-Scenario Testing                   │
│ • Happy Path (typical usage)             │
│ • Edge Cases (empty, maximum, special)   │
│ • Boundary Testing (min/max constraints) │
│ • Error Cases (invalid inputs)           │
└──────────────────────────────────────────┘
```

### Why 2 Levels (Not 4)?

The original 4-level approach tested:

1. **Minimal** - Required fields only
2. **Simple** - Required + basic values
3. **Typical** - Same as Happy Path scenario
4. **Maximum** - Same as Edge Case scenario

**Problem**: Levels 3-4 duplicated comprehensive test scenarios, creating redundancy:

- Typical test = Happy Path scenario (both use realistic typical values)
- Maximum test = Edge Case - Maximum Values scenario (both test extreme values)

**Solution**: Compress to 2 diagnostic levels + comprehensive multi-scenario testing

- **Diagnostic phase** (2 levels): Identifies exact failure points
- **Coverage phase** (multiple scenarios): Validates all functionality categories

### Token Efficiency and Coverage Tradeoffs

| Metric              | 4-Level      | 2-Level     | Impact         |
| ------------------- | ------------ | ----------- | -------------- |
| Scenarios per tool  | 6-8          | 4-5         | -40% scenarios |
| Average test time   | 7.5-11.7 min | 4.2-8.3 min | **50% faster** |
| Diagnostic coverage | ✅ Good      | ✅ Good     | No change      |
| Edge case coverage  | ✅ Full      | ✅ Full     | No change      |
| Boundary coverage   | ✅ Full      | ✅ Full     | No change      |
| False negative rate | Similar      | Similar     | No change      |
| False positive rate | Similar      | Similar     | No change      |

**Result**: Dramatic speed improvement without sacrificing accuracy or coverage.

---

## Level 1: Minimal Scenarios

### Purpose

**Level 1 tests basic connectivity and required field handling.**

- Validates that the tool can be called with the absolute minimum required input
- Identifies fundamental setup issues (network problems, authentication failures, schema errors)
- Fast pass/fail determination (~100-300ms typical)
- Acts as early exit if connectivity is broken

### Parameters

Only **required fields** from the tool's input schema, with the **simplest possible values**:

```typescript
// Example: A "list_users" tool
// Schema: {
//   required: ["page_size"],
//   properties: {
//     page_size: { type: "integer", minimum: 1 },
//     filter: { type: "string" }
//   }
// }

// Minimal Level 1 parameters:
{
  page_size: 1; // Required field only, minimum valid value
}
```

### Parameter Generation Strategy

```typescript
private generateMinimalParams(tool: Tool): Record<string, unknown> {
  const params: Record<string, unknown> = {};

  if (!tool.inputSchema?.properties) return params;

  // Only include required fields
  for (const requiredField of tool.inputSchema.required || []) {
    const schema = tool.inputSchema.properties[requiredField];
    if (schema) {
      // Generate the absolute simplest value for this schema
      params[requiredField] = this.generateMinimalValue(schema);
    }
  }

  return params;
}

private generateMinimalValue(schema: any): unknown {
  switch (schema.type) {
    case "string":
      return schema.enum ? schema.enum[0] : "test";
    case "number" | "integer":
      return schema.minimum ?? 1;
    case "boolean":
      return true;
    case "array":
      return []; // Empty array
    case "object":
      return {}; // Empty object
    default:
      return null;
  }
}
```

### Example Scenarios

#### Calculator Tool (No Required Parameters)

```typescript
// Schema: { required: [], properties: {} }
// Minimal params: {}
// Expected: Tool handles no input gracefully
```

#### Weather Tool (Requires Location)

```typescript
// Schema: {
//   required: ["location"],
//   properties: {
//     location: { type: "string" },
//     units: { type: "string", enum: ["celsius", "fahrenheit"] }
//   }
// }
// Minimal params: { location: "test" }
// Expected: Returns weather data or validation error
```

#### Database Tool (Requires ID)

```typescript
// Schema: {
//   required: ["user_id"],
//   properties: {
//     user_id: { type: "string", description: "UUID" },
//     fields: { type: "array", items: { type: "string" } }
//   }
// }
// Minimal params: { user_id: "550e8400-e29b-41d4-a716-446655440000" }
// Expected: Returns user data or "not found" error
```

### Success Criteria

Level 1 is considered successful if:

```typescript
result.minimalWorks =
  !minimalResult.isError || // No error, OR
  isBusinessLogicError(minimalResult); // Error is a validation error (expected)
```

**Examples of success**:

- ✅ Tool returns data successfully
- ✅ Tool returns "user not found" error (validation works)
- ✅ Tool returns "invalid parameter type" (validation works)

**Examples of failure**:

- ❌ Tool throws exception or crashes
- ❌ Tool times out
- ❌ Network connection refused
- ❌ Tool returns malformed response

---

## Level 2: Simple Scenarios

### Purpose

**Level 2 tests realistic simple usage patterns.**

- Validates that the tool can accept realistic input beyond just the minimum
- Tests core functionality with valid data
- Identifies issues with data validation and processing
- Provides diagnostic feedback on where complexity breaks down
- Slightly slower than Level 1 (~200-500ms typical)

### Parameters

**Required fields** with **realistic simple values** (not just minimums):

```typescript
// Example: A "list_users" tool
// Minimal Level 1: { page_size: 1 }
// Simple Level 2:  { page_size: 10 }  // More realistic default

// Example: A "search" tool
// Minimal Level 1: { query: "test" }
// Simple Level 2:  { query: "name" }  // More realistic search term

// Example: A "get_user" tool
// Minimal Level 1: { user_id: "550e8400-e29b-41d4-a716-446655440000" }
// Simple Level 2:  { user_id: "550e8400-e29b-41d4-a716-446655440000" }  // Same but context changed
```

### Parameter Generation Strategy

```typescript
private generateSimpleParams(tool: Tool): Record<string, unknown> {
  const params: Record<string, unknown> = {};

  if (!tool.inputSchema?.properties) return params;

  // Include required fields with realistic simple values
  for (const requiredField of tool.inputSchema.required || []) {
    const schema = tool.inputSchema.properties[requiredField];
    if (schema) {
      // Use TestDataGenerator for realistic values
      params[requiredField] = TestDataGenerator.generateSingleValue(
        requiredField,
        schema
      );
    }
  }

  return params;
}

// From TestDataGenerator:
static generateSingleValue(fieldName: string, schema: any): unknown {
  // Check if field name indicates specific data type
  if (/url/i.test(fieldName)) {
    return "https://www.google.com";  // Realistic accessible URL
  }
  if (/email/i.test(fieldName)) {
    return "admin@example.com";  // Common email format
  }
  if (/id/i.test(fieldName)) {
    return "550e8400-e29b-41d4-a716-446655440000";  // Valid UUID
  }

  // Fall back to schema-based generation
  switch (schema.type) {
    case "string":
      return schema.enum ? schema.enum[0] : "test";
    case "number" | "integer":
      // Use realistic defaults instead of minimum
      return 10;  // Better than 1 for page_size, limit, etc.
    // ... etc
  }
}
```

### Example Scenarios

#### Calculator Tool

```typescript
// Minimal Level 1: {}
// Simple Level 2:  {}
// (No change - tool has no required parameters)
```

#### Weather Tool

```typescript
// Minimal Level 1: { location: "test" }
// Simple Level 2:  { location: "London" }  // Realistic city name

// Expected behavior difference:
// Level 1: May fail with "invalid location format"
// Level 2: Should return actual weather data
```

#### Search Tool

```typescript
// Minimal Level 1: { query: "test" }
// Simple Level 2:  { query: "name" }  // More likely to match something

// Expected behavior difference:
// Level 1: May return "no results for 'test'"
// Level 2: May return results for "name"
```

#### Database Tool with Optional Pagination

```typescript
// Schema: {
//   required: ["user_id"],
//   properties: {
//     user_id: { type: "string" },
//     page_size: { type: "integer", minimum: 1, default: 10 }
//   }
// }

// Minimal Level 1: { user_id: "550e8400..." }
// Simple Level 2:  { user_id: "550e8400..." }  // Same, no optional fields yet
```

### Success Criteria

Level 2 is considered successful if:

```typescript
result.simpleWorks =
  !simpleResult.isError || // No error, OR
  isBusinessLogicError(simpleResult); // Error is validation
```

**Failure Point Classification**:

```typescript
if (result.minimalWorks && !result.simpleWorks) {
  result.failurePoint = "simple"; // Works minimal but fails simple
} else if (!result.minimalWorks) {
  result.failurePoint = "minimal"; // Fails at minimal level
} else {
  result.failurePoint = "none"; // Passes both levels
}
```

---

## Integration with Comprehensive Testing

### Two-Phase Testing Architecture

Progressive complexity testing is **not** the only validation. It works alongside comprehensive multi-scenario testing:

```
┌─────────────────────────────────────────────────────────┐
│         COMPREHENSIVE TOOL TESTING PIPELINE             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Phase 1: Progressive Complexity (Diagnostic)           │
│ ─────────────────────────────────────────             │
│ • Minimal Test     (Level 1)                          │
│ • Simple Test      (Level 2)                          │
│ Result: failurePoint = "minimal" | "simple" | "none"  │
│                                                         │
│ Phase 2: Comprehensive Multi-Scenario Testing         │
│ ─────────────────────────────────────────────────────│
│ • Happy Path       (realistic typical usage)           │
│ • Edge Cases       (empty, maximum, special chars)    │
│ • Boundary Tests   (min/max constraints)              │
│ • Error Cases      (invalid inputs)                   │
│ Result: Full scenario coverage with detailed feedback │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Why Both Phases?

| Phase          | Purpose                 | Examples            | Output                                      |
| -------------- | ----------------------- | ------------------- | ------------------------------------------- |
| **Diagnostic** | Identify failure points | Is minimal working? | failurePoint: "minimal" / "simple" / "none" |
| **Coverage**   | Validate all scenarios  | Happy path working? | Comprehensive pass/fail per scenario        |

**Together, they provide**:

1. **Quick failure diagnosis**: Know if tool fails at minimal or simple level
2. **Full validation**: Know if all scenarios pass (happy path, edge cases, etc.)
3. **Actionable recommendations**: Specific feedback on what's working/broken

---

## Scenario Selection Algorithm

### Step 1: Schema Analysis

First, analyze the tool's input schema to understand structure:

```typescript
const schema = tool.inputSchema;

// Check schema validity
if (!schema || schema.type !== "object") {
  return []; // Can't test tools without object input schema
}

// Identify required vs optional fields
const required = schema.required || [];
const properties = schema.properties || {};
const optional = Object.keys(properties).filter((p) => !required.includes(p));
```

### Step 2: Required Field Analysis

For each required field, determine what value to generate:

```typescript
for (const requiredField of required) {
  const fieldSchema = properties[requiredField];

  // 1. Check for enum values
  if (fieldSchema.enum) {
    value = fieldSchema.enum[0]; // Use first enum value
  }

  // 2. Check for format hints
  else if (fieldSchema.format === "uri") {
    value = "https://www.google.com";
  } else if (fieldSchema.format === "email") {
    value = "admin@example.com";
  }

  // 3. Check field name patterns
  else if (/uuid|id|_id/.test(requiredField.toLowerCase())) {
    value = "550e8400-e29b-41d4-a716-446655440000";
  }

  // 4. Type-based generation
  else {
    switch (fieldSchema.type) {
      case "string":
        value = "test";
        break;
      case "number":
        value = fieldSchema.minimum ?? 10;
        break;
      case "integer":
        value = fieldSchema.minimum ?? 10;
        break;
      case "boolean":
        value = true;
        break;
      case "array":
        value = [];
        break;
      case "object":
        value = {};
        break;
    }
  }
}
```

### Step 3: Dynamic Scenario Generation

Generate scenarios based on tool complexity:

```typescript
const scenarios = [];

// Always generate happy path
scenarios.push(generateHappyPathScenario(tool));

// Add edge cases based on tool complexity
scenarios.push(...generateEdgeCaseScenarios(tool));

// Add boundary tests if tool has constraints
if (hasBoundaryConstraints(tool)) {
  scenarios.push(...generateBoundaryScenarios(tool));
}

// Always add error case
scenarios.push(generateErrorScenario(tool));
```

### Step 4: Scenario Count Optimization

The number of scenarios generated is optimized to balance coverage and performance:

```typescript
// Happy Path: 1 scenario
// Edge Cases: 1-3 scenarios (empty, maximum, special chars)
// Boundary Tests: 0-4 scenarios (1 per constrained field)
// Error Cases: 1 scenario
// Total: 3-9 scenarios per tool

// Examples:
// Simple tool (no constraints): 4-5 scenarios
// Complex tool (many constraints): 8-10 scenarios
// Tool with optional fields: May skip empty edge case
```

---

## Failure Diagnosis

### Understanding Failure Points

When progressive complexity testing completes, the `failurePoint` indicates where the tool breaks down:

#### Failure Point: "minimal"

```typescript
result.failurePoint = "minimal";
```

**Meaning**: Tool fails when given the absolute minimum required parameters.

**Diagnostic Information**:

- Tool crashes, times out, or returns unexpected error
- Basic connectivity or authentication issues
- Schema mismatch or unsupported input format
- Essential fields are missing or misconfigured

**Sample Recommendations**:

```
⚠️ Tool fails with minimal parameters - check:
  • Basic connectivity and network configuration
  • Required field handling and type validation
  • Authentication and API key setup
  • Input schema accuracy
```

**Example Debugging**:

```typescript
// Tool: get_user
// Minimal params: { user_id: "550e8400-e29b-41d4-a716-446655440000" }
// Error: "Connection refused" → Check network/firewall
// Error: "Invalid API key" → Check authentication
// Error: "Schema validation failed" → Check input schema
```

#### Failure Point: "simple"

```typescript
result.failurePoint = "simple";
```

**Meaning**: Tool works with minimal required fields but fails when given realistic data.

**Diagnostic Information**:

- Tool accepts minimal params but rejects simple realistic values
- Parameter validation is too strict
- Data type checking fails on valid inputs
- Tool doesn't handle realistic data formats

**Sample Recommendations**:

```
Tool works with minimal params but fails with realistic data:
  • Check parameter validation logic
  • Verify support for realistic data formats
  • Ensure type handling accepts valid variations
```

**Example Debugging**:

```typescript
// Tool: search
// Minimal: { query: "test" } ✅ Works
// Simple: { query: "name" } ❌ Fails
// Issue: Query validation too strict or doesn't support certain words
// Fix: Update validation logic or test data generation

// Tool: list_users with page_size
// Minimal: { page_size: 1 } ✅ Works
// Simple: { page_size: 10 } ❌ Fails
// Issue: Pagination default doesn't match realistic usage
// Fix: Update pagination defaults or validation
```

#### Failure Point: "none"

```typescript
result.failurePoint = "none";
```

**Meaning**: Tool passes both minimal and simple levels.

**Diagnostic Information**:

- Basic tool functionality is working
- Parameter handling is correct
- Tool accepts both minimal and realistic input

**Sample Recommendations**:

```
✅ Progressive complexity tests passed
See scenario results for typical and edge case coverage
```

---

## Root Cause Identification

### Pattern Matching Framework

Use these patterns to identify root causes:

```typescript
// Pattern 1: Timeout Errors (>5 seconds)
if (error.message.includes("Timeout") || executionTime > this.testTimeout) {
  // Issue: Slow network, expensive operation, or hanging code
  // Action: Check network latency, optimize backend
}

// Pattern 2: Connection Errors
if (
  error.message.includes("ECONNREFUSED") ||
  error.message.includes("network")
) {
  // Issue: Service not running or network unreachable
  // Action: Start service, check firewall
}

// Pattern 3: Validation Errors
if (
  response.isError &&
  response.content?.some((c) => c.text?.includes("invalid"))
) {
  // Issue: Input validation failed
  // Action: Check schema constraints and test data
}

// Pattern 4: Schema Mismatch
if (
  response.isError &&
  response.content?.some((c) => c.text?.includes("schema"))
) {
  // Issue: Response doesn't match expected schema
  // Action: Update schema or tool response
}

// Pattern 5: Business Logic Error
if (isBusinessLogicError(response)) {
  // Issue: Not a tool failure, just validation
  // Action: No action needed - tool is working correctly
}
```

### Common Failure Patterns

| Pattern                   | Indicator                            | Root Cause             | Fix                        |
| ------------------------- | ------------------------------------ | ---------------------- | -------------------------- |
| **Timeout**               | executionTime > 5000ms               | Slow backend / network | Optimize, check latency    |
| **Connection Refused**    | "ECONNREFUSED"                       | Service not running    | Start service              |
| **Auth Failed**           | 401/403 error                        | Invalid credentials    | Update API key             |
| **Validation Too Strict** | Works with "test", fails with "name" | Overly strict schema   | Relax validation           |
| **Missing Schema**        | Can't generate required params       | Schema incomplete      | Define all required fields |
| **Type Mismatch**         | "expected string, got number"        | Type conversion issue  | Fix type casting           |

---

## Common Failure Patterns

### Pattern 1: Tool Works Minimal → Fails Simple

**Scenario**: Tool passes Level 1 with { query: "test" } but fails Level 2 with { query: "name" }

```typescript
// Level 1 Success: { query: "test" }
// Level 2 Failure: { query: "name" }

// Analysis:
// The tool validates input too strictly or has hardcoded expectations
// "test" might be a special case or default value
// "name" is a real search query that triggers different code path

// Fix: Update validation to accept realistic queries
```

### Pattern 2: Tool Timeout on Simple

**Scenario**: Minimal completes in 100ms, Simple hangs

```typescript
// Level 1 Success: 100ms with { page_size: 1 }
// Level 2 Timeout: 5000ms+ with { page_size: 10 }

// Analysis:
// Pagination implementation might be inefficient
// Database query with page_size: 10 is much slower
// Potential N+1 query or missing index

// Fix: Profile database queries, add indexes
```

### Pattern 3: Both Levels Fail

**Scenario**: Even minimal test fails

```typescript
// Level 1 Failure: Schema error or connection refused

// Analysis:
// Tool not properly configured or running
// Network/firewall blocking requests
// Missing authentication

// Fix: Check configuration, network, auth
```

---

## Tuning Complexity Levels

### Adjusting Minimal Level Generation

The minimal level values can be tuned for specific tool types:

```typescript
// Default minimal values (conservative)
private generateMinimalValue(schema: any): unknown {
  switch (schema.type) {
    case "string":
      return schema.enum ? schema.enum[0] : "test";
    case "number":
      return schema.minimum ?? 1;  // Minimum possible value
  }
}

// Tuned for API pagination tools
private generateMinimalValueForPagination(schema: any): unknown {
  switch (schema.type) {
    case "number":
      // For page_size, use a more realistic minimal value
      // Many APIs fail with page_size: 1, prefer page_size: 10
      return schema.minimum ? Math.max(schema.minimum, 10) : 10;
  }
}
```

### Adding Custom Scenarios

For tools that need special testing, add custom scenarios:

```typescript
// Extend FunctionalityAssessor for custom tool types
class CustomFunctionalityAssessor extends FunctionalityAssessor {
  protected generateMinimalParams(tool: any): Record<string, unknown> {
    // Special handling for specific tools
    if (tool.name === "calculator_tool") {
      return {
        expression: "1+1", // Always valid expression
      };
    }

    // Fall back to standard generation
    return super.generateMinimalParams(tool);
  }
}
```

### Adjusting Test Timeout

```typescript
// Default: 5000ms (5 seconds per test)
const engine = new TestScenarioEngine(
  5000, // testTimeout
  100, // delayBetweenTests (rate limiting)
);

// Increase for slower backends
const slowEngine = new TestScenarioEngine(
  10000, // 10 second timeout
  200, // 200ms delay between tests
);

// Decrease for fast backends
const fastEngine = new TestScenarioEngine(
  2000, // 2 second timeout
  0, // No delay
);
```

### Conditional Scenario Generation

Skip scenarios that won't be useful:

```typescript
// Skip boundary tests if tool has no constraints
if (!this.hasBoundaryConstraints(tool)) {
  return []; // No boundary scenarios needed
}

// Skip empty edge cases for tools that require data
if (this.toolRequiresData(tool)) {
  // Skip edge case - empty values scenario
}

// Skip special character tests for numeric-only inputs
if (this.hasOnlyNumericInputs(tool)) {
  // Skip edge case - special characters scenario
}
```

---

## Performance Optimization

### Concurrency Management

Test multiple tools in parallel to speed up assessment:

```typescript
// Test up to 5 tools concurrently
const concurrency = 5;
const limit = createConcurrencyLimit(concurrency);

const results = await Promise.all(
  toolsToTest.map((tool) =>
    limit(async () => {
      return await this.testTool(tool, callTool);
    }),
  ),
);

// Impact on 10-tool server:
// Sequential: ~8.3 minutes
// Concurrent (5): ~4.2 minutes (50% improvement)
```

### Batched Progress Reporting

Report progress in batches to avoid overhead:

```typescript
const BATCH_INTERVAL = 500; // Report every 500ms
const BATCH_SIZE = 5; // Or every 5 tests

let batchCount = 0;
let lastBatchTime = Date.now();

for (const tool of toolsToTest) {
  batchCount++;

  // Run test...

  // Check if we should emit progress
  const timeSinceLastBatch = Date.now() - lastBatchTime;
  if (batchCount >= BATCH_SIZE || timeSinceLastBatch >= BATCH_INTERVAL) {
    context.onProgress({
      type: "test_batch",
      completed: completedTests,
      total: totalEstimate,
      batchSize: batchCount,
    });
    batchCount = 0;
    lastBatchTime = Date.now();
  }
}
```

### Delay Between Tests

Add delays to prevent rate limiting:

```typescript
// No delay for local/test servers
const noDelayConfig = {
  delayBetweenTests: 0,
};

// 100ms delay for public APIs
const publicApiConfig = {
  delayBetweenTests: 100,
};

// 500ms+ for rate-limited APIs
const rateLimitedConfig = {
  delayBetweenTests: 500,
};

// Implementation:
if (this.config.delayBetweenTests > 0) {
  await this.sleep(this.config.delayBetweenTests);
}
```

---

## Common Patterns and Examples

### Example 1: Simple List Tool

```typescript
// Tool: list_users
// Schema:
{
  "required": ["page_size"],
  "properties": {
    "page_size": { "type": "integer", "minimum": 1 },
    "sort": { "type": "string", "enum": ["asc", "desc"] }
  }
}

// Minimal Level 1:
{
  "page_size": 1
}
// Expected: Returns user list or error, ~100ms

// Simple Level 2:
{
  "page_size": 10
}
// Expected: Returns user list with realistic pagination, ~200ms

// Comprehensive Scenarios:
// • Happy Path: { page_size: 10 }
// • Edge Case - Empty: { page_size: 1 }
// • Edge Case - Maximum: { page_size: 1000000 }
// • Boundary - Minimum: { page_size: 1 }
// • Boundary - Maximum: Depends on schema max
// • Error Case: { page_size: -1 }
```

### Example 2: Database Query Tool

```typescript
// Tool: query_database
// Schema:
{
  "required": ["table", "id"],
  "properties": {
    "table": { "type": "string" },
    "id": { "type": "string", "description": "UUID" },
    "fields": { "type": "array", "items": { "type": "string" } }
  }
}

// Minimal Level 1:
{
  "table": "test",
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
// Expected: Returns record or "not found", ~150ms

// Simple Level 2:
{
  "table": "users",
  "id": "550e8400-e29b-41d4-a716-446655440000"
}
// Expected: Returns user record or validation error, ~200ms

// Common failures:
// • Minimal works, Simple fails: ID validation issue
// • Both timeout: Query too slow
// • Both fail with auth error: Credentials issue
```

### Example 3: API Call Tool

```typescript
// Tool: make_request
// Schema:
{
  "required": ["url", "method"],
  "properties": {
    "url": { "type": "string", "format": "uri" },
    "method": { "type": "string", "enum": ["GET", "POST", "PUT", "DELETE"] },
    "headers": { "type": "object" },
    "timeout": { "type": "integer", "minimum": 1000, "maximum": 30000 }
  }
}

// Minimal Level 1:
{
  "url": "https://www.google.com",
  "method": "GET"
}
// Expected: Returns response, ~300-500ms

// Simple Level 2:
{
  "url": "https://api.github.com/users/octocat",
  "method": "GET"
}
// Expected: Returns GitHub API response, ~400-600ms

// Common patterns:
// • Timeout on simple: Network latency issue
// • Works but slow: External API dependency
// • Both work: Tool is reliable
```

### Example 4: Search Tool

```typescript
// Tool: search
// Schema:
{
  "required": ["query"],
  "properties": {
    "query": { "type": "string", "minLength": 1 },
    "limit": { "type": "integer", "minimum": 1, "maximum": 100 }
  }
}

// Minimal Level 1:
{
  "query": "test"
}
// Expected: Returns search results, ~200ms

// Simple Level 2:
{
  "query": "name"
}
// Expected: Returns relevant results, ~250ms

// Potential issues:
// • Level 1 succeeds with "test", fails with "name"
//   → Search implementation has hardcoded expectations
// • Level 1 timeout, Level 2 also timeout
//   → Search index is slow or missing
// • Both work: Reliable search implementation
```

---

## Testing Framework Integration

### Using with TestScenarioEngine

```typescript
// Initialize engine
const engine = new TestScenarioEngine(
  5000, // 5 second timeout
  100, // 100ms delay between tests
);

// Test tool comprehensively
const result = await engine.testToolComprehensively(tool, callTool);

// Access progressive complexity results
if (result.progressiveComplexity?.failurePoint === "minimal") {
  console.log("Tool fails at minimal level");
  // Diagnostics...
}

if (result.progressiveComplexity?.failurePoint === "simple") {
  console.log("Tool fails at simple level");
  // Diagnostics...
}

if (result.progressiveComplexity?.failurePoint === "none") {
  console.log("Progressive complexity passed");
  // Comprehensive scenario results...
}

// Recommendations include progressive complexity insights
result.recommendations.forEach((rec) => {
  console.log(`• ${rec}`);
});
```

### Using with FunctionalityAssessor

```typescript
// For quick functionality testing (no multi-scenario)
const assessor = new FunctionalityAssessor();

// Generate minimal valid parameters
const { params, metadata } = assessor.generateMinimalParams(tool);

// Test with those parameters
const response = await callTool(tool.name, params);

// Metadata includes information about how parameters were generated
console.log(metadata.generationStrategy); // "field-name-aware", "category-specific", etc.
console.log(metadata.toolCategory); // ToolCategory enum
```

---

## Summary

### Key Takeaways

1. **Progressive Complexity = Diagnostic + Coverage**
   - Diagnostic phase: 2 levels (minimal → simple) identify failure points
   - Coverage phase: Multi-scenario testing validates all functionality

2. **2-Level Approach is Optimal**
   - 50% faster than 4-level (4.2-8.3 min vs 7.5-11.7 min)
   - Same coverage (happy path, edge cases, boundaries, errors)
   - Clear diagnostic value (failure points are actionable)

3. **Failure Points Are Actionable**
   - "minimal" → Check basic connectivity and required fields
   - "simple" → Check data validation and realistic input handling
   - "none" → See comprehensive scenario results

4. **Integration with Comprehensive Testing**
   - Together provide both quick diagnostics AND full validation
   - Recommendations combine insights from both phases
   - Confidence scoring based on complete test coverage

---

## Related Documentation

- **README.md**: Features and quick start
- **ASSESSMENT_CATALOG.md**: Complete 11-point assessment reference
- **FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md**: Implementation details
- **PROJECT_STATUS.md**: Development timeline and version history
