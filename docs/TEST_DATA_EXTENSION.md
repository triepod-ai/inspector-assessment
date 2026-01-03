# Test Data Extension Guide

> **Part of the Test Data Generation documentation series:**
>
> - [Architecture](TEST_DATA_ARCHITECTURE.md) - Core architecture, field handlers, boundaries
> - [Scenarios](TEST_DATA_SCENARIOS.md) - Scenario categories, tool-aware generation, examples
> - **Extension** (this document) - Adding handlers, debugging, integration

## Overview

This guide covers extending the TestDataGenerator with new field type handlers, debugging common issues, integration with the Test Scenario Engine, and best practices.

---

## Table of Contents

- [Overview](#overview)
- [1. Adding New Field Type Handlers](#1-adding-new-field-type-handlers)
- [2. Common Issues and Debugging](#2-common-issues-and-debugging)
- [3. Integration with Test Scenario Engine](#3-integration-with-test-scenario-engine)
- [4. Performance Considerations](#4-performance-considerations)
- [5. Testing Your Implementation](#5-testing-your-implementation)
- [6. Best Practices](#6-best-practices)

---

## 1. Adding New Field Type Handlers

### Step-by-Step Guide

#### Step 1: Identify the New Type

For example, suppose you need to handle `format: "email"` in addition to field name detection.

#### Step 2: Locate the Handler Switch Statement

The main handler is in `generateRealisticValue()` (lines 471-766):

```typescript
private static generateRealisticValue(
  fieldName: string,
  schema: any,
  variant: "typical" | "empty" | "maximum" | "special",
): unknown {
  switch (schema.type) {
    case "string":
      // STRING HANDLER - add logic here
    case "number":
    case "integer":
      // NUMBER HANDLER
    case "boolean":
      // BOOLEAN HANDLER
    // ... etc
  }
}
```

#### Step 3: Add Format-Based Detection

Inside the appropriate type handler, add format-based detection before field-name detection:

```typescript
case "string":
  // 1. Check for enums first (highest priority)
  if (schema.enum && schema.enum.length > 0) {
    return variant === "typical"
      ? schema.enum[0]
      : schema.enum[schema.enum.length - 1];
  }

  // 2. NEW: Check for JSON Schema format property
  if (schema.format === "email") {
    return variant === "empty"
      ? ""
      : this.REALISTIC_DATA.emails[
          Math.floor(Math.random() * this.REALISTIC_DATA.emails.length)
        ];
  }

  if (schema.format === "uri") {
    return variant === "empty"
      ? ""
      : this.REALISTIC_DATA.urls[
          Math.floor(Math.random() * this.REALISTIC_DATA.urls.length)
        ];
  }

  if (schema.format === "uuid") {
    return variant === "empty"
      ? "00000000-0000-0000-0000-000000000000"
      : "550e8400-e29b-41d4-a716-446655440000";
  }

  // 3. Existing field-name-based detection
  if (lowerFieldName.includes("email") || ...) {
    // existing logic
  }
  // ... more field-name patterns
```

#### Step 4: Add to Recursive Handler (if needed)

If your type is used in nested objects/arrays, also update `generateValueFromSchema()`:

```typescript
private static generateValueFromSchema(
  schema: any,
  variant: "typical" | "empty" | "maximum" | "special",
): unknown {
  // ... existing logic

  case "string":
    if (schema.format === "email") {
      return variant === "empty" ? "" : "test@example.com";
    }
    return variant === "empty" ? "" : "test";

  // ... rest of method
}
```

#### Step 5: Add a Data Pool (if needed)

If you're generating many instances, add a data pool:

```typescript
private static readonly REALISTIC_DATA = {
  // ... existing pools

  // NEW POOL
  phonenumbers: [
    "+1-555-0100", // North American format
    "+44-20-7946-0958", // UK format
    "+81-3-1234-5678", // Japan format
    "+1-555-0101",
    "+1-555-0102",
  ],
};
```

And use it in the handler:

```typescript
if (schema.format === "phone") {
  return variant === "empty"
    ? ""
    : this.REALISTIC_DATA.phonenumbers[
        Math.floor(Math.random() * this.REALISTIC_DATA.phonenumbers.length)
      ];
}
```

### Step 6: Write Tests

Create a test file in `client/src/services/assessment/__tests__/`:

```typescript
// TestDataGenerator.phone.test.ts
import { TestDataGenerator } from "../TestDataGenerator";

describe("TestDataGenerator - Phone Number Format", () => {
  it("should generate valid phone numbers for format: phone", () => {
    const schema = {
      type: "string",
      format: "phone",
      description: "Phone number",
    };

    const value = (TestDataGenerator as any).generateRealisticValue(
      "phone_number",
      schema,
      "typical",
    );

    expect(value).toBeTruthy();
    expect(typeof value).toBe("string");
    expect(value).toMatch(/^\+\d{1,3}-/); // Starts with + and country code
  });

  it("should generate empty string for phone format with empty variant", () => {
    const schema = { type: "string", format: "phone" };
    const value = (TestDataGenerator as any).generateRealisticValue(
      "phone",
      schema,
      "empty",
    );
    expect(value).toBe("");
  });

  it("should include phone numbers in tool scenario generation", () => {
    const tool = {
      name: "contact_tool",
      description: "Manages contact information",
      inputSchema: {
        type: "object",
        properties: {
          phone_number: {
            type: "string",
            format: "phone",
            description: "Contact phone number",
          },
        },
        required: ["phone_number"],
      },
    };

    const scenarios = TestDataGenerator.generateTestScenarios(tool);
    const happyPath = scenarios.find((s) => s.category === "happy_path");

    expect(happyPath).toBeDefined();
    expect(happyPath?.params.phone_number).toBeTruthy();
    expect(typeof happyPath?.params.phone_number).toBe("string");
  });
});
```

#### Step 7: Run Tests and Validate

```bash
# Run tests for new handler
npm test -- TestDataGenerator.phone.test.ts

# Run all TestDataGenerator tests to ensure no regressions
npm test -- TestDataGenerator

# Run full test suite
npm test
```

---

## 2. Common Issues and Debugging

### Issue 1: "Missing Required Fields in Generated Params"

**Symptoms**:

- Tests fail because required fields are not included in generated params
- Tool returns "Missing required field" error for every scenario

**Root Cause**:

- `generateRealisticParams()` doesn't check the `required` array
- Generator attempts to generate values for all properties (required and optional)

**Solution**:
The current implementation generates params for ALL properties. To restrict to only required fields:

```typescript
public static generateRealisticParams(
  tool: Tool,
  variant: "typical" | "empty" | "maximum" | "special",
): Record<string, unknown> {
  const params: Record<string, unknown> = {};

  if (!tool.inputSchema || tool.inputSchema.type !== "object") {
    return params;
  }

  const properties = tool.inputSchema.properties || {};
  const required = tool.inputSchema.required || [];

  // Only generate params for required fields (FIX)
  for (const requiredField of required) {
    const schema = properties[requiredField];
    if (schema) {
      params[requiredField] = this.generateRealisticValue(
        requiredField,
        schema as any,
        variant,
      );
    }
  }

  return params;
}
```

### Issue 2: "Generated Values Don't Exist (404 Errors)"

**Symptoms**:

- All tests fail with "resource not found" or 404 errors
- Tool can't find the generated ID/URL/resource

**Root Cause**:

- Test data uses synthetic values (e.g., `"123"`, `"/tmp/test.txt"`)
- These resources don't actually exist on the server/filesystem

**Solution**:
This is expected behavior. ResponseValidator detects this as "business logic error" (tool correctly rejecting bad input).

To test with real resources:

1. Modify data pools to use known resources
2. Use environment variables for dynamic test data
3. Mock the backend or use test fixtures

```typescript
// Before: Uses synthetic data
private static readonly REALISTIC_DATA = {
  ids: ["1", "123", "550e8400-e29b-41d4-a716-446655440000"],
};

// After: Use environment-based data
private static getRealisticIds(): string[] {
  const envId = process.env.TEST_RESOURCE_ID;
  return envId ? [envId] : ["1", "123"];
}
```

### Issue 3: "Boundary Tests Not Generated for Constrained Fields"

**Symptoms**:

- Tool has `minimum: 0, maximum: 100` on a field
- No boundary scenarios are generated

**Root Cause**:

- Field has constraints but `generateBoundaryScenarios()` returned empty array
- Likely due to optimization that checks for boundaries before generating

**Debugging**:

```typescript
// Add logging to check if boundaries are detected
let hasBoundaries = false;
for (const [key, schema] of Object.entries(properties)) {
  const schemaObj = schema as any;
  const hasMin = schemaObj.minimum !== undefined;
  const hasMax = schemaObj.maximum !== undefined;
  const hasMinLen = schemaObj.minLength !== undefined;
  const hasMaxLen = schemaObj.maxLength !== undefined;

  console.log(`Field ${key}:`, { hasMin, hasMax, hasMinLen, hasMaxLen });

  if (hasMin || hasMax || hasMinLen || hasMaxLen) {
    hasBoundaries = true;
  }
}
console.log(`hasBoundaries=${hasBoundaries}`);
```

**Solution**:
Ensure schema properly defines constraints. Check for:

- Correct constraint names (not `min`/`max`, use `minimum`/`maximum`)
- Numeric types (constraints on strings vs numbers differ)

```typescript
// Correct
{
  type: "number",
  minimum: 0,      // Correct: minimum (not min)
  maximum: 100     // Correct: maximum (not max)
}

// Incorrect
{
  type: "number",
  min: 0,          // Wrong: should be minimum
  max: 100         // Wrong: should be maximum
}
```

### Issue 4: "Special Characters Test Using Wrong Characters"

**Symptoms**:

- Special characters scenario generates `!@#$%^&*()` but tool needs Unicode
- Tool fails to process generated special characters

**Root Cause**:

- Current implementation uses ASCII special characters
- Tool may require proper Unicode handling

**Solution**:
Modify the special variant string to include Unicode:

```typescript
// Current: ASCII special characters only
variant === "special"
  ? 'Special chars: !@#$%^&*()_+-=[]{}|;:",.<>?/~`'
  : "test";

// Improved: Include Unicode characters
variant === "special" ? "Spécial™ chârs: !@#$%^&*() 中文 العربية" : "test";
```

### Issue 5: "Empty Variant Generates Invalid Data for Required Fields"

**Symptoms**:

- Test with `variant === "empty"` generates empty string `""`
- Tool requires at least 1 character (minLength: 1)
- Test fails with validation error

**Root Cause**:

- Empty variant prioritizes minimal input but violates schema constraints
- Not checked against schema bounds

**Solution**:
Respect schema constraints in all variants:

```typescript
if (variant === "empty") {
  // Check if field has minimum constraints
  const minLength = schema.minLength || 0;
  const minimum = schema.minimum || 0;

  if (schema.type === "string" && minLength > 0) {
    return "a".repeat(minLength); // Generate minimum valid string
  }
  if ((schema.type === "number" || schema.type === "integer") && minimum > 0) {
    return minimum;
  }

  // Only use empty for truly optional fields
  return "";
}
```

### Issue 6: "UUID Detection Not Working"

**Symptoms**:

- Field named `resource_id` should get UUID format but gets simple ID
- Generator returning `"123"` instead of `"550e8400-e29b-41d4-a716-446655440000"`

**Root Cause**:

- UUID detection relies on specific field name patterns
- Field name `resource_id` doesn't match detection patterns

**Solution**:
Check detection patterns in lines 561-576:

```typescript
const requiresUuid =
  lowerFieldName.includes("uuid") ||
  lowerFieldName.includes("page_id") ||
  lowerFieldName.includes("database_id") ||
  lowerFieldName.includes("user_id") ||
  lowerFieldName.includes("block_id") ||
  lowerFieldName.includes("comment_id") ||
  lowerFieldName.includes("workspace_id") ||
  lowerFieldName.includes("notion") ||
  // Check schema description for UUID hints
  (schema.description &&
    (schema.description.toLowerCase().includes("uuid") ||
      schema.description.toLowerCase().includes("universally unique")));
```

Add your field name pattern:

```typescript
const requiresUuid =
  lowerFieldName.includes("uuid") ||
  lowerFieldName.includes("resource_id") || // ADD THIS
  lowerFieldName.includes("page_id") ||
  // ... rest of patterns
```

Or use schema description:

```typescript
{
  type: "string",
  description: "Resource ID as a UUID" // Will be detected
}
```

### Issue 7: "Array Generation Creating Wrong Number of Items"

**Symptoms**:

- Schema says `maxItems: 3` but generator creates 10 items
- Tool rejects for having too many items

**Root Cause**:

- Maximum variant hardcodes count to 10 regardless of schema
- Doesn't respect `maxItems` constraint

**Solution**:
Respect array constraints:

```typescript
case "array":
  if (variant === "maximum") {
    // Use maxItems from schema if defined, otherwise 10
    const count = Math.min(
      schema.maxItems || 10,
      10 // Cap at 10 for performance
    );

    if (schema.items) {
      return Array(count)
        .fill(0)
        .map(() => this.generateValueFromSchema(schema.items, variant));
    }
    return Array(count).fill(0).map((_, i) => `item_${i}`);
  }
```

### Issue 8: "Enum Values Not Recognized"

**Symptoms**:

- Schema has `enum: ["read", "write", "delete"]`
- Generated value is `"test"` instead of one of the enum values

**Root Cause**:

- Enum handling might be skipped if field name pattern matches first
- Enum check should be highest priority

**Solution**:
Ensure enum check is first in the handler (it is, lines 480-485):

```typescript
// Check for enums FIRST - highest priority
if (schema.enum && schema.enum.length > 0) {
  return variant === "typical"
    ? schema.enum[0]
    : schema.enum[schema.enum.length - 1];
}

// Then check field names
if (lowerFieldName.includes("email") || ...) {
  // ...
}
```

If this isn't working, verify:

1. Schema actually has `enum` property (not `const` or other)
2. Enum array is not empty
3. No other constraint is returning before enum check

---

## 3. Integration with Test Scenario Engine

### Flow Diagram

```
TestScenarioEngine.testToolComprehensively(tool)
  ↓
  ├─→ testProgressiveComplexity()
  │    ├─→ generateMinimalParams()
  │    ├─→ callTool(tool.name, minimalParams)
  │    └─→ isBusinessLogicError()
  │
  ├─→ TestDataGenerator.generateTestScenarios(tool)
  │    ├─→ generateHappyPathScenario()
  │    ├─→ generateEdgeCaseScenarios()
  │    ├─→ generateBoundaryScenarios()
  │    └─→ generateErrorScenario()
  │
  └─→ for each scenario:
       ├─→ executeScenario()
       │    ├─→ callTool(tool.name, scenario.params)
       │    ├─→ ResponseValidator.validateResponse()
       │    └─→ return ScenarioTestResult
       │
       └─→ aggregate results
            ├─→ determineOverallStatus()
            ├─→ calculateConfidence()
            └─→ generateRecommendations()
```

### Scenario Result Structure

Each scenario execution produces a `ScenarioTestResult`:

```typescript
interface ScenarioTestResult {
  scenario: TestScenario; // Original test scenario
  executed: boolean; // Did it run?
  executionTime: number; // Milliseconds
  response?: CompatibilityCallToolResult; // Tool response
  error?: string; // Execution error if any
  validation: ValidationResult; // Response validation
}
```

### Response Validation

After tool execution, `ResponseValidator` evaluates the response:

```typescript
const validation = ResponseValidator.validateResponse({
  tool,
  input: scenario.params,
  response,
  scenarioCategory: scenario.category,
});

// validation includes:
// - isValid: boolean (test passed/failed)
// - confidence: 0-100 (how confident in result)
// - classification: "fully_working" | "partially_working" | etc.
// - issues: string[] (what went wrong)
// - evidence: string[] (how we know)
```

### Comprehensive Test Result

Final result aggregates all scenarios:

```typescript
interface ComprehensiveToolTestResult {
  toolName: string;
  tested: boolean;
  totalScenarios: number;
  scenariosExecuted: number;
  scenariosPassed: number;
  scenariosFailed: number;
  overallStatus:
    | "fully_working"
    | "partially_working"
    | "connectivity_only"
    | "broken"
    | "untested";
  confidence: number; // 0-100
  executionTime: number;
  scenarioResults: ScenarioTestResult[]; // All scenario results
  summary: {
    happyPathSuccess: boolean;
    edgeCasesHandled: number;
    edgeCasesTotal: number;
    boundariesRespected: number;
    boundariesTotal: number;
    errorHandlingWorks: boolean;
  };
  progressiveComplexity?: {
    minimalWorks: boolean;
    simpleWorks: boolean;
    failurePoint?: "minimal" | "simple" | "none";
  };
  recommendations: string[];
}
```

---

## 4. Performance Considerations

### Optimization: Conditional Boundary Generation

**Problem**: Generating boundary tests for every tool adds unnecessary scenarios.

**Solution** (v1.17.1): Check if any field actually has constraints before generating:

```typescript
// OPTIMIZATION: Check if any fields have boundary constraints
let hasBoundaries = false;
for (const [_key, schema] of Object.entries(properties)) {
  const schemaObj = schema as any;
  if (
    schemaObj.minimum !== undefined ||
    schemaObj.maximum !== undefined ||
    schemaObj.minLength !== undefined ||
    schemaObj.maxLength !== undefined
  ) {
    hasBoundaries = true;
    break;
  }
}

// Early return if no boundaries defined - saves 0-4 test scenarios per tool
if (!hasBoundaries) {
  return scenarios;
}
```

**Impact**:

- Tools without constraint definitions skip boundary test generation
- ~30-50% reduction in scenario count for typical tools
- Still maintains full coverage for tools that define constraints

### Lazy Evaluation

The generator uses lazy field-name detection:

```typescript
// Only check field names if no explicit type was used
if (schema.enum && schema.enum.length > 0) {
  return schema.enum[0]; // Return immediately
}

if (lowerFieldName.includes("email")) {
  return email; // Return immediately
}

// Only reach here if previous checks didn't apply
return defaultValue;
```

### Data Pool Randomization

Data pools use random selection to create variety:

```typescript
this.REALISTIC_DATA.urls[
  Math.floor(Math.random() * this.REALISTIC_DATA.urls.length)
];
```

For deterministic testing, use index selection:

```typescript
// Deterministic: always use first value
this.REALISTIC_DATA.urls[0];

// With seed: use seed to determine index
const seededIndex = seed % this.REALISTIC_DATA.urls.length;
this.REALISTIC_DATA.urls[seededIndex];
```

---

## 5. Testing Your Implementation

### Unit Tests

For your custom handler, create tests in `client/src/services/assessment/__tests__/`:

```bash
# Create test file
touch /home/bryan/inspector/client/src/services/assessment/__tests__/TestDataGenerator.myformat.test.ts
```

```typescript
// TestDataGenerator.myformat.test.ts
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator } from "../TestDataGenerator";

describe("TestDataGenerator - My Custom Format", () => {
  it("should generate correct format for my_field", () => {
    const tool: Tool = {
      name: "my_tool",
      description: "Test tool",
      inputSchema: {
        type: "object",
        properties: {
          my_field: {
            type: "string",
            description: "My custom field",
          },
        },
        required: ["my_field"],
      },
    };

    const scenarios = TestDataGenerator.generateTestScenarios(tool);
    const happyPath = scenarios.find((s) => s.category === "happy_path");

    expect(happyPath).toBeDefined();
    expect(happyPath?.params.my_field).toMatch(/expected_pattern/);
  });

  it("should handle edge cases correctly", () => {
    const tool: Tool = {
      name: "my_tool",
      description: "Test tool",
      inputSchema: {
        type: "object",
        properties: {
          my_field: {
            type: "string",
            minLength: 5,
            maxLength: 20,
          },
        },
        required: ["my_field"],
      },
    };

    const scenarios = TestDataGenerator.generateTestScenarios(tool);
    const edgeCases = scenarios.filter((s) => s.category === "edge_case");

    expect(edgeCases.length).toBeGreaterThan(0);
    edgeCases.forEach((scenario) => {
      const fieldValue = scenario.params.my_field as string;
      expect(fieldValue).toBeTruthy();
    });
  });

  it("should respect boundaries", () => {
    const tool: Tool = {
      name: "my_tool",
      description: "Test tool",
      inputSchema: {
        type: "object",
        properties: {
          my_field: {
            type: "string",
            minLength: 5,
            maxLength: 20,
          },
        },
        required: ["my_field"],
      },
    };

    const scenarios = TestDataGenerator.generateTestScenarios(tool);
    const boundaries = scenarios.filter((s) => s.category === "boundary");

    expect(boundaries.length).toBe(2); // min and max
    expect((boundaries[0].params.my_field as string).length).toBe(5);
    expect((boundaries[1].params.my_field as string).length).toBe(20);
  });
});
```

### Running Tests

```bash
# Run specific test file
npm test -- TestDataGenerator.myformat.test.ts

# Run all TestDataGenerator tests
npm test -- TestDataGenerator

# Run with coverage
npm test -- --coverage TestDataGenerator

# Watch mode for development
npm test -- --watch TestDataGenerator
```

---

## 6. Best Practices

### 1. Keep Data Pools Realistic

- Use publicly available, stable URLs (Google, GitHub, JSONPlaceholder)
- Avoid URLs that might change or become unavailable
- Include multiple examples for variety

### 2. Field Name Patterns Should Be Specific

- `email` matches "email_address", "user_email", "email_contact" ✅
- `url` matches "webhook_url", "base_url", "endpoint_url" ✅
- Avoid overly broad patterns that might match unintended fields

### 3. Respect Schema Constraints in All Variants

- Even "empty" variant should respect minLength, minimum, etc.
- If field requires minLength: 3, don't generate empty string

### 4. Document New Handlers

- Add JSDoc comments explaining detection logic
- Include examples of which field names/formats trigger the handler
- Document any special variants (if different from default)

### 5. Test Against Real Tools

- Run scenarios against actual MCP servers
- Check if generated data results in business logic errors (expected) vs actual tool failures (bugs)
- Adjust data pools if tests consistently fail on valid tools

### 6. Use Category-Aware Generation for Generic Fields

- Tools with generic field names like `input`, `query`, `command`
- Use tool category to guide value generation (calculator vs search tool)
- Fall back to field-name detection for unknown categories

### 7. Monitor Test Scenario Count

- Use boundary optimization to avoid unnecessary scenarios
- For tools without constraints, you should get ~4-5 scenarios (happy path, edge cases, error)
- For tools with many constraints, expect more boundary scenarios

---

## Summary

The TestDataGenerator is a sophisticated, context-aware system that:

1. **Parses JSON Schema** to extract field types and constraints
2. **Detects Field Purpose** using field names and schema properties
3. **Generates Multi-Variant Data** (typical, empty, maximum, special) for each field
4. **Respects Constraints** (minimum, maximum, minLength, maxLength, enum, required)
5. **Creates Comprehensive Scenarios** (happy path, edge cases, boundaries, error cases)
6. **Uses Realistic Data Pools** with public, stable values
7. **Handles Nested Structures** recursively for objects and arrays
8. **Optimizes Performance** by skipping unnecessary boundary tests

To extend it, simply add new handlers in the appropriate switch statement, respect existing patterns, test your changes, and document the behavior.

---

## Related Documentation

- [Test Data Architecture](TEST_DATA_ARCHITECTURE.md) - Core architecture, field handlers, boundaries
- [Test Data Scenarios](TEST_DATA_SCENARIOS.md) - Scenario categories, tool-aware generation, examples
- [Response Validation Guide](RESPONSE_VALIDATION_CORE.md) - Validation after test execution
- [Progressive Complexity Guide](PROGRESSIVE_COMPLEXITY_GUIDE.md) - Multi-level testing strategy
