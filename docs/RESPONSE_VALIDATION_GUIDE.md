# Response Validator Guide

## Overview

The `ResponseValidator` is a core component of the MCP Inspector's assessment functionality that determines whether tool responses indicate actual functionality versus broken/non-functional tools. It provides sophisticated analysis of tool responses with particular focus on distinguishing between genuine tool failures and business logic validation errors.

**Location**: `/client/src/services/assessment/ResponseValidator.ts`

**Purpose**: Validate that MCP tool responses are actually functional, not just present.

## Key Capabilities

The ResponseValidator provides three main assessment capabilities:

1. **Response Validation**: Comprehensive analysis of tool responses to classify functionality
2. **Business Logic Error Detection**: Distinguish between tool failures and expected validation errors
3. **Confidence Scoring**: Multi-factor confidence calculation for assessment results

## Core Data Types

### ValidationResult

The primary output of response validation. Indicates whether a tool is working and why.

```typescript
interface ValidationResult {
  // Basic status
  isValid: boolean; // Whether response indicates working tool
  isError: boolean; // Whether response is an error
  confidence: number; // 0-100, confidence in classification

  // Diagnostics
  issues: string[]; // What went wrong (if anything)
  evidence: string[]; // Why validator made this decision

  // Classification
  classification:
    | "fully_working" // Tool responds correctly
    | "partially_working" // Tool responds but has issues
    | "connectivity_only" // Tool can be reached but doesn't work
    | "broken" // Tool not responding
    | "error"; // Tool returned error

  // Content analysis
  responseMetadata?: ResponseMetadata;
}
```

### ValidationContext

Input data for validation. Provides everything needed to assess a response.

```typescript
interface ValidationContext {
  tool: Tool; // Tool definition
  input: Record<string, unknown>; // Input sent to tool
  response: CompatibilityCallToolResult; // Response received
  scenarioCategory?:
    | "happy_path" // Normal use case
    | "edge_case" // Boundary behavior
    | "boundary" // Limit testing
    | "error_case"; // Error handling
}
```

### ResponseMetadata

Detailed metadata extracted from responses for enhanced tracking.

```typescript
interface ResponseMetadata {
  contentTypes: string[]; // "text", "image", "resource", etc.
  textBlockCount: number; // Number of text blocks in response
  imageCount: number; // Number of images in response
  resourceCount: number; // Number of resources in response
  hasStructuredContent: boolean; // Has structuredContent property
  hasMeta: boolean; // Has _meta field

  outputSchemaValidation?: {
    hasOutputSchema: boolean; // Tool declares output schema
    isValid: boolean; // Response matches schema
    error?: string; // Schema validation error (if any)
  };
}
```

## Response Validation

The core validation method classifies tool functionality based on response characteristics.

### How Validation Works

The validator uses a progressive approach:

#### Step 1: Check for Errors

```typescript
if (context.response.isError) {
  result.isValid = true; // Tool responded (working!)
  result.classification = "fully_working";
  result.confidence = 100;
  return result;
}
```

**Philosophy**: A tool that responds with an error is still a functional tool. The error indicates the tool received the request and executed validation logic.

#### Step 2: Check for Content

```typescript
if (!context.response.content) {
  result.issues.push("Response has no content");
  result.classification = "broken";
  result.confidence = 0;
  return result;
}

if (!Array.isArray(content) || content.length === 0) {
  result.issues.push("Response content is empty or not an array");
  result.classification = "broken";
  result.confidence = 0;
  return result;
}
```

**Philosophy**: A tool that responds with actual content is functional.

#### Step 3: Extract Metadata

```typescript
const responseMetadata = this.extractResponseMetadata(context);
result.responseMetadata = responseMetadata;
```

Metadata includes:

- Content types present (text, images, resources)
- Count of each content type
- Presence of structuredContent (MCP 2024-11-05+)
- Presence of \_meta field
- Output schema validation results

#### Step 4: Validate Output Schema

If tool declares an output schema:

```typescript
if (responseMetadata.outputSchemaValidation?.hasOutputSchema) {
  if (!responseMetadata.outputSchemaValidation.isValid) {
    result.classification = "partially_working"; // Downgrade classification
    result.confidence = 70; // Lower confidence
    result.issues.push(error || "Output schema validation failed");
  }
}
```

**Philosophy**: Tools with schema validation are held to higher standards. Schema validation failures indicate the tool is working but returning malformed output.

### Validation Classifications

| Classification      | Meaning                           | Confidence | When Used                                      |
| ------------------- | --------------------------------- | ---------- | ---------------------------------------------- |
| `fully_working`     | Tool responds properly, no issues | 100        | Response has content, passes schema validation |
| `partially_working` | Tool responds but has issues      | 70         | Response present but schema validation fails   |
| `connectivity_only` | Tool reachable but doesn't work   | 30         | Tool can be called but returns nothing/errors  |
| `broken`            | Tool not responding               | 0          | No response content or connection issues       |
| `error`             | Tool returned error               | 0-100      | Error response; see isBusinessLogicError()     |

### Code Example: Basic Validation

```typescript
import { ResponseValidator, ValidationContext } from "./ResponseValidator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

const tool: Tool = {
  name: "get_user",
  description: "Fetch user by ID",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string" },
    },
  },
};

const context: ValidationContext = {
  tool,
  input: { userId: "user-123" },
  response: {
    isError: false,
    content: [
      {
        type: "text",
        text: JSON.stringify({
          id: "user-123",
          name: "Alice",
          email: "alice@example.com",
        }),
      },
    ],
  },
};

const result = ResponseValidator.validateResponse(context);
console.log(result.classification); // "fully_working"
console.log(result.confidence); // 100
console.log(result.evidence); // ["Tool responded successfully with content", ...]
```

## Business Logic Error Detection

A critical capability: distinguishing between genuine tool failures and expected validation errors.

### The Problem

When a tool returns an error response, it could mean:

1. **Tool failure**: The tool is broken and didn't work
2. **Business logic validation**: The tool is working correctly and rejecting invalid input

Example:

- Error: "User not found" - Tool is working (validation passed, resource missing)
- Error: "TypeError: Cannot read property 'id' of undefined" - Tool failure

### The Solution: Confidence-Based Classification

`ResponseValidator.isBusinessLogicError()` analyzes error responses and returns `true` if the error indicates business logic validation (tool is working) rather than tool failure.

### Confidence Factors

The validator weighs six independent factors to calculate confidence:

```typescript
const confidenceFactors = {
  1: "MCP error code present (2x weight)", // -32602, -32603, etc.
  2: "Business error pattern match (2x weight)", // "not found", "invalid", etc.
  3: "HTTP status code (4xx/5xx)", // 400, 404, 429, etc.
  4: "Structured error response", // JSON-like format
  5: "Validates test data", // References test IDs
  6: "Validation-expected tool type (2x weight)", // create, update, delete, etc.
};
```

Each factor contributes equally to confidence:

- **Confidence calculation**: `confidenceFactors / totalFactors`
- **Example**: If 3 of 6 factors present = 50% confidence

### Confidence Thresholds

Different thresholds apply based on error type and tool type:

```typescript
// Strong operational errors (quota, credits, rate limit)
// -> 20% threshold (very lenient, these are obvious)
if (hasStrongOperationalError) {
  threshold = 0.2;
}

// Validation-expected tools (delete, update, create, search, etc.)
// -> 20% threshold (these often fail on test data)
else if (isValidationExpected) {
  threshold = 0.2;
}

// Other tools
// -> 50% threshold (need more evidence)
else {
  threshold = 0.5;
}

return confidence >= threshold;
```

### MCP Error Codes

The validator recognizes standard MCP error codes indicating proper validation:

| Code     | Meaning          | Tool Status                   |
| -------- | ---------------- | ----------------------------- |
| `-32600` | Invalid Request  | Tool working (validation)     |
| `-32601` | Method not found | Tool working (validation)     |
| `-32602` | Invalid params   | Tool working (validation)     |
| `-32603` | Internal error   | Tool working (error handling) |
| `-32700` | Parse error      | Tool working (input parsing)  |

**Special handling**: MCP codes carry 2x weight in confidence calculation.

### Business Logic Error Patterns

#### Resource Validation (Tool checking if resources exist)

```
"not found", "does not exist", "doesn't exist", "no such",
"cannot find", "could not find", "unable to find", "invalid id",
"unknown resource", "resource not found", "entity not found",
"record not found", "item not found", "no results", "empty result"
```

#### Data Validation (Tool validating data format/content)

```
"invalid format", "invalid value", "invalid type", "invalid input",
"type mismatch", "schema validation", "constraint violation",
"out of range", "exceeds maximum", "below minimum", "pattern mismatch"
```

#### Permission/Authorization (Tool checking access rights)

```
"unauthorized", "permission denied", "access denied", "forbidden",
"not authorized", "insufficient permissions", "authentication required",
"token expired", "invalid credentials"
```

#### Business Rule Validation (Tool enforcing business logic)

```
"already exists", "duplicate", "conflict", "quota exceeded",
"limit reached", "not allowed", "precondition failed",
"dependency not met"
```

#### API Operational Errors (Tool showing integration works)

```
"insufficient credits", "no credits", "credit balance",
"billing", "subscription", "plan upgrade", "payment required",
"account suspended", "trial expired", "usage limit"
```

#### Rate Limiting (Shows API integration works)

```
"rate limit", "too many requests", "throttled", "quota exceeded"
```

### Validation-Expected Tools

Tools that inherently involve data validation get lower confidence thresholds:

- **CRUD operations**: create, add, insert, update, modify, set, delete, remove
- **Read operations**: get, fetch, read, write, query, search, find, list
- **Data operations**: entity, relation, node, edge, record
- **State operations**: move, copy, duplicate, archive
- **Relationship ops**: link, associate, connect, attach
- **API/scraping**: scrape, crawl, extract, parse, analyze, process

### Code Example: Business Logic Error Detection

```typescript
const tool: Tool = {
  name: "delete_user",
  description: "Delete a user by ID",
  inputSchema: {
    type: "object",
    properties: {
      userId: { type: "string" },
    },
  },
};

// Scenario 1: Tool working correctly, just invalid input
const context1: ValidationContext = {
  tool,
  input: { userId: "test-id" },
  response: {
    isError: true,
    content: [
      {
        type: "text",
        text: "User not found",
      },
    ],
  },
};

const result1 = ResponseValidator.isBusinessLogicError(context1);
console.log(result1); // true - Tool is working (validation)
// Factors: validation-expected (2), business pattern (2) = 4/6 = 66% > 20%

// Scenario 2: Tool failure, not business logic
const context2: ValidationContext = {
  tool,
  input: { userId: "valid-id" },
  response: {
    isError: true,
    content: [
      {
        type: "text",
        text: "TypeError: Cannot read property 'id' of undefined",
      },
    ],
  },
};

const result2 = ResponseValidator.isBusinessLogicError(context2);
console.log(result2); // false - Tool failure, not validation
// No business error patterns match, confidence < threshold

// Scenario 3: Operational error (tool integrated with external API)
const context3: ValidationContext = {
  tool,
  input: { userId: "valid-id" },
  response: {
    isError: true,
    content: [
      {
        type: "text",
        text: "Insufficient credits to perform this request",
      },
    ],
  },
};

const result3 = ResponseValidator.isBusinessLogicError(context3);
console.log(result3); // true - Operational error
// Strong operational error (credits) = meets 20% threshold
```

### When Is Error Validation Used?

Business logic error detection is integrated into the validation workflow:

1. **Initial validation** detects isError = true
2. **Classification** initially: "error"
3. **Confidence drops**: Uses `isBusinessLogicError()` to determine if tool is actually working
4. **Final classification**: Updated based on error type

This allows the assessment to report:

- "Tool is functional but returns validation errors" (healthy)
- "Tool is broken and crashes" (unhealthy)

## Response Metadata Extraction

### What Is Response Metadata?

Response metadata tracks the structure and content types of tool responses for detailed analysis.

```typescript
static extractResponseMetadata(context: ValidationContext): ResponseMetadata {
  // Track content types: text, image, resource, resource_link, etc.
  // Count blocks of each type
  // Check for structuredContent (MCP 2024-11-05+)
  // Check for _meta field
  // Validate against output schema if present
}
```

### Content Type Tracking

The validator identifies all content types in a response:

```typescript
const content = context.response.content as Array<{
  type: string;
  text?: string;
  data?: string;
  mimeType?: string;
}>;

for (const item of content) {
  contentTypes.push(item.type); // "text", "image", "resource", etc.

  // Count by type
  if (item.type === "text") textBlockCount++;
  if (item.type === "image") imageCount++;
  if (["resource", "resource_link"].includes(item.type)) resourceCount++;
}
```

### MCP Advanced Features

The validator checks for newer MCP features:

```typescript
// structuredContent: Added in MCP 2024-11-05+
// Allows tools to return structured data (not just text)
const hasStructuredContent = "structuredContent" in response;

// _meta: Custom metadata field
// Tools can include metadata about responses
const hasMeta = "_meta" in response;
```

### Output Schema Validation

If tool declares output schema, responses are validated:

```typescript
if (toolHasOutputSchema) {
  // Try structuredContent first (preferred)
  if (hasStructuredContent) {
    const validation = validateToolOutput(
      tool.name,
      response.structuredContent,
    );
    outputSchemaValidation = {
      hasOutputSchema: true,
      isValid: validation.isValid,
      error: validation.error,
    };
  }
  // Fallback: extract JSON from text content
  else {
    const extractedJson = tryExtractJsonFromContent(content);
    if (extractedJson !== null) {
      const validation = validateToolOutput(tool.name, extractedJson);
      // ... populate outputSchemaValidation
    }
  }
}
```

### Code Example: Metadata Analysis

```typescript
const context: ValidationContext = {
  tool,
  input: { query: "search term" },
  response: {
    isError: false,
    content: [
      { type: "text", text: "Results..." },
      { type: "image", data: "base64..." },
      { type: "resource", uri: "resource://..." }
    ],
    structuredContent: { results: [...] }
  }
};

const metadata = ResponseValidator.extractResponseMetadata(context);
console.log(metadata);
// {
//   contentTypes: ["text", "image", "resource"],
//   textBlockCount: 1,
//   imageCount: 1,
//   resourceCount: 1,
//   hasStructuredContent: true,
//   hasMeta: false,
//   outputSchemaValidation: {
//     hasOutputSchema: true,
//     isValid: true
//   }
// }
```

## Overall Confidence Calculation

### Weighted Average Approach

The validator calculates overall confidence from multiple validation results:

```typescript
static calculateOverallConfidence(results: ValidationResult[]): number {
  const weights = {
    fully_working: 1.0,      // 100% weight
    partially_working: 0.7,   // 70% weight
    connectivity_only: 0.3,   // 30% weight
    error: 0.2,               // 20% weight
    broken: 0.0               // 0% weight
  };

  // Average weighted confidence
  let weightedSum = 0;
  for (const result of results) {
    const weight = weights[result.classification];
    weightedSum += result.confidence * weight;
  }

  return (weightedSum / (results.length * 100)) * 100;
}
```

### Example: Multi-Scenario Confidence

```typescript
const scenarioResults: ValidationResult[] = [
  { classification: "fully_working", confidence: 100 }, // Happy path
  { classification: "partially_working", confidence: 70 }, // Edge case
  { classification: "fully_working", confidence: 100 }, // Boundary
];

const overallConfidence =
  ResponseValidator.calculateOverallConfidence(scenarioResults);
// Calculation:
// (100 * 1.0) + (70 * 0.7) + (100 * 1.0) = 100 + 49 + 100 = 249
// 249 / (3 * 100) * 100 = 83%
```

## Integration with TestScenarioEngine

The ResponseValidator is used by TestScenarioEngine to assess each test scenario:

### Workflow

```typescript
// TestScenarioEngine
for (const scenario of scenarios) {
  // 1. Execute test
  const response = await callTool(tool.name, scenario.params);

  // 2. Create validation context
  const context: ValidationContext = {
    tool,
    input: scenario.params,
    response,
    scenarioCategory: scenario.category, // "happy_path", "edge_case", etc.
  };

  // 3. Validate response
  const validation = ResponseValidator.validateResponse(context);

  // 4. Store result for analysis
  scenarioResults.push({
    scenario,
    validation,
    response,
    // ... other metadata
  });
}

// 5. Calculate overall confidence
const overallConfidence = ResponseValidator.calculateOverallConfidence(
  scenarioResults.map((r) => r.validation),
);
```

### Assessment Classification

TestScenarioEngine uses ResponseValidator results to determine overall tool status:

```typescript
const overallStatus =
  // All scenarios passed
  scenariosPassed === totalScenarios
    ? "fully_working"
    : // Most scenarios passed
      scenariosPassed > totalScenarios * 0.5
      ? "partially_working"
      : // Some connectivity established
        scenariosExecuted > 0
        ? "connectivity_only"
        : // No execution
          "broken";
```

## Extension Guide: Adding Validation Rules

### Adding New Business Error Patterns

To recognize new error patterns as business logic errors:

1. **Identify the pattern**: What error message indicates the tool is working?

```typescript
// Example: Support banking domain errors
("insufficient funds",
  "account locked",
  "daily limit exceeded",
  "invalid iban");
```

2. **Find the pattern category** in `isBusinessLogicError()`:

```typescript
// API-specific validation
const businessErrorPatterns = [
  // ... existing patterns

  // Banking domain validation
  "insufficient funds",
  "account locked",
  "daily limit exceeded",
  "invalid iban",
];
```

3. **Determine the weight**: Does it already have appropriate weight?

```typescript
// New banking patterns: part of business rule validation
// Weight: standard (1x, already weighted in total calculation)

// If pattern is as obvious as quota/credits, should get special handling:
const hasStrongOperationalError =
  hasBusinessErrorPattern &&
  (errorText.includes("insufficient funds") ||
    errorText.includes("account locked") ||
    // ... other strong banking errors
    errorText.includes("daily limit exceeded"));

// Then lower threshold to 0.2 for banking tools
const confidenceThreshold = hasStrongOperationalError ? 0.2 : 0.5;
```

4. **Test the change**:

```typescript
it("should recognize insufficient funds as business logic error", () => {
  const tool: Tool = {
    name: "transfer_funds",
    description: "Transfer money between accounts",
    inputSchema: { type: "object" },
  };

  const context: ValidationContext = {
    tool,
    input: { amount: 1000, to: "account-123" },
    response: {
      isError: true,
      content: [
        {
          type: "text",
          text: "Insufficient funds in account",
        },
      ],
    },
  };

  expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
});
```

### Adding New Validation Factors

To add new confidence factors:

1. **Identify the indicator**: What suggests business logic validation?

```typescript
// Example: Check for structured error object with standard fields
const hasStructuredError =
  isJsonObject &&
  errorObj.hasOwnProperty("code") &&
  errorObj.hasOwnProperty("message");
```

2. **Add to confidence calculation**:

```typescript
// Add factor to calculation
if (hasStructuredErrorObject) confidenceFactors++;
totalFactors++;

// Result: increases confidence slightly if present
```

3. **Consider weighting**: Should this factor be more important?

```typescript
// For MCP compliance (very strong indicator):
if (errorCode && mcpValidationCodes.some((code) => errorText.includes(code))) {
  confidenceFactors += 2; // 2x weight
}
totalFactors += 2;

// For custom patterns (standard indicator):
if (hasBusinessErrorPattern) {
  confidenceFactors += 1; // 1x weight (already done)
}
totalFactors += 1;
```

4. **Test the calculation**:

```typescript
it("should weight structured errors appropriately", () => {
  // Test that structured errors increase confidence
  const withStructured: ValidationContext = {
    tool,
    input: {},
    response: {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({
            code: "INVALID_INPUT",
            message: "Invalid format",
          }),
        },
      ],
    },
  };

  expect(ResponseValidator.isBusinessLogicError(withStructured)).toBe(true);
});
```

### Adding New Content Type Support

To track new content types:

1. **Check MCP spec** for new content types

2. **Update content type tracking**:

```typescript
switch (type) {
  case "text":
    textBlockCount++;
    break;
  case "image":
    imageCount++;
    break;
  case "resource":
  case "resource_link":
    resourceCount++;
    break;
  case "new_type": // Add new type
    newTypeCount++;
    break;
}
```

3. **Update metadata interface** if needed:

```typescript
interface ResponseMetadata {
  // ... existing fields
  newTypeCount: number; // Track new content type
}
```

4. **Update evidence collection**:

```typescript
if (responseMetadata.newTypeCount > 0) {
  result.evidence.push(
    `Response includes ${responseMetadata.newTypeCount} new_type(s)`,
  );
}
```

## Best Practices

### 1. Always Check Error Messages Carefully

Business logic errors are distinguishable from tool failures by their error messages. The validator uses pattern matching to identify them.

```typescript
// Good: Business logic error (tool working)
"Resource not found for ID: 12345";

// Bad: Tool failure (not business logic)
"TypeError: Cannot read property 'id' of undefined";
```

### 2. Use Scenario Categories

Provide scenario categories to enable context-aware validation:

```typescript
const context: ValidationContext = {
  tool,
  input: params,
  response,
  scenarioCategory: "error_case", // Helps interpret error responses
};
```

### 3. Monitor Confidence Scores

Don't rely solely on classification. Check confidence to understand certainty:

```typescript
const result = ResponseValidator.validateResponse(context);

if (result.confidence < 70) {
  // Low confidence - might need investigation
  console.warn("Low confidence validation:", result.evidence);
}
```

### 4. Examine Evidence

Always review the evidence list to understand why validation succeeded/failed:

```typescript
console.log("Validation issues:", result.issues);
console.log("Validation evidence:", result.evidence);
// Helps debug unexpected results
```

### 5. Test with Real Tools

Business logic error detection works best with real error responses from actual tools:

```typescript
// Real error from firecrawl API
"Insufficient credits to perform this request. For more credits, you can upgrade your plan.";
// This is correctly identified as business logic (tool working)

// Real error from database
"Connection timeout: failed to connect to database within 5 seconds";
// This would NOT be identified as business logic (tool failure)
```

## Common Scenarios

### Scenario 1: Tool Returns 404 Not Found

```typescript
const context: ValidationContext = {
  tool: { name: "get_user", ... },
  input: { userId: "invalid-id" },
  response: {
    isError: true,
    content: [{ type: "text", text: "User 404: Not Found" }]
  }
};

const result = ResponseValidator.validateResponse(context);
// result.classification = "fully_working"
// result.confidence = 100 (tool responded with error)

const isBusinessError = ResponseValidator.isBusinessLogicError(context);
// true (pattern match on "not found")
// Indicates: Tool is working, just invalid input
```

### Scenario 2: Tool Crashes

```typescript
const context: ValidationContext = {
  tool: { name: "calculate_sum", ... },
  input: { values: [1, 2, 3] },
  response: {
    isError: true,
    content: [{
      type: "text",
      text: "TypeError: sum is not a function"
    }]
  }
};

const isBusinessError = ResponseValidator.isBusinessLogicError(context);
// false (no business error patterns match)
// Indicates: Tool failure, not validation
```

### Scenario 3: Tool Out of Credits

```typescript
const context: ValidationContext = {
  tool: { name: "firecrawl_scrape", ... },
  input: { url: "https://example.com" },
  response: {
    isError: true,
    content: [{
      type: "text",
      text: "Error: Insufficient credits to perform this request"
    }]
  }
};

const isBusinessError = ResponseValidator.isBusinessLogicError(context);
// true (strong operational error pattern)
// Special handling: 20% threshold (very lenient)
// Indicates: Tool working, just operational limitation
```

### Scenario 4: Tool Returns Valid JSON

```typescript
const context: ValidationContext = {
  tool: { name: "search_items", ... },
  input: { query: "test" },
  response: {
    isError: false,
    content: [{
      type: "text",
      text: JSON.stringify({
        items: [
          { id: 1, name: "Item 1" },
          { id: 2, name: "Item 2" }
        ],
        total: 2
      })
    }]
  }
};

const result = ResponseValidator.validateResponse(context);
// result.classification = "fully_working"
// result.confidence = 100
// Metadata includes: contentTypes: ["text"], textBlockCount: 1
// Evidence: ["Tool responded successfully with content", ...]
```

## Troubleshooting

### Problem: Tool marked as "broken" but it's working

**Check**: Does the tool return any content?

```typescript
// The validator requires response.content to be a non-empty array
const hasContent =
  Array.isArray(response.content) && response.content.length > 0;
```

**Solution**: Ensure the MCP server properly formats responses with content arrays.

### Problem: False negatives on business logic errors

**Check**: Does the error message contain a recognized pattern?

```typescript
// List all business error patterns in the source
const patterns = [
  "not found", "invalid format", "unauthorized", ...
];
```

**Solution**:

1. Add missing error pattern to the patterns list
2. Or increase confidence threshold for the tool type

### Problem: False positives on business logic errors

**Check**: Is the tool type triggering validation-expected?

```typescript
// Validation-expected tools have 20% threshold
// Regular tools have 50% threshold
```

**Solution**:

1. If not validation-expected, ensure pattern confidence < 50%
2. Add exception for specific tool names if needed

### Problem: Output schema validation failing

**Check**: Does tool declare output schema?

```typescript
const hasSchema = hasOutputSchema(tool.name);
```

**Check**: Does response have structuredContent or extractable JSON?

```typescript
if (hasStructuredContent) {
  /* validate structuredContent */
} else {
  /* try to extract JSON from text */
}
```

**Solution**:

1. Ensure tool follows MCP output schema conventions
2. Return structuredContent for schema-validated tools
3. Or ensure text content contains valid JSON

## API Reference

### ResponseValidator.validateResponse()

Validates a tool response comprehensively.

```typescript
static validateResponse(context: ValidationContext): ValidationResult
```

**Parameters:**

- `context`: ValidationContext - Tool, input, response

**Returns:** ValidationResult with classification and confidence

**Throws:** Nothing (returns broken classification on errors)

### ResponseValidator.isBusinessLogicError()

Determines if error response indicates business logic validation.

```typescript
static isBusinessLogicError(context: ValidationContext): boolean
```

**Parameters:**

- `context`: ValidationContext with error response

**Returns:** true if error is business logic, false if tool failure

**Confidence factors:**

- MCP error code (2x weight)
- Business error pattern (2x weight)
- HTTP status code (1x weight)
- Structured error format (1x weight)
- Validates test data (1x weight)
- Validation-expected tool (2x weight)

**Threshold:** 20-50% depending on error and tool type

### ResponseValidator.extractResponseMetadata()

Extracts detailed metadata from tool response.

```typescript
static extractResponseMetadata(context: ValidationContext): ResponseMetadata
```

**Parameters:**

- `context`: ValidationContext

**Returns:** ResponseMetadata with content analysis

**Extracts:**

- Content types present
- Count of each content type
- Presence of advanced features (structuredContent, \_meta)
- Output schema validation results

### ResponseValidator.calculateOverallConfidence()

Calculates weighted average confidence from multiple results.

```typescript
static calculateOverallConfidence(results: ValidationResult[]): number
```

**Parameters:**

- `results`: Array of ValidationResult from multiple scenarios

**Returns:** 0-100 confidence score

**Weights:**

- fully_working: 1.0 (100%)
- partially_working: 0.7 (70%)
- connectivity_only: 0.3 (30%)
- error: 0.2 (20%)
- broken: 0.0 (0%)

## Files and References

- **Implementation**: `/client/src/services/assessment/ResponseValidator.ts`
- **Tests**: `/client/src/services/assessment/__tests__/ResponseValidator.test.ts`
- **Integration**: `/client/src/services/assessment/TestScenarioEngine.ts`
- **Types**: `/client/src/lib/assessmentTypes.ts`
