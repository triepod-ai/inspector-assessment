# Response Validation Core

> **Part of the Response Validation documentation series:**
>
> - **Core** (this document) - Validation logic, business error detection, confidence scoring
> - [Extension](RESPONSE_VALIDATION_EXTENSION.md) - Adding rules, best practices, troubleshooting, API reference

## Overview

The `ResponseValidator` is a core component of the MCP Inspector's assessment functionality that determines whether tool responses indicate actual functionality versus broken/non-functional tools. It provides sophisticated analysis of tool responses with particular focus on distinguishing between genuine tool failures and business logic validation errors.

**Location**: `/client/src/services/assessment/ResponseValidator.ts`

**Purpose**: Validate that MCP tool responses are actually functional, not just present.

---

## Table of Contents

- [Overview](#overview)
- [1. Key Capabilities](#1-key-capabilities)
- [2. Core Data Types](#2-core-data-types)
  - [ValidationResult](#validationresult)
  - [ValidationContext](#validationcontext)
  - [ResponseMetadata](#responsemetadata)
- [3. Response Validation](#3-response-validation)
  - [How Validation Works](#how-validation-works)
  - [Validation Classifications](#validation-classifications)
  - [Code Example](#code-example-basic-validation)
- [4. Business Logic Error Detection](#4-business-logic-error-detection)
  - [The Problem](#the-problem)
  - [Confidence-Based Classification](#the-solution-confidence-based-classification)
  - [MCP Error Codes](#mcp-error-codes)
  - [Business Logic Error Patterns](#business-logic-error-patterns)
  - [Validation-Expected Tools](#validation-expected-tools)
  - [Code Example](#code-example-business-logic-error-detection)
- [5. Response Metadata Extraction](#5-response-metadata-extraction)
- [6. Overall Confidence Calculation](#6-overall-confidence-calculation)
- [7. Integration with TestScenarioEngine](#7-integration-with-testscenarioengine)

---

## 1. Key Capabilities

The ResponseValidator provides three main assessment capabilities:

1. **Response Validation**: Comprehensive analysis of tool responses to classify functionality
2. **Business Logic Error Detection**: Distinguish between tool failures and expected validation errors
3. **Confidence Scoring**: Multi-factor confidence calculation for assessment results

---

## 2. Core Data Types

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

---

## 3. Response Validation

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

---

## 4. Business Logic Error Detection

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

// High-confidence validation patterns (Issue #203)
// -> 20% threshold (file not found, permission denied, etc.)
else if (hasHighConfidenceValidationPattern) {
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

#### File/Media Validation (Issue #203)

High-confidence validation patterns that unambiguously indicate proper input validation:

```
"file not found", "path not found", "directory not found",
"does not exist", "no such file", "no such directory",
"invalid path", "permission denied", "access denied",
"unauthorized", "authentication required", "missing required",
"required parameter", "invalid parameter", "invalid input",
"validation failed"
```

**Special handling**: These patterns use the 20% confidence threshold (same as strong operational errors) because they are unambiguous indicators of working validation logic.

### Validation-Expected Tools

Tools that inherently involve data validation get lower confidence thresholds:

- **CRUD operations**: create, add, insert, update, modify, set, delete, remove
- **Read operations**: get, fetch, read, write, query, search, find, list
- **Data operations**: entity, relation, node, edge, record
- **State operations**: move, copy, duplicate, archive
- **Relationship ops**: link, associate, connect, attach
- **API/scraping**: scrape, crawl, extract, parse, analyze, process
- **File/media operations** (Issue #203): load, open, save, close, play, stop, pause
- **IO operations**: upload, download, import, export
- **Execution operations**: run, execute, invoke, call
- **Send/receive operations**: send, receive, post, put

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

// Scenario 4: File validation error (Issue #203)
const context4: ValidationContext = {
  tool: {
    name: "load_audio",
    description: "Load audio file",
    inputSchema: { type: "object" },
  },
  input: { path: "/nonexistent/file.mp3" },
  response: {
    isError: true,
    content: [
      {
        type: "text",
        text: "File not found: /nonexistent/file.mp3",
      },
    ],
  },
};

const result4 = ResponseValidator.isBusinessLogicError(context4);
console.log(result4); // true - High-confidence validation pattern
// "file not found" pattern + file operation tool = 20% threshold
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

---

## 5. Response Metadata Extraction

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

---

## 6. Overall Confidence Calculation

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

---

## 7. Integration with TestScenarioEngine

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

---

## Related Documentation

- [Response Validation Extension](RESPONSE_VALIDATION_EXTENSION.md) - Adding rules, best practices, troubleshooting
- [Test Data Scenarios](TEST_DATA_SCENARIOS.md) - Test scenario categories
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete assessment reference
