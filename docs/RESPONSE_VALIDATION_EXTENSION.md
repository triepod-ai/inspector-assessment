# Response Validation Extension Guide

> **Part of the Response Validation documentation series:**
>
> - [Core](RESPONSE_VALIDATION_CORE.md) - Validation logic, business error detection, confidence scoring
> - **Extension** (this document) - Adding rules, best practices, troubleshooting, API reference

## Overview

This guide covers how to extend the ResponseValidator with new validation rules, best practices for using it effectively, common scenarios, troubleshooting, and the complete API reference.

---

## Table of Contents

- [Overview](#overview)
- [1. Extension Guide: Adding Validation Rules](#1-extension-guide-adding-validation-rules)
  - [Adding New Business Error Patterns](#adding-new-business-error-patterns)
  - [Adding New Validation Factors](#adding-new-validation-factors)
  - [Adding New Content Type Support](#adding-new-content-type-support)
- [2. Best Practices](#2-best-practices)
- [3. Common Scenarios](#3-common-scenarios)
- [4. Troubleshooting](#4-troubleshooting)
- [5. API Reference](#5-api-reference)
- [6. Files and References](#6-files-and-references)

---

## 1. Extension Guide: Adding Validation Rules

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

---

## 2. Best Practices

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

---

## 3. Common Scenarios

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

---

## 4. Troubleshooting

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

---

## 5. API Reference

### ResponseValidator.validateResponse()

Validates a tool response comprehensively.

```typescript
static validateResponse(context: ValidationContext): ValidationResult
```

**Parameters:**

- `context`: ValidationContext - Tool, input, response

**Returns:** ValidationResult with classification and confidence

**Throws:** Nothing (returns broken classification on errors)

---

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

---

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

---

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

---

## 6. Files and References

- **Implementation**: `/client/src/services/assessment/ResponseValidator.ts`
- **Tests**: `/client/src/services/assessment/__tests__/ResponseValidator.test.ts`
- **Integration**: `/client/src/services/assessment/TestScenarioEngine.ts`
- **Types**: `/client/src/lib/assessment/` (modular structure - see [ASSESSMENT_TYPES_IMPORT_GUIDE.md](ASSESSMENT_TYPES_IMPORT_GUIDE.md))
  - Core types: `/client/src/lib/assessment/coreTypes.ts`
  - Result types: `/client/src/lib/assessment/resultTypes.ts`
  - Configuration types: `/client/src/lib/assessment/configTypes.ts`

---

## Related Documentation

- [Response Validation Core](RESPONSE_VALIDATION_CORE.md) - Core validation logic and data types
- [Test Data Architecture](TEST_DATA_ARCHITECTURE.md) - Test data generation
- [ASSESSMENT_MODULE_DEVELOPER_GUIDE.md](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Assessment module development
