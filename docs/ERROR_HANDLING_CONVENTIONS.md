# Error Handling Conventions

This document describes the standardized error handling patterns used across assessment modules.

## Overview

All assessment modules should follow consistent error handling patterns to ensure:

- **Visibility**: All errors are logged for debugging
- **Consistency**: Same error structure across all modules
- **Recoverability**: Clear indication of whether errors are recoverable

## Error Types

### ErrorCategory Enum

Located in `client/src/services/assessment/lib/errors.ts`:

| Category     | Description                   | Examples                                 |
| ------------ | ----------------------------- | ---------------------------------------- |
| `CONNECTION` | Network connectivity issues   | ECONNREFUSED, DNS failures, timeouts     |
| `PROTOCOL`   | MCP protocol violations       | Invalid responses, malformed messages    |
| `VALIDATION` | Input validation failures     | Missing required fields, invalid formats |
| `TIMEOUT`    | Operation exceeded time limit | Tool call timeout, request timeout       |
| `PARSE`      | Data parsing failures         | Invalid JSON, malformed data             |
| `UNKNOWN`    | Unclassified errors           | Catch-all for unexpected errors          |

### AssessmentError Class

```typescript
import { AssessmentError, ErrorCategory } from "../lib/errors";

// Create a specific error
throw new AssessmentError(
  "Failed to connect to MCP server",
  ErrorCategory.CONNECTION,
  false, // not recoverable
  { url: "http://localhost:3000", attempt: 3 },
);
```

## Standard Patterns

### Pattern 1: Using handleError() (Recommended)

Use `handleError()` in catch blocks to log and return structured errors:

```typescript
async testTool(tool: Tool): Promise<ToolResult> {
  try {
    const response = await this.callTool(tool.name, params);
    return { passed: true, response };
  } catch (error) {
    // Logs error AND returns structured result
    return this.handleError(error, `Tool test failed: ${tool.name}`, {
      toolName: tool.name,
      passed: false,
    });
  }
}
```

### Pattern 2: Using logError() for Simple Cases

When you need to continue execution after logging:

```typescript
try {
  const data = JSON.parse(responseText);
  // ... use data
} catch (error) {
  this.logError("Failed to parse response JSON", error);
  // Continue with fallback behavior
}
```

### Pattern 3: Debug Logging for Expected Errors

For expected failures that aren't actual errors:

```typescript
try {
  await context.getPrompt(prompt.name, invalidArgs);
  // If we got here, validation failed
  return false;
} catch (error) {
  // Expected - invalid args should throw
  this.logger.debug(`Args correctly rejected for ${prompt.name}`, {
    error: error instanceof Error ? error.message : String(error),
  });
  continue;
}
```

## When to Use Each Pattern

| Scenario                           | Pattern          | Log Level |
| ---------------------------------- | ---------------- | --------- |
| Tool execution failure             | `handleError()`  | ERROR     |
| Validation failure                 | `handleError()`  | ERROR     |
| Expected rejection (security test) | `logger.debug()` | DEBUG     |
| Parse failure with fallback        | `logError()`     | ERROR     |
| Network retry                      | `logger.debug()` | DEBUG     |

## Anti-Patterns to Avoid

### DON'T: Silent Catches

```typescript
// BAD - Silent failure, impossible to debug
try {
  await this.callTool(tool);
} catch {
  return { passed: false };
}
```

### DON'T: console.log/console.error

```typescript
// BAD - Bypasses structured logging
try {
  await this.callTool(tool);
} catch (error) {
  console.error("Tool failed:", error); // Use this.logError() instead
}
```

### DON'T: Throw Without Context

```typescript
// BAD - Loses context
catch (error) {
  throw error; // Loses call context
}

// GOOD - Add context
catch (error) {
  throw new AssessmentError(
    `Failed during ${operation}`,
    ErrorCategory.UNKNOWN,
    true,
    { originalError: error.message }
  );
}
```

## Error Result Interface

All result types that may contain errors should extend `ErrorResult`:

```typescript
import { ErrorResult, ErrorInfo } from "../lib/errors";

interface ToolTestResult extends ErrorResult {
  toolName: string;
  passed: boolean;
  response?: unknown;
}

// Result will have optional error field:
// {
//   toolName: "example_tool",
//   passed: false,
//   error: {
//     message: "Connection refused",
//     code: "CONNECTION",
//     recoverable: false,
//     stack: "..."
//   }
// }
```

## Testing Error Handling

When testing error handling:

```typescript
it("should log and return structured error on failure", async () => {
  const assessor = new TestAssessor(config);

  // Mock a failure
  jest
    .spyOn(assessor, "callTool")
    .mockRejectedValue(new Error("Connection refused"));

  const result = await assessor.testTool(mockTool);

  expect(result.error).toBeDefined();
  expect(result.error?.code).toBe("CONNECTION");
  expect(result.error?.recoverable).toBe(false);
});
```

## Migration Guide

To update existing code to use standardized error handling:

1. **Import error types**:

   ```typescript
   import { ErrorCategory, ErrorInfo } from "../lib/errors";
   ```

2. **Replace silent catches** with `handleError()` or `logError()`

3. **Update result types** to extend `ErrorResult` if they don't already

4. **Add error field** to returned objects where appropriate

## Related Documentation

- [LOGGING_GUIDE.md](LOGGING_GUIDE.md) - Structured logging configuration
- [ASSESSMENT_MODULE_DEVELOPER_GUIDE.md](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating new assessment modules
