# Type-Safe Testing Patterns: Lessons from Issue #186

**Date**: 2026-01-17
**Context**: Fixing 189 ESLint `@typescript-eslint/no-explicit-any` warnings across 30+ test files
**Impact**: Improved type safety, better IDE support, reduced runtime errors, maintainable test code

---

## Executive Summary

Issue #186 involved replacing `any` types in test mocks with proper TypeScript types across the inspector-assessment test suite. This document captures the patterns, techniques, and best practices that emerged from this work, serving as a guide for the test-automator agent and future test development.

**Key Achievement**: Eliminated 189 type safety violations while maintaining 100% test functionality across ~1560 tests.

---

## Core Patterns

### 1. Type-Safe Private Method Access

**Problem**: Testing internal methods requires accessing private class members, typically done with `(instance as any).method()`, which bypasses type checking.

**Solution**: Generic helper function with proper type inference.

```typescript
// Helper in testUtils.ts
export function getPrivateMethod<T, R>(
  instance: T,
  methodName: string,
): (...args: unknown[]) => R {
  const method = (instance as Record<string, unknown>)[methodName];
  if (typeof method === "function") {
    return method.bind(instance) as (...args: unknown[]) => R;
  }
  throw new Error(`Method ${methodName} not found`);
}
```

**Usage in tests**:

```typescript
// Define return type alias at top of test file
type DetectSuggestionFn = (msg: string) => {
  hasSuggestions: boolean;
  suggestions: string[];
};

// Get typed method reference in test
const detectSuggestionPatterns = getPrivateMethod<
  ErrorHandlingAssessor,
  ReturnType<DetectSuggestionFn>
>(assessor, "detectSuggestionPatterns");

// Call with full type safety
const result = detectSuggestionPatterns("error: missing field");
expect(result.hasSuggestions).toBe(true);
```

**Benefits**:

- ✅ Type-safe method calls with autocomplete
- ✅ Compile-time error detection
- ✅ Self-documenting test code via type aliases
- ✅ Centralized runtime validation (throws if method missing)

**Agent Recommendation**: When generating tests for private methods, always use `getPrivateMethod` with explicit type parameters rather than `as any` casts.

---

### 2. Type Aliases for Test Return Types

**Problem**: Complex return types from functions/methods make test code verbose and repetitive.

**Solution**: Define type aliases at the top of test files for reusability.

```typescript
// At top of test file
type TestResponse = Pick<CompatibilityCallToolResult, "content">;
type IsErrorResponseFn = (response: unknown) => boolean;
type AnalysisResult = {
  classification: string;
  shouldPenalize: boolean;
  penaltyAmount: number;
};
```

**Usage patterns**:

```typescript
// 1. Pick utility type for partial SDK types
type TestResponse = Pick<CompatibilityCallToolResult, "content">;
const response: TestResponse = {
  content: [{ type: "text", text: "success" }],
};

// 2. Function signature aliases
type ExtractErrorInfoFn = (response: unknown) => {
  code?: number;
  message: string;
};
const extractErrorInfo = getPrivateMethod<Assessor, ExtractErrorInfoFn>(
  assessor,
  "extractErrorInfo",
);

// 3. Object structure aliases
type MetricsResult = {
  mcpComplianceScore: number;
};
```

**Benefits**:

- ✅ DRY principle - define once, use many times
- ✅ Easy to update if SDK types change
- ✅ Clear documentation of expected structures
- ✅ Reduced cognitive load when reading tests

**Agent Recommendation**: Generate type aliases for any return type used more than twice in a test file. Place them at the top of the file with clear comments.

---

### 3. Intentional Invalid Input Testing

**Problem**: Testing error handling requires passing invalid data that doesn't match expected types (e.g., `undefined` schema, malformed JSON Schema).

**Anti-Pattern** (avoid):

```typescript
// DON'T: Silences all type checking
inputSchema: undefined as any;
```

**Solution 1**: Double type assertion (best for truly invalid types)

```typescript
// Use when testing code that should handle invalid input gracefully
inputSchema: undefined as unknown as Tool["inputSchema"];
```

**Solution 2**: Custom partial type (best for partial schemas)

```typescript
// Define in testUtils.ts
export type PartialToolSchema = Partial<Tool["inputSchema"]> | undefined;

// Use in tests
const tool: Tool = {
  name: "no_schema",
  description: "Tool without schema",
  inputSchema: undefined as PartialToolSchema as Tool["inputSchema"],
};
```

**Solution 3**: Intentional type mismatch (for specific property testing)

```typescript
// Test array schema when object expected
const tool = createTool("array_schema", {
  type: "array",
} as unknown as Tool["inputSchema"]);
```

**When to use each**:

| Pattern                      | Use Case                   | Example                             |
| ---------------------------- | -------------------------- | ----------------------------------- |
| `as unknown as T`            | Completely invalid input   | `undefined` → `Tool["inputSchema"]` |
| `PartialToolSchema`          | Missing or partial schemas | Testing schema-optional code paths  |
| `as unknown as T` (specific) | Wrong type for property    | `{ type: "array" }` → object schema |

**Benefits**:

- ✅ Explicit about intentional type violations
- ✅ Maintains type safety in the rest of the test
- ✅ Documents edge cases being tested
- ✅ ESLint-compliant

**Agent Recommendation**: When generating error handling tests, use `as unknown as T` for intentionally invalid input and add a comment explaining the test's purpose.

---

### 4. Extended Types for SDK Gaps

**Problem**: Testing features that exist in real-world MCP servers but aren't yet in the official SDK types (e.g., MCP 2025-06-18 `outputSchema`).

**Solution**: Create extended types that add optional properties.

```typescript
// For features not yet in SDK types
type ToolWithOutputSchema = Tool & {
  outputSchema?: Record<string, unknown>;
};

// Usage
const hasOutputSchema = !!(tool as ToolWithOutputSchema).outputSchema;

// Conditional logic
if ((tool as ToolWithOutputSchema).outputSchema) {
  // Process output schema
}
```

**Pattern variations**:

```typescript
// 1. Extended with optional feature
type ToolWithAnnotations = Tool & {
  annotations?: {
    title?: string;
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
  };
};

// 2. Extended with metadata
type ToolWithMetadata = Tool & {
  metadata?: {
    category?: string;
    tags?: string[];
  };
};

// 3. Extended with internal properties
type InternalToolRepresentation = Tool & {
  _internal?: {
    lastModified?: number;
    version?: string;
  };
};
```

**Benefits**:

- ✅ Type-safe access to future/experimental features
- ✅ Documents SDK version differences
- ✅ Easy to remove when SDK catches up
- ✅ Prevents breaking when SDK is updated

**Agent Recommendation**: When testing servers with features beyond the SDK, create extended types with clear comments explaining the feature and its status.

---

### 5. Property Schema Interfaces

**Problem**: Accessing JSON Schema properties (e.g., `type`, `enum`, `minimum`) requires type assertions for each access.

**Solution**: Define reusable schema interfaces.

```typescript
// Minimal property schema
interface PropertySchema {
  type?: string;
  description?: string;
  enum?: unknown[];
  minimum?: number;
  maximum?: number;
  format?: string;
  pattern?: string;
}

// Usage
const properties = tool.inputSchema?.properties || {};
for (const [name, prop] of Object.entries(properties)) {
  const propSchema = prop as PropertySchema;

  // Type-safe access
  if (propSchema.enum) {
    // Handle enum validation
  }

  if (propSchema.minimum !== undefined) {
    // Handle minimum constraint
  }
}
```

**Extended patterns**:

```typescript
// Full JSON Schema types (when needed)
interface DetailedPropertySchema extends PropertySchema {
  items?: PropertySchema | PropertySchema[];
  properties?: Record<string, PropertySchema>;
  required?: string[];
  additionalProperties?: boolean | PropertySchema;
  oneOf?: PropertySchema[];
  anyOf?: PropertySchema[];
  allOf?: PropertySchema[];
}

// Type-safe schema analysis
function analyzeSchema(schema: PropertySchema): SchemaInfo {
  return {
    hasEnum: schema.enum !== undefined,
    hasRange: schema.minimum !== undefined || schema.maximum !== undefined,
    hasFormat: schema.format !== undefined,
  };
}
```

**Benefits**:

- ✅ Single cast per object instead of per property
- ✅ Reusable across test files
- ✅ Easy to extend with more properties
- ✅ Documents which JSON Schema features are used

**Agent Recommendation**: Generate `PropertySchema` interfaces when tests need to inspect JSON Schema structures. Place in `testUtils.ts` if used across multiple files.

---

## Test Data Generation Patterns

### Factory Functions with Type Safety

**Pattern**: Create factory functions that return properly typed test objects.

```typescript
// Mock tool factory
export function createMockTool(overrides?: Partial<Tool>): Tool {
  return {
    name: "test-tool",
    description: "A test tool",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
      },
    },
    ...overrides,
  };
}

// Mock assessment context factory
export function createMockAssessmentContext(
  overrides?: Partial<AssessmentContext>,
): AssessmentContext {
  return {
    serverName: "test-server",
    tools: [createMockTool()],
    callTool: jest.fn().mockResolvedValue({
      content: [{ type: "text", text: "success" }],
      isError: false,
    } as CompatibilityCallToolResult),
    config: createMockAssessmentConfig(),
    ...overrides,
  };
}

// Specialized factory for specific scenarios
export function createMockToolWithAnnotations(overrides?: {
  name?: string;
  description?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
}): ToolWithAnnotations {
  const tool = createMockTool({
    name: overrides?.name ?? "test-tool",
    description: overrides?.description ?? "A test tool",
  }) as ToolWithAnnotations;

  tool.annotations = {
    readOnlyHint: overrides?.readOnlyHint,
    destructiveHint: overrides?.destructiveHint,
  };

  return tool;
}
```

**Benefits**:

- ✅ Consistent test data across all tests
- ✅ Type-safe overrides
- ✅ Easy to update defaults globally
- ✅ Self-documenting API

---

### Helper Functions for Complex Mocks

**Pattern**: Create domain-specific helpers for complex test scenarios.

```typescript
// Helper for error test scenarios
export function createInvalidValuesTest(
  toolName: string,
  isError: boolean,
  rawResponse: unknown,
  errorMessage?: string,
): ErrorTestDetail {
  return {
    toolName,
    testType: "invalid_values",
    testInput: { query: "" },
    expectedError: "Invalid parameter values",
    actualResponse: {
      isError,
      errorCode: isError ? -32602 : undefined,
      errorMessage: errorMessage || (isError ? "Validation failed" : undefined),
      rawResponse,
    },
    passed: isError,
    reason: isError ? undefined : "Tool accepted invalid values",
  };
}

// Helper for temporal test scenarios
export function createTemporalTestTool(
  name: string,
  schema: Record<string, unknown> = {},
): Tool {
  return {
    name,
    description: `Test tool: ${name}`,
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      ...schema,
    },
  };
}

// Helper for source code analysis scenarios
export function createMockSourceCodeFiles(
  files?: Record<string, string>,
): Map<string, string> {
  const defaultFiles: Record<string, string> = {
    "src/index.ts": `
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({
  name: "test-server",
  version: "1.0.0",
});

server.start();
`,
    "package.json": JSON.stringify(createMockPackageJson(), null, 2),
  };

  return new Map(Object.entries({ ...defaultFiles, ...files }));
}
```

**Benefits**:

- ✅ Domain-specific test creation
- ✅ Reduces boilerplate in test files
- ✅ Ensures consistency across related tests
- ✅ Easy to update when types change

---

## Anti-Patterns to Avoid

### 1. Inline Type Assertions (avoid)

```typescript
// ❌ BAD: Loses type safety throughout function
function testSomething(tool: any) {
  const schema = tool.inputSchema;
  const props = schema.properties;
  // No type checking anywhere
}

// ✅ GOOD: Type-safe with clear intent
function testSomething(tool: Tool) {
  const schema = tool.inputSchema;
  if (!schema || schema.type !== "object") return;

  const props = schema.properties as Record<string, PropertySchema>;
  for (const [name, prop] of Object.entries(props)) {
    // Type-safe operations
  }
}
```

### 2. Repeated Type Assertions (avoid)

```typescript
// ❌ BAD: Cast every time
expect((result as any).vulnerable).toBe(true);
expect((result as any).deviationCount).toBe(2);
expect((result as any).pattern).toBe("RUG_PULL");

// ✅ GOOD: Type once, use many times
type AnalysisResult = {
  vulnerable: boolean;
  deviationCount: number;
  pattern: string;
};

const result = analyzeResponses(tool, responses) as AnalysisResult;
expect(result.vulnerable).toBe(true);
expect(result.deviationCount).toBe(2);
expect(result.pattern).toBe("RUG_PULL");
```

### 3. Unnecessary `any` in Jest Mocks (avoid)

```typescript
// ❌ BAD: Loses type information
const mockCallTool = jest.fn() as any;

// ✅ GOOD: Properly typed mock
const mockCallTool = jest
  .fn<Promise<CompatibilityCallToolResult>, [string, unknown]>()
  .mockResolvedValue({
    content: [{ type: "text", text: "success" }],
    isError: false,
  });

// ✅ ALTERNATIVE: Use createMockAssessmentContext factory
const mockContext = createMockAssessmentContext({
  callTool: jest.fn().mockResolvedValue(/* ... */),
});
```

### 4. Overly Permissive Types (avoid)

```typescript
// ❌ BAD: Too loose
const response: Record<string, any> = await callTool();

// ✅ GOOD: Specific but flexible
type CallToolResponse = {
  content?: Array<{ type: string; text: string }>;
  isError?: boolean;
  error?: { code: number; message: string };
};
const response: CallToolResponse = await callTool();
```

---

## Test-Automator Agent Guidelines

### When Generating Unit Tests

1. **Always import type utilities**:

   ```typescript
   import {
     getPrivateMethod,
     PartialToolSchema,
     createMockTool,
     createMockAssessmentContext,
   } from "@/test/utils/testUtils";
   ```

2. **Define type aliases at top of file**:

   ```typescript
   // Type definitions for private methods
   type MethodNameFn = (arg: ArgType) => ReturnType;
   type HelperResult = { field1: Type1; field2: Type2 };
   ```

3. **Use factories over manual construction**:

   ```typescript
   // ✅ DO THIS
   const tool = createMockTool({ name: "test" });

   // ❌ NOT THIS
   const tool = {
     name: "test",
     description: "...",
     inputSchema: { ... },
   };
   ```

4. **Type private method access properly**:

   ```typescript
   const privateMethod = getPrivateMethod<ClassType, ReturnType>(
     instance,
     "methodName",
   );
   ```

5. **Use `as unknown as T` for intentionally invalid input**:
   ```typescript
   // Testing error handling
   const invalidTool: Tool = {
     name: "test",
     description: "test",
     inputSchema: undefined as unknown as Tool["inputSchema"],
   };
   ```

### When Testing Private Methods

**Generated test structure**:

```typescript
describe("ClassName - privateMethod", () => {
  let instance: ClassName;
  let privateMethod: MethodSignature;

  beforeEach(() => {
    instance = new ClassName(config);
    privateMethod = getPrivateMethod<ClassName, ReturnType>(
      instance,
      "privateMethod",
    );
  });

  it("should handle normal case", () => {
    const result = privateMethod(normalInput);
    expect(result).toEqual(expectedOutput);
  });

  it("should handle edge case", () => {
    const result = privateMethod(edgeInput);
    expect(result).toEqual(edgeOutput);
  });
});
```

### When Testing Error Handling

```typescript
describe("error handling", () => {
  it("should reject invalid input", () => {
    // Use double assertion for truly invalid input
    const invalidSchema = undefined as unknown as Tool["inputSchema"];

    // Or use PartialToolSchema for partial schemas
    const partialSchema = { type: "invalid" } as PartialToolSchema;

    expect(() => validateSchema(invalidSchema)).toThrow();
  });

  it("should provide helpful error messages", () => {
    const error = { code: -32602, message: "Invalid params" };
    const response: CallToolResponse = { error };

    expect(extractErrorMessage(response)).toContain("Invalid params");
  });
});
```

### When Testing SDK Integration

```typescript
describe("SDK integration", () => {
  it("should handle future SDK features", () => {
    // Use extended types for experimental features
    type ToolWithFeature = Tool & {
      futureFeature?: SomeType;
    };

    const tool = createMockTool() as ToolWithFeature;
    tool.futureFeature = {
      /* ... */
    };

    // Test with clear documentation
    if ((tool as ToolWithFeature).futureFeature) {
      // Handle feature
    }
  });
});
```

---

## Checklist for Type-Safe Tests

When generating or reviewing tests, verify:

- [ ] No `as any` casts (use `as unknown as T` for intentional violations)
- [ ] Type aliases defined for complex/repeated return types
- [ ] `getPrivateMethod` used for private method access
- [ ] Factory functions used for mock data creation
- [ ] Extended types documented with SDK version comments
- [ ] `PropertySchema` interfaces used for JSON Schema access
- [ ] All intentional type violations have explanatory comments
- [ ] Jest mocks are properly typed
- [ ] No repeated type assertions (use type aliases)
- [ ] Clear separation between valid and invalid test data

---

## Performance Considerations

### Type Inference vs Explicit Typing

```typescript
// Type inference (preferred when clear)
const result = analyzeResponses(tool, responses);
expect(result.vulnerable).toBe(true); // IntelliSense works

// Explicit typing (use when inference fails or for clarity)
const result = analyzeResponses(tool, responses) as AnalysisResult;
expect(result.vulnerable).toBe(true);
```

### Factory Function Overhead

Factory functions add minimal overhead:

- **Negligible**: Object creation is fast in V8
- **Benefit**: Consistency and type safety outweigh any performance cost
- **Best practice**: Use factories for setup, direct construction for performance-critical paths (rare in tests)

---

## Migration Strategy

When updating existing tests to use these patterns:

1. **Start with type aliases**: Define at top of file
2. **Replace `as any` with specific types**: Use search/replace with verification
3. **Introduce factory functions**: Create once, migrate incrementally
4. **Update private method access**: Use `getPrivateMethod` helper
5. **Add property schema interfaces**: For JSON Schema manipulation
6. **Test after each change**: Ensure no regressions

---

## Real-World Examples

### Example 1: Error Handling Test (from errorHandlingAssessor.test.ts)

```typescript
// Type definitions at top
type IsErrorResponseFn = (response: unknown) => boolean;
type ExtractErrorInfoFn = (response: unknown) => {
  code?: number;
  message: string;
};

describe("ErrorHandlingAssessor", () => {
  let assessor: ErrorHandlingAssessor;
  let isErrorResponse: IsErrorResponseFn;
  let extractErrorInfo: ExtractErrorInfoFn;

  beforeEach(() => {
    assessor = new ErrorHandlingAssessor(mockConfig);

    // Type-safe private method access
    isErrorResponse = getPrivateMethod(assessor, "isErrorResponse");
    extractErrorInfo = getPrivateMethod(assessor, "extractErrorInfo");
  });

  it("should detect MCP error responses", () => {
    const response = { error: { code: -32602, message: "Invalid params" } };

    expect(isErrorResponse(response)).toBe(true);
    expect(extractErrorInfo(response)).toEqual({
      code: -32602,
      message: "Invalid params",
    });
  });
});
```

### Example 2: Temporal Analysis Test (from TemporalAssessor.test.ts)

```typescript
// Import helper types and functions
import {
  getPrivateMethod,
  createConfig,
  createTool,
  createMockContext,
} from "@/test/utils/testUtils";

describe("TemporalAssessor", () => {
  let assessor: TemporalAssessor;
  let analyzeResponsesFn: (
    tool: Tool,
    responses: Array<{
      invocation: number;
      response: unknown;
      error?: string;
      timestamp: number;
    }>,
    context: unknown,
  ) => unknown;

  beforeEach(() => {
    assessor = new TemporalAssessor(createConfig());
    analyzeResponsesFn = getPrivateMethod(assessor, "analyzeResponses");
  });

  it("detects deviation at specific invocation", () => {
    const tool = createTool("test_tool");
    const responses = [
      { invocation: 1, response: { result: "safe" }, timestamp: 1 },
      { invocation: 2, response: { result: "safe" }, timestamp: 2 },
      { invocation: 3, response: { result: "malicious!" }, timestamp: 3 },
    ];

    // Type assertion after function call
    const result = analyzeResponsesFn(tool, responses, {}) as {
      vulnerable: boolean;
      firstDeviationAt: number;
      deviationCount: number;
      pattern: string;
      severity: string;
    };

    expect(result.vulnerable).toBe(true);
    expect(result.firstDeviationAt).toBe(3);
    expect(result.pattern).toBe("RUG_PULL_TEMPORAL");
  });
});
```

### Example 3: Invalid Input Testing (from TestScenarioEngine.paramGeneration.test.ts)

```typescript
import { PartialToolSchema } from "@/test/utils/testUtils";

describe("TestScenarioEngine - parameter generation", () => {
  it("should handle tool without inputSchema", () => {
    // Intentionally invalid schema for error handling test
    const tool: Tool = {
      name: "no_schema",
      description: "Tool without schema",
      inputSchema: undefined as PartialToolSchema as Tool["inputSchema"],
    };

    const result = generateMinimalParams(tool);
    expect(result).toEqual({});
  });

  it("should handle non-object schema type", () => {
    // Wrong schema type for testing error path
    const tool = createTool("array_schema", {
      type: "array",
    } as unknown as Tool["inputSchema"]);

    const result = generateMinimalParams(tool);
    expect(result).toEqual({});
  });
});
```

---

## Impact Metrics

### Before (with `any` types)

- **ESLint warnings**: 189 `@typescript-eslint/no-explicit-any` violations
- **Type safety**: Minimal - tests could pass with incorrect types
- **IDE support**: Limited autocomplete and type hints
- **Refactoring risk**: High - changes could break tests silently

### After (type-safe patterns)

- **ESLint warnings**: 0 `@typescript-eslint/no-explicit-any` violations
- **Type safety**: Full - compile-time validation of all test code
- **IDE support**: Complete autocomplete and inline documentation
- **Refactoring risk**: Low - TypeScript catches breaking changes

### Maintenance Benefits

- **Code reviews**: Type errors caught before merge
- **Onboarding**: New developers see expected types immediately
- **Debugging**: Type information available at runtime (for IDEs)
- **Documentation**: Types serve as inline API documentation

---

## Future Enhancements

### 1. Generate Type Definitions from Runtime Values

**Idea**: Create TypeScript type definitions from actual MCP server responses.

```typescript
// Future: Auto-generate from server response
type AutoGeneratedToolResponse = GenerateTypeFromValue<actualResponse>;
```

### 2. Shared Type Library

**Idea**: Extract common test types into a shared library.

```typescript
// @inspector-assessment/test-types
export {
  PropertySchema,
  ToolWithOutputSchema,
  TestResponse,
  /* ... */
};
```

### 3. Type-Safe Test Builders

**Idea**: Fluent API for building type-safe test scenarios.

```typescript
const scenario = TestScenario.forTool("calculator")
  .withInput({ expression: "2+2" })
  .expectSuccess()
  .withResponseMatching({ result: 4 })
  .build();
```

---

## References

- **Issue #186**: [GitHub Issue - Type safety in test mocks](https://github.com/triepod-ai/inspector-assessment/issues/186)
- **testUtils.ts**: `/home/bryan/inspector/client/src/test/utils/testUtils.ts`
- **MCP SDK Types**: `@modelcontextprotocol/sdk/types.js`
- **TypeScript Handbook**: [Type Assertions](https://www.typescriptlang.org/docs/handbook/2/everyday-types.html#type-assertions)

---

## Conclusion

Type-safe testing patterns significantly improve code quality, maintainability, and developer experience. By following these patterns, the test-automator agent can generate tests that are:

1. **Type-safe**: Catch errors at compile time
2. **Self-documenting**: Types explain expected structures
3. **Maintainable**: Easy to refactor and update
4. **IDE-friendly**: Full autocomplete and inline help

**Next Steps**:

1. Integrate these patterns into test-automator's code generation templates
2. Create validation rules to ensure generated tests follow these patterns
3. Update test-automator documentation with examples from this guide

---

**Document Version**: 1.0
**Last Updated**: 2026-01-17
**Maintained By**: Test Automator Agent
