# Type-Safe Testing: Quick Reference Card

**For**: Test Automator Agent & Test Developers
**Source**: Issue #186 - Eliminating 189 `@typescript-eslint/no-explicit-any` violations

---

## 5 Core Patterns

### 1. Private Method Access

```typescript
// ❌ DON'T
const result = (instance as any).privateMethod();

// ✅ DO
type MethodFn = (arg: ArgType) => ReturnType;
const privateMethod = getPrivateMethod<ClassName, MethodFn>(
  instance,
  "methodName",
);
const result = privateMethod(arg);
```

### 2. Type Aliases

```typescript
// ❌ DON'T (repeated casts)
expect((result as any).field1).toBe(true);
expect((result as any).field2).toBe(2);

// ✅ DO (type once)
type Result = { field1: boolean; field2: number };
const result = method() as Result;
expect(result.field1).toBe(true);
expect(result.field2).toBe(2);
```

### 3. Invalid Input Tests

```typescript
// ❌ DON'T
const invalid = undefined as any;

// ✅ DO
const invalid = undefined as unknown as Tool["inputSchema"];

// Or use custom type
import { PartialToolSchema } from "@/test/utils/testUtils";
const partial = undefined as PartialToolSchema as Tool["inputSchema"];
```

### 4. Extended Types (SDK Gaps)

```typescript
// ❌ DON'T
if ((tool as any).outputSchema) {
  /* ... */
}

// ✅ DO
type ToolWithOutputSchema = Tool & {
  outputSchema?: Record<string, unknown>;
};

if ((tool as ToolWithOutputSchema).outputSchema) {
  /* ... */
}
```

### 5. Property Schemas

```typescript
// ❌ DON'T (cast every access)
const type = (prop as any).type;
const min = (prop as any).minimum;

// ✅ DO (interface + single cast)
interface PropertySchema {
  type?: string;
  minimum?: number;
  maximum?: number;
}

const propSchema = prop as PropertySchema;
const type = propSchema.type;
const min = propSchema.minimum;
```

---

## Import Checklist

```typescript
// Always import from testUtils
import {
  getPrivateMethod, // Private method access
  PartialToolSchema, // Invalid input testing
  createMockTool, // Mock factory
  createMockAssessmentContext, // Context factory
  createMockAssessmentConfig, // Config factory
} from "@/test/utils/testUtils";
```

---

## Test File Template

```typescript
import { ClassName } from "../path/to/ClassName";
import {
  getPrivateMethod,
  createMockAssessmentContext,
} from "@/test/utils/testUtils";

// Type definitions for private methods
type PrivateMethodFn = (arg: ArgType) => ReturnType;
type ComplexResult = {
  field1: Type1;
  field2: Type2;
};

describe("ClassName", () => {
  let instance: ClassName;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    mockContext = createMockAssessmentContext();
    instance = new ClassName(mockContext);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("publicMethod", () => {
    it("should handle normal input", () => {
      const result = instance.publicMethod(normalInput);
      expect(result).toBeDefined();
    });

    it("should handle invalid input", () => {
      // Intentional type violation for error testing
      const invalid = undefined as unknown as RequiredType;
      expect(() => instance.publicMethod(invalid)).toThrow();
    });
  });

  describe("privateMethod (private)", () => {
    let privateMethod: PrivateMethodFn;

    beforeEach(() => {
      privateMethod = getPrivateMethod<ClassName, PrivateMethodFn>(
        instance,
        "privateMethod",
      );
    });

    it("should process input correctly", () => {
      const result = privateMethod(testInput);
      expect(result).toEqual(expectedOutput);
    });
  });
});
```

---

## Common Scenarios

### Testing Error Responses

```typescript
describe("error handling", () => {
  it("should detect MCP errors", () => {
    const response = {
      error: { code: -32602, message: "Invalid params" },
    };

    const isError = detectError(response);
    expect(isError).toBe(true);
  });
});
```

### Testing JSON Schema Manipulation

```typescript
interface PropertySchema {
  type?: string;
  enum?: unknown[];
  minimum?: number;
}

describe("schema analysis", () => {
  it("should analyze property constraints", () => {
    const props = schema.properties as Record<string, PropertySchema>;

    for (const [name, prop] of Object.entries(props)) {
      const propSchema = prop as PropertySchema;

      if (propSchema.enum) {
        // Handle enum constraint
      }

      if (propSchema.minimum !== undefined) {
        // Handle minimum constraint
      }
    }
  });
});
```

### Testing with Factories

```typescript
describe("context-based tests", () => {
  it("should process multiple tools", () => {
    const mockContext = createMockAssessmentContext({
      tools: [
        createMockTool({ name: "tool1" }),
        createMockTool({ name: "tool2" }),
      ],
    });

    const result = processTools(mockContext);
    expect(result.toolsProcessed).toBe(2);
  });
});
```

---

## Anti-Patterns to Avoid

| Anti-Pattern         | Problem                    | Solution                      |
| -------------------- | -------------------------- | ----------------------------- |
| `as any`             | Bypasses all type checking | Use `as unknown as T`         |
| `// @ts-ignore`      | Hides real issues          | Fix the underlying type issue |
| Repeated casts       | Verbose, error-prone       | Use type alias                |
| Manual mocks         | Inconsistent defaults      | Use factory functions         |
| Inline complex types | Hard to read/maintain      | Extract to type alias         |

---

## Pre-Submit Checklist

- [ ] No `as any` casts
- [ ] All imports typed
- [ ] Type aliases for complex types
- [ ] Factory functions for mocks
- [ ] Private methods use `getPrivateMethod`
- [ ] Invalid input uses `as unknown as T`
- [ ] Extended types documented
- [ ] Tests pass: `npm test`
- [ ] ESLint passes: `npm run lint`

---

## Measurement

### Before (with `any`)

- 189 ESLint warnings
- No type safety in tests
- Limited IDE support

### After (type-safe)

- 0 ESLint warnings
- 100% type safety
- Full IDE autocomplete

---

## Full Documentation

- **Detailed Patterns**: [Type-Safe Testing Patterns](./type-safe-testing-patterns.md) (926 lines)
- **Implementation Guide**: [Test Automator Implementation](./test-automator-implementation-guide.md) (953 lines)
- **Index**: [Lessons Learned Index](./README.md)

---

**Version**: 1.0
**Last Updated**: 2026-01-17
**Print This**: Keep handy when writing tests
