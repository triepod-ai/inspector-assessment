# Test Utilities API Reference

This document provides a complete reference for the test utility functions available in `client/src/test/utils/testUtils.ts`.

## Overview

The test utilities module provides mock factories and helper functions for testing assessment modules. These utilities standardize test setup and reduce boilerplate across test files.

**Location**: `client/src/test/utils/testUtils.ts`

**Import Pattern**:

```typescript
import {
  createMockTool,
  createMockAssessmentContext,
  createConfig,
  createTool,
} from "@/test/utils/testUtils";
```

---

## Table of Contents

- [Core Mock Factories](#core-mock-factories)
- [MCP Directory Compliance Utilities](#mcp-directory-compliance-utilities)
- [Security Testing Utilities](#security-testing-utilities)
- [Temporal Assessment Utilities](#temporal-assessment-utilities)
- [Convenience Aliases](#convenience-aliases)
- [Usage Examples](#usage-examples)

---

## Core Mock Factories

### createMockTool

Creates a mock Tool object for testing.

```typescript
function createMockTool(overrides?: Partial<Tool>): Tool;
```

**Parameters**:

- `overrides` - Optional partial Tool object to customize the mock

**Returns**: A Tool object with default values

**Default Values**:

- `name`: "test-tool"
- `description`: "A test tool"
- `inputSchema`: Object with `input` string property

**Example**:

```typescript
// Default tool
const tool = createMockTool();

// Custom tool
const customTool = createMockTool({
  name: "my-tool",
  description: "Custom description",
});
```

---

### createMockAssessmentContext

Creates a mock AssessmentContext for testing assessors.

```typescript
function createMockAssessmentContext(
  overrides?: Partial<AssessmentContext>,
): AssessmentContext;
```

**Parameters**:

- `overrides` - Optional partial context to customize

**Returns**: An AssessmentContext with mocked callTool and default configuration

**Default Values**:

- `serverName`: "test-server"
- `tools`: Array with one default mock tool
- `callTool`: Jest mock returning success response
- `config`: Default assessment configuration

**Example**:

```typescript
const context = createMockAssessmentContext();

// With custom tools
const contextWithTools = createMockAssessmentContext({
  tools: [createMockTool({ name: "custom-tool" })],
});
```

---

### createMockAssessmentConfig

Creates a mock AssessmentConfiguration.

```typescript
function createMockAssessmentConfig(
  overrides?: Partial<AssessmentConfiguration>,
): AssessmentConfiguration;
```

**Parameters**:

- `overrides` - Optional partial configuration

**Returns**: AssessmentConfiguration with testing defaults

**Default Values**:

- `testTimeout`: 5000
- `skipBrokenTools`: true
- `enableExtendedAssessment`: false
- `parallelTesting`: false
- `maxParallelTests`: 3
- `enableDomainTesting`: true

---

### createMockCallToolResponse

Creates a mock CompatibilityCallToolResult.

```typescript
function createMockCallToolResponse(
  content: string,
  isError?: boolean,
): CompatibilityCallToolResult;
```

**Parameters**:

- `content` - Text content for the response
- `isError` - Whether the response represents an error (default: false)

**Example**:

```typescript
const success = createMockCallToolResponse("Operation completed");
const error = createMockCallToolResponse("Error occurred", true);
```

---

### createMockTools

Creates an array of mock tools with sequential naming.

```typescript
function createMockTools(count: number): Tool[];
```

**Parameters**:

- `count` - Number of tools to create

**Returns**: Array of tools named "tool-0", "tool-1", etc.

---

### createMockServerInfo

Creates a mock server info object.

```typescript
function createMockServerInfo(): {
  name: string;
  version: string;
  metadata: { capabilities: string[] };
};
```

---

### createMockPackageJson

Creates a mock package.json content object.

```typescript
function createMockPackageJson(): Record<string, unknown>;
```

**Returns**: Object with standard package.json fields including:

- `name`: "test-package"
- `version`: "1.0.0"
- `dependencies`: { express, axios }
- `devDependencies`: { jest, typescript }

---

### createMockReadmeContent

Creates mock README markdown content.

```typescript
function createMockReadmeContent(): string;
```

**Returns**: A complete README template with description, installation, usage, API, and security sections.

---

## MCP Directory Compliance Utilities

These utilities support testing MCP Directory compliance assessors.

### createMockToolWithAnnotations

Creates a tool with MCP tool annotations.

```typescript
function createMockToolWithAnnotations(overrides?: {
  name?: string;
  description?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}): Tool;
```

**Example**:

```typescript
const readOnlyTool = createMockToolWithAnnotations({
  name: "get_data",
  readOnlyHint: true,
});

const destructiveTool = createMockToolWithAnnotations({
  name: "delete_file",
  destructiveHint: true,
});
```

---

### createMockManifestJson

Creates a mock MCPB manifest.json schema.

```typescript
function createMockManifestJson(
  overrides?: Partial<ManifestJsonSchema>,
): ManifestJsonSchema;
```

**Default Values**:

- `manifest_version`: "0.3"
- `name`: "test-mcp-server"
- `version`: "1.0.0"
- `author`: "Test Author"
- `mcp_config`: Standard command configuration

---

### createMockSourceCodeFiles

Creates a Map of mock source code files.

```typescript
function createMockSourceCodeFiles(
  files?: Record<string, string>,
): Map<string, string>;
```

**Default Files**:

- `src/index.ts`: Basic MCP server implementation
- `package.json`: Standard package.json content

**Example**:

```typescript
// Add custom files
const files = createMockSourceCodeFiles({
  "src/tools.ts": "export const tools = [];",
});
```

---

### createMockAssessmentContextWithSource

Creates context with source code analysis enabled.

```typescript
function createMockAssessmentContextWithSource(
  overrides?: Partial<AssessmentContext>,
): AssessmentContext;
```

**Returns**: Context with:

- `sourceCodePath` set
- `sourceCodeFiles` populated
- `enableExtendedAssessment`: true
- `enableSourceCodeAnalysis`: true
- All assessment categories enabled

---

### createMockPackageJsonWithProhibited

Creates package.json with specified prohibited libraries.

```typescript
function createMockPackageJsonWithProhibited(
  libraries: string[],
): Record<string, unknown>;
```

**Example**:

```typescript
const pkg = createMockPackageJsonWithProhibited(["puppeteer", "selenium"]);
```

---

### createMockReadmeWithAUPViolation

Creates README content containing AUP violation patterns.

```typescript
function createMockReadmeWithAUPViolation(
  violationType:
    | "weapons"
    | "malware"
    | "surveillance"
    | "harassment"
    | "fraud",
): string;
```

**Use Case**: Testing AUP compliance detection.

---

## Security Testing Utilities

### expectSecureStatus

Helper function to validate security assessment results with test validity warnings.

```typescript
function expectSecureStatus(result: {
  status: string;
  testValidityWarning?: string;
}): void;
```

**Parameters**:

- `result` - Security assessment result with status and optional testValidityWarning

**Behavior**:

- If `status === "NEED_MORE_INFO"`: Expects `testValidityWarning` to be defined
- Otherwise: Expects `status === "PASS"`

**Purpose**: Handles the common pattern where uniform mock responses trigger test validity warnings in security assessments. This prevents false negatives in tests when a tool is secure but the test data was insufficient.

**Example**:

```typescript
import { expectSecureStatus } from "@/test/utils/testUtils";

const result = await assessor.assess(context);
expectSecureStatus(result);
// Passes if result.status is PASS, or if NEED_MORE_INFO with testValidityWarning
```

---

## Temporal Assessment Utilities

These utilities are optimized for testing the TemporalAssessor module.

### getPrivateMethod

Access private methods via reflection for unit testing.

```typescript
function getPrivateMethod<T, M>(instance: T, methodName: string): M;
```

**Parameters**:

- `instance` - The class instance containing the private method
- `methodName` - Name of the private method to access

**Returns**: The method bound to the instance (preserves `this` context)

**Example**:

```typescript
const assessor = new TemporalAssessor(config);
const analyzeResponses = getPrivateMethod(assessor, "analyzeResponses");
const result = analyzeResponses(tool, responses);
```

**Notes**:

- Binds method to instance to preserve `this` context
- Returns the value as-is if not a function (for accessing private properties)
- Use for unit testing internal logic; prefer public API for integration tests

---

### createTemporalTestConfig

Creates AssessmentConfiguration optimized for temporal testing.

```typescript
function createTemporalTestConfig(
  overrides?: Partial<AssessmentConfiguration>,
): AssessmentConfiguration;
```

**Default Values** (optimized for fast tests):

- `testTimeout`: 5000
- `skipBrokenTools`: false
- `delayBetweenTests`: 0
- `assessmentCategories.temporal`: true (others false)
- `temporalInvocations`: 5

**Also exported as**: `createConfig`

---

### createTemporalTestTool

Creates a minimal mock tool for temporal testing.

```typescript
function createTemporalTestTool(
  name: string,
  schema?: Record<string, unknown>,
): Tool;
```

**Parameters**:

- `name` - Tool name (required)
- `schema` - Optional inputSchema overrides

**Also exported as**: `createTool`

---

### createTemporalMockContext

Creates a lightweight mock context for temporal testing.

```typescript
function createTemporalMockContext(
  tools: Tool[],
  callToolFn: (name: string, args: unknown) => Promise<unknown>,
): AssessmentContext;
```

**Parameters**:

- `tools` - Array of tools for the context
- `callToolFn` - Custom callTool implementation

**Also exported as**: `createMockContext`

---

## Convenience Aliases

For temporal testing, shorter aliases are available:

| Full Name                   | Alias               |
| --------------------------- | ------------------- |
| `createTemporalTestConfig`  | `createConfig`      |
| `createTemporalTestTool`    | `createTool`        |
| `createTemporalMockContext` | `createMockContext` |

Import directly:

```typescript
import {
  createConfig,
  createTool,
  createMockContext,
} from "@/test/utils/testUtils";
```

---

## Usage Examples

### Basic Assessor Test Setup

```typescript
import {
  createMockAssessmentContext,
  createMockTool,
} from "@/test/utils/testUtils";

describe("MyAssessor", () => {
  let context: AssessmentContext;

  beforeEach(() => {
    context = createMockAssessmentContext({
      tools: [
        createMockTool({ name: "tool1" }),
        createMockTool({ name: "tool2" }),
      ],
    });
  });

  it("assesses tools correctly", async () => {
    const assessor = new MyAssessor(context.config);
    const result = await assessor.assess(context);
    expect(result).toBeDefined();
  });
});
```

### Private Method Unit Testing

```typescript
import { getPrivateMethod, createConfig } from "@/test/utils/testUtils";

describe("TemporalAssessor - Internal Methods", () => {
  let assessor: TemporalAssessor;
  let analyzeResponses: (tool: Tool, responses: unknown[]) => AnalysisResult;

  beforeEach(() => {
    assessor = new TemporalAssessor(createConfig());
    analyzeResponses = getPrivateMethod(assessor, "analyzeResponses");
  });

  it("detects response deviation", () => {
    const tool = createTool("test-tool");
    const responses = [{ data: "a" }, { data: "b" }];
    const result = analyzeResponses(tool, responses);
    expect(result.hasDeviation).toBe(true);
  });
});
```

### Custom Mock Responses

```typescript
import { createTool, createMockContext } from "@/test/utils/testUtils";

const tools = [createTool("get_weather")];
let invocationCount = 0;

const context = createMockContext(tools, async (name, args) => {
  invocationCount++;
  if (invocationCount > 3) {
    return { error: "Rate limited" };
  }
  return { temperature: 72, unit: "F" };
});
```

### Testing MCP Directory Compliance

```typescript
import {
  createMockAssessmentContextWithSource,
  createMockToolWithAnnotations,
  createMockManifestJson,
} from "@/test/utils/testUtils";

describe("ToolAnnotationAssessor", () => {
  it("detects missing annotations on destructive tools", async () => {
    const context = createMockAssessmentContextWithSource({
      tools: [
        createMockToolWithAnnotations({
          name: "delete_file",
          destructiveHint: undefined, // Missing annotation
        }),
      ],
      manifest: createMockManifestJson(),
    });

    const assessor = new ToolAnnotationAssessor(context.config);
    const result = await assessor.assess(context);

    expect(result.missingAnnotations).toContain("destructiveHint");
  });
});
```

---

## Related Documentation

- [Test Organization Pattern](TEST_ORGANIZATION_PATTERN.md) - How to structure test files
- [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Writing assessment modules
