# Test File Organization Patterns

This document describes the conventions for organizing test files in the inspector-assessment project, particularly for large test suites that benefit from splitting into focused files.

## Overview

As test suites grow, monolithic test files become difficult to maintain. This project uses a **split test file pattern** where large test suites are divided into focused files, each testing a specific feature or concern.

**Benefits**:

- Easier navigation and discovery
- Faster test runs when targeting specific features
- Clear ownership and boundaries
- Reduced merge conflicts
- Better IDE performance

---

## Table of Contents

- [File Naming Convention](#file-naming-convention)
- [When to Split Test Files](#when-to-split-test-files)
- [Test File Header Template](#test-file-header-template)
- [Import Pattern](#import-pattern)
- [Examples](#examples)

---

## File Naming Convention

### Core Test Files

The primary test file uses the assessor name:

```
ModuleName.test.ts
```

**Examples**:

- `SecurityAssessor.test.ts`
- `TemporalAssessor.test.ts`
- `FunctionalityAssessor.test.ts`

### Feature-Focused Split Files

Split files append a feature name with a hyphen:

```
ModuleName-FeatureName.test.ts
```

**Examples**:

- `SecurityAssessor-AuthBypass.test.ts`
- `TemporalAssessor-StatefulTools.test.ts`
- `SecurityAssessor-ReflectionFalsePositives.test.ts`

### Integration Test Files

Tests that hit real servers or external resources use `.integration.test.ts`:

```
ModuleName-*.integration.test.ts
```

**Example**:

- `SecurityAssessor-VulnerableTestbed.integration.test.ts`

### Pattern Summary

| Pattern                        | Purpose                             |
| ------------------------------ | ----------------------------------- |
| `Module.test.ts`               | Core functionality + integration    |
| `Module-Feature.test.ts`       | Focused feature/concern tests       |
| `Module-*.integration.test.ts` | Real server/external resource tests |

---

## When to Split Test Files

### Thresholds

Consider splitting when a test file exceeds:

- **1,500+ lines** - File becomes difficult to navigate
- **100+ test cases** - Too many tests for one file
- **5+ distinct concerns** - Multiple unrelated test groups

### Signs You Should Split

1. **Multiple large `describe` blocks** covering different concerns
2. **Long scroll times** to find specific tests
3. **Different setup requirements** for different test groups
4. **Frequent merge conflicts** in the same file
5. **Test runs take too long** when working on one feature

### What Goes in the Core File

The `Module.test.ts` file should contain:

- **Integration tests** for the main `assess()` method
- **Edge cases** that don't fit other categories
- **Basic unit tests** for public API methods
- **Cross-reference header** listing all related test files

### What Goes in Split Files

Each `Module-Feature.test.ts` file should:

- Focus on **one specific feature** or internal method
- Have a **clear scope** defined in the header
- Reference the **GitHub issue** if applicable
- Be **self-contained** (all setup in beforeEach)

---

## Test File Header Template

### Core Test File Header

```typescript
/**
 * ModuleName Test Suite (Core)
 *
 * Brief description of what this module tests.
 *
 * This is the core test file containing:
 * - methodName1: Description of what's tested
 * - methodName2: Description of what's tested
 * - assess (integration): End-to-end assessment tests
 * - edge cases: Unusual but valid scenarios
 *
 * Related test files:
 * - ModuleName-Feature1.test.ts: Description (XX tests)
 * - ModuleName-Feature2.test.ts: Description (XX tests)
 * - ModuleName-Feature3.test.ts: Description (XX tests)
 */
```

### Split File Header

```typescript
/**
 * ModuleName - Feature Name Tests (Issue #XX)
 *
 * Brief description of the specific feature being tested.
 * Include what vulnerabilities/behaviors are being detected.
 */
```

---

## Import Pattern

### Using Centralized Utilities

Always import from `testUtils.ts` rather than creating local mock factories:

```typescript
// Good - uses centralized utilities
import {
  getPrivateMethod,
  createConfig,
  createTool,
  createMockContext,
} from "@/test/utils/testUtils";

// Bad - duplicates utility code
const createConfig = () => ({ ... });
```

### Importing Convenience Aliases

For temporal testing, use the short aliases:

```typescript
import {
  getPrivateMethod,
  createConfig, // alias for createTemporalTestConfig
  createTool, // alias for createTemporalTestTool
  createMockContext, // alias for createTemporalMockContext
} from "@/test/utils/testUtils";
```

### Type Imports

Import types separately when needed for casting:

```typescript
import { TemporalAssessor } from "../modules/TemporalAssessor";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
```

---

## Examples

### SecurityAssessor Pattern

The SecurityAssessor test suite is split across 7 files:

```
SecurityAssessor.test.ts                          # Core (not shown)
SecurityAssessor-AuthBypass.test.ts               # Auth bypass detection
SecurityAssessor-ReflectionFalsePositives.test.ts # Safe reflection patterns
SecurityAssessor-HTTP404FalsePositives.test.ts    # HTTP 404 handling
SecurityAssessor-APIWrapperFalsePositives.test.ts # API wrapper detection
SecurityAssessor-ValidationFalsePositives.test.ts # Input validation patterns
SecurityAssessor-ClaudeBridge.test.ts             # Claude integration
SecurityAssessor-VulnerableTestbed.integration.test.ts # Real server tests
```

**Split Rationale**:

- Each file tests a specific detection concern
- False positive tests are grouped by pattern type
- Integration tests are clearly separated

### TemporalAssessor Pattern

The TemporalAssessor test suite (213 tests) is split across 6 files:

```
TemporalAssessor.test.ts                         # Core (92 tests)
TemporalAssessor-StatefulTools.test.ts           # Stateful tool handling (31 tests)
TemporalAssessor-SecondaryContent.test.ts        # Rug pull content detection (39 tests)
TemporalAssessor-DefinitionMutation.test.ts      # Definition mutation (13 tests)
TemporalAssessor-VarianceClassification.test.ts  # Resource variance (15 tests)
TemporalAssessor-ResponseNormalization.test.ts   # Response normalization (23 tests)
```

**Split Rationale**:

- Original file was 2,201 lines (too large)
- Each split file focuses on one internal method or concern
- Issue tracking (Issue #7, #69) included in headers
- Test counts documented for verification

### Example Split File Structure

```typescript
/**
 * TemporalAssessor - Stateful Tool Handling Tests
 *
 * Tests for detecting and handling stateful tools (those where content variation is expected).
 * Includes isStatefulTool, extractFieldNames, compareSchemas, and integration tests.
 */

import { TemporalAssessor } from "../modules/TemporalAssessor";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  getPrivateMethod,
  createConfig,
  createTool,
  createMockContext,
} from "@/test/utils/testUtils";

describe("TemporalAssessor - Stateful Tool Handling", () => {
  let assessor: TemporalAssessor;
  let isStatefulTool: (tool: Tool) => boolean;
  let compareSchemas: (r1: unknown, r2: unknown) => boolean;

  beforeEach(() => {
    assessor = new TemporalAssessor(createConfig());
    isStatefulTool = getPrivateMethod(assessor, "isStatefulTool");
    compareSchemas = getPrivateMethod(assessor, "compareSchemas");
  });

  describe("isStatefulTool", () => {
    it.each([
      ["get_current_time", true],
      ["get_weather", true],
      ["list_files", false],
      ["calculate_sum", false],
    ])("classifies %s as stateful=%s", (name, expected) => {
      const tool = createTool(name);
      expect(isStatefulTool(tool)).toBe(expected);
    });
  });

  // ... more tests
});
```

---

## Private Method Testing

### When to Use getPrivateMethod

Use `getPrivateMethod()` for unit testing internal logic that:

- Is complex enough to warrant direct testing
- Has edge cases not easily covered through public API
- Needs isolation from other module behavior

### Pattern

```typescript
let privateMethod: (arg: ArgType) => ReturnType;

beforeEach(() => {
  const instance = new ModuleClass(config);
  privateMethod = getPrivateMethod(instance, "methodName");
});

it("handles edge case", () => {
  const result = privateMethod(edgeCaseInput);
  expect(result).toBe(expectedOutput);
});
```

### Considerations

- Private methods may change - these tests are more brittle
- Prefer public API testing for behavior verification
- Use private method testing for algorithm verification
- Document why direct testing is necessary

---

## CI/CD Considerations

### Running Specific Test Files

```bash
# Run all TemporalAssessor tests
npm test -- TemporalAssessor

# Run specific feature tests
npm test -- TemporalAssessor-StatefulTools

# Run integration tests only
npm test -- integration
```

### Excluding Integration Tests

Integration tests that require running servers can be excluded:

```bash
# Run unit tests only
npm test -- --testPathIgnorePatterns=integration
```

---

## Related Documentation

- [Test Utilities Reference](TEST_UTILITIES_REFERENCE.md) - Mock factory API
- [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating modules
