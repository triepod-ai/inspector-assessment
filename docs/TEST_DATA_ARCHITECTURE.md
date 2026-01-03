# Test Data Architecture Guide

> **Part of the Test Data Generation documentation series:**
>
> - **Architecture** (this document) - Core architecture, field handlers, boundaries
> - [Scenarios](TEST_DATA_SCENARIOS.md) - Scenario categories, tool-aware generation, examples
> - [Extension](TEST_DATA_EXTENSION.md) - Adding handlers, debugging, integration

## Overview

The MCP Inspector's **TestDataGenerator** is a sophisticated system for automatically generating realistic, context-aware test data based on JSON Schema definitions. This guide explains the core architecture and field type handlers.

The generator intelligently creates test scenarios across multiple categories (happy path, edge cases, boundary testing, and error cases) to comprehensively test MCP tool implementations without requiring manual test data creation.

---

## Table of Contents

- [Overview](#overview)
- [1. Generator Architecture Overview](#1-generator-architecture-overview)
  - [High-Level Flow](#high-level-flow)
  - [Key Components](#key-components)
- [2. Field Type Handlers](#2-field-type-handlers)
  - [String Handler](#string-handler)
  - [Number/Integer Handler](#numberinteger-handler)
  - [Boolean Handler](#boolean-handler)
  - [Array Handler](#array-handler)
  - [Object Handler](#object-handler)
  - [Enum Handler](#enum-handler)
- [3. Boundary Testing](#3-boundary-testing)
  - [Detection Logic](#detection-logic)
  - [Numeric Boundaries](#numeric-boundaries)
  - [String Length Boundaries](#string-length-boundaries)
- [4. Realistic Data Sources](#4-realistic-data-sources)
  - [REALISTIC_DATA Pool](#realistic_data-pool)
  - [Value Selection Logic](#value-selection-logic)

---

## 1. Generator Architecture Overview

### High-Level Flow

```
Tool (with inputSchema)
    ↓
TestDataGenerator.generateTestScenarios(tool)
    ↓
    ├─→ generateHappyPathScenario() → "typical" variant
    ├─→ generateEdgeCaseScenarios() → "empty", "maximum", "special" variants
    ├─→ generateBoundaryScenarios() → min/max value testing
    └─→ generateErrorScenario() → type mismatch testing
    ↓
TestScenario[]
    ↓
TestScenarioEngine.testToolComprehensively()
    ↓
ScenarioTestResult[]
```

### Key Components

#### 1. **TestDataGenerator** (`TestDataGenerator.ts`)

The core class responsible for:

- JSON Schema parsing and interpretation
- Field name analysis for context-aware generation
- Multi-variant generation (typical, empty, maximum, special)
- Boundary constraint detection and testing

#### 2. **TestScenarioEngine** (`TestScenarioEngine.ts`)

The orchestrator that:

- Calls TestDataGenerator to create scenarios
- Executes each scenario against actual tools
- Validates responses using ResponseValidator
- Aggregates results into comprehensive test reports

#### 3. **JSON Schema Parsing**

The generator parses JSON Schema using the standard `type` field and constraint properties:

```typescript
// Example Schema
{
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "description": "User email address"
    },
    "age": {
      "type": "number",
      "minimum": 0,
      "maximum": 150
    },
    "tags": {
      "type": "array",
      "items": { "type": "string" },
      "minItems": 1,
      "maxItems": 10
    }
  },
  "required": ["email"]
}
```

#### 4. **Field Type Detection**

Two-tier detection system:

1. **Explicit Schema Type**: Uses the `type` field (string, number, boolean, array, object)
2. **Field Name Heuristics**: Analyzes field names for semantic meaning
   - `email`, `mail` → email format
   - `url`, `link`, `endpoint` → URL format
   - `path`, `file`, `directory`, `folder` → file path format
   - `id`, `key`, `identifier` → identifier format
   - `uuid` → universally unique identifier
   - `name`, `title`, `label` → descriptive text
   - `date`, `time` → timestamp format
   - `query`, `search`, `filter` → search query
   - `port` → port number (typically 8080)
   - `timeout`, `delay` → milliseconds
   - `count`, `limit` → numeric count
   - `page`, `offset` → pagination numbers

---

## 2. Field Type Handlers

Each field type has specialized handler logic for generating realistic test values.

### String Handler

**Location**: `TestDataGenerator.ts`, lines 479-624

**Core Logic**:

```typescript
case "string":
  // 1. Check for enums first
  if (schema.enum && schema.enum.length > 0) {
    return schema.enum[0]; // Pick first enum value
  }

  // 2. Context-aware generation based on field name
  if (lowerFieldName.includes("url") || ...) {
    // URL-specific logic
  } else if (lowerFieldName.includes("email") || ...) {
    // Email-specific logic
  } else if (lowerFieldName.includes("path") || ...) {
    // Path-specific logic
  }
  // ... more field name patterns

  // 3. Default fallback
  return "test";
```

**String Variants**:

| Variant   | Example                                       | Use Case                   |
| --------- | --------------------------------------------- | -------------------------- |
| `typical` | `https://www.google.com`                      | Normal usage               |
| `empty`   | `""`                                          | Empty value handling       |
| `maximum` | Very long URL with many parameters            | Length boundary testing    |
| `special` | `https://example.com/path?special=!@#$%^&*()` | Special character handling |

**Realistic Data Pools** (lines 42-134):

```typescript
urls: [
  "https://www.google.com",
  "https://api.github.com/users/octocat",
  "https://jsonplaceholder.typicode.com/posts/1",
  // ... 4 more realistic, stable URLs
];

emails: [
  "admin@example.com",
  "support@example.com",
  // ... 5 more common patterns
];

paths: [
  "/tmp/test.txt",
  "./README.md",
  "./package.json",
  // ... 6 more common project paths
];
```

**Special Handling for Query/Search Fields** (lines 538-554):

```typescript
if (lowerFieldName.includes("query") ||
    lowerFieldName.includes("search") ||
    lowerFieldName.includes("filter")) {

  // For "empty" variant, use "test" instead of ""
  // This ensures search tools have valid test input
  // Empty searches are often not meaningful for testing
  return variant === "empty" ? "test" : ...
}
```

### Number/Integer Handler

**Location**: `TestDataGenerator.ts`, lines 626-665

**Core Logic**:

```typescript
case "number":
case "integer":
  if (variant === "maximum") {
    return schema.maximum || 999999; // Use schema max if defined
  }
  if (variant === "empty") {
    return schema.minimum || 0; // Use schema min if defined
  }

  // Context-aware generation
  if (lowerFieldName.includes("port")) {
    return 8080; // Standard web server port
  }
  if (lowerFieldName.includes("timeout") || lowerFieldName.includes("delay")) {
    return 5000; // 5 seconds in milliseconds
  }
  if (lowerFieldName.includes("count") || lowerFieldName.includes("limit")) {
    return 10; // Common pagination limit
  }
  if (lowerFieldName.includes("page") || lowerFieldName.includes("offset")) {
    return 0; // First page/zero offset
  }
  if (lowerFieldName.includes("size") || lowerFieldName.includes("length")) {
    return 100; // Common size value
  }

  return schema.minimum || 1; // Safe default
```

**Examples**:

- `port: 5432` → `8080` (typical web server port)
- `timeout: undefined` → `5000` (5 seconds)
- `page_number: undefined` → `0` (first page)
- `count: {minimum: 0, maximum: 100}` → `100` (for maximum variant)

### Boolean Handler

**Location**: `TestDataGenerator.ts`, lines 666-667

**Logic**:

```typescript
case "boolean":
  return variant === "empty" ? false : true;
```

**Variants**:

- `typical` → `true`
- `empty` → `false`
- `maximum` → `true` (same as typical)
- `special` → `true` (same as typical)

### Array Handler

**Location**: `TestDataGenerator.ts`, lines 669-718

**Special Logic**:

Arrays have special handling for mutation tools (tools that modify data):

```typescript
case "array":
  if (variant === "empty") {
    // Check if this is a mutation field
    const isMutationField =
      lowerFieldName.includes("entities") ||
      lowerFieldName.includes("relations") ||
      lowerFieldName.includes("observations") ||
      lowerFieldName.includes("documents");

    if (isMutationField && schema.items) {
      // For mutation tools, generate at least one item
      // An empty array is valid but useless for testing
      const item = this.generateValueFromSchema(schema.items, "empty");
      return [item];
    }
    return [];
  }

  if (variant === "maximum") {
    // Generate multiple items (up to 10)
    const count = 10;
    if (schema.items) {
      return Array(count)
        .fill(0)
        .map(() => this.generateValueFromSchema(schema.items, variant));
    }
    return Array(count).fill(0).map((_, i) => `item_${i}`);
  }

  // Typical variant: generate 1-2 items
  if (schema.items) {
    const item = this.generateValueFromSchema(schema.items, variant);
    return [item];
  }
```

**Variants**:

| Variant   | Example                                       | Items                          |
| --------- | --------------------------------------------- | ------------------------------ |
| `typical` | `[{id: 1, name: "Test"}]`                     | 1 item                         |
| `empty`   | `[]` (or `[minimal_item]` for mutation tools) | 0 or 1                         |
| `maximum` | 10 items                                      | 10                             |
| `special` | `[item_with_special_chars]`                   | 1+ items with special handling |

**Context-Aware Array Generation** (lines 707-718):

```typescript
// Context-aware array generation (fallback for simple arrays without schema.items)
if (lowerFieldName.includes("tag") || lowerFieldName.includes("label")) {
  return ["tag1", "tag2", "tag3"];
}
if (lowerFieldName.includes("id")) {
  return ["id_1", "id_2", "id_3"];
}
```

### Object Handler

**Location**: `TestDataGenerator.ts`, lines 720-760

**Logic**:

```typescript
case "object":
  // For maximum variant, return deeply nested structure
  if (variant === "maximum") {
    return this.REALISTIC_DATA.jsonObjects[4]; // Deeply nested
  }

  // Context-aware object generation
  if (lowerFieldName.includes("config") || lowerFieldName.includes("settings")) {
    return variant === "empty"
      ? { enabled: false }
      : { enabled: true, timeout: 5000, retries: 3 };
  }

  if (lowerFieldName.includes("metadata") || lowerFieldName.includes("meta")) {
    return variant === "empty"
      ? { version: "1.0.0" }
      : {
          created: new Date().toISOString(),
          version: "1.0.0",
          author: "test"
        };
  }

  if (lowerFieldName.includes("filter") || lowerFieldName.includes("query")) {
    return variant === "empty"
      ? { limit: 1 }
      : { status: "active", type: "user", limit: 10 };
  }

  // Default fallback
  return variant === "empty"
    ? { id: 1 }
    : { message: "Hello World" };
```

**Special Handling**: Objects are recursively processed:

```typescript
case "object": {
  const obj: Record<string, unknown> = {};
  if (schema.properties) {
    for (const [key, propSchema] of Object.entries(schema.properties)) {
      // Recursively generate values for nested properties
      obj[key] = this.generateRealisticValue(
        key,
        propSchema as any,
        variant,
      );
    }
  }
  return obj;
}
```

### Enum Handler

**Location**: `TestDataGenerator.ts`, lines 480-485

**Logic**:

```typescript
// Check for enums first (before other string handling)
if (schema.enum && schema.enum.length > 0) {
  return variant === "typical"
    ? schema.enum[0] // First value for typical
    : schema.enum[schema.enum.length - 1]; // Last value for other variants
}
```

**Example**:

```typescript
// Schema
{ type: "string", enum: ["red", "green", "blue"] }

// Generated values
typical → "red"
special → "blue"
maximum → "blue"
empty   → "blue"
```

---

## 3. Boundary Testing

### Overview

Boundary testing generates scenarios that test schema constraints (minimum, maximum, minLength, maxLength, minItems, maxItems).

**Key Optimization** (v1.17.1): Only generates boundary tests when constraints are actually defined, avoiding unnecessary test scenarios.

### Detection Logic

```typescript
// Check if any fields have boundary constraints
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

// Early return if no boundaries defined
if (!hasBoundaries) {
  return scenarios; // Empty array, saves test generation
}
```

### Numeric Boundaries

**Generates**: Minimum and maximum value scenarios

```typescript
// Test numeric boundaries
if (schemaObj.type === "number" || schemaObj.type === "integer") {
  if (schemaObj.minimum !== undefined) {
    const params = this.generateRealisticParams(tool, "typical");
    params[key] = schemaObj.minimum; // Set to minimum
    scenarios.push({
      name: `Boundary - ${key} at minimum`,
      description: `Test ${key} at its minimum value`,
      params,
      expectedBehavior: "Should accept minimum value",
      category: "boundary",
    });
  }

  if (schemaObj.maximum !== undefined) {
    const params = this.generateRealisticParams(tool, "typical");
    params[key] = schemaObj.maximum; // Set to maximum
    scenarios.push({
      name: `Boundary - ${key} at maximum`,
      description: `Test ${key} at its maximum value`,
      params,
      expectedBehavior: "Should accept maximum value",
      category: "boundary",
    });
  }
}
```

**Example**:

```typescript
// Schema
{
  type: "object",
  properties: {
    age: { type: "number", minimum: 0, maximum: 150 }
  }
}

// Generated boundary scenarios
[
  {
    name: "Boundary - age at minimum",
    params: { age: 0 },
    category: "boundary"
  },
  {
    name: "Boundary - age at maximum",
    params: { age: 150 },
    category: "boundary"
  }
]
```

### String Length Boundaries

**Generates**: Minimum and maximum length scenarios

```typescript
if (schemaObj.type === "string") {
  if (schemaObj.minLength !== undefined) {
    const params = this.generateRealisticParams(tool, "typical");
    params[key] = "a".repeat(schemaObj.minLength); // Repeat to exact length
    scenarios.push({
      name: `Boundary - ${key} at min length`,
      description: `Test ${key} at minimum length`,
      params,
      expectedBehavior: "Should accept minimum length string",
      category: "boundary",
    });
  }

  if (schemaObj.maxLength !== undefined) {
    const params = this.generateRealisticParams(tool, "typical");
    params[key] = "a".repeat(schemaObj.maxLength); // Repeat to exact length
    scenarios.push({
      name: `Boundary - ${key} at max length`,
      description: `Test ${key} at maximum length`,
      params,
      expectedBehavior: "Should accept maximum length string",
      category: "boundary",
    });
  }
}
```

**Example**:

```typescript
// Schema
{
  type: "object",
  properties: {
    username: {
      type: "string",
      minLength: 3,
      maxLength: 20
    }
  }
}

// Generated boundary scenarios
[
  {
    name: "Boundary - username at min length",
    params: { username: "aaa" }, // 3 'a' characters
    category: "boundary"
  },
  {
    name: "Boundary - username at max length",
    params: { username: "aaaaaaaaaaaaaaaaaaaa" }, // 20 'a' characters
    category: "boundary"
  }
]
```

### Boundary Test Results

All boundary test results are stored with:

- `scenarioResults` array containing each boundary test
- `summary.boundariesTotal` → total boundary scenarios
- `summary.boundariesRespected` → boundary scenarios that passed

---

## 4. Realistic Data Sources

### REALISTIC_DATA Pool

The generator maintains a pool of real, stable test values:

```typescript
private static readonly REALISTIC_DATA = {
  urls: [
    "https://www.google.com",        // Always accessible
    "https://api.github.com/users/octocat", // Public API endpoint
    "https://jsonplaceholder.typicode.com/posts/1", // Test API
    "https://httpbin.org/get",       // HTTP testing service
    "https://example.com",           // RFC 2606 reserved domain
    "https://www.wikipedia.org",     // Public, stable site
    "https://api.openweathermap.org/data/2.5/weather?q=London", // Public API
  ],

  emails: [
    "admin@example.com",             // Common admin pattern
    "support@example.com",           // Common support pattern
    "info@example.com",              // Common info pattern
    "test@test.com",                 // Generic test email
    "user@domain.com",               // Generic user email
    "noreply@example.com",           // Common no-reply format
    "hello@world.com",               // Simple, memorable
  ],

  names: [
    "Default",
    "Admin",
    "Test User",
    "Sample Item",
    "Example Project",
    "Demo Application",
    "Main",
  ],

  ids: [
    "1",                             // Simple numeric ID
    "123",                           // Common test ID
    "550e8400-e29b-41d4-a716-446655440000", // Valid UUID v4
    "default",                       // Common default ID
    "main",                          // Common main ID
    "264051cd-48ab-80ff-864e-d1aa9bc41429", // Valid UUID
    "00000000-0000-0000-0000-000000000000", // Nil UUID
    "admin",                         // Common admin ID
    "user1",                         // Common user ID pattern
  ],

  paths: [
    "/tmp/test.txt",                 // Common temp file (usually writable)
    "/home",                         // Common home directory
    "./README.md",                   // Often exists in projects
    "./package.json",                // Common in Node projects
    "./src",                         // Common source directory
    "./test",                        // Common test directory
    "./config",                      // Common config directory
    "/var/log",                      // Common log directory (readable)
    "/etc",                          // Common config directory (readable)
  ],

  timestamps: [
    new Date().toISOString(),        // Current time (always valid)
    new Date(Date.now() - 86400000).toISOString(), // Yesterday
    new Date(Date.now() + 86400000).toISOString(), // Tomorrow
    "2024-01-01T00:00:00Z",          // New Year 2024
    "2023-12-31T23:59:59Z",          // End of 2023
    new Date(0).toISOString(),       // Unix epoch
    "2024-06-15T12:00:00Z",          // Midday mid-year
  ],

  queries: [
    "test",                          // Simple search term
    "hello",                         // Common greeting
    "*",                             // Wildcard matching everything
    "name",                          // Common field name
    "id:1",                          // Common ID search
    "status:active",                 // Common status filter
    "type:user",                     // Common type filter
    "limit:10",                      // Common pagination
    '{"match_all": {}}',             // Elasticsearch match all
  ],

  // ... more pools
};
```

### Value Selection Logic

The generator randomly selects from these pools using:

```typescript
this.REALISTIC_DATA.urls[
  Math.floor(Math.random() * this.REALISTIC_DATA.urls.length)
];
```

This ensures:

- **Variability**: Different values on each call (good for randomized testing)
- **Realism**: Values that are likely to actually exist or be valid
- **Stability**: All values are tried; no single failure breaks all tests
- **Public Data**: Uses public APIs and RFC-reserved domains to avoid dependencies

### Seed Values for Reproducibility

For reproducible testing, you can modify the selection logic:

```typescript
// Current: Random selection
const pool = this.REALISTIC_DATA.urls;
return pool[Math.floor(Math.random() * pool.length)];

// Reproducible: Use index-based selection
const pool = this.REALISTIC_DATA.urls;
return pool[0]; // Always return first value
```

---

## Related Documentation

- [Test Data Scenarios](TEST_DATA_SCENARIOS.md) - Scenario categories, tool-aware generation, examples
- [Test Data Extension](TEST_DATA_EXTENSION.md) - Adding handlers, debugging, integration
- [Response Validation Guide](RESPONSE_VALIDATION_CORE.md) - Validation after test execution
- [Progressive Complexity Guide](PROGRESSIVE_COMPLEXITY_GUIDE.md) - Multi-level testing strategy
