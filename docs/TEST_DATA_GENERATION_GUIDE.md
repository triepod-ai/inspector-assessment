# Test Data Generation Guide

## Overview

The MCP Inspector's **TestDataGenerator** is a sophisticated system for automatically generating realistic, context-aware test data based on JSON Schema definitions. This guide explains how it works, how to extend it, and how to troubleshoot common issues.

The generator intelligently creates test scenarios across multiple categories (happy path, edge cases, boundary testing, and error cases) to comprehensively test MCP tool implementations without requiring manual test data creation.

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

## 5. Scenario Categories

### Happy Path Scenario

**Purpose**: Test normal usage with realistic, typical input

**Generation**:

```typescript
private static generateHappyPathScenario(tool: Tool): TestScenario {
  const params = this.generateRealisticParams(tool, "typical");

  return {
    name: "Happy Path - Typical Usage",
    description: `Test ${tool.name} with typical, valid inputs`,
    params,
    expectedBehavior: "Should execute successfully and return valid response",
    category: "happy_path",
  };
}
```

**Data Variant**: `"typical"` - realistic, commonly-used values

**Expectations**: Tool should succeed and return meaningful results

### Edge Case Scenarios

**Purpose**: Test with unusual but valid input

**Generated**:

1. **Empty Values**: Minimal but valid input

   ```typescript
   const emptyParams = this.generateRealisticParams(tool, "empty");
   ```

2. **Maximum Values**: Large but valid input

   ```typescript
   const maxParams = this.generateRealisticParams(tool, "maximum");
   ```

3. **Special Characters**: Unicode and special character handling
   ```typescript
   const specialParams = this.generateRealisticParams(tool, "special");
   ```

**Expectations**: Tool should gracefully handle these edge cases

### Boundary Scenarios

**Purpose**: Test exact schema constraints (if defined)

**Generated When**: Tool schema has `minimum`, `maximum`, `minLength`, or `maxLength`

**Examples**:

- Number at minimum value
- Number at maximum value
- String at minimum length
- String at maximum length

**Expectations**: Tool should accept values exactly at boundaries

### Error Case Scenario

**Purpose**: Test error handling with invalid input types

**Generation**:

```typescript
private static generateErrorScenario(tool: Tool): TestScenario {
  const params: Record<string, unknown> = {};

  // Intentionally provide wrong types
  for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
    const schemaObj = schema as any;

    switch (schemaObj.type) {
      case "string":
        params[key] = 123; // Wrong type (number instead of string)
        break;
      case "number":
      case "integer":
        params[key] = "not_a_number"; // Wrong type (string instead of number)
        break;
      // ... more type mismatches
    }

    break; // Only set one wrong parameter to make error clear
  }

  return {
    name: "Error Case - Invalid Type",
    description: "Test error handling with invalid parameter types",
    params,
    expectedBehavior: "Should return clear error about invalid parameter type",
    category: "error_case",
  };
}
```

**Expectations**: Tool should reject with clear error message (not crash)

---

## 6. Tool Category-Aware Generation

### Category Detection

For tools where field names don't clearly indicate the expected input type, the generator uses tool category hints:

```typescript
static readonly TOOL_CATEGORY_DATA: Record<string, Record<string, string[]>> = {
  calculator: {
    default: ["2+2", "10*5", "100/4", "sqrt(16)", "15-7"],
  },
  search_retrieval: {
    default: [
      "hello world",
      "example query",
      "recent changes",
      "find documents",
    ],
  },
  system_exec: {
    default: ["echo hello", "pwd", "date", "whoami"],
  },
  url_fetcher: {
    default: [
      "https://api.github.com",
      "https://httpbin.org/get",
      "https://jsonplaceholder.typicode.com/posts/1",
    ],
  },
};
```

### Priority System

**Specific Field Names** (highest priority):

- Field name patterns like `url`, `email`, `path`, etc. take precedence over tool category
- Example: A `calculator_tool` with a field named `email_address` will get email-specific values

**Tool Categories** (second priority):

- If field name is generic (like `input`, `params`, `query`), use category-specific values
- Example: A `search_retrieval` tool with a field named `input` gets search queries

**Field Name Fallback** (lowest priority):

- Generic field name with unknown tool category uses standard field-name heuristics
- Example: Generic `calculate` tool with `input` field gets generic "test" value

**Usage**:

```typescript
static generateValueForCategory(
  fieldName: string,
  schema: Record<string, unknown>,
  category: string,
): unknown {
  // Specific field names (url, email, path, etc.) take precedence
  const isSpecificFieldName = this.SPECIFIC_FIELD_PATTERNS.some((pattern) =>
    pattern.test(fieldName),
  );
  if (isSpecificFieldName) {
    return this.generateSingleValue(fieldName, schema);
  }

  // For specific tool categories, use category-specific test values
  const categoryData = this.TOOL_CATEGORY_DATA[category];
  if (categoryData?.default) {
    return categoryData.default[0];
  }

  // Fall back to field-name-based generation
  return this.generateSingleValue(fieldName, schema);
}
```

---

## 7. Adding New Field Type Handlers

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

## 8. Common Issues and Debugging

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
variant === "special" ? "Spécial™ chârs: !@#$%^&*() 中文 العربية 😀🎉" : "test";
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

## 9. Integration with Test Scenario Engine

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

## 10. Performance Considerations

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

## 11. Examples

### Example 1: Simple Calculator Tool

```typescript
const calculatorTool: Tool = {
  name: "calculate",
  description: "Performs basic math",
  inputSchema: {
    type: "object",
    properties: {
      expression: {
        type: "string",
        description: "Math expression to evaluate",
      },
      decimal_places: {
        type: "number",
        minimum: 0,
        maximum: 10,
        description: "Decimal precision",
      },
    },
    required: ["expression"],
  },
};

// Generated scenarios:
[
  {
    name: "Happy Path - Typical Usage",
    params: { expression: "2+2", decimal_places: 2 },
    category: "happy_path",
  },
  {
    name: "Edge Case - Empty Values",
    params: { expression: "" }, // or "test"
    category: "edge_case",
  },
  {
    name: "Edge Case - Maximum Values",
    params: { expression: "x".repeat(100), decimal_places: 10 },
    category: "edge_case",
  },
  {
    name: "Edge Case - Special Characters",
    params: { expression: "sqrt(-1) + log(0)" },
    category: "edge_case",
  },
  {
    name: "Boundary - decimal_places at minimum",
    params: { expression: "test", decimal_places: 0 },
    category: "boundary",
  },
  {
    name: "Boundary - decimal_places at maximum",
    params: { expression: "test", decimal_places: 10 },
    category: "boundary",
  },
  {
    name: "Error Case - Invalid Type",
    params: { expression: 123 }, // Wrong type: number instead of string
    category: "error_case",
  },
];
```

### Example 2: Web Scraper Tool with URL

```typescript
const scraperTool: Tool = {
  name: "scrape_web",
  description: "Fetches and parses web content",
  inputSchema: {
    type: "object",
    properties: {
      url: {
        type: "string",
        description: "URL to scrape",
        minLength: 10,
        maxLength: 2000,
      },
      timeout_ms: {
        type: "number",
        minimum: 100,
        maximum: 30000,
      },
    },
    required: ["url", "timeout_ms"],
  },
};

// Generated scenarios:
[
  {
    name: "Happy Path - Typical Usage",
    params: {
      url: "https://www.google.com", // From REALISTIC_DATA.urls
      timeout_ms: 5000, // Detected as timeout field
    },
    category: "happy_path",
  },
  {
    name: "Edge Case - Empty Values",
    params: {
      url: "", // Empty variant
      timeout_ms: 100,
    },
    category: "edge_case",
  },
  {
    name: "Edge Case - Maximum Values",
    params: {
      url: "https://very-long-domain-name...", // maxLength variant
      timeout_ms: 30000,
    },
    category: "edge_case",
  },
  {
    name: "Boundary - url at min length",
    params: {
      url: "aaaaaaaaaa", // Exactly 10 'a' characters
      timeout_ms: 5000,
    },
    category: "boundary",
  },
  {
    name: "Boundary - url at max length",
    params: {
      url: "a".repeat(2000), // Exactly 2000 'a' characters
      timeout_ms: 5000,
    },
    category: "boundary",
  },
  {
    name: "Boundary - timeout_ms at minimum",
    params: {
      url: "https://example.com",
      timeout_ms: 100,
    },
    category: "boundary",
  },
  {
    name: "Boundary - timeout_ms at maximum",
    params: {
      url: "https://example.com",
      timeout_ms: 30000,
    },
    category: "boundary",
  },
  {
    name: "Error Case - Invalid Type",
    params: {
      url: 123, // Wrong type
      timeout_ms: 5000,
    },
    category: "error_case",
  },
];
```

### Example 3: Nested Object with Arrays

```typescript
const dataStoreTool: Tool = {
  name: "store_entities",
  description: "Stores data entities",
  inputSchema: {
    type: "object",
    properties: {
      entities: {
        type: "array",
        items: {
          type: "object",
          properties: {
            id: {
              type: "string",
              description: "Entity UUID"
            },
            name: {
              type: "string",
              minLength: 1,
              maxLength: 100
            },
            metadata: {
              type: "object",
              properties: {
                created_at: { type: "string" },
                tags: {
                  type: "array",
                  items: { type: "string" }
                }
              }
            }
          },
          required: ["id", "name"]
        },
        minItems: 1,
        maxItems: 50
      }
    },
    required: ["entities"]
  }
};

// Happy path scenario:
{
  name: "Happy Path - Typical Usage",
  params: {
    entities: [
      {
        id: "550e8400-e29b-41d4-a716-446655440000", // UUID detected
        name: "Default", // From names pool
        metadata: {
          created_at: "2024-01-01T00:00:00Z", // Timestamp pool
          tags: ["tag1", "tag2", "tag3"] // Context-aware array
        }
      }
    ]
  },
  category: "happy_path"
}

// Boundary scenario (maxItems):
{
  name: "Boundary - entities at maximum",
  params: {
    entities: Array(50).fill({
      id: "550e8400-e29b-41d4-a716-446655440000",
      name: "Item",
      metadata: { tags: [] }
    })
  },
  category: "boundary"
}
```

---

## 12. Testing Your Implementation

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

## 13. Best Practices

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
