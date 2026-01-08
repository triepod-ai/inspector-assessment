# Behavior Inference System Guide

**Module**: `BehaviorInference`
**Location**: `client/src/services/assessment/modules/annotations/BehaviorInference.ts`
**Enhanced in**: Issue #57

---

## Overview

The Behavior Inference system determines whether MCP tools are:

- **Read-only** (safe, only retrieves data)
- **Write** (modifies data but reversible)
- **Destructive** (permanently modifies/deletes data)

This classification helps operators assess risk before granting tool access to AI agents.

---

## Two Inference Modes

### Basic Inference: `inferBehavior()`

Single-signal inference using tool name patterns only.

```typescript
const result = inferBehavior("delete_user", "Delete a user from the database");
// { expectedReadOnly: false, expectedDestructive: true, confidence: "high" }
```

### Enhanced Inference: `inferBehaviorEnhanced()`

Multi-signal inference combining four signal sources:

1. **Name patterns** - Tool name keywords
2. **Description** - Description text analysis
3. **Input schema** - Parameter structure analysis
4. **Output schema** - Return value analysis

```typescript
const result = inferBehaviorEnhanced(
  "get_users",
  "Retrieve a list of users",
  { type: "object", properties: { limit: { type: "number" } } },
  { type: "array", items: { type: "object" } },
);
// Higher confidence with multiple signals agreeing
```

---

## Signal Types

### 1. Name Pattern Signal

Matches tool names against predefined patterns.

| Category    | Patterns                                            | Example Tools                        |
| ----------- | --------------------------------------------------- | ------------------------------------ |
| Read-only   | `get_`, `list_`, `fetch_`, `query_`, `search_`      | `get_user`, `list_files`             |
| Write       | `create_`, `add_`, `update_`, `set_`, `modify_`     | `create_user`, `update_config`       |
| Destructive | `delete_`, `remove_`, `drop_`, `purge_`, `destroy_` | `delete_user`, `drop_table`          |
| Ambiguous   | `run_`, `execute_`, `process_`, `handle_`           | `run_query` (could be read or write) |

**Exception**: `run_` + analysis suffix = read-only

- `runAccessibilityAudit` → read-only
- `runSecurityCheck` → read-only
- `runAnalysis` → read-only

### 2. Description Signal

Analyzes description text for behavioral keywords.

**Read-only indicators** (by confidence):

- **High**: retrieves, returns, lists, displays, shows, searches, queries, reads, fetches
- **Medium**: gets, views, looks up, finds, checks, inspects
- **Low**: accesses, obtains, provides

**Destructive indicators** (by confidence):

- **High**: deletes, removes, destroys, drops, erases, purges, wipes, clears permanently
- **Medium**: truncates, kills, terminates, revokes
- **Low**: resets, restores (context-dependent)

**Write indicators**:

- creates, modifies, updates, sets, changes, writes, saves, stores

### 3. Input Schema Signal

Analyzes input parameters for behavioral patterns.

| Pattern                    | Indicates   | Example                                    |
| -------------------------- | ----------- | ------------------------------------------ |
| ID-only parameters         | Read-only   | `{ userId: string }`                       |
| Query/filter parameters    | Read-only   | `{ query: string, limit: number }`         |
| Pagination (offset, limit) | Read-only   | `{ page: number, pageSize: number }`       |
| Force/hard flags           | Destructive | `{ force: boolean, hardDelete: boolean }`  |
| Data payload objects       | Write       | `{ data: { name: string, email: string }}` |
| Update parameters          | Write       | `{ updates: object }`                      |

### 4. Output Schema Signal

Analyzes return value structure.

| Pattern                     | Indicates   | Example                               |
| --------------------------- | ----------- | ------------------------------------- |
| Array returns               | Read-only   | `{ type: "array" }`                   |
| Single record return        | Read-only   | `{ type: "object", properties: {} }`  |
| Status/confirmation returns | Destructive | `{ success: boolean, deleted: true }` |
| Created resource returns    | Write       | `{ created: object, id: string }`     |

---

## Signal Aggregation Algorithm

When multiple signals are present, they're aggregated following these rules:

### Priority Order

1. **Strong destructive signals** (confidence ≥ 70) take priority
2. **Write vs Read-only** - Write signals override if confidence is similar
3. **Read-only signals** - Aggregated when no conflicting write signals
4. **Write signals** - Used when no read-only or destructive signals

### Conflict Handling

- Conflicting signals **reduce confidence by 10**
- Result is marked as **ambiguous** when conflicts exist
- Multiple agreeing signals **boost confidence by 3 per additional signal**

### Confidence Calculation

```
Final Confidence = Average(signal confidences) + (agreeing_signals - 1) * 3 - conflicts * 10
```

Capped at 0-100 range.

---

## Persistence Classification

For write operations, the system determines if changes are **immediate** or **deferred**.

### Three-Tier Priority

1. **Description explicitly indicates deferred**
   - Keywords: "in-memory", "temporary", "staged", "pending"
   - Result: Not destructive (can be undone)

2. **Description explicitly indicates immediate**
   - Keywords: "persists", "saves immediately", "writes to database"
   - Result: Potentially destructive

3. **Server-level persistence model**
   - If server has `save_` tools → deferred (in-memory until save)
   - If server has no `save_` tools → immediate persistence

### CREATE vs UPDATE

**CREATE operations are NEVER destructive**:

- `create_user`, `add_item`, `insert_record` → Write, not destructive
- They only **add** new data

**UPDATE operations MAY be destructive**:

- `update_user`, `modify_config` → Depends on persistence model
- They **modify** existing data

---

## API Reference

### `inferBehavior(toolName, description?, compiledPatterns?, persistenceContext?)`

Basic single-signal inference.

**Parameters:**

```typescript
toolName: string;              // Tool name to analyze
description?: string;          // Tool description
compiledPatterns?: CompiledPatterns;  // Custom patterns (optional)
persistenceContext?: ServerPersistenceContext;  // Server persistence info
```

**Returns:**

```typescript
interface BehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
}
```

### `inferBehaviorEnhanced(toolName, description?, inputSchema?, outputSchema?, compiledPatterns?, persistenceContext?)`

Multi-signal enhanced inference.

**Parameters:**

```typescript
toolName: string;
description?: string;
inputSchema?: JSONSchema;      // Input parameter schema
outputSchema?: JSONSchema;     // Output/return schema
compiledPatterns?: CompiledPatterns;
persistenceContext?: ServerPersistenceContext;
```

**Returns:**

```typescript
interface EnhancedBehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
  signals: {
    namePatternSignal?: InferenceSignal;
    descriptionSignal?: InferenceSignal;
    inputSchemaSignal?: InferenceSignal;
    outputSchemaSignal?: InferenceSignal;
  };
  aggregatedConfidence: number; // 0-100
}
```

---

## Type Definitions

### `InferenceSignal`

```typescript
interface InferenceSignal {
  /** Whether this signal indicates read-only behavior */
  expectedReadOnly: boolean;
  /** Whether this signal indicates destructive behavior */
  expectedDestructive: boolean;
  /** Confidence level (0-100) */
  confidence: number;
  /** Evidence explaining why this signal was detected */
  evidence: string[];
}
```

### `EnhancedBehaviorInferenceResult`

```typescript
interface EnhancedBehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
  signals: {
    namePatternSignal?: InferenceSignal;
    descriptionSignal?: InferenceSignal;
    inputSchemaSignal?: InferenceSignal;
    outputSchemaSignal?: InferenceSignal;
  };
  aggregatedConfidence: number;
}
```

---

## Examples

### Example 1: Clear Read-Only Tool

```typescript
const result = inferBehaviorEnhanced(
  "list_users",
  "Returns a paginated list of all users",
  {
    type: "object",
    properties: {
      page: { type: "number" },
      limit: { type: "number" },
    },
  },
  { type: "array", items: { type: "object" } },
);

// Result:
// {
//   expectedReadOnly: true,
//   expectedDestructive: false,
//   confidence: "high",
//   aggregatedConfidence: 93,
//   signals: {
//     namePatternSignal: { expectedReadOnly: true, confidence: 90 },
//     descriptionSignal: { expectedReadOnly: true, confidence: 85 },
//     inputSchemaSignal: { expectedReadOnly: true, confidence: 80 },
//     outputSchemaSignal: { expectedReadOnly: true, confidence: 75 }
//   }
// }
```

### Example 2: Destructive Tool

```typescript
const result = inferBehaviorEnhanced(
  "delete_user",
  "Permanently removes a user and all their data",
  {
    type: "object",
    properties: {
      userId: { type: "string" },
      force: { type: "boolean" },
    },
  },
  { type: "object", properties: { success: { type: "boolean" } } },
);

// Result:
// {
//   expectedReadOnly: false,
//   expectedDestructive: true,
//   confidence: "high",
//   aggregatedConfidence: 95,
//   reason: "Destructive behavior detected from: name pattern, description"
// }
```

### Example 3: Conflicting Signals

```typescript
const result = inferBehaviorEnhanced(
  "get_and_update_user",
  "Retrieves user info and updates last access time",
  { type: "object", properties: { userId: { type: "string" } } },
  { type: "object", properties: { user: { type: "object" } } },
);

// Result:
// {
//   expectedReadOnly: false,  // Write takes precedence
//   expectedDestructive: false,
//   confidence: "medium",
//   isAmbiguous: true,        // Flagged due to conflict
//   aggregatedConfidence: 62,
//   reason: "Write behavior detected... (conflicts with read-only signals)"
// }
```

### Example 4: Create Operation (Not Destructive)

```typescript
const result = inferBehaviorEnhanced(
  "create_user",
  "Creates a new user account",
  { type: "object", properties: { name: { type: "string" } } },
);

// Result:
// {
//   expectedReadOnly: false,
//   expectedDestructive: false,  // CREATE is never destructive
//   confidence: "high",
//   reason: "Tool name matches create pattern - create operations only add data"
// }
```

---

## Confidence Levels

| Level  | Numeric Range | Meaning                            |
| ------ | ------------- | ---------------------------------- |
| High   | 80-100        | Strong agreement, multiple signals |
| Medium | 50-79         | Some signals, possible conflicts   |
| Low    | 0-49          | Weak signals, high ambiguity       |

---

## Ambiguity Detection

A result is marked **ambiguous** (`isAmbiguous: true`) when:

1. Only one weak signal (confidence < 50) exists
2. Destructive and read-only signals conflict
3. Write and read-only signals conflict with similar confidence
4. No clear behavior signals detected

**Recommended handling for ambiguous results:**

- Flag for human review
- Request additional context
- Apply conservative (safer) interpretation

---

## Related Documentation

- [Architecture Detection Guide](ARCHITECTURE_DETECTION_GUIDE.md) - Server infrastructure analysis
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - All assessment modules
- [Description Analyzer](#description-analyzer) - Description keyword analysis
- [Schema Analyzer](#schema-analyzer) - Schema pattern analysis

---

## Import Paths

```typescript
// From published package
import {
  inferBehavior,
  inferBehaviorEnhanced,
} from "@bryan-thompson/inspector-assessment/client/dist/lib";

// Types
import type {
  BehaviorInferenceResult,
  EnhancedBehaviorInferenceResult,
  InferenceSignal,
} from "@bryan-thompson/inspector-assessment/client/dist/lib";
```

---

## Supporting Modules

### Description Analyzer

**File**: `modules/annotations/DescriptionAnalyzer.ts`

```typescript
import { analyzeDescription } from "./DescriptionAnalyzer";

const signal = analyzeDescription("Permanently deletes all user data");
// { expectedDestructive: true, confidence: 85, evidence: ["permanently", "deletes"] }
```

### Schema Analyzer

**File**: `modules/annotations/SchemaAnalyzer.ts`

```typescript
import { analyzeInputSchema, analyzeOutputSchema } from "./SchemaAnalyzer";

const inputSignal = analyzeInputSchema({
  type: "object",
  properties: { force: { type: "boolean" } },
});
// { expectedDestructive: true, confidence: 70, evidence: ["force flag"] }
```
