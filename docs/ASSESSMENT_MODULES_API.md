# Assessment Modules API Reference

**Complete developer guide for security testing and annotation modules extracted from MCP Inspector.**

This document provides comprehensive API documentation for the newly extracted assessment modules, including interfaces, types, and integration patterns.

---

## Table of Contents

1. [Overview](#overview)
2. [Security Testing Modules](#security-testing-modules)
3. [Annotation Modules](#annotation-modules)
4. [Type Definitions](#type-definitions)
5. [Usage Examples](#usage-examples)
6. [Integration Patterns](#integration-patterns)

---

## Overview

The MCP Inspector assessment framework has been refactored into specialized modules:

- **Security Testing Modules** (`client/src/services/assessment/modules/securityTests/`)
  - Evidence-based vulnerability detection
  - Multi-payload test execution with batching
  - Smart tool classification and parameter injection

- **Annotation Modules** (`client/src/services/assessment/modules/annotations/`)
  - Tool description poisoning detection (40+ patterns)
  - Annotation deception detection
  - Expected behavior inference from tool patterns

All modules use TypeScript with strict type safety and export public APIs for programmatic use.

---

## Security Testing Modules

The security testing framework provides three main components:

- **SecurityResponseAnalyzer** - Analyzes tool responses for vulnerability evidence
- **SecurityPayloadTester** - Executes tests with batching and progress tracking
- **SecurityPayloadGenerator** - Creates language-aware test parameters

### SecurityResponseAnalyzer

Analyzes tool responses for security vulnerabilities with evidence-based detection that distinguishes between safe reflection and actual execution.

**Location**: `client/src/services/assessment/modules/securityTests/SecurityResponseAnalyzer.ts`

**Architecture** (v2.0.0+): Refactored facade pattern (Issue #53) with 6 extracted classes for maintainability and testability. Original 1,638 lines → ~570 line facade delegating to focused analyzers.

#### Public Exports

```typescript
export class SecurityResponseAnalyzer {
  analyzeResponse(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    tool: Tool,
  ): AnalysisResult;

  calculateConfidence(
    tool: Tool,
    isVulnerable: boolean,
    evidence: string,
    responseText: string,
    payload: SecurityPayload,
  ): ConfidenceResult;

  isConnectionError(response: CompatibilityCallToolResult): boolean;
  isConnectionErrorFromException(error: unknown): boolean;
  classifyError(response: CompatibilityCallToolResult): ErrorClassification;
  classifyErrorFromException(error: unknown): ErrorClassification;

  // Internal analysis methods (public for testing)
  isReflectionResponse(responseText: string): boolean;
  isValidationRejection(response: CompatibilityCallToolResult): boolean;
  isMCPValidationError(errorInfo: any, responseText: string): boolean;
  isHttpErrorResponse(responseText: string): boolean;
  isComputedMathResult(payload: string, responseText: string): boolean;
  hasExecutionEvidence(responseText: string): boolean;
  detectExecutionArtifacts(responseText: string): boolean;
  isSearchResultResponse(responseText: string): boolean;
  isCreationResponse(responseText: string): boolean;

  extractResponseContent(response: CompatibilityCallToolResult): string;
}
```

#### Extracted Analysis Classes (v2.0.0+)

The SecurityResponseAnalyzer facade delegates to 6 focused classes (Issue #53):

**1. SecurityPatternLibrary** - Centralized regex patterns (eliminates 16 duplicate pattern collections)

- **Exports**: HTTP_ERROR_PATTERNS, VALIDATION_ERROR_PATTERNS, EXECUTION_INDICATORS, EXECUTION_ARTIFACT_PATTERNS, CONNECTION_ERROR_PATTERNS, REFLECTION_PATTERNS, SEARCH_RESPONSE_PATTERNS, SAFE_CREATION_PATTERNS, ECHOED_PAYLOAD_PATTERNS, matchesAny(), hasMcpErrorPrefix()

**2. ErrorClassifier** - Error classification and connection detection

- **Methods**: isConnectionError(), isConnectionErrorFromException(), classifyError(), classifyErrorFromException(), extractErrorInfo()
- **Type**: ErrorClassification ("connection" | "server" | "protocol"), ErrorInfo

**3. ExecutionArtifactDetector** - Detects execution evidence

- **Methods**: hasExecutionEvidence(), detectExecutionArtifacts(), containsEchoedInjectionPayload()
- **Purpose**: Distinguishes safe reflection from actual command/code execution

**4. MathAnalyzer** - Calculator injection detection

- **Methods**: isComputedMathResult()
- **Type**: MathResultAnalysis (with confidence levels)
- **Purpose**: Detects simple math expressions (1+2=3) to avoid false positives

**5. SafeResponseDetector** - Safe response pattern detection

- **Methods**: isReflectionResponse(), isValidationRejection(), isSearchResultResponse(), isCreationResponse()
- **Type**: AnalysisResult
- **Purpose**: Identifies legitimate safe responses (stored, saved, search results, etc.)

**6. ConfidenceScorer** - Confidence calculation for manual review

- **Methods**: calculateConfidence()
- **Type**: ConfidenceResult
- **Purpose**: Determines if finding requires manual review based on evidence strength

#### Interfaces

```typescript
/**
 * Result of confidence calculation
 */
export interface ConfidenceResult {
  confidence: "high" | "medium" | "low";
  requiresManualReview: boolean;
  manualReviewReason?: string;
  reviewGuidance?: string;
}

/**
 * Result of response analysis
 */
export interface AnalysisResult {
  isVulnerable: boolean;
  evidence?: string;
}

/**
 * Error classification types
 */
export type ErrorClassification = "connection" | "server" | "protocol";
```

#### Analysis Algorithm

The `analyzeResponse()` method uses a multi-step analysis pipeline:

1. **MCP Validation Errors** (HIGHEST PRIORITY)
   - Error code -32602 indicates parameter validation
   - HTTP 4xx/5xx errors indicate tool rejection
   - Safe validation patterns are recognized

2. **Tool Classification**
   - Categories: SEARCH_RETRIEVAL, CRUD_CREATION, READ_ONLY_INFO, SAFE_STORAGE
   - Prevents false positives on legitimately data-returning tools
   - Uses ToolClassifier for consistent categorization

3. **Reflection Detection**
   - Checks if tool safely echoed input without execution
   - Two-layer defense: Match reflection patterns, verify NO execution evidence
   - 50+ reflection patterns recognized

4. **Math Result Detection**
   - Detects computed math expressions (Issue #14 fix)
   - Analyzes simple expressions (1+2, 10\*5, etc.)
   - Distinguishes computation from echoed input

5. **Evidence Pattern Matching**
   - Uses payload-specific evidence regex patterns
   - Validates execution indicators
   - Handles validation pattern ambiguity

#### Example Usage

```typescript
import { SecurityResponseAnalyzer } from "@/services/assessment/modules/securityTests";

const analyzer = new SecurityResponseAnalyzer();

// Analyze a tool response
const result = analyzer.analyzeResponse(
  response, // CompatibilityCallToolResult from tool execution
  payload, // SecurityPayload with evidence pattern
  tool, // Tool definition
);

if (result.isVulnerable) {
  console.log(`Vulnerability found: ${result.evidence}`);
} else {
  console.log(`Tool is safe: ${result.evidence}`);
}

// Calculate confidence for manual review
const confidence = analyzer.calculateConfidence(
  tool,
  result.isVulnerable,
  result.evidence || "",
  responseText,
  payload,
);

if (confidence.requiresManualReview) {
  console.log(`⚠ MANUAL REVIEW NEEDED: ${confidence.manualReviewReason}`);
  console.log(`Guidance: ${confidence.reviewGuidance}`);
}

// Classify errors
if (analyzer.isConnectionError(response)) {
  const errorType = analyzer.classifyError(response);
  console.log(`Connection Error (${errorType}): Test unreliable`);
}
```

#### Key Detection Patterns

**Safe Reflection Patterns** (90+ patterns):

- Storage operations: "stored", "saved", "added to collection"
- Processing status: "processed successfully", "validated"
- Sanitization: "filtered", "sanitized", "redacted"
- Safe data handling: "without execution", "as data"

**Execution Indicators**:

- Command artifacts: `uid=`, file listings, PID numbers
- Exception types: NullPointerException, SegmentationFault
- Query results: "query returned", "rows affected"
- Execution logs: "execution result", "command output"

**MCP Validation Errors** (20+ patterns):

- Schema validation failures
- Parameter validation errors
- Required field missing
- Invalid format/type

---

### SecurityPayloadTester

Executes security tests against MCP tools with concurrency management, progress tracking, and batching.

**Location**: `client/src/services/assessment/modules/securityTests/SecurityPayloadTester.ts`

#### Public Exports

```typescript
export class SecurityPayloadTester {
  constructor(
    config: PayloadTestConfig,
    logger: TestLogger,
    executeWithTimeout: <T>(promise: Promise<T>, timeout: number) => Promise<T>,
  );

  async runUniversalSecurityTests(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    onProgress?: TestProgressCallback,
  ): Promise<SecurityTestResult[]>;

  async runBasicSecurityTests(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    onProgress?: TestProgressCallback,
  ): Promise<SecurityTestResult[]>;

  async testPayload(
    tool: Tool,
    attackName: string,
    payload: SecurityPayload,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult>;
}
```

#### Interfaces

```typescript
/**
 * Configuration for payload testing
 */
export interface PayloadTestConfig {
  enableDomainTesting?: boolean; // Enable advanced mode (all patterns)
  maxParallelTests?: number; // Concurrency limit (default: 5)
  securityTestTimeout?: number; // Test timeout in ms (default: 5000)
  selectedToolsForTesting?: string[]; // Optional tool name filter
}

/**
 * Logger interface for test execution
 */
export interface TestLogger {
  log: (message: string) => void;
  logError: (message: string, error: unknown) => void;
}

/**
 * Re-export for external use
 */
export type TestProgressCallback = ProgressCallback;
```

#### Test Modes

**ADVANCED Mode** (`runUniversalSecurityTests`):

- Tests ALL 23 attack patterns with diverse payloads
- Full security assessment
- ~1000+ tests per tool
- For comprehensive security evaluation

**BASIC Mode** (`runBasicSecurityTests`):

- Tests only 5 critical injection patterns
- 1 generic payload per pattern
- ~5 tests per tool
- Fast security pre-flight check

#### Progress Events

The tester emits progress events through `TestProgressCallback`:

```typescript
// Test batch progress
interface TestBatchProgress {
  type: "test_batch";
  module: "security";
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number; // milliseconds
}

// Vulnerability found
interface VulnerabilityFoundProgress {
  type: "vulnerability_found";
  tool: string;
  pattern: string; // Attack pattern name
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload: string;
}
```

#### Example Usage

```typescript
import { SecurityPayloadTester } from "@/services/assessment/modules/securityTests";

// Setup logger
const logger = {
  log: (msg) => console.log(`[Security] ${msg}`),
  logError: (msg, err) => console.error(`[Security ERROR] ${msg}`, err),
};

// Setup timeout handler
const executeWithTimeout = async (promise, timeout) => {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Test timeout")), timeout),
    ),
  ]);
};

// Create tester with advanced mode
const tester = new SecurityPayloadTester(
  {
    enableDomainTesting: true, // Advanced: all patterns
    maxParallelTests: 5,
    securityTestTimeout: 5000,
  },
  logger,
  executeWithTimeout,
);

// Run tests with progress tracking
const results = await tester.runUniversalSecurityTests(
  tools,
  callTool,
  (event) => {
    if (event.type === "test_batch") {
      console.log(
        `Progress: ${event.completed}/${event.total} tests (${event.elapsed}ms elapsed)`,
      );
    } else if (event.type === "vulnerability_found") {
      console.log(`🚨 ${event.tool}: ${event.pattern} (${event.confidence})`);
    }
  },
);

// Process results
const vulnerabilities = results.filter((r) => r.vulnerable);
console.log(`Found ${vulnerabilities.length} vulnerabilities`);
```

#### Special Cases

**API Wrapper Tools**:

- Execution-based tests are skipped automatically
- API wrappers return external data as text (not code)
- Marked safe with evidence: "API wrapper tool..."

**Tools Without Input Parameters**:

- Cannot be exploited via payload injection
- All tests pass with evidence: "Tool has no input parameters..."

---

### SecurityPayloadGenerator

Creates language-aware test parameters for security payload injection.

**Location**: `client/src/services/assessment/modules/securityTests/SecurityPayloadGenerator.ts`

#### Public Exports

```typescript
export class SecurityPayloadGenerator {
  hasInputParameters(tool: Tool): boolean;

  createTestParameters(
    payload: SecurityPayload,
    tool: Tool,
  ): Record<string, unknown>;

  isApiWrapper(tool: Tool): boolean;

  isExecutionTest(attackName: string): boolean;
}
```

#### Parameter Injection Algorithm

The `createTestParameters()` method uses a priority-based injection system (Issue #81):

1. **PRIORITY 1: Auth Payloads** (Issue #81)
   - Targets: token, auth_token, authorization, api_key, access_token
   - Ensures auth bypass tests trigger actual auth checks
   - Prevents false positives from payload going to primary input params

2. **PRIORITY 2: Auth Failure Payloads** (Issue #79)
   - Targets: simulate_failure, failure_mode, failure_type
   - Tests fail-open/fail-closed authentication patterns

3. **PRIORITY 3: Language Detection**
   - Detects Python, JavaScript, Java, SQL execution parameters
   - Uses LanguageAwarePayloadGenerator for language-specific payloads

4. **PRIORITY 4: Type-Based Matching**
   - Matches payloadTypes to parameter names
   - Example: "command" parameter for command injection

5. **PRIORITY 5: Generic Injection**
   - Falls back to first string parameter if no match found

6. **Required Parameter Filling**
   - Fills required parameters with safe defaults
   - Types: string="test", number=1, boolean=true, object={}, array=[]

#### Example Usage

```typescript
import { SecurityPayloadGenerator } from "@/services/assessment/modules/securityTests";

const generator = new SecurityPayloadGenerator();

// Check if tool can be tested
if (!generator.hasInputParameters(tool)) {
  console.log("Tool has no input parameters - cannot be exploited");
  return;
}

// Create test parameters
const params = generator.createTestParameters(payload, tool);

// Example output:
// { command: "whoami && echo injected" }
// or
// { query: "; DROP TABLE users; --" }

// Check if tool is an API wrapper (safe)
if (generator.isApiWrapper(tool)) {
  console.log("Tool is an API wrapper - skips execution tests");
}

// Check attack type
if (generator.isExecutionTest("Command Injection")) {
  console.log("This is an execution-based test");
}
```

---

## Annotation Modules

The annotation framework provides three main components:

- **DescriptionPoisoningDetector** - Detects malicious content in tool descriptions
- **AnnotationDeceptionDetector** - Detects misaligned metadata annotations
- **BehaviorInference** - Infers expected tool behavior from patterns

### DescriptionPoisoningDetector

Detects hidden instructions and malicious content in tool descriptions using 40+ configurable patterns.

**Location**: `client/src/services/assessment/modules/annotations/DescriptionPoisoningDetector.ts`

#### Public Exports

```typescript
export const DESCRIPTION_POISONING_PATTERNS: PoisoningPattern[];

export function scanDescriptionForPoisoning(tool: Tool): PoisoningScanResult;
```

#### Pattern Categories

**Hidden Instructions** (4 patterns):

- `<HIDDEN>...</HIDDEN>` tags
- `<IMPORTANT>...</IMPORTANT>` tags
- `<SYSTEM>...</SYSTEM>` tags
- `<INSTRUCTION>...</INSTRUCTION>` tags

**Override Commands** (4 patterns):

- "ignore ... instructions"
- "disregard ... instructions"
- "you are now ..."
- "system: override"

**Concealment** (3 patterns):

- "do not mention/tell/reveal"
- "secretly"
- "hide from user"

**Data Exfiltration** (4 patterns):

- "return ... api keys"
- "include ... credentials"
- "reveal ... secrets"
- "access ... internal ... credentials"

**Delimiter Injection** (5 patterns):

- ````system` code blocks
- `[INST]...[/INST]` tags
- `<|im_start|>system` (ChatML)
- `<<SYS>>` (Llama)
- `[USER]...[ASSISTANT]` blocks

**Role/Persona Injection** (4 patterns):

- "act as/like ..."
- "pretend to be ..."
- "roleplay as ..."
- "new task/instruction..."

**Encoding Bypass** (3 patterns):

- Large Base64 strings (50+ chars)
- Unicode escape sequences (3+ consecutive)
- HTML entities (3+ consecutive)

**Typoglycemia/Evasion** (2 patterns):

- Obfuscated "ignore instructions" variants
- Obfuscated "disregard" variants

**DVMCP CTF Patterns** (7 patterns):

- "override_auth_protocol"
- "internal://...", "system://...", etc.
- "get_secrets()"
- "master_password"
- "access confidential"
- "if query contains exact phrase"

#### Interfaces

```typescript
/**
 * Tool description poisoning pattern definition
 */
export interface PoisoningPattern {
  name: string;
  pattern: RegExp;
  severity: "LOW" | "MEDIUM" | "HIGH";
  category: string;
}

/**
 * Result of description poisoning scan
 */
export interface PoisoningScanResult {
  detected: boolean;
  patterns: Array<{
    name: string;
    pattern: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    category: string;
    evidence: string;
  }>;
  riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
}
```

#### Risk Level Calculation

Risk levels are determined by the highest severity match:

- **HIGH**: Any pattern with severity "HIGH"
- **MEDIUM**: Best match is severity "MEDIUM"
- **LOW**: Only severity "LOW" patterns detected
- **NONE**: No patterns detected

#### Example Usage

```typescript
import {
  scanDescriptionForPoisoning,
  DESCRIPTION_POISONING_PATTERNS,
} from "@/services/assessment/modules/annotations";

// Scan a tool
const result = scanDescriptionForPoisoning(tool);

if (result.detected) {
  console.log(
    `⚠ Tool description contains ${result.patterns.length} poisoning patterns`,
  );
  console.log(`Risk Level: ${result.riskLevel}`);

  // Group by category
  const byCategory = result.patterns.reduce((acc, p) => {
    if (!acc[p.category]) acc[p.category] = [];
    acc[p.category].push(p);
    return acc;
  }, {});

  for (const [category, patterns] of Object.entries(byCategory)) {
    console.log(`\n${category}:`);
    for (const pattern of patterns) {
      console.log(`  - ${pattern.name} (${pattern.severity})`);
      console.log(`    Evidence: ${pattern.evidence}`);
    }
  }
}

// Custom pattern checking
const customPattern = DESCRIPTION_POISONING_PATTERNS.find(
  (p) => p.name === "hidden_tag",
);
if (customPattern) {
  const matches = tool.description?.match(customPattern.pattern);
  console.log(`Found ${matches?.length || 0} hidden tags`);
}
```

---

### AnnotationDeceptionDetector

Detects misaligned metadata annotations through keyword matching and rule-based logic.

**Location**: `client/src/services/assessment/modules/annotations/AnnotationDeceptionDetector.ts`

#### Public Exports

```typescript
export const READONLY_CONTRADICTION_KEYWORDS: string[];
export const RUN_READONLY_EXEMPT_SUFFIXES: string[];
export const DESTRUCTIVE_CONTRADICTION_KEYWORDS: string[];

export function containsKeyword(
  toolName: string,
  keywords: string[],
): string | null;

export function isRunKeywordExempt(toolName: string): boolean;

export function isActionableConfidence(confidence: string): boolean;

export function detectAnnotationDeception(
  toolName: string,
  annotations: { readOnlyHint?: boolean; destructiveHint?: boolean },
): DeceptionResult | null;
```

#### Keyword Lists

**READONLY_CONTRADICTION_KEYWORDS** (24 keywords):

- Execution: exec, execute, run, shell, command, spawn, invoke
- Write: write, create, delete, modify, update, edit, set, put
- Deployment: install, deploy, upload, push
- Communication: send, post, submit, publish
- Destructive: destroy, drop, purge, wipe, clear

**DESTRUCTIVE_CONTRADICTION_KEYWORDS** (14 keywords):

- delete, remove, drop, destroy, purge, wipe, erase, truncate, clear, reset, kill, terminate, revoke, cancel

**RUN_READONLY_EXEMPT_SUFFIXES** (11 suffixes):

- audit, check, mode, test, scan, analyze, report, status, validate, verify, inspect, lint, benchmark, diagnostic

#### Interfaces

```typescript
/**
 * Deception detection result
 */
export interface DeceptionResult {
  field: "readOnlyHint" | "destructiveHint";
  matchedKeyword: string;
  reason: string;
}
```

#### Keyword Matching Algorithm

The `containsKeyword()` function uses intelligent word-boundary matching:

1. **Normalization**
   - Converts camelCase to snake_case: `putFile` → `put_file`
   - Handles PascalCase: `DeleteUser` → `delete_user`

2. **Segment Matching**
   - Splits by `_` and `-` separators
   - Matches exact segment or segment prefix
   - Avoids false positives: "put" doesn't match "output"

3. **Case Handling**
   - Fully case-insensitive matching

#### Special Cases

**Issue #18 - Analysis Tools**:

- Tools like `runAccessibilityAudit` are genuinely read-only
- Matched by `isRunKeywordExempt()` for audit/check/scan suffixes
- Prevents false positive deception detection

#### Example Usage

```typescript
import {
  detectAnnotationDeception,
  containsKeyword,
  READONLY_CONTRADICTION_KEYWORDS,
  isRunKeywordExempt,
} from "@/services/assessment/modules/annotations";

// Check for obvious deception
const deception = detectAnnotationDeception("deleteUserData", {
  readOnlyHint: true, // Claims read-only
});

if (deception) {
  console.log(`🚨 DECEPTION DETECTED: ${deception.reason}`);
  console.log(`Field: ${deception.field}`);
  console.log(`Matched Keyword: ${deception.matchedKeyword}`);
}

// Check keyword presence
const keyword = containsKeyword("execCommand", READONLY_CONTRADICTION_KEYWORDS);
if (keyword) {
  console.log(`Tool contains modification keyword: ${keyword}`);
}

// Check if "run" tool is analysis-related
if (isRunKeywordExempt("runAccessibilityAudit")) {
  console.log("This is a read-only audit tool (not deceptive)");
}
```

---

### BehaviorInference

Infers expected tool behavior from name patterns and descriptions with configurable precision and ambiguity handling.

**Location**: `client/src/services/assessment/modules/annotations/BehaviorInference.ts`

#### Public Exports

```typescript
export function inferBehavior(
  toolName: string,
  description?: string,
  compiledPatterns?: CompiledPatterns,
  persistenceContext?: ServerPersistenceContext,
): BehaviorInferenceResult;
```

#### Interfaces

```typescript
/**
 * Result of behavior inference
 */
export interface BehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
}

/**
 * Server persistence context for classification
 */
export interface ServerPersistenceContext {
  model: "immediate" | "deferred";
  // immediate: write operations persist immediately
  // deferred: write operations are in-memory until explicit save
}
```

#### Classification Pipeline

1. **Analysis Tool Check** (Issue #18)
   - Tools with "run" + analysis suffix are read-only
   - Suffixes: audit, check, scan, validate, verify, inspect, lint

2. **Pattern Matching**
   - Uses configurable pattern rules from `annotationPatterns.ts`
   - Categories: ambiguous, destructive, readOnly, write, unknown

3. **Persistence Model Analysis** (Tier 3)
   - For write operations, determines if destructive
   - Checks tool description for persistence hints
   - Uses server-level persistence context

4. **Description-Based Hints**
   - Falls back to description keywords: delete, remove, read, get, fetch

5. **Default Fallback**
   - Returns low-confidence ambiguous result

#### Behavior Categories

**Read-Only Tools**:

- High confidence: Matching read-only pattern
- Medium confidence: Description indicates read-only operation
- Reason: Pattern or description-based inference

**Write (Non-Destructive) Tools**:

- CREATE operations: Only add data, never destructive
- Deferred persistence: In-memory until explicit save
- Medium confidence: Based on persistence model

**Destructive Tools**:

- High confidence: Matching destructive pattern
- Medium confidence: Immediate persistence detected
- Category includes: delete, remove, drop, destroy, etc.

**Ambiguous Tools**:

- Low confidence: Cannot infer behavior
- isAmbiguous: true - behavior varies by implementation
- Requires manual review or testing

#### Example Usage

```typescript
import { inferBehavior } from "@/services/assessment/modules/annotations";

// Infer behavior for a tool
const result = inferBehavior(
  "updateUserProfile",
  "Updates user profile in persistent storage",
  compiledPatterns,
  { model: "immediate" }, // writes persist immediately
);

console.log(`Expected Read-Only: ${result.expectedReadOnly}`);
console.log(`Expected Destructive: ${result.expectedDestructive}`);
console.log(`Confidence: ${result.confidence}`);
console.log(`Reason: ${result.reason}`);

if (result.isAmbiguous) {
  console.log("⚠ Behavior is ambiguous - manual review recommended");
}

// Handle different confidence levels
switch (result.confidence) {
  case "high":
    console.log("✅ High confidence - use for validation");
    break;
  case "medium":
    console.log("⚠ Medium confidence - verify with manual testing");
    break;
  case "low":
    console.log("❓ Low confidence - cannot determine behavior");
    break;
}
```

#### Persistence Model Detection

Three-tier classification for UPDATE/MODIFY operations:

1. **Description Explicit** (Priority 1)
   - Description says "saves to disk" → immediate/destructive
   - Description says "in-memory buffer" → deferred/safe

2. **Server Context** (Priority 2)
   - If server has save operations → deferred/safe
   - If server has no save operations → immediate/destructive

3. **Pattern Default** (Priority 3)
   - Returns medium confidence ambiguous result

---

## Type Definitions

### From assessmentTypes

```typescript
// From @/lib/assessmentTypes
export type SecurityRiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type InferenceConfidence = "high" | "medium" | "low";
```

### From resultTypes

```typescript
// From @/lib/assessment/resultTypes
export interface SecurityTestResult {
  testName: string;
  description: string;
  payload: string;
  riskLevel: SecurityRiskLevel;
  toolName: string;
  vulnerable: boolean;
  evidence?: string;
  response?: string;
  confidence?: "high" | "medium" | "low";
  requiresManualReview?: boolean;
  connectionError?: boolean;
  errorType?: ErrorClassification;
  testReliability?: "passed" | "failed";
}
```

### From progressTypes

```typescript
// From @/lib/assessment/progressTypes
export type ProgressCallback = (event: ProgressEvent) => void;

export interface TestBatchProgress {
  type: "test_batch";
  module: "security";
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

export interface VulnerabilityFoundProgress {
  type: "vulnerability_found";
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: SecurityRiskLevel;
  requiresReview: boolean;
  payload: string;
}
```

### From securityPatterns

```typescript
// From @/lib/securityPatterns
export interface SecurityPayload {
  payload: string;
  description: string;
  payloadType: string;
  evidence?: RegExp;
  parameterTypes?: string[];
  riskLevel: SecurityRiskLevel;
}
```

### From MCP SDK

```typescript
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

export interface Tool {
  name: string;
  description?: string;
  inputSchema: JSONSchema;
}

export interface CompatibilityCallToolResult {
  type: string;
  content?: ContentBlock[];
  isError?: boolean;
}

export interface ContentBlock {
  type: string;
  text?: string;
}
```

---

## Usage Examples

### Complete Security Assessment Workflow

```typescript
import {
  SecurityPayloadTester,
  SecurityResponseAnalyzer,
  SecurityPayloadGenerator,
} from "@/services/assessment/modules/securityTests";

async function runSecurityAssessment(tools, callTool) {
  // Setup components
  const logger = {
    log: (msg) => console.log(`[Security] ${msg}`),
    logError: (msg, err) => console.error(`[Error] ${msg}`, err),
  };

  const executeWithTimeout = async (promise, timeout) => {
    return Promise.race([
      promise,
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), timeout),
      ),
    ]);
  };

  // Run tests
  const tester = new SecurityPayloadTester(
    {
      enableDomainTesting: true,
      maxParallelTests: 5,
      securityTestTimeout: 5000,
    },
    logger,
    executeWithTimeout,
  );

  const results = await tester.runUniversalSecurityTests(
    tools,
    callTool,
    (event) => {
      if (event.type === "vulnerability_found") {
        console.log(`Found: ${event.tool} - ${event.pattern}`);
      }
    },
  );

  // Filter vulnerabilities
  const vulnerabilities = results.filter((r) => r.vulnerable);

  // Analyze high-confidence findings
  const criticalFindings = vulnerabilities.filter(
    (v) => v.confidence === "high",
  );

  console.log(`Critical: ${criticalFindings.length}`);
  console.log(`Total: ${vulnerabilities.length}`);

  return {
    total: results.length,
    vulnerable: vulnerabilities.length,
    critical: criticalFindings.length,
    results,
  };
}
```

### Complete Annotation Assessment Workflow

```typescript
import {
  scanDescriptionForPoisoning,
  detectAnnotationDeception,
  inferBehavior,
} from "@/services/assessment/modules/annotations";

function assessToolAnnotations(tool) {
  // Check description poisoning
  const poisoning = scanDescriptionForPoisoning(tool);

  // Check annotation deception
  const deception = detectAnnotationDeception(tool.name, {
    readOnlyHint: tool.readOnlyHint,
    destructiveHint: tool.destructiveHint,
  });

  // Infer expected behavior
  const behavior = inferBehavior(tool.name, tool.description);

  // Build assessment report
  return {
    tool: tool.name,
    poisoning: {
      detected: poisoning.detected,
      riskLevel: poisoning.riskLevel,
      patterns: poisoning.patterns.map((p) => ({
        name: p.name,
        severity: p.severity,
      })),
    },
    deception: deception
      ? {
          field: deception.field,
          keyword: deception.matchedKeyword,
        }
      : null,
    expectedBehavior: {
      readOnly: behavior.expectedReadOnly,
      destructive: behavior.expectedDestructive,
      confidence: behavior.confidence,
      reason: behavior.reason,
    },
    annotations: {
      actual: {
        readOnlyHint: tool.readOnlyHint,
        destructiveHint: tool.destructiveHint,
      },
      conflicts: {
        readOnlyConflict:
          tool.readOnlyHint !== behavior.expectedReadOnly &&
          behavior.confidence === "high",
        destructiveConflict:
          tool.destructiveHint !== behavior.expectedDestructive &&
          behavior.confidence === "high",
      },
    },
  };
}
```

---

## Integration Patterns

### Module Index Exports

All modules provide barrel exports through `index.ts`:

```typescript
// client/src/services/assessment/modules/securityTests/index.ts
export {
  SecurityResponseAnalyzer,
  type ConfidenceResult,
  type AnalysisResult,
  type ErrorClassification,
} from "./SecurityResponseAnalyzer";

export {
  SecurityPayloadTester,
  type TestProgressCallback,
  type PayloadTestConfig,
  type TestLogger,
} from "./SecurityPayloadTester";

export { SecurityPayloadGenerator } from "./SecurityPayloadGenerator";
```

### TypeScript Import Paths

Use absolute path imports with the `@/` alias:

```typescript
// ✅ Correct
import { SecurityResponseAnalyzer } from "@/services/assessment/modules/securityTests";

// ✅ Also correct (barrel export)
import { SecurityPayloadTester } from "@/services/assessment/modules/securityTests";

// ❌ Avoid relative imports
import { SecurityPayloadTester } from "../../../modules/securityTests";
```

### Dependency Injection Pattern

All modules follow dependency injection for testability:

```typescript
// SecurityPayloadTester accepts config + logger + timeout handler
const tester = new SecurityPayloadTester(config, logger, executeWithTimeout);

// SecurityResponseAnalyzer uses internal ToolClassifier
// Stateless methods for easy testing
const result = analyzer.analyzeResponse(response, payload, tool);
```

### Error Handling Pattern

All async operations should handle both connection errors and validation errors:

```typescript
try {
  const result = await tester.testPayload(tool, attackName, payload, callTool);

  if (result.connectionError) {
    // Server/network failure - test unreliable
    console.log(`Skipping result due to: ${result.errorType}`);
  } else if (result.vulnerable) {
    // Actual vulnerability found
    console.log(`VULNERABLE: ${result.evidence}`);
  } else {
    // Safe tool
    console.log(`SAFE: ${result.evidence}`);
  }
} catch (error) {
  // Check if connection error
  if (analyzer.isConnectionErrorFromException(error)) {
    console.log("Connection error - test unreliable");
  } else {
    // Tool rejected input
    console.log(`Tool rejected: ${error.message}`);
  }
}
```

---

## Testing Modules Programmatically

### Unit Testing Pattern

```typescript
import { test, expect } from "vitest";
import { SecurityResponseAnalyzer } from "@/services/assessment/modules/securityTests";

test("analyzeResponse detects code execution", () => {
  const analyzer = new SecurityResponseAnalyzer();

  const response = {
    content: [{ type: "text", text: "uid=0(root) gid=0(root) groups=0(root)" }],
  };

  const result = analyzer.analyzeResponse(response, payload, tool);

  expect(result.isVulnerable).toBe(true);
  expect(result.evidence).toContain("executed");
});

test("analyzeResponse detects safe reflection", () => {
  const analyzer = new SecurityResponseAnalyzer();

  const response = {
    content: [{ type: "text", text: "Query stored successfully" }],
  };

  const result = analyzer.analyzeResponse(response, payload, tool);

  expect(result.isVulnerable).toBe(false);
  expect(result.evidence).toContain("reflected");
});
```

---

## Maintenance and Extension

### Adding Custom Patterns

**For description poisoning**:

```typescript
// In DescriptionPoisoningDetector.ts
export const CUSTOM_PATTERNS: PoisoningPattern[] = [
  {
    name: "my_custom_pattern",
    pattern: /my\s+malicious\s+instruction/i,
    severity: "HIGH",
    category: "custom",
  },
];

// Merge with defaults
const allPatterns = [...DESCRIPTION_POISONING_PATTERNS, ...CUSTOM_PATTERNS];
```

**For deception detection**:

```typescript
// In AnnotationDeceptionDetector.ts
export const CUSTOM_KEYWORDS = ["myKeyword"];

const matched = containsKeyword(toolName, CUSTOM_KEYWORDS);
```

### Performance Considerations

- **SecurityPayloadTester**: Respects maxParallelTests for concurrency
- **SecurityResponseAnalyzer**: ~100ms per response analysis
- **Pattern Matching**: ~50ms for full description scan
- Batch processing reduces memory overhead (BATCH_SIZE=10, BATCH_INTERVAL=500ms)

---

## Migration Guide

### SecurityResponseAnalyzer Refactoring (Issue #53, v2.0.0)

If you have code using internal SecurityResponseAnalyzer methods:

**Backward Compatibility** (v2.0.0+):

- All public methods remain on SecurityResponseAnalyzer facade
- No API changes - existing code continues to work
- Internal implementation details are now delegated to focused classes

**Direct Class Usage** (for advanced scenarios):

```typescript
// OLD: Use facade (still works!)
import { SecurityResponseAnalyzer } from "@/services/assessment/modules/securityTests";
const analyzer = new SecurityResponseAnalyzer();
const result = analyzer.analyzeResponse(response, payload, tool);

// NEW: Direct access to focused classes (if needed)
import {
  ErrorClassifier,
  ExecutionArtifactDetector,
  MathAnalyzer,
  SafeResponseDetector,
  ConfidenceScorer,
} from "@/services/assessment/modules/securityTests";

const errorClassifier = new ErrorClassifier();
const isConnection = errorClassifier.isConnectionError(response);

const executionDetector = new ExecutionArtifactDetector();
const hasExecution = executionDetector.hasExecutionEvidence(responseText);
```

**Why This Refactoring**:

- **Cyclomatic Complexity**: Reduced from 218 to ~50 (facade only)
- **Maintainability**: Each class handles one responsibility
- **Testability**: Focused classes are easier to unit test
- **Pattern Reuse**: SecurityPatternLibrary eliminates 16 duplicate pattern collections

### From Monolithic SecurityAssessor to Modular Components

If moving from legacy SecurityAssessor:

```typescript
// OLD: Single monolithic class
import { SecurityAssessor } from "@/services/assessment/modules";
const assessor = new SecurityAssessor();

// NEW: Modular components
import {
  SecurityPayloadTester,
  SecurityResponseAnalyzer,
  SecurityPayloadGenerator,
} from "@/services/assessment/modules/securityTests";

const tester = new SecurityPayloadTester(config, logger, executeWithTimeout);
const analyzer = new SecurityResponseAnalyzer();
const generator = new SecurityPayloadGenerator();

// Same interfaces, more flexible composition
```

---

## Related Documentation

- **ASSESSMENT_CATALOG.md** - Complete assessment module reference
- **SECURITY_PATTERNS_CATALOG.md** - Attack patterns and payloads
- **ASSESSMENT_MODULE_DEVELOPER_GUIDE.md** - Creating custom assessment modules
- **CLI_ASSESSMENT_GUIDE.md** - CLI usage and integration
- **ARCHITECTURE_AND_VALUE.md** - System architecture overview

---

## Support and Contributions

For issues or contributions:

1. Check existing test files in `client/src/services/assessment/__tests__/`
2. Follow TypeScript strict mode guidelines
3. Add tests for new patterns or behaviors
4. Update this documentation for new exports

---

**Last Updated**: January 2025
**Module Version**: 1.25.x+
**Target Audience**: Developer integrating MCP Inspector assessment modules
