# Assessment Module Developer Guide

A comprehensive guide for understanding, extending, and maintaining the MCP Inspector's 16+ assessment modules.

## Table of Contents

1. [Registry Pattern Overview](#registry-pattern-overview)
2. [Module Anatomy Overview](#module-anatomy-overview)
3. [Existing Modules Reference](#existing-modules-reference)
4. [Adding a New Module](#adding-a-new-module)
5. [Testing Assessment Modules](#testing-assessment-modules)
6. [Module Scoring Integration](#module-scoring-integration)
7. [Advanced Patterns](#advanced-patterns)

---

## Registry Pattern Overview

The MCP Inspector uses a registry pattern (Issue #91) to manage assessor instantiation, execution phases, and configuration. This architecture replaced 1149+ lines of imperative code in AssessmentOrchestrator with a declarative, modular system.

### Architecture Components

**Location**: `client/src/services/assessment/registry/`

| Module                   | Purpose                                                                                               |
| ------------------------ | ----------------------------------------------------------------------------------------------------- |
| `types.ts`               | Core interfaces: `AssessorDefinition`, `AssessmentPhase`, `AssessorConfigFlags`, `RegisteredAssessor` |
| `AssessorRegistry.ts`    | Central registry managing instance lifecycle, execution phases, and Claude bridge wiring              |
| `AssessorDefinitions.ts` | Declarative config for all 19 assessors - single source of truth                                      |
| `estimators.ts`          | Test count estimation functions for progress events                                                   |
| `index.ts`               | Public API exports                                                                                    |

### How It Works

1. **Definition**: Each assessor is declared once in `AssessorDefinitions.ts` with:
   - Assessor class and constructor
   - Configuration flags (primary + deprecated for BC)
   - Execution phase (0-5)
   - Test count estimator
   - Optional custom setup function

2. **Registration**: `AssessorRegistry.registerAll()` instantiates enabled assessors based on config:
   - Skips disabled assessors
   - Runs custom setup (e.g., pattern compilation for ToolAnnotationAssessor)
   - Wires Claude bridge if enabled
   - Tracks failed registrations for resilience reporting

3. **Execution**: `AssessorRegistry.executeAll()` runs assessors in phase order:
   - Phase 0 (PRE): Always sequential for baseline capture
   - Phases 1-5: Parallel or sequential based on `config.parallelTesting`
   - Uses `Promise.allSettled()` for graceful degradation (P1 fix)
   - Emits progress events for each assessor

### Key Benefits

- **Modularity**: Assessor logic isolated from orchestration
- **Declarative**: Single source of truth for all assessor config
- **Testability**: Registry and assessors tested independently
- **Resilience**: Failed assessor doesn't block others (graceful degradation)
- **Discoverability**: New developers can see all assessors at a glance

### Important API Notes

- **`updateConfig()`**: Only updates config for future operations, does NOT re-register assessors
- **Failed Registration Tracking**: Use `getFailedRegistrations()` to report partial results
- **Phase Ordering**: Phase 0 always runs first and sequentially; other phases respect `parallelTesting` config

For implementation details, see `AssessorRegistry` class documentation in the source.

---

## Module Anatomy Overview

### File Structure and Naming Conventions

Assessment modules follow a consistent structure for discoverability and maintainability:

```
client/src/services/assessment/modules/
├── index.ts                           # Central export hub
├── BaseAssessor.ts                    # Base class with common functionality
├── FunctionalityAssessor.ts           # Original module (core)
├── FunctionalityAssessor.test.ts      # Unit tests
├── SecurityAssessor.ts                # Original module (core)
├── SecurityAssessor.test.ts
├── DocumentationAssessor.ts
├── DocumentationAssessor.test.ts
├── ErrorHandlingAssessor.ts
├── ErrorHandlingAssessor.test.ts
├── UsabilityAssessor.ts
├── UsabilityAssessor.test.ts
├── MCPSpecComplianceAssessor.ts       # Extended module
├── MCPSpecComplianceAssessor.test.ts
├── AUPComplianceAssessor.ts           # MCP Directory compliance
├── AUPComplianceAssessor.test.ts
├── ToolAnnotationAssessor.ts          # Policy #17
├── ToolAnnotationAssessor.test.ts
├── ProhibitedLibrariesAssessor.ts     # Policy #28-30
├── ProhibitedLibrariesAssessor.test.ts
├── ManifestValidationAssessor.ts      # MCPB manifest
├── ManifestValidationAssessor.test.ts
├── PortabilityAssessor.ts             # Portability checks
├── PortabilityAssessor.test.ts
├── ExternalAPIScannerAssessor.ts      # API detection
├── TemporalAssessor.ts                # Rug pull detection (orchestrator)
├── temporal/
│   ├── index.ts                       # Barrel exports
│   ├── MutationDetector.ts            # Definition mutation detection
│   └── VarianceClassifier.ts          # Response variance classification
├── ResourceAssessor.ts                # MCP Resources capability
├── PromptAssessor.ts                  # MCP Prompts capability
├── CrossCapabilitySecurityAssessor.ts # Cross-capability security
├── AuthenticationAssessor.ts          # OAuth evaluation
└── helpers/
    ├── ExternalAPIDependencyDetector.ts  # Shared helper: external API detection
    └── ExternalAPIDependencyDetector.test.ts
```

### Base Interfaces

All assessment modules extend `BaseAssessor` and implement the core `assess()` method:

```typescript
/**
 * Base class for all assessment modules
 * Location: client/src/services/assessment/modules/BaseAssessor.ts
 *
 * Generic Type Parameter:
 * - T (optional, defaults to unknown): Specifies the return type for type-safe assess() method
 * - Enables compile-time type checking when implementing custom assessment modules
 * - Usage: export class YourAssessor extends BaseAssessor<YourAssessmentType>
 */
export abstract class BaseAssessor<T = unknown> {
  protected config: AssessmentConfiguration;
  protected testCount: number = 0;

  constructor(config: AssessmentConfiguration) {
    this.config = config;
  }

  // REQUIRED: Implement this abstract method with proper return type
  abstract assess(context: AssessmentContext): Promise<T>;

  // OPTIONAL: Override utility methods
  protected determineStatus(
    passed: number,
    total: number,
    threshold: number = 0.8,
  ): AssessmentStatus {
    // Helper: calculates "PASS" / "FAIL" / "NEED_MORE_INFO"
  }

  protected log(message: string): void {
    // Helper: logs with [ModuleName] prefix
  }

  protected logError(message: string, error?: any): void {
    // Helper: logs errors with module context
  }

  // Utility methods for common patterns
  protected async executeWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs?: number,
  ): Promise<T> {}

  protected safeJsonParse(text: string): any {}

  protected extractErrorMessage(error: any): string {}

  protected isErrorResponse(
    response: any,
    strictMode: boolean = false,
  ): boolean {}

  protected isFeatureEnabled(
    feature: keyof AssessmentConfiguration["assessmentCategories"],
  ): boolean {}

  protected async sleep(ms: number): Promise<void> {}
}
```

### AssessmentContext Interface

Each `assess()` method receives an `AssessmentContext` containing all MCP server information:

```typescript
/**
 * Assessment context passed to each module's assess() method
 * Location: client/src/services/assessment/AssessmentOrchestrator.ts
 */
export interface AssessmentContext {
  // Server metadata
  serverName: string;
  serverVersion?: string;
  serverInfo?: ServerInfo;

  // Tool and capability data
  tools: Tool[]; // MCP tools/list response
  resources?: MCPResource[]; // MCP resources capability
  resourceTemplates?: MCPResourceTemplate[]; // Resource templates
  prompts?: MCPPrompt[]; // MCP prompts capability

  // File content for analysis
  readmeContent?: string; // Raw README.md content
  sourceCodePath?: string; // Path to source code for analysis
  packageJsonContent?: string; // package.json or pyproject.toml

  // Configuration and utilities
  config: AssessmentConfiguration;
  callTool: (
    name: string,
    args: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  listResources?: () => Promise<MCPResource[]>;

  // MCPB bundle specific
  manifestContent?: string; // manifest.json for MCPB bundles
  bundleRootPath?: string; // Root path for bundle portability checks
}
```

### Return Type Contract

Every assessment module returns a specific assessment type. The return type name follows the pattern: `{Module}Assessment`.

```typescript
// FunctionalityAssessor returns FunctionalityAssessment
export interface FunctionalityAssessment {
  totalTools: number;
  testedTools: number;
  workingTools: number;
  brokenTools: string[];
  coveragePercentage: number;
  status: AssessmentStatus; // "PASS" | "FAIL" | "NEED_MORE_INFO"
  explanation: string;
  toolResults: ToolTestResult[];
}

// SecurityAssessor returns SecurityAssessment
export interface SecurityAssessment {
  promptInjectionTests: SecurityTestResult[];
  vulnerabilities: string[];
  overallRiskLevel: SecurityRiskLevel;
  status: AssessmentStatus;
  explanation: string;
}
```

**Key rule**: The module name (without "Assessor") + "Assessment" = return type name.

---

## Existing Modules Reference

### 1. FunctionalityAssessor (Core)

**Purpose**: Tests tool execution and validates basic functionality

**Key Features**:

- Multi-scenario testing per tool (happy path, edge cases, boundaries)
- Progressive complexity detection
- Concurrency-limited parallel testing
- Context-aware test data generation

**Return Type**: `FunctionalityAssessment`

**Configuration**:

```typescript
{
  selectedToolsForTesting?: string[];      // Tools to test (undefined = all)
  scenariosPerTool?: number;               // Max scenarios per tool (default 5-20)
  maxParallelTests?: number;               // Concurrency limit (default 5)
  testTimeout?: number;                    // Per-test timeout in ms (default 30000)
}
```

**Implementation Location**: `client/src/services/assessment/modules/FunctionalityAssessor.ts`

**Key Methods**:

- `selectToolsForTesting(tools)` - Respects configuration, defaults to all tools
- `runUniversalSecurityTests(context)` - Multi-scenario testing orchestration
- `determineStatus()` - Calculates pass/fail based on scenario pass rate

---

### 2. SecurityAssessor (Core)

**Purpose**: Detects backend API security vulnerabilities using 23 focused attack patterns

**Vulnerability Categories**:

- Critical Injection (6): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
- Input Validation (3): Type Safety, Boundary Testing, Required Fields
- Protocol Compliance (2): MCP Error Format, Timeout Handling
- Tool-Specific (6): SSRF, Nested Injection, Package Squatting, Data Exfiltration, Configuration Drift, Tool Shadowing
- Encoding Bypass (1): Unicode Bypass
- Resource Exhaustion (1): DoS/Resource Exhaustion
- Deserialization (1): Insecure Deserialization

**Return Type**: `SecurityAssessment`

**Configuration**:

```typescript
{
  securityPatternsToTest?: number;    // Number of patterns to test (default 8)
  enableDomainTesting?: boolean;      // Advanced testing (default true)
  selectedToolsForTesting?: string[];
}
```

**Implementation Location**: `client/src/services/assessment/modules/SecurityAssessor.ts`

**Key Methods**:

- `runUniversalSecurityTests(context)` - Test all attack types on selected tools
- `selectToolsForTesting(tools)` - Filter tools based on configuration
- `separateConnectionErrors(tests)` - Distinguish connection errors from true vulnerabilities

**Helper Functions** (SecurityPatternLibrary):

- `isPayloadInErrorContext(response, payload)` - Checks if payload appears in error context (Issue #146)
- `hasSuccessContext(response)` - Detects success indicators in response (72 patterns)
- `hasErrorContext(response)` - Detects error indicators in response (61 patterns)
- `classifyVulnerabilityContext(response, payload, toolName)` - Classifies execution context to reduce false positives
- `adjustSeverityForAnnotations(attackName, riskLevel, annotations, serverReadOnly, serverClosed)` - Adjusts severity based on tool annotations (Issue #170)

**False Positive Reduction** (Issue #146):

The SecurityAssessor now includes execution context classification to distinguish between:

- **Actual code execution**: Payload executed and returned results → `executionContext: "CONFIRMED"`
- **Safe error reflection**: Payload echoed in error message → `executionContext: "LIKELY_FALSE_POSITIVE"`
- **Ambiguous cases**: Unclear context → `executionContext: "SUSPECTED"`

Example usage:

```typescript
const context = classifyVulnerabilityContext(response, payload, toolName);
if (context.executionContext === "LIKELY_FALSE_POSITIVE") {
  // Skip false positive - payload was rejected but echoed in error
  return { safe: true, evidence: context.contextEvidence };
}
```

**SecurityTestResult Fields**:

- `executionContext`: Classification of execution context (Issue #146)
- `contextEvidence`: Human-readable explanation
- `operationSucceeded`: Whether operation succeeded or failed
- `annotationAdjustment`: Tracks severity adjustments based on tool annotations (Issue #170)
  - `original`: Original risk level before adjustment
  - `adjusted`: Adjusted risk level after considering annotations
  - `reason`: Human-readable explanation for the adjustment

**Pattern Arrays** (SecurityPatternLibrary):

- `ERROR_CONTEXT_PATTERNS`: 61 error indicators (e.g., "invalid", "rejected", "validation failed")
- `SUCCESS_CONTEXT_PATTERNS`: 72 success indicators (e.g., "executed successfully", "operation completed")
- `AUTH_FAIL_OPEN_PATTERNS`: Authentication fail-open indicators (Issue #75)
- `AUTH_FAIL_CLOSED_PATTERNS`: Authentication fail-closed indicators (Issue #75)
- `STATE_AUTH_VULNERABLE_PATTERNS`: State-based auth bypass indicators (Issue #92)
- `STATE_AUTH_SAFE_PATTERNS`: Safe state management indicators (Issue #92)

---

### 3. DocumentationAssessor (Core)

**Purpose**: Evaluates README quality and tool documentation completeness

**Checks**:

- README presence and length
- Code example quality and count
- Installation instructions
- Usage guides
- API reference completeness
- Tool documentation gaps

**Return Type**: `DocumentationAssessment`

**Configuration**:

```typescript
{
  documentationVerbosity?: "minimal" | "standard" | "verbose";
  // minimal: boolean flags only
  // standard: includes readmeLength, sectionHeadings, toolDocumentation
  // verbose: includes full readmeContent (truncated to 5000 chars)
}
```

**Implementation Location**: `client/src/services/assessment/modules/DocumentationAssessor.ts`

**Key Methods**:

- `analyzeDocumentation(content, tools, verbosity)` - Multi-level documentation analysis
- `determineDocumentationStatus(metrics)` - Status calculation
- `generateRecommendations(metrics)` - Actionable improvement suggestions

---

### 4. ErrorHandlingAssessor (Core)

**Purpose**: Tests MCP protocol compliance for error handling

**Validation Tests**:

- Missing required parameters
- Wrong parameter types
- Extra/unexpected parameters
- Null/empty values
- Boundary conditions

**Return Type**: `ErrorHandlingAssessment`

**Configuration**:

```typescript
{
  selectedToolsForTesting?: string[];  // Tools to test (undefined = all, [] = none)
  // maxToolsToTestForErrors is deprecated - use selectedToolsForTesting instead
}
```

**Implementation Location**: `client/src/services/assessment/modules/ErrorHandlingAssessor.ts`

---

### 5. UsabilityAssessor (Core)

**Purpose**: Evaluates tool naming conventions, parameter clarity, and schema quality

**Checks**:

- Naming convention consistency (camelCase, snake_case, kebab-case)
- Description quality and length
- Parameter schema completeness
- Best practices alignment

**Return Type**: `UsabilityAssessment`

**Implementation Location**: `client/src/services/assessment/modules/UsabilityAssessor.ts`

---

### 6. MCPSpecComplianceAssessor (Extended)

**Purpose**: Verifies MCP protocol specification compliance

**Hybrid Structure**:

- **Protocol Checks** (high confidence, tested via MCP calls):
  - JSON-RPC compliance
  - Server info validity
  - Schema compliance
  - Error response compliance
  - Structured output support
  - Capabilities compliance

- **Metadata Hints** (low confidence, parsed from metadata):
  - Transport detection (stdio, HTTP, SSE)
  - OAuth configuration hints
  - Annotation support hints
  - Streaming support hints

**Return Type**: `MCPSpecComplianceAssessment`

**Implementation Location**: `client/src/services/assessment/modules/MCPSpecComplianceAssessor.ts`

---

### 7. AUPComplianceAssessor (MCP Directory)

**Purpose**: Detects Acceptable Use Policy violations in 14 categories

**Categories Scanned**:

- A: Child Sexual Abuse Material
- B: Weapons of Mass Destruction
- C: Malware & Cyberweapons
- D: Disinformation & Election Interference
- E: Fraud & Deception
- F: Harassment & Abuse
- G: Privacy Violations
- H: Unauthorized Practice
- I: Copyright Circumvention
- J: High-Risk Decisions
- K: Critical Infrastructure
- L: Adult Content
- M: Illegal Activities
- N: Other Prohibited Uses

**Scan Locations**:

- Tool names and descriptions
- README content
- Source code (if available)

**Return Type**: `AUPComplianceAssessment`

**Implementation Location**: `client/src/services/assessment/modules/AUPComplianceAssessor.ts`

---

### 8. ToolAnnotationAssessor (MCP Directory - Policy #17)

**Purpose**: Verifies tool annotations accuracy and completeness

**Checks**:

- `readOnlyHint` presence and accuracy
- `destructiveHint` presence and accuracy
- Tool behavior inference from name patterns
- Annotation misalignment detection
- Description poisoning detection (Issue #8)

**Alignment Statuses**:

- `ALIGNED`: Annotations match inferred behavior
- `MISALIGNED`: Clear contradiction (e.g., delete\_\* with readOnlyHint=true)
- `REVIEW_RECOMMENDED`: Ambiguous patterns (e.g., store*\*, cache*\*)
- `UNKNOWN`: No annotations and no clear name pattern

**Return Type**: `ToolAnnotationAssessment`

**Implementation Location**: `client/src/services/assessment/modules/ToolAnnotationAssessor.ts`

**Key Methods**:

- `inferBehaviorFromName(toolName)` - Pattern-based behavior inference
- `detectDescriptionPoisoning(description)` - Malicious instruction detection
- `checkAnnotationAlignment(tool)` - Annotation vs behavior comparison

---

### 9. ProhibitedLibrariesAssessor (MCP Directory - Policy #28-30)

**Purpose**: Detects prohibited financial and media processing libraries

**Prohibited Categories**:

- Financial: stripe, square, payment SDKs
- Media: ffmpeg, imagemagick, video processing
- Payments: payment gateways
- Banking: banking SDKs

**Scan Locations**:

- package.json dependencies
- requirements.txt (Python)
- Cargo.toml (Rust)
- Source code imports

**Return Type**: `ProhibitedLibrariesAssessment`

**Implementation Location**: `client/src/services/assessment/modules/ProhibitedLibrariesAssessor.ts`

---

### 10. ManifestValidationAssessor (MCPB Bundle-Specific)

**Purpose**: Validates MCPB manifest.json structure and content

**Checks**:

- manifest_version validity
- Required fields presence (name, version, mcp_config)
- Icon validity and presence
- Privacy policy URLs accessibility
- Command and args format
- Semantic versioning compliance
- Author email format validation

**Return Type**: `ManifestValidationAssessment`

**Configuration**:

```typescript
manifestValidation?: boolean;  // Only enabled in bundle-specific assessment modes
```

**Implementation Constants** (Issue #140):

- `SEMVER_PATTERN`: Shared regex for semantic version validation (FIX-001)
  - Pattern: `/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/`
  - Validates: X.Y.Z format with optional pre-release and build metadata
  - Used by: `extractVersionInfo()` and `validateVersionFormat()`

**Email Validation** (Issue #140 FIX-002):

- Author string format: `"Name <email@example.com>"`
- Regex pattern: `/<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>/`
- Validates: Proper email format with TLD (2+ characters)
- Rejects: Invalid emails like `<invalid>`, `<test@localhost>`

**Testing Coverage** (56 total tests, 16 added in v1.24.2):

- Levenshtein distance algorithm: 13 tests (edit distance calculations, Unicode support)
- findClosestMatch integration: 6 tests (typo suggestions, threshold logic)
- fetchWithRetry exponential backoff: 6 tests (retry logic, HEAD/GET fallback)

**Implementation Location**: `client/src/services/assessment/modules/ManifestValidationAssessor.ts`

---

### 11. PortabilityAssessor (MCPB Bundle-Specific)

**Purpose**: Detects hardcoded paths and platform-specific code

**Issue Types**:

- Hardcoded paths (/home/user, C:\Users)
- Platform-specific code (Windows-only, Linux-only)
- Bundle root antipatterns
- Absolute paths
- User home directory paths

**Return Type**: `PortabilityAssessment`

**Implementation Location**: `client/src/services/assessment/modules/PortabilityAssessor.ts`

---

### 12. ExternalAPIScannerAssessor

**Purpose**: Detects external API usage and verifies affiliation claims

**Scanned Services**:

- GitHub APIs
- Slack APIs
- AWS APIs
- OpenAI APIs
- Anthropic APIs

**Checks**:

- API endpoint detection in source
- Service affiliation verification
- Unverified affiliation warnings

**Return Type**: `ExternalAPIScannerAssessment`

**Implementation Location**: `client/src/services/assessment/modules/ExternalAPIScannerAssessor.ts`

---

### 13. AuthenticationAssessor

**Purpose**: Evaluates OAuth and API key authentication appropriateness

**Auth Methods**:

- OAuth 2.0
- API Key
- No authentication
- Unknown

**Return Type**: `AuthenticationAssessment`

**Implementation Location**: `client/src/services/assessment/modules/AuthenticationAssessor.ts`

---

### 14. TemporalAssessor (Rug Pull Detection)

**Purpose**: Detects tools that change behavior after N invocations

**Vulnerability Patterns**:

- RUG_PULL_TEMPORAL: Tool changes behavior after N invocations
- RUG_PULL_DEFINITION: Tool schema/description mutates during invocations

**Configuration**:

```typescript
{
  temporalInvocations?: number;  // Invocations per tool (default 3)
}
```

**Return Type**: `TemporalAssessment`

**Architecture** (Issue #106 refactoring):

The TemporalAssessor is split into focused modules for maintainability:

- **TemporalAssessor.ts** (561 lines) - Orchestration and invocation loop
- **temporal/MutationDetector.ts** (202 lines) - Definition & content mutation detection
  - Detects schema changes and description poisoning
  - Used to identify DVMCP Challenge 4 (rug pull via description mutation)
- **temporal/VarianceClassifier.ts** (517 lines) - Response variance classification
  - Distinguishes legitimate variance (side-effect tools) from anomalies
  - Reduces false positives with pattern-based tool classification

**Implementation Location**: `client/src/services/assessment/modules/TemporalAssessor.ts` (primary) + `temporal/` helpers

---

### 15. ResourceAssessor (MCP Resources Capability)

**Purpose**: Tests MCP resources for security and compliance vulnerabilities

**Checks**:

- Path traversal vulnerabilities
- Sensitive data exposure
- Prompt injection in resources
- Access control validation
- URI validity

**Return Type**: `ResourceAssessment`

**Implementation Location**: `client/src/services/assessment/modules/ResourceAssessor.ts`

---

### 16. PromptAssessor (MCP Prompts Capability)

**Purpose**: Tests MCP prompts for security and AUP compliance

**Checks**:

- Argument validation
- AUP compliance
- Prompt injection vulnerabilities
- Template safety

**Return Type**: `PromptAssessment`

**Implementation Location**: `client/src/services/assessment/modules/PromptAssessor.ts`

---

### 17. CrossCapabilitySecurityAssessor

**Purpose**: Tests interactions between tools, resources, and prompts for privilege escalation

**Test Types**:

- tool_to_resource: Can tools access sensitive resources?
- prompt_to_tool: Can prompts invoke dangerous tools?
- resource_to_tool: Can resource data influence tool behavior?
- privilege_escalation: Data exfiltration chains?

**Return Type**: `CrossCapabilitySecurityAssessment`

**Implementation Location**: `client/src/services/assessment/modules/CrossCapabilitySecurityAssessor.ts`

---

## Adding a New Module

### Step 1: Create the Module File

Create `client/src/services/assessment/modules/YourNewAssessor.ts`:

```typescript
/**
 * Your New Assessor Module
 * Brief description of what it assesses
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentStatus } from "@/lib/assessment/coreTypes";
import type { YourNewAssessment } from "@/lib/assessment/resultTypes";
// Or use barrel export for convenience:
// import type { YourNewAssessment, AssessmentStatus } from "@/lib/assessment";

export class YourNewAssessor extends BaseAssessor {
  /**
   * Main assessment method - called by orchestrator
   * @param context - Assessment context with tools, resources, config, etc.
   * @returns Assessment results with status and recommendations
   */
  async assess(context: AssessmentContext): Promise<YourNewAssessment> {
    this.log("Starting your new assessment");

    // 1. Perform analysis
    const analysisResults = this.performAnalysis(context);

    // 2. Determine status
    const status = this.determineStatus(
      analysisResults.passed,
      analysisResults.total,
      0.8, // threshold
    );

    // 3. Generate explanation
    const explanation = this.generateExplanation(analysisResults);

    // 4. Generate recommendations
    const recommendations = this.generateRecommendations(analysisResults);

    return {
      status,
      explanation,
      recommendations,
      // ... your specific assessment fields
    };
  }

  private performAnalysis(context: AssessmentContext): AnalysisResult {
    // Your analysis logic here
    // Access context.tools, context.readmeContent, context.config, etc.

    // Example: iterate through tools
    for (const tool of context.tools) {
      this.log(`Analyzing tool: ${tool.name}`);
      // Perform checks
    }

    return {
      passed: 10,
      total: 15,
      // ... other results
    };
  }

  private generateExplanation(results: AnalysisResult): string {
    // Create human-readable explanation of results
    return `Your assessment found X issues and Y recommendations.`;
  }

  private generateRecommendations(results: AnalysisResult): string[] {
    // Return array of actionable recommendations
    return ["Fix X", "Improve Y"];
  }
}
```

### Step 2: Define Return Type in Assessment Module

The assessment types are organized into focused modules. Choose the correct module based on your type's purpose:

**Module Selection Guide:**

| Type Purpose                                | Target Module        | Add To                               |
| ------------------------------------------- | -------------------- | ------------------------------------ |
| Status, enums, metadata                     | `coreTypes.ts`       | Base type definitions                |
| Configuration-related types                 | `configTypes.ts`     | AssessmentConfiguration interfaces   |
| **Main assessment result (recommended)**    | **`resultTypes.ts`** | **MCPDirectoryAssessment interface** |
| Extended/compliance types (AUP, Annotation) | `extendedTypes.ts`   | Extended assessment types            |
| Progress/streaming events                   | `progressTypes.ts`   | Event type definitions               |
| Constant values or lookup arrays            | `constants.ts`       | Constant exports                     |

**For most new assessments, add your type to `client/src/lib/assessment/resultTypes.ts`:**

```typescript
/**
 * Your New Assessment
 */
export interface YourNewResult {
  toolName: string;
  passed: boolean;
  issues: string[];
}

export interface YourNewAssessment {
  results: YourNewResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  // Additional fields specific to your assessment
  metrics?: {
    checked: number;
    passed: number;
    coverage: number;
  };
}

// Add to MCPDirectoryAssessment (in same file)
export interface MCPDirectoryAssessment {
  // ... existing fields ...
  yourNewAssessment?: YourNewAssessment; // NEW
}
```

**If your assessment needs configuration options, add to `client/src/lib/assessment/configTypes.ts`:**

```typescript
export interface AssessmentConfiguration {
  assessmentCategories?: {
    // ... existing categories ...
    yourNewAssessment?: boolean; // NEW
  };
}
```

**If your assessment needs metadata, add to `client/src/lib/assessment/coreTypes.ts`:**

```typescript
export const ASSESSMENT_CATEGORY_METADATA: Record<
  string,
  AssessmentCategoryMetadata
> = {
  // ... existing entries ...
  yourNewAssessment: {
    tier: "core",                           // or "optional"
    description: "Your assessment description",
    applicableTo?: "All MCP servers",       // optional
  },
};
```

**Import Guide:**

- Exports continue to work via barrel export: `import type { YourNewAssessment } from "@/lib/assessment"`
- Or import from specific modules: `import type { YourNewAssessment } from "@/lib/assessment/resultTypes"`
- See [ASSESSMENT_TYPES_IMPORT_GUIDE.md](ASSESSMENT_TYPES_IMPORT_GUIDE.md) for detailed module organization

### Step 3: Export from index.ts

Add to `client/src/services/assessment/modules/index.ts`:

```typescript
/**
 * MCP Server Assessment Modules
 */

// ... existing exports ...

// Your new module
export { YourNewAssessor } from "./YourNewAssessor";
```

### Step 4: Register in AssessmentOrchestrator

Add to `client/src/services/assessment/AssessmentOrchestrator.ts`:

```typescript
import { YourNewAssessor } from "./modules/YourNewAssessor";

export class AssessmentOrchestrator {
  private yourNewAssessor: YourNewAssessor;

  constructor(config: AssessmentConfiguration) {
    // ... existing initializations ...

    // Initialize your new assessor
    this.yourNewAssessor = new YourNewAssessor(config);
  }

  async runAssessment(
    context: AssessmentContext,
  ): Promise<MCPDirectoryAssessment> {
    const result: MCPDirectoryAssessment = {
      // ... existing results ...
    };

    // Add your assessment if enabled
    if (this.config.assessmentCategories?.yourNewAssessment) {
      emitModuleStartedEvent("yourNewAssessment", estimatedTests, toolCount);

      try {
        result.yourNewAssessment = await this.yourNewAssessor.assess(context);
        emitModuleProgress(
          "yourNewAssessment",
          result.yourNewAssessment.status,
          result.yourNewAssessment,
        );
      } catch (error) {
        this.logError("Your new assessment failed", error);
      }
    }

    return result;
  }
}
```

### Step 5: Add Data Extraction for CLI (if applicable)

If your module should be extracted for CLI analysis, add to `scripts/data-extraction.js`:

```javascript
// In the extractModuleData function
case "yourNewAssessment":
  return {
    status: result.yourNewAssessment?.status,
    explanation: result.yourNewAssessment?.explanation,
    recommendations: result.yourNewAssessment?.recommendations,
    metrics: result.yourNewAssessment?.metrics,
    resultsCount: result.yourNewAssessment?.results?.length || 0,
  };
```

### Step 6: Add to Stage Transformation (if applicable)

If your module affects the overall assessment stage, add to `scripts/stage-transformation.js`:

```javascript
// Add to stage determination logic
if (
  result.yourNewAssessment?.status === "FAIL" &&
  result.assessment.assessmentMetadata?.sourceCodeAvailable
) {
  // This could affect stage determination
}
```

---

## Testing Assessment Modules

### Unit Test Pattern

Create `client/src/services/assessment/modules/YourNewAssessor.test.ts`:

```typescript
import { YourNewAssessor } from "./YourNewAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("YourNewAssessor", () => {
  let assessor: YourNewAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new YourNewAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should return assessment with all tools checked", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "tool1" }),
        createMockTool({ name: "tool2" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.status).toBe("PASS");
      expect(result.recommendations).toBeDefined();
      expect(Array.isArray(result.recommendations)).toBe(true);
    });

    it("should detect issues correctly", async () => {
      // Arrange
      mockContext.tools = [createMockTool({ name: "problematic_tool" })];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.results?.length).toBeGreaterThan(0);
      expect(result.explanation).toContain("issue");
    });

    it("should handle empty tool list", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("NEED_MORE_INFO");
    });
  });
});
```

### Integration Testing with Vulnerable MCP Testbed

Test your module against known-vulnerable and known-safe servers:

```bash
# Test with vulnerable server (should detect issues)
npm run assess -- --server vulnerable-mcp \
  --config /tmp/vulnerable-mcp-config.json

# Test with hardened server (should find no issues)
npm run assess -- --server hardened-mcp \
  --config /tmp/hardened-mcp-config.json

# Expected A/B difference indicates correct detection
```

### Configuration for Testing

```typescript
// test/fixtures/assessment-config.ts
export const TEST_CONFIG: AssessmentConfiguration = {
  testTimeout: 5000,
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true,
  maxParallelTests: 2,
  assessmentCategories: {
    yourNewAssessment: true,
    // ... other categories
  },
};
```

---

## Module Scoring Integration

### How Scores Flow to Overall Assessment

The MCP Inspector uses a weighted scoring system:

```
Overall Score = Σ(Module Score × Module Weight) / Σ(Weights)
```

### Calculate Module Score

Use the `calculateModuleScore()` helper from `client/src/lib/moduleScoring.ts`:

```typescript
import { calculateModuleScore } from "@/lib/moduleScoring";

// In AssessmentOrchestrator
const score = calculateModuleScore(result.yourNewAssessment);
// Automatically converts:
// - "PASS" → 100
// - "NEED_MORE_INFO" → 50
// - "FAIL" → 0
```

### Score Calculation Logic

```typescript
// In lib/moduleScoring.ts
export function calculateModuleScore(assessment: any): number {
  if (!assessment) return 0;

  if (assessment.status === "PASS") return 100;
  if (assessment.status === "NEED_MORE_INFO") return 50;
  if (assessment.status === "FAIL") return 0;

  // Handle edge cases
  return 0;
}
```

### Module Weights (if custom weighting needed)

```typescript
// client/src/lib/moduleScoring.ts
const MODULE_WEIGHTS = {
  functionality: 1.0, // Core requirement
  security: 1.0, // Core requirement
  documentation: 0.8, // Important but not critical
  errorHandling: 0.9, // Critical for compliance
  usability: 0.7, // Enhancement
  yourNewAssessment: 0.6, // Custom weight for your module
};
```

### Handling N/A Modules

Some modules may be inapplicable to a server (e.g., portability only applies to MCPB bundles):

```typescript
// In your assessor
async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  // Check if assessment is applicable
  if (!this.isApplicable(context)) {
    return {
      status: "NEED_MORE_INFO",  // Not "FAIL" - indicates inapplicable
      explanation: "This assessment is only applicable to MCPB bundles",
      recommendations: [],
    };
  }

  // Normal assessment logic
}
```

### Real-Time Progress Events

Modules can emit real-time progress events for CLI integration:

```typescript
// In your assessor
private emitProgress(moduleName: string, status: string, result: any): void {
  const score = calculateModuleScore(result);

  console.error(JSON.stringify({
    event: "module_complete",
    module: moduleName,
    status,
    score,
    testsRun: result.results?.length || 0,
    duration: Date.now() - this.moduleStartTime,
  }));
}
```

---

## Advanced Patterns

### Pattern 1: Multi-Tool Concurrent Testing

Use `createConcurrencyLimit()` for parallel tool testing with rate limiting:

```typescript
import { createConcurrencyLimit } from "../lib/concurrencyLimit";

async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  const concurrency = this.config.maxParallelTests ?? 5;
  const limit = createConcurrencyLimit(concurrency);

  const promises = context.tools.map((tool) =>
    limit(() => this.testTool(tool))
  );

  const results = await Promise.all(promises);
  // ... process results
}
```

### Pattern 2: Tool Behavior Inference

Infer tool behavior from naming patterns (used in ToolAnnotationAssessor):

```typescript
private inferBehaviorFromName(toolName: string): {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  reason: string;
} {
  const lower = toolName.toLowerCase();

  // Destructive patterns
  if (
    /^(delete|remove|destroy|drop|purge|unlink)_/.test(lower)
  ) {
    return {
      expectedDestructive: true,
      expectedReadOnly: false,
      reason: "Tool name matches destructive pattern (delete_*, remove_*, etc.)",
    };
  }

  // Read-only patterns
  if (/^(get|list|fetch|read|search|query)_/.test(lower)) {
    return {
      expectedDestructive: false,
      expectedReadOnly: true,
      reason: "Tool name matches read-only pattern (get_*, list_*, etc.)",
    };
  }

  return {
    expectedDestructive: false,
    expectedReadOnly: false,
    reason: "Tool name does not match known pattern",
  };
}
```

### Pattern 2b: Annotation Exemption Patterns (Issue #18)

When inference patterns produce false positives, add exemption patterns to handle edge cases:

```typescript
// Step 1: Define exempt suffixes that override default inference
const RUN_READONLY_EXEMPT_SUFFIXES = [
  "audit", "check", "scan", "test", "mode", "analyze",
  "report", "status", "validate", "verify", "inspect", "lint",
  "benchmark", "diagnostic"
];

// Step 2: Create exemption check function
function isRunKeywordExempt(toolName: string): boolean {
  const lowerName = toolName.toLowerCase();
  if (!lowerName.includes("run")) return false;
  return RUN_READONLY_EXEMPT_SUFFIXES.some((suffix) =>
    lowerName.includes(suffix),
  );
}

// Step 3: Apply exemption BEFORE pattern matching in inferBehavior()
private inferBehavior(toolName: string, description?: string) {
  // Exemption check first (handles runAccessibilityAudit, runSEOAudit, etc.)
  if (isRunKeywordExempt(toolName)) {
    return {
      expectedReadOnly: true,
      expectedDestructive: false,
      reason: "Tool name contains 'run' with analysis suffix - read-only operation",
      confidence: "medium",
    };
  }

  // Then apply standard pattern matching...
  const patternMatch = matchToolPattern(toolName, this.compiledPatterns);
  // ...
}

// Step 4: Also apply in detectAnnotationDeception() to prevent false deception flags
if (keyword === "run" && isRunKeywordExempt(toolName)) {
  // Skip deception flagging - tool is legitimately read-only
} else {
  return { field: "readOnlyHint", reason: "DECEPTIVE..." };
}
```

**Key Points**:

- Exemption checks run BEFORE standard pattern matching
- Use "medium" confidence for exempted tools (inferred from naming, not behavior)
- Add comprehensive tests for exempted AND non-exempted cases
- Reference: See `ToolAnnotationAssessor.ts` lines 104-119 for Issue #18 implementation

### Pattern 3: Regex Pattern Matching (for scanning)

AUPComplianceAssessor demonstrates pattern-based vulnerability scanning:

```typescript
private scanForPatterns(
  content: string,
  patterns: ScanPattern[]
): ViolationMatch[] {
  const matches: ViolationMatch[] = [];

  for (const pattern of patterns) {
    const regex = new RegExp(pattern.regex, "gi");
    let match;

    while ((match = regex.exec(content)) !== null) {
      matches.push({
        pattern: pattern.name,
        matchedText: match[0],
        position: match.index,
        severity: pattern.severity,
      });
    }
  }

  return matches;
}
```

### Pattern 4: Annotation-Aware Security Testing (Issue #170)

Use tool annotations to reduce false positives in security assessments:

```typescript
import { extractToolAnnotationsContext } from "../helpers/ToolAnnotationExtractor";
import { adjustSeverityForAnnotations } from "../modules/securityTests/AnnotationAwareSeverity";
import type {
  ToolAnnotationsContext,
  SecurityAnnotations,
} from "@/lib/assessment/coreTypes";

// Step 1: Extract annotations context during assessment preparation
const annotationsContext = extractToolAnnotationsContext(context.tools);

// Step 2: Pass context to security tester
const tester = new SecurityPayloadTester(/* ... */);
tester.setToolAnnotationsContext(annotationsContext);

// Step 3: Severity adjustment is applied automatically during testing
// Results include annotationAdjustment field when severity was adjusted

// Step 4: Manually adjust severity for custom security tests
const adjustment = adjustSeverityForAnnotations(
  "Command Injection", // Attack name
  "HIGH", // Original risk level
  toolAnnotations, // Per-tool annotations
  annotationsContext.serverIsReadOnly, // Server-level read-only flag
  annotationsContext.serverIsClosed, // Server-level closed-world flag
);

if (adjustment.wasAdjusted) {
  console.log(adjustment.adjustmentReason);
  // Use adjustment.adjustedRiskLevel instead of original
}
```

**Key Concepts**:

- **Execution-Type Attacks**: Command Injection, Code Execution, Path Traversal, etc.
  - Downgraded to LOW for tools with `readOnlyHint: true`
- **Exfiltration-Type Attacks**: SSRF, Data Exfiltration, Token Theft, etc.
  - Downgraded to LOW for tools with `openWorldHint: false`
- **Server-Level Flags**: Apply when ALL annotated tools have the same annotation
- **Transparency**: All adjustments tracked in `SecurityTestResult.annotationAdjustment`

**Implementation Files**:

- `client/src/services/assessment/helpers/ToolAnnotationExtractor.ts` - Context extraction
- `client/src/services/assessment/modules/securityTests/AnnotationAwareSeverity.ts` - Adjustment logic
- `client/src/services/assessment/modules/securityTests/SecurityPayloadTester.ts` - Integration point

### Pattern 5: Configuration-Driven Assessment

Use `this.isFeatureEnabled()` to conditionally run assessment features:

```typescript
async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  // Check if detailed analysis is enabled
  if (this.isFeatureEnabled("yourNewAssessment")) {
    const detailedResults = await this.performDetailedAnalysis(context);
    // ... use detailed results
  } else {
    const quickResults = await this.performQuickCheck(context);
    // ... use quick results
  }
}
```

### Pattern 5: Timeout Protection

Wrap long-running operations with timeout protection:

```typescript
private async testToolWithTimeout(
  tool: Tool,
  context: AssessmentContext
): Promise<TestResult> {
  try {
    return await this.executeWithTimeout(
      this.testTool(tool, context),
      this.config.testTimeout
    );
  } catch (error) {
    if (error instanceof TimeoutError) {
      return {
        toolName: tool.name,
        error: `Tool test timed out after ${this.config.testTimeout}ms`,
        status: "timeout",
      };
    }
    throw error;
  }
}
```

### Pattern 6: Progress Callback Emission

For long-running assessments, emit progress events:

```typescript
async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  const results = [];
  const total = context.tools.length;

  for (let i = 0; i < total; i++) {
    const tool = context.tools[i];
    const result = await this.testTool(tool);
    results.push(result);

    // Emit progress batch every 5 tests
    if ((i + 1) % 5 === 0) {
      context.onProgress?.({
        type: "test_batch",
        module: "yourNewAssessment",
        completed: i + 1,
        total,
        batchSize: 5,
        elapsed: Date.now() - this.startTime,
      });
    }
  }

  return { /* ... */ };
}
```

### Pattern 6.5: Accurate Progress Estimation with selectedToolsForTesting

When your assessment module respects the `selectedToolsForTesting` configuration option, ensure progress estimation only counts the selected tools:

```typescript
async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  // Get tools to actually test (respects selectedToolsForTesting config)
  const toolsToTest = this.selectToolsForTesting(context.tools);

  // Calculate correct total based on selected tools, NOT all tools
  const correctTotal = toolsToTest.length * PATTERNS_PER_TOOL;

  // Emit accurate module_started event
  this.emitModuleStarted("yourModule", correctTotal, toolsToTest.length);

  // Progress callback uses actual selected tools
  for (let i = 0; i < toolsToTest.length; i++) {
    const tool = toolsToTest[i];
    await this.testTool(tool, context);

    // Emit progress relative to SELECTED tool count, not total
    context.onProgress?.({
      type: "test_batch",
      module: "yourModule",
      completed: (i + 1) * PATTERNS_PER_TOOL,
      total: correctTotal,
      batchSize: PATTERNS_PER_TOOL,
      elapsed: Date.now() - this.startTime,
    });
  }
}

// Helper method that respects selectedToolsForTesting
private selectToolsForTesting(tools: Tool[]): Tool[] {
  if (this.config.selectedToolsForTesting !== undefined) {
    const selectedNames = new Set(this.config.selectedToolsForTesting);
    return tools.filter((tool) => selectedNames.has(tool.name));
  }
  return tools;
}
```

**Key Points**:

- Always filter tools using `selectedToolsForTesting` before progress estimation
- Calculate totals based on SELECTED tools, never all tools
- Emit progress relative to selected tool count
- This prevents progress bars from showing inaccurate completion percentages

**Example Scenario**:

If you have 50 tools but only selected 5 to test:

- Incorrect: report "Test 10/100" (confusing - user thinks 90 tests remain)
- Correct: report "Test 10/10" (clear - shows actual progress)

### Pattern 6.6: Security Testing with Configurable Timeouts

For SecurityAssessor-like modules that test multiple payloads, support the `securityTestTimeout` configuration:

```typescript
private async testPayloadAgainstTool(
  tool: Tool,
  payload: string,
  context: AssessmentContext
): Promise<SecurityTestResult> {
  // Use security-specific timeout if configured (default 5000ms)
  const timeout = this.config.securityTestTimeout ?? 5000;

  try {
    const result = await this.executeWithTimeout(
      context.callTool(tool.name, { input: payload }),
      timeout
    );

    return {
      toolName: tool.name,
      payload,
      vulnerable: this.detectVulnerability(result),
      responseTime: Date.now() - startTime,
    };
  } catch (error) {
    if (error.message?.includes("timed out")) {
      // Timeout may indicate vulnerability (e.g., ReDoS)
      return {
        toolName: tool.name,
        payload,
        vulnerable: true,
        reason: `Timeout after ${timeout}ms - possible DoS vulnerability`,
      };
    }
    throw error;
  }
}
```

**Configuration**:

- `securityTestTimeout`: Optional timeout for payload-based security tests (default: 5000ms)
- Allows faster security scanning by limiting time per payload test
- Critical for servers with slow-responding tools

### Pattern 7: Source Code Analysis

When source code is available, analyze implementation details:

```typescript
async assess(context: AssessmentContext): Promise<YourNewAssessment> {
  const sourceCode = context.sourceCodePath ?
    await readFile(context.sourceCodePath, "utf-8") : "";

  if (sourceCode) {
    const codePatterns = this.findPatternsInCode(sourceCode);
    this.log(`Found ${codePatterns.length} patterns in source code`);
  }

  // ... continue assessment
}
```

### Pattern 8: Shared Detection Helpers (Issue #168)

For detection logic used across multiple assessors, create shared helper classes in `helpers/` directory.

**Example: ExternalAPIDependencyDetector**

Used by TemporalAssessor, FunctionalityAssessor, and ErrorHandlingAssessor to detect external API dependencies with two-phase detection:

```typescript
// Location: client/src/services/assessment/helpers/ExternalAPIDependencyDetector.ts

import { Tool } from "@modelcontextprotocol/sdk/types.js";

export interface ExternalAPIDependencyInfo {
  toolsWithExternalAPIDependency: Set<string>;
  detectedCount: number;
  confidence: "high" | "medium" | "low";
  detectedTools: string[];
  domains?: string[]; // Extracted from source code
  sourceCodeScanned?: boolean; // Whether source was available
  implications?: ExternalAPIImplications; // Guidance for downstream assessors
}

export class ExternalAPIDependencyDetector {
  /**
   * Detect external API dependencies from tools and optional source code.
   *
   * @param tools - List of MCP tools to analyze
   * @param sourceCodeFiles - Optional map of file paths to content for source scanning
   * @returns Detection results with tool names, domains, and implications
   */
  detect(
    tools: Tool[],
    sourceCodeFiles?: Map<string, string>,
  ): ExternalAPIDependencyInfo {
    // Phase 1: Name/description pattern matching (always runs)
    const toolsWithExternalAPI = new Set<string>();
    for (const tool of tools) {
      if (this.isExternalAPITool(tool)) {
        toolsWithExternalAPI.add(tool.name);
      }
    }

    // Phase 2: Source code scanning (when available)
    let domains: string[] | undefined;
    if (sourceCodeFiles && sourceCodeFiles.size > 0) {
      domains = this.scanSourceCode(sourceCodeFiles);
    }

    // Combine results
    return {
      toolsWithExternalAPIDependency: toolsWithExternalAPI,
      detectedCount: toolsWithExternalAPI.size,
      confidence: this.computeConfidence(toolsWithExternalAPI.size, domains),
      detectedTools: Array.from(toolsWithExternalAPI),
      domains,
      sourceCodeScanned: sourceCodeFiles?.size ?? 0 > 0,
      implications: this.generateImplications(domains),
    };
  }

  // Private methods: isExternalAPITool(), scanSourceCode(), computeConfidence(), etc.
}
```

**Usage in an Assessor**:

```typescript
export class TemporalAssessor extends BaseAssessor {
  private apiDetector = new ExternalAPIDependencyDetector();

  async assess(context: AssessmentContext): Promise<TemporalAssessment> {
    // Get external API detection info
    const apiInfo = this.apiDetector.detect(
      context.tools,
      context.sourceCodeFiles, // Optional - improves accuracy
    );

    // Use detection info to adjust temporal thresholds
    for (const tool of context.tools) {
      const isExternal = apiInfo.toolsWithExternalAPIDependency.has(tool.name);
      const variance = await this.measureVariance(tool);

      // Relax variance thresholds for external API tools
      const threshold = isExternal ? 0.4 : 0.1;
      const isMutating = variance > threshold;

      // Track domain information if available
      if (apiInfo.domains?.length) {
        this.log(
          `Tool ${tool.name} may depend on: ${apiInfo.domains.join(", ")}`,
        );
      }
    }

    return {
      /* ... */
    };
  }
}
```

**Key Design Patterns**:

1. **Two-Phase Detection**: Fast patterns (always) + accurate source code scanning (optional)
2. **Confidence Levels**: Both methods combined boost confidence ("high" when both agree)
3. **Downstream Guidance**: Helper returns `implications` object for other assessors
4. **ReDoS Protection**: Source scanning has limits (500KB/file, 100 matches/file)
5. **Locality Filtering**: Automatically skips localhost, test files, node_modules

**When to Create Shared Helpers**:

- Detection logic used by 2+ assessors
- Complex pattern sets (50+ lines) repeated across modules
- Information generated in context-prep phase (affects multiple assessors)
- Reusable business logic (variance classification, pattern matching, etc.)

**Registration Pattern**:

Helpers don't need registry entries - just import and instantiate in assessors:

```typescript
import { ExternalAPIDependencyDetector } from "../helpers/ExternalAPIDependencyDetector";

export class YourAssessor extends BaseAssessor {
  private detector = new ExternalAPIDependencyDetector();
  // ... use detector in assess() method
}
```

---

## Testing Checklist

Before submitting a new module:

- [ ] Module extends `BaseAssessor`
- [ ] `assess()` method implemented
- [ ] Return type defined in `assessmentTypes.ts`
- [ ] Module exported from `index.ts`
- [ ] Registered in `AssessmentOrchestrator`
- [ ] Unit tests cover happy path and edge cases
- [ ] Integration tests pass with testbed servers
- [ ] Configuration options implemented and documented
- [ ] Progress events emitted (for long-running modules)
- [ ] Error handling implemented with proper logging
- [ ] Timeout protection applied to external calls
- [ ] README updated with module documentation
- [ ] Module scoring integrated

---

## Resources and References

- **Assessment Types** (modular): `client/src/lib/assessment/` (see [ASSESSMENT_TYPES_IMPORT_GUIDE.md](ASSESSMENT_TYPES_IMPORT_GUIDE.md))
  - `coreTypes.ts` - Foundational types and enums
  - `configTypes.ts` - Configuration interfaces
  - `resultTypes.ts` - Assessment result types
  - `extendedTypes.ts` - Extended assessment types
  - `progressTypes.ts` - Progress event types
  - `constants.ts` - Constant values
- **Orchestrator**: `client/src/services/assessment/AssessmentOrchestrator.ts`
- **Test Utilities**: `client/src/test/utils/testUtils.ts`
- **Module Scoring**: `client/src/lib/moduleScoring.ts`
- **Security Patterns**: `client/src/lib/securityPatterns/` (modularized in v1.37.0)
- **Test Data Generation**: `client/src/services/assessment/TestDataGenerator.ts`
- **Response Validation**: `client/src/services/assessment/ResponseValidator.ts`

---

## Versioning

Assessment modules are versioned via `INSPECTOR_VERSION` in `client/src/lib/moduleScoring.ts`. Update this when:

- Adding a new module
- Significantly changing module behavior
- Fixing critical detection bugs

Current version: Check `package.json` in the root directory.
