# Type Reference: @bryan-thompson/inspector-assessment

> **Version**: 1.23.2+
> **Last Updated**: 2026-01-04
>
> **Related Documentation:**
> [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) | [API Reference](API_REFERENCE.md) | [Integration Guide](INTEGRATION_GUIDE.md)

Complete TypeScript type reference for the programmatic API. All types are fully exported and designed for type-safe integration.

---

## Table of Contents

- [Overview](#overview)
- [Import Patterns](#import-patterns)
  - [Special Case: AssessmentContext](#special-case-assessmentcontext)
- [Core Types](#core-types)
  - [AssessmentStatus](#assessmentstatus)
  - [SecurityRiskLevel](#securityrisklevel)
  - [AlignmentStatus](#alignmentstatus)
  - [AssessmentModuleName](#assessmentmodulename)
- [Configuration Types](#configuration-types)
  - [AssessmentConfiguration](#assessmentconfiguration)
  - [ClaudeCodeConfig](#claudecodeconfig)
  - [Configuration Presets](#configuration-presets)
- [Result Types](#result-types)
  - [MCPDirectoryAssessment](#mcpdirectoryassessment)
  - [Module Result Types](#module-result-types)
  - [Test Result Types](#test-result-types)
- [Progress Types](#progress-types)
- [Extended Assessment Types](#extended-assessment-types)
- [Type Hierarchy Diagram](#type-hierarchy-diagram)

---

## Overview

The type system is organized into focused modules for better tree-shaking and maintainability:

| Module          | Purpose                              | Key Exports                                                |
| --------------- | ------------------------------------ | ---------------------------------------------------------- |
| `coreTypes`     | Foundational enums and status types  | `AssessmentStatus`, `SecurityRiskLevel`, `AlignmentStatus` |
| `configTypes`   | Configuration interfaces and presets | `AssessmentConfiguration`, `ClaudeCodeConfig`              |
| `resultTypes`   | Assessment result structures         | `MCPDirectoryAssessment`, `FunctionalityAssessment`        |
| `extendedTypes` | Extended assessment types            | `AUPComplianceAssessment`, `ToolAnnotationAssessment`      |
| `progressTypes` | Real-time progress events            | `ProgressEvent`, `ProgressCallback`                        |
| `constants`     | Security test definitions            | `PROMPT_INJECTION_TESTS`                                   |

---

## Import Patterns

### Recommended: Import from Package Entry Points

```typescript
// Import types from the types entry point
import type {
  MCPDirectoryAssessment,
  AssessmentStatus,
  SecurityRiskLevel,
} from "@bryan-thompson/inspector-assessment/types";

// Import config presets from config entry point
import { AssessmentConfiguration } from "@bryan-thompson/inspector-assessment/config";
```

### Alternative: Import from Specific Entry Points

For better tree-shaking, use specific entry points:

```typescript
// Types (status, enums, interfaces)
import type {
  AssessmentStatus,
  SecurityRiskLevel,
} from "@bryan-thompson/inspector-assessment/types";

// Configuration presets and interfaces
import {
  AssessmentConfiguration,
  AUDIT_MODE_CONFIG,
} from "@bryan-thompson/inspector-assessment/config";

// Result types
import type { MCPDirectoryAssessment } from "@bryan-thompson/inspector-assessment/results";

// Progress events
import type { ProgressEvent } from "@bryan-thompson/inspector-assessment/progress";
```

### Special Case: AssessmentContext

While most types are organized in the `/lib/assessment/` focused modules, `AssessmentContext` is exported from the **main entry point** alongside `AssessmentOrchestrator`:

```typescript
// AssessmentContext comes from the main entry point, NOT /types
import {
  AssessmentOrchestrator,
  type AssessmentContext,
} from "@bryan-thompson/inspector-assessment";

// Other types come from /types (or focused sub-modules)
import type { MCPDirectoryAssessment } from "@bryan-thompson/inspector-assessment/types";
```

**Why?** `AssessmentContext` is defined in `AssessmentOrchestrator.ts` and is tightly coupled with the orchestrator class. This design ensures the context type is immediately available when you import the orchestrator.

**Usage Example:**

```typescript
const orchestrator = new AssessmentOrchestrator(AUDIT_MODE_CONFIG);

const context: AssessmentContext = {
  serverName: "my-server",
  tools,
  callTool,
  config: orchestrator.getConfig(),
};

const results = await orchestrator.runFullAssessment(context);
```

See [API Reference](API_REFERENCE.md) for complete `AssessmentContext` field documentation.

### Package Entry Points Reference

| Entry Point                                     | Compiled Path                             | Contents                                  |
| ----------------------------------------------- | ----------------------------------------- | ----------------------------------------- |
| `@bryan-thompson/inspector-assessment`          | Main                                      | AssessmentOrchestrator, AssessmentContext |
| `@bryan-thompson/inspector-assessment/types`    | ./client/lib/lib/assessment               | All types (barrel export)                 |
| `@bryan-thompson/inspector-assessment/config`   | ./client/lib/lib/assessment/configTypes   | Config presets                            |
| `@bryan-thompson/inspector-assessment/results`  | ./client/lib/lib/assessment/resultTypes   | Result types                              |
| `@bryan-thompson/inspector-assessment/progress` | ./client/lib/lib/assessment/progressTypes | Progress events                           |

---

## Core Types

### AssessmentStatus

The primary status indicator for all assessment modules.

```typescript
type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO";
```

| Value              | Meaning                                         |
| ------------------ | ----------------------------------------------- |
| `"PASS"`           | Assessment criteria met                         |
| `"FAIL"`           | Assessment criteria not met, issues found       |
| `"NEED_MORE_INFO"` | Cannot determine status, manual review required |

### SecurityRiskLevel

Risk severity for security findings.

```typescript
type SecurityRiskLevel = "LOW" | "MEDIUM" | "HIGH";
```

| Level      | Meaning                                              |
| ---------- | ---------------------------------------------------- |
| `"LOW"`    | Minor issue, low impact                              |
| `"MEDIUM"` | Moderate risk, should be addressed                   |
| `"HIGH"`   | Critical vulnerability, immediate attention required |

### AlignmentStatus

Status for tool annotation validation (MCP 2025-03 spec).

```typescript
type AlignmentStatus =
  | "ALIGNED" // Annotations match inferred behavior
  | "MISALIGNED" // Clear contradiction detected
  | "REVIEW_RECOMMENDED" // Ambiguous pattern, human review suggested
  | "UNKNOWN"; // Cannot determine alignment (no annotations)
```

### AssessmentModuleName

Type-safe module names derived from the assessment category metadata.

```typescript
type AssessmentModuleName =
  | "functionality"
  | "security"
  | "documentation"
  | "errorHandling"
  | "usability"
  | "mcpSpecCompliance"
  | "aupCompliance"
  | "toolAnnotations"
  | "prohibitedLibraries"
  | "manifestValidation"
  | "portability"
  | "externalAPIScanner"
  | "authentication"
  | "temporal"
  | "resources"
  | "prompts"
  | "crossCapability";
```

---

## Configuration Types

### AssessmentConfiguration

Main configuration interface for controlling assessment behavior.

```typescript
interface AssessmentConfiguration {
  // Timing
  testTimeout: number; // Per-tool timeout in ms (default: 30000)
  securityTestTimeout?: number; // Security test timeout in ms (default: 5000)
  delayBetweenTests?: number; // Rate limiting delay in ms

  // Execution mode
  skipBrokenTools: boolean; // Skip tools that fail initial test
  reviewerMode?: boolean; // Optimized for human review workflow
  parallelTesting?: boolean; // Enable parallel test execution
  maxParallelTests?: number; // Max concurrent tests (default: 5)

  // Testing scope
  enableExtendedAssessment?: boolean; // Enable extended modules
  scenariosPerTool?: number; // Max scenarios per tool (5-20)
  selectedToolsForTesting?: string[]; // Specific tools to test (undefined = all)
  securityPatternsToTest?: number; // Number of security patterns (default: 8)
  enableDomainTesting?: boolean; // Enable advanced security testing

  // Protocol
  mcpProtocolVersion?: string; // MCP spec version (default: "2025-06")

  // Analysis
  enableSourceCodeAnalysis?: boolean; // Enable source code scanning
  patternConfigPath?: string; // Custom pattern config file
  documentationVerbosity?: "minimal" | "standard" | "verbose";

  // Logging
  logging?: LoggingConfig;

  // Claude integration
  claudeCode?: ClaudeCodeConfig;

  // Temporal detection
  temporalInvocations?: number; // Rug pull detection invocations (default: 25)

  // Module selection
  assessmentCategories?: {
    functionality: boolean;
    security: boolean;
    documentation: boolean;
    errorHandling: boolean;
    usability: boolean;
    mcpSpecCompliance?: boolean;
    aupCompliance?: boolean;
    toolAnnotations?: boolean;
    prohibitedLibraries?: boolean;
    manifestValidation?: boolean;
    portability?: boolean;
    externalAPIScanner?: boolean;
    authentication?: boolean;
    temporal?: boolean;
    resources?: boolean;
    prompts?: boolean;
    crossCapability?: boolean;
  };
}
```

### ClaudeCodeConfig

Configuration for Claude Code integration (advanced semantic analysis).

```typescript
interface ClaudeCodeConfig {
  enabled: boolean;
  features: {
    intelligentTestGeneration: boolean; // Use Claude for test params
    aupSemanticAnalysis: boolean; // Semantic AUP violation detection
    annotationInference: boolean; // Infer tool behavior
    documentationQuality: boolean; // Assess docs semantically
  };
  timeout: number; // Per-call timeout in ms
  workingDir?: string; // Working directory for Claude
  maxRetries?: number; // Max retries on failure (default: 1)
}
```

### Configuration Presets

Pre-configured settings for common use cases:

```typescript
// Import all presets from the config entry point
import {
  DEFAULT_ASSESSMENT_CONFIG, // General testing - balanced settings
  REVIEWER_MODE_CONFIG, // Fast reviews - 5 core modules, parallel
  DEVELOPER_MODE_CONFIG, // Debugging - all assessment modules, verbose
  AUDIT_MODE_CONFIG, // Directory compliance - all assessment modules
  CLAUDE_ENHANCED_AUDIT_CONFIG, // Semantic analysis with Claude Code
} from "@bryan-thompson/inspector-assessment/config";
```

| Preset                         | Use Case             | Modules | Parallel |
| ------------------------------ | -------------------- | ------- | -------- |
| `DEFAULT_ASSESSMENT_CONFIG`    | General testing      | 5 core  | No       |
| `REVIEWER_MODE_CONFIG`         | Fast reviews         | 5 core  | Yes      |
| `DEVELOPER_MODE_CONFIG`        | Debugging            | All     | No       |
| `AUDIT_MODE_CONFIG`            | Directory compliance | All     | Yes      |
| `CLAUDE_ENHANCED_AUDIT_CONFIG` | Semantic analysis    | All     | No       |

---

## Result Types

### MCPDirectoryAssessment

The top-level assessment result interface.

```typescript
interface MCPDirectoryAssessment {
  // Identification
  serverName: string;
  assessmentDate: string;
  assessorVersion: string;

  // Core assessment results (Original 5)
  functionality: FunctionalityAssessment;
  security: SecurityAssessment;
  documentation: DocumentationAssessment;
  errorHandling: ErrorHandlingAssessment;
  usability: UsabilityAssessment;

  // Extended assessment results (Optional)
  mcpSpecCompliance?: MCPSpecComplianceAssessment;
  aupCompliance?: AUPComplianceAssessment;
  toolAnnotations?: ToolAnnotationAssessment;
  prohibitedLibraries?: ProhibitedLibrariesAssessment;
  manifestValidation?: ManifestValidationAssessment;
  portability?: PortabilityAssessment;
  externalAPIScanner?: ExternalAPIScannerAssessment;
  authentication?: AuthenticationAssessment;
  temporal?: TemporalAssessment;

  // Capability assessment results
  resources?: ResourceAssessment;
  prompts?: PromptAssessment;
  crossCapability?: CrossCapabilitySecurityAssessment;

  // Overall assessment
  overallStatus: AssessmentStatus;
  summary: string;
  recommendations: string[];

  // Metadata
  executionTime: number; // Total duration in ms
  totalTestsRun: number;
  evidenceFiles?: string[];
  mcpProtocolVersion?: string;
  assessmentMetadata?: {
    sourceCodeAvailable: boolean;
    transportType?: "stdio" | "sse" | "streamable-http";
  };
}
```

### Module Result Types

Each module has a corresponding result type:

#### FunctionalityAssessment

```typescript
interface FunctionalityAssessment {
  totalTools: number;
  testedTools: number;
  workingTools: number;
  brokenTools: string[];
  coveragePercentage: number;
  status: AssessmentStatus;
  explanation: string;
  toolResults: ToolTestResult[];
  tools?: DiscoveredTool[]; // Raw tool definitions from MCP
}
```

#### SecurityAssessment

```typescript
interface SecurityAssessment {
  promptInjectionTests: SecurityTestResult[];
  vulnerabilities: string[];
  overallRiskLevel: SecurityRiskLevel;
  status: AssessmentStatus;
  explanation: string;
}
```

#### DocumentationAssessment

```typescript
interface DocumentationAssessment {
  metrics: DocumentationMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

#### ErrorHandlingAssessment

```typescript
interface ErrorHandlingAssessment {
  metrics: ErrorHandlingMetrics;
  errorTests?: ErrorTestDetail[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

#### UsabilityAssessment

```typescript
interface UsabilityAssessment {
  metrics: UsabilityMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

### Test Result Types

#### ToolTestResult

Basic tool test result structure.

```typescript
interface ToolTestResult {
  toolName: string;
  tested: boolean;
  status: "working" | "broken" | "untested";
  error?: string;
  executionTime?: number;
  testParameters?: Record<string, unknown>;
  response?: unknown;
  testInputMetadata?: TestInputMetadata;
  responseMetadata?: ResponseMetadata;
}
```

#### EnhancedToolTestResult

Detailed multi-scenario test result.

```typescript
interface EnhancedToolTestResult {
  toolName: string;
  tested: boolean;
  status:
    | "fully_working"
    | "partially_working"
    | "connectivity_only"
    | "broken"
    | "untested";
  confidence: number; // 0-100
  scenariosExecuted: number;
  scenariosPassed: number;
  scenariosFailed: number;
  executionTime: number;
  validationSummary: {
    happyPathSuccess: boolean;
    edgeCasesHandled: number;
    edgeCasesTotal: number;
    boundariesRespected: number;
    boundariesTotal: number;
    errorHandlingWorks: boolean;
  };
  recommendations: string[];
  detailedResults?: Array<{
    scenarioName: string;
    category: "happy_path" | "edge_case" | "boundary" | "error_case";
    passed: boolean;
    confidence: number;
    issues: string[];
    evidence: string[];
  }>;
}
```

#### SecurityTestResult

Security vulnerability test result.

```typescript
interface SecurityTestResult {
  testName: string;
  description: string;
  payload: string;
  vulnerable: boolean;
  evidence?: string;
  riskLevel: SecurityRiskLevel;
  toolName?: string;
  response?: string;
  confidence?: "high" | "medium" | "low";
  requiresManualReview?: boolean;
  manualReviewReason?: string;
  reviewGuidance?: string;
  connectionError?: boolean;
  errorType?: "connection" | "server" | "protocol";
  testReliability?: "completed" | "failed" | "retried";
}
```

---

## Progress Types

For real-time progress monitoring during assessment.

### ProgressCallback

```typescript
interface ProgressCallback {
  (event: ProgressEvent): void;
}
```

### ProgressEvent

Union type for all progress events:

```typescript
type ProgressEvent =
  | ModuleStartedProgress
  | TestBatchProgress
  | ModuleCompleteProgress
  | VulnerabilityFoundProgress
  | AnnotationMissingProgress
  | AnnotationMisalignedProgress
  | AnnotationReviewRecommendedProgress
  | AnnotationPoisonedProgress
  | AnnotationAlignedProgress;
```

#### ModuleStartedProgress

```typescript
interface ModuleStartedProgress {
  type: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
}
```

#### TestBatchProgress

```typescript
interface TestBatchProgress {
  type: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}
```

#### ModuleCompleteProgress

```typescript
interface ModuleCompleteProgress {
  type: "module_complete";
  module: string;
  status: AssessmentStatus;
  score: number;
  testsRun: number;
  duration: number;
}
```

#### VulnerabilityFoundProgress

```typescript
interface VulnerabilityFoundProgress {
  type: "vulnerability_found";
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string;
}
```

---

## Extended Assessment Types

### AUPComplianceAssessment

Acceptable Use Policy (Anthropic's 14 categories) compliance.

```typescript
interface AUPComplianceAssessment {
  violations: AUPViolation[];
  highRiskDomains: string[];
  scannedLocations: {
    toolNames: boolean;
    toolDescriptions: boolean;
    readme: boolean;
    sourceCode: boolean;
  };
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

type AUPCategory =
  | "A"
  | "B"
  | "C"
  | "D"
  | "E"
  | "F"
  | "G"
  | "H"
  | "I"
  | "J"
  | "K"
  | "L"
  | "M"
  | "N";
type AUPSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "FLAG";
```

### ToolAnnotationAssessment

MCP 2025-03 annotation compliance.

```typescript
interface ToolAnnotationAssessment {
  toolResults: ToolAnnotationResult[];
  annotatedCount: number;
  missingAnnotationsCount: number;
  misalignedAnnotationsCount: number;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  metrics?: {
    coverage: number; // % with annotations
    consistency: number; // % without contradictions
    correctness: number; // % correctly aligned
    reviewRequired: number;
  };
  alignmentBreakdown?: {
    aligned: number;
    misaligned: number;
    reviewRecommended: number;
    unknown: number;
  };
  poisonedDescriptionsDetected?: number;
}
```

### TemporalAssessment

Rug pull / temporal mutation detection.

```typescript
interface TemporalAssessment {
  toolsTested: number;
  invocationsPerTool: number;
  rugPullsDetected: number;
  definitionMutationsDetected: number;
  details: TemporalToolResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

### ResourceAssessment

MCP Resources capability security.

```typescript
interface ResourceAssessment {
  resourcesTested: number;
  resourceTemplatesTested: number;
  accessibleResources: number;
  securityIssuesFound: number;
  pathTraversalVulnerabilities: number;
  sensitiveDataExposures: number;
  promptInjectionVulnerabilities: number;
  results: ResourceTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

### PromptAssessment

MCP Prompts capability security.

```typescript
interface PromptAssessment {
  promptsTested: number;
  aupViolations: number;
  injectionVulnerabilities: number;
  argumentValidationIssues: number;
  results: PromptTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

### CrossCapabilitySecurityAssessment

Cross-capability security testing (tools x resources x prompts).

```typescript
interface CrossCapabilitySecurityAssessment {
  testsRun: number;
  vulnerabilitiesFound: number;
  privilegeEscalationRisks: number;
  dataFlowViolations: number;
  results: CrossCapabilityTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}
```

---

## Type Hierarchy Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Type Module Hierarchy                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Tier 0 (No Dependencies)                                           │
│  ┌─────────────────┐  ┌─────────────────┐                          │
│  │   coreTypes     │  │   configTypes   │                          │
│  │ ─────────────── │  │ ─────────────── │                          │
│  │ AssessmentStatus│  │ Assessment-     │                          │
│  │ SecurityRiskLvl │  │   Configuration │                          │
│  │ AlignmentStatus │  │ ClaudeCodeConfig│                          │
│  │ ModuleName      │  │ Config Presets  │                          │
│  └────────┬────────┘  └────────┬────────┘                          │
│           │                    │                                    │
│  ─────────┴────────────────────┴───────────────────────────────────│
│                                                                     │
│  Tier 1 (Depends on Tier 0)                                         │
│  ┌─────────────────┐  ┌─────────────────┐                          │
│  │  extendedTypes  │  │  progressTypes  │                          │
│  │ ─────────────── │  │ ─────────────── │                          │
│  │ AUPCompliance   │  │ ProgressCallback│                          │
│  │ ToolAnnotation  │  │ ProgressEvent   │                          │
│  │ Temporal        │  │ ModuleStarted   │                          │
│  │ Resource/Prompt │  │ VulnFound       │                          │
│  └────────┬────────┘  └────────┬────────┘                          │
│           │                    │                                    │
│  ─────────┴────────────────────┴───────────────────────────────────│
│                                                                     │
│  Tier 2 (Depends on Tier 0 + 1)                                     │
│  ┌─────────────────────────────────────────┐                       │
│  │              resultTypes                 │                       │
│  │ ─────────────────────────────────────── │                       │
│  │ MCPDirectoryAssessment (top-level)      │                       │
│  │ FunctionalityAssessment                 │                       │
│  │ SecurityAssessment                      │                       │
│  │ DocumentationAssessment                 │                       │
│  │ ErrorHandlingAssessment                 │                       │
│  │ UsabilityAssessment                     │                       │
│  │ MCPSpecComplianceAssessment             │                       │
│  └────────────────────┬────────────────────┘                       │
│                       │                                             │
│  ─────────────────────┴────────────────────────────────────────────│
│                                                                     │
│  Tier 3 (Depends on Tier 2)                                         │
│  ┌─────────────────┐                                               │
│  │   constants     │                                               │
│  │ ─────────────── │                                               │
│  │ PROMPT_INJECTION│                                               │
│  │ _TESTS constant │                                               │
│  └─────────────────┘                                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Related Documentation

- [PROGRAMMATIC_API_GUIDE.md](PROGRAMMATIC_API_GUIDE.md) - How to use AssessmentOrchestrator
- [API_REFERENCE.md](API_REFERENCE.md) - Full API documentation
- [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) - Complete assessment module reference
- [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) - CLI usage guide
- [JSONL_EVENTS_REFERENCE.md](JSONL_EVENTS_REFERENCE.md) - Real-time progress events (13 types)

---

_Last updated: 2026-01-06 | Package version: 1.23.5_
