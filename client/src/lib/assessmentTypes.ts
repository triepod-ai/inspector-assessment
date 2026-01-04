/**
 * MCP Directory Review Assessment Types
 *
 * @deprecated This file has been split into focused modules for better maintainability.
 * All exports are re-exported from the new `assessment/` directory for backward compatibility.
 *
 * For new code, prefer importing from specific modules:
 * - `@/lib/assessment/coreTypes` - AssessmentStatus, SecurityRiskLevel, AlignmentStatus
 * - `@/lib/assessment/configTypes` - AssessmentConfiguration, config presets
 * - `@/lib/assessment/resultTypes` - MCPDirectoryAssessment, assessment result types
 * - `@/lib/assessment/extendedTypes` - AUP, Annotation, Temporal assessment types
 * - `@/lib/assessment/progressTypes` - Progress event types for JSONL streaming
 * - `@/lib/assessment/constants` - PROMPT_INJECTION_TESTS constant
 *
 * Or import everything from `@/lib/assessment`:
 * ```typescript
 * import { MCPDirectoryAssessment, AssessmentConfiguration } from "@/lib/assessment";
 * ```
 *
 * See GitHub Issue #21 for details on this refactoring.
 *
 * @module assessmentTypes
 */

export * from "./assessment";
