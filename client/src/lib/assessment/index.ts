/**
 * Assessment Types - Barrel Export
 *
 * Re-exports all assessment types from focused modules.
 * This provides backward compatibility for existing imports.
 *
 * @public
 * @example
 * // Existing imports continue to work:
 * import { MCPDirectoryAssessment, AssessmentConfiguration } from "@/lib/assessment";
 *
 * // Or import from specific modules for better tree-shaking:
 * import { MCPDirectoryAssessment } from "@/lib/assessment/resultTypes";
 * import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
 *
 * @module assessment
 */

// ============================================================================
// Module Dependency Graph (acyclic, ordered by dependency tier)
// ============================================================================
//
// Tier 0 - No internal dependencies:
//   coreTypes.ts      - Foundational types (AssessmentStatus, enums, metadata)
//   configTypes.ts    - Configuration interfaces and presets
//
// Tier 1 - Depends on Tier 0 only (modularized per Issue #164):
//   aupComplianceTypes.ts      - AUP category compliance types
//   toolAnnotationTypes.ts     - Tool annotations, behavior inference, architecture
//   policyComplianceTypes.ts   - Prohibited libraries, manifest, portability
//   externalServicesTypes.ts   - External APIs, authentication
//   temporalSecurityTypes.ts   - Temporal/rug pull detection, variance
//   capabilityAssessmentTypes.ts - Resources, prompts, protocol, conformance, devex
//   progressTypes.ts           - Progress event types for JSONL streaming
//   extendedTypes.ts           - DEPRECATED: Re-export shim for backward compatibility
//
// Tier 2 - Depends on Tier 0 and Tier 1:
//   resultTypes.ts    - Core result interfaces (MCPDirectoryAssessment, etc.)
//
// Tier 3 - Depends on Tier 2:
//   constants.ts      - Constant values (PROMPT_INJECTION_TESTS)
//
// Note: coreTypes.ts re-exports PersistenceModel and ServerPersistenceContext
// from services/assessment/config/annotationPatterns for backward compatibility.
// This is a type-only cross-layer import that doesn't affect runtime behavior.
// ============================================================================

// Tier 0: Foundational types
export * from "./coreTypes";
export * from "./configTypes";

// Tier 1: Types depending on coreTypes (modularized per Issue #164)
export * from "./aupComplianceTypes";
export * from "./toolAnnotationTypes";
export * from "./policyComplianceTypes";
export * from "./externalServicesTypes";
export * from "./temporalSecurityTypes";
export * from "./capabilityAssessmentTypes";
export * from "./progressTypes";

// Tier 2: Result types depending on coreTypes and extendedTypes
export * from "./resultTypes";

// Tier 3: Constants depending on resultTypes
export * from "./constants";
