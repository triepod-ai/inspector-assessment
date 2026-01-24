/**
 * Extended Assessment Types - DEPRECATED
 *
 * This file is maintained for backward compatibility only.
 * All types have been modularized into focused domain modules per Issue #164.
 *
 * @deprecated Import from specific type modules or from './index' instead:
 *
 * - AUP compliance: import from './aupComplianceTypes'
 * - Tool annotations: import from './toolAnnotationTypes'
 * - Policy compliance: import from './policyComplianceTypes'
 * - External services: import from './externalServicesTypes'
 * - Temporal security: import from './temporalSecurityTypes'
 * - Capability assessment: import from './capabilityAssessmentTypes'
 *
 * Or use the barrel export:
 * import { AUPCategory, ToolAnnotationResult, ... } from '@/lib/assessment';
 *
 * @module assessment/extendedTypes
 * @see https://github.com/triepod-ai/inspector-assessment/issues/164
 */

// Re-export all types for backward compatibility
export * from "./aupComplianceTypes";
export * from "./toolAnnotationTypes";
export * from "./policyComplianceTypes";
export * from "./externalServicesTypes";
export * from "./temporalSecurityTypes";
export * from "./capabilityAssessmentTypes";
export * from "./dependencyVulnerabilityTypes";
