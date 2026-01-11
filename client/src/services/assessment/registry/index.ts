/**
 * Assessment Registry Module
 *
 * Exports all registry components for use by AssessmentOrchestrator.
 *
 * @module assessment/registry
 * @see GitHub Issue #91
 */

// Types
export {
  AssessmentPhase,
  type AssessorDefinition,
  type AssessorConfigFlags,
  type AssessorConstructor,
  type AssessorSetupFn,
  type TestEstimatorFn,
  type RegisteredAssessor,
  type AssessorExecutionResult,
  type ClaudeBridgeCapable,
  supportsClaudeBridge,
} from "./types";

// Definitions
export {
  ASSESSOR_DEFINITIONS,
  ASSESSOR_DEFINITION_MAP,
  getDefinitionsByPhase,
  getOrderedPhases,
} from "./AssessorDefinitions";

// Registry
export { AssessorRegistry, type FailedRegistration } from "./AssessorRegistry";

// Estimators
export {
  estimateTemporalTests,
  estimateFunctionalityTests,
  estimateSecurityTests,
  estimateDocumentationTests,
  estimateErrorHandlingTests,
  estimateUsabilityTests,
  estimateProtocolComplianceTests,
  estimateAUPComplianceTests,
  estimateToolAnnotationTests,
  estimateProhibitedLibrariesTests,
  estimateManifestValidationTests,
  estimatePortabilityTests,
  estimateExternalAPIScannerTests,
  estimateAuthenticationTests,
  estimateResourceTests,
  estimatePromptTests,
  estimateCrossCapabilityTests,
  estimateFileModularizationTests,
  estimateConformanceTests,
  ESTIMATOR_MAP,
} from "./estimators";
