/**
 * Test Count Estimators for AssessorRegistry
 *
 * Functions that estimate the number of tests each assessor will run.
 * Used for progress event emission (emitModuleStartedEvent).
 * Extracted from AssessmentOrchestrator for reuse in registry pattern.
 *
 * @module assessment/registry/estimators
 * @see GitHub Issue #91
 */

import type { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type { AssessmentContext } from "../AssessmentOrchestrator";
import type { TestEstimatorFn } from "./types";

/**
 * Helper to get filtered tool count based on selectedToolsForTesting config.
 */
function getToolCount(
  context: AssessmentContext,
  config: AssessmentConfiguration,
): number {
  const tools = context.tools ?? [];
  if (config.selectedToolsForTesting !== undefined) {
    const selectedNames = new Set(config.selectedToolsForTesting);
    return tools.filter((tool) => selectedNames.has(tool.name)).length;
  }
  return tools.length;
}

/**
 * Get resource count from context (for ResourceAssessor).
 */
function getResourceCount(context: AssessmentContext): number {
  return context.resources?.length ?? 0;
}

/**
 * Get prompt count from context (for PromptAssessor).
 */
function getPromptCount(context: AssessmentContext): number {
  return context.prompts?.length ?? 0;
}

// ============================================================================
// Phase 0: PRE (Temporal)
// ============================================================================

/**
 * Temporal assessor: toolCount × temporalInvocations (default 3)
 */
export const estimateTemporalTests: TestEstimatorFn = (context, config) => {
  const toolCount = getToolCount(context, config);
  const invocationsPerTool = config.temporalInvocations ?? 3;
  return toolCount * invocationsPerTool;
};

// ============================================================================
// Phase 1: CORE (Functionality, Security, Documentation, ErrorHandling, Usability)
// ============================================================================

/**
 * Functionality assessor: toolCount × 10 scenarios
 */
export const estimateFunctionalityTests: TestEstimatorFn = (context, config) =>
  getToolCount(context, config) * 10;

/**
 * Security assessor: toolCount × securityPatternsToTest (default 8)
 */
export const estimateSecurityTests: TestEstimatorFn = (context, config) => {
  const toolCount = getToolCount(context, config);
  const patternsToTest = config.securityPatternsToTest ?? 8;
  return toolCount * patternsToTest;
};

/**
 * Documentation assessor: fixed 5 checks
 */
export const estimateDocumentationTests: TestEstimatorFn = () => 5;

/**
 * Error handling assessor: toolCount × 5 error scenarios
 */
export const estimateErrorHandlingTests: TestEstimatorFn = (context, config) =>
  getToolCount(context, config) * 5;

/**
 * Usability assessor: fixed 10 checks
 */
export const estimateUsabilityTests: TestEstimatorFn = () => 10;

// ============================================================================
// Phase 2: PROTOCOL (Protocol Compliance)
// ============================================================================

/**
 * Protocol compliance assessor: fixed 10 protocol checks
 */
export const estimateProtocolComplianceTests: TestEstimatorFn = () => 10;

// ============================================================================
// Phase 3: COMPLIANCE (AUP, Annotations, Libraries, Manifest, Portability, APIs, Auth)
// ============================================================================

/**
 * AUP compliance assessor: fixed 20 checks (14 AUP categories + violations)
 */
export const estimateAUPComplianceTests: TestEstimatorFn = () => 20;

/**
 * Tool annotations assessor: 1 check per tool
 */
export const estimateToolAnnotationTests: TestEstimatorFn = (context, config) =>
  getToolCount(context, config);

/**
 * Prohibited libraries assessor: fixed 5 library checks
 */
export const estimateProhibitedLibrariesTests: TestEstimatorFn = () => 5;

/**
 * Dependency vulnerability assessor: fixed 1 audit execution (Issue #193)
 */
export const estimateDependencyVulnerabilityTests: TestEstimatorFn = () => 1;

/**
 * Manifest validation assessor: fixed 10 manifest checks
 */
export const estimateManifestValidationTests: TestEstimatorFn = () => 10;

/**
 * Portability assessor: fixed 10 portability checks
 */
export const estimatePortabilityTests: TestEstimatorFn = () => 10;

/**
 * External API scanner assessor: fixed 10 API checks
 */
export const estimateExternalAPIScannerTests: TestEstimatorFn = () => 10;

/**
 * Authentication assessor: toolCount × 3 auth scenarios
 */
export const estimateAuthenticationTests: TestEstimatorFn = (context, config) =>
  getToolCount(context, config) * 3;

// ============================================================================
// Phase 4: CAPABILITY (Resources, Prompts, CrossCapability)
// ============================================================================

/**
 * Resource assessor: resourceCount × 5 resource tests
 */
export const estimateResourceTests: TestEstimatorFn = (context) =>
  getResourceCount(context) * 5;

/**
 * Prompt assessor: promptCount × 10 prompt tests
 */
export const estimatePromptTests: TestEstimatorFn = (context) =>
  getPromptCount(context) * 10;

/**
 * Cross-capability assessor: sum of capabilities × 5
 */
export const estimateCrossCapabilityTests: TestEstimatorFn = (context) => {
  const resourceCount = getResourceCount(context);
  const promptCount = getPromptCount(context);
  return (resourceCount + promptCount) * 5;
};

// ============================================================================
// Phase 5: QUALITY (FileModularization, Conformance)
// ============================================================================

/**
 * File modularization assessor: 1 check per source file (or fixed 10 if no source)
 */
export const estimateFileModularizationTests: TestEstimatorFn = (context) => {
  const sourceFiles = context.sourceCodeFiles?.size ?? 0;
  return sourceFiles > 0 ? sourceFiles : 10;
};

/**
 * Conformance assessor: fixed 7 conformance tests
 */
export const estimateConformanceTests: TestEstimatorFn = () => 7;

// ============================================================================
// Estimator Map (for dynamic lookup by assessor ID)
// ============================================================================

/**
 * Map of assessor ID to test estimator function.
 * Used by AssessorRegistry for dynamic test count estimation.
 */
export const ESTIMATOR_MAP: Record<string, TestEstimatorFn> = {
  // Phase 0: PRE
  temporal: estimateTemporalTests,

  // Phase 1: CORE
  functionality: estimateFunctionalityTests,
  security: estimateSecurityTests,
  documentation: estimateDocumentationTests,
  errorHandling: estimateErrorHandlingTests,
  usability: estimateUsabilityTests,

  // Phase 2: PROTOCOL
  protocolCompliance: estimateProtocolComplianceTests,

  // Phase 3: COMPLIANCE
  aupCompliance: estimateAUPComplianceTests,
  toolAnnotations: estimateToolAnnotationTests,
  prohibitedLibraries: estimateProhibitedLibrariesTests,
  dependencyVulnerability: estimateDependencyVulnerabilityTests,
  manifestValidation: estimateManifestValidationTests,
  portability: estimatePortabilityTests,
  externalAPIScanner: estimateExternalAPIScannerTests,
  authentication: estimateAuthenticationTests,

  // Phase 4: CAPABILITY
  resources: estimateResourceTests,
  prompts: estimatePromptTests,
  crossCapability: estimateCrossCapabilityTests,

  // Phase 5: QUALITY
  fileModularization: estimateFileModularizationTests,
  conformance: estimateConformanceTests,
};
