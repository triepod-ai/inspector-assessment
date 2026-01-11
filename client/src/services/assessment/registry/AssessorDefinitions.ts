/**
 * Assessor Definitions
 *
 * Declarative configuration for all 19 assessors.
 * Single source of truth for assessor registration, phase ordering,
 * config flags, and Claude bridge support.
 *
 * @module assessment/registry/AssessorDefinitions
 * @see GitHub Issue #91
 */

import type { AssessorDefinition } from "./types";
import { AssessmentPhase } from "./types";

// Core assessor imports
import { FunctionalityAssessor } from "../modules/FunctionalityAssessor";
import { SecurityAssessor } from "../modules/SecurityAssessor";
import { DocumentationAssessor } from "../modules/DocumentationAssessor";
import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor";
import { UsabilityAssessor } from "../modules/UsabilityAssessor";

// Protocol compliance
import { ProtocolComplianceAssessor } from "../modules/ProtocolComplianceAssessor";

// MCP Directory compliance gap assessors
import { AUPComplianceAssessor } from "../modules/AUPComplianceAssessor";
import { ToolAnnotationAssessor } from "../modules/ToolAnnotationAssessor";
import { ProhibitedLibrariesAssessor } from "../modules/ProhibitedLibrariesAssessor";
import { ManifestValidationAssessor } from "../modules/ManifestValidationAssessor";
import { PortabilityAssessor } from "../modules/PortabilityAssessor";
import { ExternalAPIScannerAssessor } from "../modules/ExternalAPIScannerAssessor";
import { TemporalAssessor } from "../modules/TemporalAssessor";
import { AuthenticationAssessor } from "../modules/AuthenticationAssessor";

// Capability assessors
import { ResourceAssessor } from "../modules/ResourceAssessor";
import { PromptAssessor } from "../modules/PromptAssessor";
import { CrossCapabilitySecurityAssessor } from "../modules/CrossCapabilitySecurityAssessor";

// Code quality assessors
import { FileModularizationAssessor } from "../modules/FileModularizationAssessor";
import { ConformanceAssessor } from "../modules/ConformanceAssessor";

// Pattern configuration for ToolAnnotationAssessor
import {
  loadPatternConfig,
  compilePatterns,
} from "../config/annotationPatterns";

// Test estimators
import {
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
} from "./estimators";

/**
 * All assessor definitions in phase order.
 * This is the single source of truth for assessor registration.
 *
 * Order within phases:
 * - Phase 0 (PRE): Temporal only
 * - Phase 1 (CORE): Functionality, Security, Documentation, ErrorHandling, Usability
 * - Phase 2 (PROTOCOL): ProtocolCompliance
 * - Phase 3 (COMPLIANCE): AUP, Annotations, Libraries, Manifest, Portability, APIs, Auth
 * - Phase 4 (CAPABILITY): Resources, Prompts, CrossCapability
 * - Phase 5 (QUALITY): FileModularization, Conformance
 */
export const ASSESSOR_DEFINITIONS: AssessorDefinition[] = [
  // ============================================================================
  // Phase 0: PRE - Temporal (must run first for clean baseline)
  // ============================================================================
  {
    id: "temporal",
    displayName: "Temporal",
    assessorClass: TemporalAssessor,
    resultField: "temporal",
    phase: AssessmentPhase.PRE,
    configFlags: {
      primary: "temporal",
      defaultEnabled: false, // Opt-in
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateTemporalTests,
  },

  // ============================================================================
  // Phase 1: CORE - The original 5 assessors
  // ============================================================================
  {
    id: "functionality",
    displayName: "Functionality",
    assessorClass: FunctionalityAssessor,
    resultField: "functionality",
    phase: AssessmentPhase.CORE,
    configFlags: {
      primary: "functionality",
      defaultEnabled: true, // Enabled unless explicitly disabled
    },
    requiresExtended: false,
    supportsClaudeBridge: false,
    estimateTests: estimateFunctionalityTests,
  },
  {
    id: "security",
    displayName: "Security",
    assessorClass: SecurityAssessor,
    resultField: "security",
    phase: AssessmentPhase.CORE,
    configFlags: {
      primary: "security",
      defaultEnabled: true,
    },
    requiresExtended: false,
    supportsClaudeBridge: true, // Supports Claude semantic analysis
    estimateTests: estimateSecurityTests,
  },
  {
    id: "documentation",
    displayName: "Documentation",
    assessorClass: DocumentationAssessor,
    resultField: "documentation",
    phase: AssessmentPhase.CORE,
    configFlags: {
      primary: "documentation",
      defaultEnabled: true,
    },
    requiresExtended: false,
    supportsClaudeBridge: false,
    estimateTests: estimateDocumentationTests,
  },
  {
    id: "errorHandling",
    displayName: "Error Handling",
    assessorClass: ErrorHandlingAssessor,
    resultField: "errorHandling",
    phase: AssessmentPhase.CORE,
    configFlags: {
      primary: "errorHandling",
      defaultEnabled: true,
    },
    requiresExtended: false,
    supportsClaudeBridge: false,
    estimateTests: estimateErrorHandlingTests,
  },
  {
    id: "usability",
    displayName: "Usability",
    assessorClass: UsabilityAssessor,
    resultField: "usability",
    phase: AssessmentPhase.CORE,
    configFlags: {
      primary: "usability",
      defaultEnabled: true,
    },
    requiresExtended: false,
    supportsClaudeBridge: false,
    estimateTests: estimateUsabilityTests,
  },

  // ============================================================================
  // Phase 2: PROTOCOL - Unified protocol compliance
  // ============================================================================
  {
    id: "protocolCompliance",
    displayName: "Protocol Compliance",
    assessorClass: ProtocolComplianceAssessor,
    resultField: "mcpSpecCompliance", // Legacy field name for BC
    phase: AssessmentPhase.PROTOCOL,
    configFlags: {
      primary: "protocolCompliance",
      // BC: Enable if ANY of these deprecated flags is true
      deprecated: ["mcpSpecCompliance", "protocolConformance"],
      defaultEnabled: false, // Opt-in
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateProtocolComplianceTests,
  },

  // ============================================================================
  // Phase 3: COMPLIANCE - MCP Directory compliance gap assessors
  // ============================================================================
  {
    id: "aupCompliance",
    displayName: "AUP",
    assessorClass: AUPComplianceAssessor,
    resultField: "aupCompliance",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "aupCompliance",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: true, // Supports Claude semantic analysis
    estimateTests: estimateAUPComplianceTests,
  },
  {
    id: "toolAnnotations",
    displayName: "Annotations",
    assessorClass: ToolAnnotationAssessor,
    resultField: "toolAnnotations",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "toolAnnotations",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: true, // Supports Claude behavior inference
    estimateTests: estimateToolAnnotationTests,
    // Custom setup for pattern configuration
    customSetup: (assessor, config, logger) => {
      if (config.patternConfigPath) {
        const patternConfig = loadPatternConfig(
          config.patternConfigPath,
          logger,
        );
        const compiledPatterns = compilePatterns(patternConfig);
        (assessor as ToolAnnotationAssessor).setPatterns(compiledPatterns);
      }
    },
  },
  {
    id: "prohibitedLibraries",
    displayName: "Libraries",
    assessorClass: ProhibitedLibrariesAssessor,
    resultField: "prohibitedLibraries",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "prohibitedLibraries",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateProhibitedLibrariesTests,
  },
  {
    id: "manifestValidation",
    displayName: "Manifest",
    assessorClass: ManifestValidationAssessor,
    resultField: "manifestValidation",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "manifestValidation",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateManifestValidationTests,
  },
  {
    id: "portability",
    displayName: "Portability",
    assessorClass: PortabilityAssessor,
    resultField: "portability",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "portability",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimatePortabilityTests,
  },
  {
    id: "externalAPIScanner",
    displayName: "External APIs",
    assessorClass: ExternalAPIScannerAssessor,
    resultField: "externalAPIScanner",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "externalAPIScanner",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateExternalAPIScannerTests,
  },
  {
    id: "authentication",
    displayName: "Authentication",
    assessorClass: AuthenticationAssessor,
    resultField: "authentication",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "authentication",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateAuthenticationTests,
  },

  // ============================================================================
  // Phase 4: CAPABILITY - Resources, Prompts, Cross-capability
  // ============================================================================
  {
    id: "resources",
    displayName: "Resources",
    assessorClass: ResourceAssessor,
    resultField: "resources",
    phase: AssessmentPhase.CAPABILITY,
    configFlags: {
      primary: "resources",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateResourceTests,
  },
  {
    id: "prompts",
    displayName: "Prompts",
    assessorClass: PromptAssessor,
    resultField: "prompts",
    phase: AssessmentPhase.CAPABILITY,
    configFlags: {
      primary: "prompts",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimatePromptTests,
  },
  {
    id: "crossCapability",
    displayName: "Cross-Capability",
    assessorClass: CrossCapabilitySecurityAssessor,
    resultField: "crossCapability",
    phase: AssessmentPhase.CAPABILITY,
    configFlags: {
      primary: "crossCapability",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateCrossCapabilityTests,
  },

  // ============================================================================
  // Phase 5: QUALITY - Code quality and conformance
  // ============================================================================
  {
    id: "fileModularization",
    displayName: "File Modularization",
    assessorClass: FileModularizationAssessor,
    resultField: "fileModularization",
    phase: AssessmentPhase.QUALITY,
    configFlags: {
      primary: "fileModularization",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateFileModularizationTests,
  },
  {
    id: "conformance",
    displayName: "Conformance",
    assessorClass: ConformanceAssessor,
    resultField: "conformance",
    phase: AssessmentPhase.QUALITY,
    configFlags: {
      primary: "conformance",
      defaultEnabled: false,
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateConformanceTests,
  },
];

/**
 * Map of assessor ID to definition for fast lookup.
 */
export const ASSESSOR_DEFINITION_MAP: Map<string, AssessorDefinition> = new Map(
  ASSESSOR_DEFINITIONS.map((def) => [def.id, def]),
);

/**
 * Get assessor definitions by phase.
 */
export function getDefinitionsByPhase(
  phase: AssessmentPhase,
): AssessorDefinition[] {
  return ASSESSOR_DEFINITIONS.filter((def) => def.phase === phase);
}

/**
 * Get all phases in execution order.
 */
export function getOrderedPhases(): AssessmentPhase[] {
  return [
    AssessmentPhase.PRE,
    AssessmentPhase.CORE,
    AssessmentPhase.PROTOCOL,
    AssessmentPhase.COMPLIANCE,
    AssessmentPhase.CAPABILITY,
    AssessmentPhase.QUALITY,
  ];
}
