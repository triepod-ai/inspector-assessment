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
import { AssessmentPhase, DEFAULT_CONTEXT_REQUIREMENTS } from "./types";

// Core assessor imports
import { FunctionalityAssessor } from "../modules/FunctionalityAssessor";
import { SecurityAssessor } from "../modules/SecurityAssessor";
import { DocumentationAssessor } from "../modules/DocumentationAssessor";
// ErrorHandlingAssessor merged into ProtocolComplianceAssessor (Issue #188)
// import { ErrorHandlingAssessor } from "../modules/ErrorHandlingAssessor";
import { UsabilityAssessor } from "../modules/UsabilityAssessor";

// Protocol compliance (unified module with error handling - Issue #188)
import { ProtocolComplianceAssessor } from "../modules/ProtocolComplianceAssessor/ProtocolComplianceAssessor";

// MCP Directory compliance gap assessors
import { AUPComplianceAssessor } from "../modules/AUPComplianceAssessor";
import { ToolAnnotationAssessor } from "../modules/ToolAnnotationAssessor";
import { ProhibitedLibrariesAssessor } from "../modules/ProhibitedLibrariesAssessor";
import { DependencyVulnerabilityAssessor } from "../modules/DependencyVulnerabilityAssessor";
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
  estimateDependencyVulnerabilityTests,
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: true,
      needsListTools: true, // For baseline capture before/after
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: DEFAULT_CONTEXT_REQUIREMENTS, // needsTools + needsCallTool
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
    contextRequirements: DEFAULT_CONTEXT_REQUIREMENTS, // needsTools + needsCallTool
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: false, // Analyzes tool definitions, doesn't call
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
  },
  // ErrorHandlingAssessor merged into ProtocolComplianceAssessor (Issue #188)
  // Error handling tests now run as part of Protocol Compliance in Phase 2
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: false, // Analyzes tool definitions
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
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
      // Issue #188: errorHandling now merged into this module
      deprecated: ["mcpSpecCompliance", "protocolConformance", "errorHandling"],
      defaultEnabled: true, // Changed to true since it includes error handling (Issue #188)
    },
    requiresExtended: false, // Changed to false since error handling is core (Issue #188)
    supportsClaudeBridge: false,
    estimateTests: (context, config) => {
      // Combined estimate: protocol checks + error handling tests
      const protocolTests = estimateProtocolComplianceTests(context, config);
      const errorTests = estimateErrorHandlingTests(context, config);
      return protocolTests + errorTests;
    },
    contextRequirements: {
      needsTools: true,
      needsCallTool: true,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: true, // Needs server capabilities
    },
    // Issue #188: Extract errorHandling result for backward compatibility
    additionalResultFields: [
      { sourceField: "errorHandling", targetField: "errorHandling" },
    ],
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: false, // Analyzes tool definitions
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Optional - enhances analysis
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: false, // Analyzes tool annotations, doesn't call
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Optional - enhances detection via source
      needsManifest: false,
      needsServerInfo: false,
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
      optIn: true, // Issue #200: Narrow scope (~25 libs), opt-in only
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateProhibitedLibrariesTests,
    contextRequirements: {
      needsTools: false, // Analyzes source/manifest only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Required - scans dependencies
      needsManifest: true, // Required - checks package.json
      needsServerInfo: false,
    },
  },
  {
    id: "dependencyVulnerability",
    displayName: "Dependency Audit",
    assessorClass: DependencyVulnerabilityAssessor,
    resultField: "dependencyVulnerability",
    phase: AssessmentPhase.COMPLIANCE,
    configFlags: {
      primary: "dependencyVulnerability",
      defaultEnabled: false,
      optIn: true, // Issue #193: Shell execution required, opt-in only
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateDependencyVulnerabilityTests,
    contextRequirements: {
      needsTools: false, // Runs npm/yarn/pnpm audit only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Required - directory to run audit in
      needsManifest: false, // Detects package manager from lock file
      needsServerInfo: false,
    },
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
      optIn: true, // Issue #200: Only for MCPB bundles, opt-in only
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateManifestValidationTests,
    contextRequirements: {
      needsTools: false, // Validates manifest.json only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: true, // Required
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: false, // Scans source code only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Required - analyzes platform-specific code
      needsManifest: false,
      needsServerInfo: false,
    },
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
      optIn: true, // Issue #200: Informational only, opt-in only
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateExternalAPIScannerTests,
    contextRequirements: {
      needsTools: false, // Scans source code only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Required - detects API calls
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: false, // Analyzes tool definitions
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Optional - enhances detection
      needsManifest: true, // Checks OAuth config in manifest
      needsServerInfo: true, // Checks server auth capabilities
    },
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
    contextRequirements: {
      needsTools: false,
      needsCallTool: false,
      needsListTools: false,
      needsResources: true, // Required - tests resources capability
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: false,
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: true, // Required - tests prompts capability
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: true,
      needsListTools: false,
      needsResources: true, // Tests resource→tool chains
      needsPrompts: true, // Tests prompt→tool chains
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: false,
    },
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
      optIn: true, // Issue #200: Code quality metric (not security), opt-in only
    },
    requiresExtended: true,
    supportsClaudeBridge: false,
    estimateTests: estimateFileModularizationTests,
    contextRequirements: {
      needsTools: false, // Analyzes source code structure only
      needsCallTool: false,
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: true, // Required - analyzes file structure
      needsManifest: false,
      needsServerInfo: false,
    },
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
    contextRequirements: {
      needsTools: true,
      needsCallTool: true, // Runs conformance protocol tests
      needsListTools: false,
      needsResources: false,
      needsPrompts: false,
      needsSourceCode: false,
      needsManifest: false,
      needsServerInfo: true, // Tests server protocol compliance
    },
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
