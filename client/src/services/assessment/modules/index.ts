/**
 * MCP Server Assessment Modules
 *
 * This module exports all assessors for comprehensive MCP server evaluation.
 * Modules are organized into 4 tiers based on assessment purpose.
 *
 * ## Module Tier Organization (v1.25.0+)
 *
 * ### Tier 1: Core Security (Always Run) - 6 modules
 * - FunctionalityAssessor - Tests tool execution and response handling
 * - SecurityAssessor - Checks for security vulnerabilities
 * - TemporalAssessor - Detects rug pull vulnerabilities
 * - ErrorHandlingAssessor - Tests error handling patterns
 * - ProtocolComplianceAssessor - MCP protocol + JSON-RPC validation (NEW)
 * - AUPComplianceAssessor - Checks for Acceptable Use Policy violations
 *
 * ### Tier 2: Compliance (MCP Directory) - 4 modules
 * - ToolAnnotationAssessor - Verifies tool annotations per Policy #17
 * - ProhibitedLibrariesAssessor - Detects prohibited libraries per Policy #28-30
 * - ManifestValidationAssessor - Validates MCPB manifest.json
 * - AuthenticationAssessor - OAuth and authentication evaluation
 *
 * ### Tier 3: Capability-Based (Conditional) - 3 modules
 * - ResourceAssessor - Resource security assessment
 * - PromptAssessor - Prompt security assessment
 * - CrossCapabilitySecurityAssessor - Cross-capability attack chains
 *
 * ### Tier 4: Extended (Optional) - 3 modules
 * - DeveloperExperienceAssessor - Documentation + usability assessment (NEW)
 * - PortabilityAssessor - Checks for portability issues
 * - ExternalAPIScannerAssessor - External API detection
 *
 * ## Deprecated Modules (v1.25.0+)
 * The following modules are deprecated and will be removed in v2.0.0:
 * - DocumentationAssessor → use DeveloperExperienceAssessor
 * - UsabilityAssessor → use DeveloperExperienceAssessor
 * - MCPSpecComplianceAssessor → use ProtocolComplianceAssessor
 * - ProtocolConformanceAssessor → use ProtocolComplianceAssessor
 *
 * @module assessment/modules
 */

// Base class
export { BaseAssessor } from "./BaseAssessor";

// ============================================================================
// Tier 1: Core Security (Always Run)
// ============================================================================

export { FunctionalityAssessor } from "./FunctionalityAssessor";
export { SecurityAssessor } from "./SecurityAssessor";
export { TemporalAssessor } from "./TemporalAssessor";
export { ErrorHandlingAssessor } from "./ErrorHandlingAssessor";
export { ProtocolComplianceAssessor } from "./ProtocolComplianceAssessor";
export { AUPComplianceAssessor } from "./AUPComplianceAssessor";

// ============================================================================
// Tier 2: Compliance (MCP Directory)
// ============================================================================

export { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
export { ProhibitedLibrariesAssessor } from "./ProhibitedLibrariesAssessor";
export { ManifestValidationAssessor } from "./ManifestValidationAssessor";
export { AuthenticationAssessor } from "./AuthenticationAssessor";

// ============================================================================
// Tier 3: Capability-Based (Conditional)
// ============================================================================

export { ResourceAssessor } from "./ResourceAssessor";
export { PromptAssessor } from "./PromptAssessor";
export { CrossCapabilitySecurityAssessor } from "./CrossCapabilitySecurityAssessor";

// ============================================================================
// Tier 4: Extended (Optional)
// ============================================================================

export { DeveloperExperienceAssessor } from "./DeveloperExperienceAssessor";
export { PortabilityAssessor } from "./PortabilityAssessor";
export { ExternalAPIScannerAssessor } from "./ExternalAPIScannerAssessor";

// ============================================================================
// Helper Modules (Extracted for maintainability)
// ============================================================================

/**
 * Security testing helper modules - extracted from SecurityAssessor
 * These are composition helpers, not standalone assessors
 */
export * from "./securityTests";

/**
 * Annotation helper modules - extracted from ToolAnnotationAssessor
 * These are composition helpers, not standalone assessors
 */
export * from "./annotations";

// ============================================================================
// Deprecated Exports (backward compatibility - will be removed in v2.0.0)
// ============================================================================

/**
 * @deprecated Use DeveloperExperienceAssessor instead.
 * DocumentationAssessor has been merged into DeveloperExperienceAssessor.
 * This export will be removed in v2.0.0.
 */
export { DocumentationAssessor } from "./DocumentationAssessor";

/**
 * @deprecated Use DeveloperExperienceAssessor instead.
 * UsabilityAssessor has been merged into DeveloperExperienceAssessor.
 * This export will be removed in v2.0.0.
 */
export { UsabilityAssessor } from "./UsabilityAssessor";

/**
 * @deprecated Use ProtocolComplianceAssessor instead.
 * MCPSpecComplianceAssessor has been merged into ProtocolComplianceAssessor.
 * This export will be removed in v2.0.0.
 */
export { MCPSpecComplianceAssessor } from "./MCPSpecComplianceAssessor";

/**
 * @deprecated Use ProtocolComplianceAssessor instead.
 * ProtocolConformanceAssessor has been merged into ProtocolComplianceAssessor.
 * This export will be removed in v2.0.0.
 */
export { ProtocolConformanceAssessor } from "./ProtocolConformanceAssessor";

// ============================================================================
// Type Re-exports (convenience for consumers)
// ============================================================================

export type {
  // Core result types
  MCPDirectoryAssessment,
  SecurityAssessment,
  FunctionalityAssessment,
  ErrorHandlingAssessment,
  DocumentationAssessment,
  UsabilityAssessment,
  MCPSpecComplianceAssessment,
  // Assessment status
  AssessmentStatus,
} from "@/lib/assessment";

export type {
  // Configuration
  AssessmentConfiguration,
} from "@/lib/assessment/configTypes";

export type {
  // Progress callbacks
  ProgressCallback,
  ProgressEvent,
} from "@/lib/assessment/progressTypes";
