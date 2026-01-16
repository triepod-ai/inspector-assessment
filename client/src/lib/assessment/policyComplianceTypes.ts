/**
 * Policy Compliance Types
 *
 * Types for prohibited library detection (Policy #28-30), MCPB manifest
 * validation (manifest_version 0.3), and portability assessment.
 *
 * @module assessment/policyComplianceTypes
 */

import type { AssessmentStatus } from "./coreTypes";

// ============================================================================
// Prohibited Libraries Types (Policy #28-30)
// Detects financial and media processing libraries
// ============================================================================

export type ProhibitedLibraryCategory =
  | "financial"
  | "media"
  | "payments"
  | "banking";

export type DependencyUsageStatus = "ACTIVE" | "UNUSED" | "UNKNOWN";

export interface ProhibitedLibraryMatch {
  name: string;
  category: ProhibitedLibraryCategory;
  location:
    | "package.json"
    | "source_import"
    | "requirements.txt"
    | "cargo.toml";
  filePath?: string;
  lineNumber?: number;
  severity: "BLOCKING" | "HIGH" | "MEDIUM";
  reason: string;
  policyReference: string;
  /** Whether the dependency is actually imported in source code (Issue #63) */
  usageStatus?: DependencyUsageStatus;
  /** Number of import statements found for this dependency */
  importCount?: number;
  /** Files where the dependency is imported */
  importFiles?: string[];
}

export interface ProhibitedLibrariesAssessment {
  matches: ProhibitedLibraryMatch[];
  scannedFiles: string[];
  hasFinancialLibraries: boolean;
  hasMediaLibraries: boolean;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Whether assessment was skipped due to missing files (Issue #154) */
  skipped?: boolean;
  /** Reason for skipping if applicable */
  skipReason?: string;
}

// ============================================================================
// MCPB Manifest Validation Types
// Based on manifest_version 0.3 spec
// ============================================================================

/**
 * MCP Config structure (used in both root-level and nested server.mcp_config)
 */
export interface McpConfigSchema {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

/**
 * Server object structure for v0.3 nested format (Issue #138)
 * mcp_config can be nested under server object instead of at root level
 */
export interface ManifestServerSchema {
  type?: string;
  entry_point?: string;
  mcp_config?: McpConfigSchema;
}

/**
 * Tool declaration in manifest.json
 * Used for manifest vs server tool name validation (Issue #140)
 */
export interface ManifestToolDeclaration {
  name: string;
  description?: string;
}

/**
 * npm-style author object format (Issue #141)
 * Supports structured author information with name, url, and email
 */
export interface ManifestAuthorObject {
  name: string;
  url?: string;
  email?: string;
}

export interface ManifestJsonSchema {
  manifest_version: string;
  name: string;
  version: string;
  description?: string;
  author?: string | ManifestAuthorObject; // Supports both string and object (Issue #141)
  repository?: string;
  license?: string;
  mcp_config?: McpConfigSchema; // Root level (legacy) - now optional
  server?: ManifestServerSchema; // v0.3 nested format (Issue #138)
  icon?: string;
  homepage?: string;
  keywords?: string[];
  privacy_policies?: string[]; // URLs to privacy policy documents
  tools?: ManifestToolDeclaration[]; // Tool declarations for validation (Issue #140)
}

/**
 * Privacy Policy URL Validation Result
 * Validates that privacy_policies URLs are accessible
 */
export interface PrivacyPolicyValidation {
  url: string;
  accessible: boolean;
  statusCode?: number;
  contentType?: string;
  error?: string;
}

export interface ManifestValidationResult {
  field: string;
  valid: boolean;
  value?: unknown;
  expectedType?: string;
  issue?: string;
  severity: "ERROR" | "WARNING" | "INFO";
}

/**
 * Extracted contact information from manifest (Issue #141)
 * Used by mcp-auditor D4 Contact Information check
 */
export interface ExtractedContactInfo {
  email?: string;
  url?: string;
  name?: string;
  source: "author_object" | "author_string" | "support" | "repository";
}

/**
 * Extracted version information from manifest (Issue #141)
 * Used by mcp-auditor D5 Version Information check
 */
export interface ExtractedVersionInfo {
  version: string;
  valid: boolean;
  semverCompliant: boolean;
}

export interface ManifestValidationAssessment {
  hasManifest: boolean;
  manifestVersion?: string;
  validationResults: ManifestValidationResult[];
  hasIcon: boolean;
  hasRequiredFields: boolean;
  missingFields: string[];
  /** Privacy policy URL validation results */
  privacyPolicies?: {
    declared: string[];
    validationResults: PrivacyPolicyValidation[];
    allAccessible: boolean;
  };
  /** Extracted contact information for D4 check (Issue #141) */
  contactInfo?: ExtractedContactInfo;
  /** Extracted version information for D5 check (Issue #141) */
  versionInfo?: ExtractedVersionInfo;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Portability Assessment Types
// Detects hardcoded paths, platform-specific code
// ============================================================================

export interface PortabilityIssue {
  type:
    | "hardcoded_path"
    | "platform_specific"
    | "bundle_root_antipattern"
    | "absolute_path"
    | "user_home_path";
  filePath: string;
  lineNumber?: number;
  matchedText: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  recommendation: string;
}

export interface PortabilityAssessment {
  issues: PortabilityIssue[];
  scannedFiles: number;
  platformSpecificCount: number;
  hardcodedPathCount: number;
  usesDirname: boolean;
  usesBundleRoot: boolean; // Anti-pattern
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  // NEW: Enriched fields for Claude analysis alignment (Issue #9)
  /** Shell command portability analysis */
  shellCommands?: Array<{
    command: string;
    isPortable: boolean;
    alternativeCommand?: string;
  }>;
  /** Platform coverage summary */
  platformCoverage?: {
    supported: "all" | "windows" | "macos" | "linux";
    missing: string[];
  };
}
