/**
 * Capability Assessment Types
 *
 * Types for MCP capability assessments including resources, prompts,
 * cross-capability security, protocol conformance, official MCP conformance,
 * file modularization, and developer experience.
 *
 * @module assessment/capabilityAssessmentTypes
 */

import type { AssessmentStatus, SecurityRiskLevel } from "./coreTypes";

// ============================================================================
// Resource Assessment Types
// Evaluates MCP server resources for security and compliance
// ============================================================================

export interface ResourceTestResult {
  resourceUri: string;
  resourceName?: string;
  mimeType?: string;
  tested: boolean;
  accessible: boolean;
  securityIssues: string[];
  pathTraversalVulnerable: boolean;
  sensitiveDataExposed: boolean;
  promptInjectionDetected: boolean;
  promptInjectionPatterns: string[];
  validUri: boolean;
  readTime?: number;
  contentSizeBytes?: number;
  error?: string;
  // NEW: Enriched fields for Claude analysis alignment (Issue #9)
  /** Sensitive data patterns detected in resource content */
  sensitivePatterns?: Array<{
    pattern: string;
    severity: "critical" | "high" | "medium";
    detected: boolean;
  }>;
  /** Access control information */
  accessControls?: {
    requiresAuth: boolean;
    authType?: string;
  };
  /** Data classification based on content analysis */
  dataClassification?: "public" | "internal" | "confidential" | "restricted";
  // Issue #119, Challenge #14: URI injection testing fields
  /** Whether URI injection testing was performed */
  uriInjectionTested?: boolean;
  /** The injection payload used in this test */
  uriInjectionPayload?: string;
  // Issue #119, Challenge #14: Hidden resource discovery fields
  /** Whether this result is from hidden resource probing */
  hiddenResourceProbe?: boolean;
  /** The pattern used to probe for this hidden resource */
  probePattern?: string;
  // Issue #127, Challenge #24: Binary resource vulnerability fields
  /** Whether blob DoS testing was performed */
  blobDosTested?: boolean;
  /** DoS risk level from size analysis */
  blobDosRiskLevel?: "HIGH" | "MEDIUM" | "LOW" | "NONE";
  /** Requested blob size in bytes */
  blobRequestedSize?: number;
  /** Whether polyglot testing was performed */
  polyglotTested?: boolean;
  /** Polyglot combination detected (e.g., "gif/javascript") */
  polyglotCombination?: string;
  /** Whether MIME validation was performed */
  mimeValidationPerformed?: boolean;
  /** MIME type mismatch detected */
  mimeTypeMismatch?: boolean;
  /** Expected MIME type based on content magic bytes */
  expectedMimeType?: string;
  /** Declared MIME type from resource */
  declaredMimeType?: string;
}

export interface ResourceAssessment {
  resourcesTested: number;
  resourceTemplatesTested: number;
  accessibleResources: number;
  securityIssuesFound: number;
  pathTraversalVulnerabilities: number;
  sensitiveDataExposures: number;
  promptInjectionVulnerabilities: number;
  // Issue #127, Challenge #24: Binary resource vulnerability metrics
  /** Number of blob DoS vulnerabilities detected */
  blobDosVulnerabilities: number;
  /** Number of polyglot file vulnerabilities detected */
  polyglotVulnerabilities: number;
  /** Number of MIME validation failures detected */
  mimeValidationFailures: number;
  results: ResourceTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Issue #196: Stage B enrichment data for Claude validation */
  enrichmentData?: ResourceEnrichmentData;
}

// ============================================================================
// Resource Stage B Enrichment Types (Issue #196)
// ============================================================================

/**
 * Resource inventory item for Stage B validation
 */
export interface ResourceInventoryItem {
  uri: string;
  name?: string;
  mimeType?: string;
  /** Inferred resource type */
  resourceType: ResourceType;
  /** Security flags based on URI/content analysis */
  securityFlags: ResourceSecurityFlag[];
  /** Data classification */
  dataClassification: "public" | "internal" | "confidential" | "restricted";
}

/**
 * Resource type categories
 */
export type ResourceType =
  | "file" // Local file resources
  | "api" // API endpoint resources
  | "database" // Database resources
  | "config" // Configuration files
  | "credential" // Credential/secret stores
  | "binary" // Binary/blob resources
  | "template" // Resource templates
  | "unknown"; // Cannot determine

/**
 * Security flags for resources
 */
export type ResourceSecurityFlag =
  | "sensitive_uri" // URI matches sensitive pattern
  | "path_traversal_tested" // Path traversal was tested
  | "sensitive_content" // Contains sensitive content
  | "prompt_injection" // Contains prompt injection patterns
  | "hidden_resource" // Undeclared/hidden resource
  | "blob_dos_risk" // Blob DoS vulnerability
  | "polyglot_risk" // Polyglot file vulnerability
  | "mime_mismatch"; // MIME type mismatch

/**
 * Security pattern coverage for resources
 */
export interface ResourcePatternCoverage {
  /** Sensitive URI patterns checked */
  sensitiveUriPatterns: number;
  /** Path traversal payloads tested */
  pathTraversalPayloads: number;
  /** URI injection payloads tested */
  uriInjectionPayloads: number;
  /** Hidden resource patterns probed */
  hiddenResourcePatterns: number;
  /** Sample patterns tested */
  samplePatterns: string[];
}

/**
 * Flag for resources that warrant review
 */
export interface ResourceFlagForReview {
  resourceUri: string;
  /** Reason for flagging */
  reason: string;
  /** Security flags that triggered the flag */
  flags: ResourceSecurityFlag[];
  /** Risk level */
  riskLevel: "critical" | "high" | "medium" | "low";
}

/**
 * Resource enrichment data for Stage B Claude validation (Issue #196)
 */
export interface ResourceEnrichmentData {
  /** Resource inventory with security analysis */
  resourceInventory: ResourceInventoryItem[];
  /** Pattern coverage showing what was tested */
  patternCoverage: ResourcePatternCoverage;
  /** Resources flagged for review */
  flagsForReview: ResourceFlagForReview[];
  /** Summary metrics */
  metrics: {
    totalResources: number;
    totalTemplates: number;
    sensitiveResources: number;
    accessibleResources: number;
    vulnerableResources: number;
  };
}

// ============================================================================
// Prompt Assessment Types
// Evaluates MCP server prompts for security and AUP compliance
// ============================================================================

export interface PromptTestResult {
  promptName: string;
  description?: string;
  tested: boolean;
  hasRequiredArguments: boolean;
  argumentsValidated: boolean;
  aupCompliant: boolean;
  injectionVulnerable: boolean;
  safetyIssues: string[];
  argumentCount: number;
  executionTime?: number;
  error?: string;
  // NEW: Enriched fields for Claude analysis alignment (Issue #9)
  /** Template analysis for prompt structure */
  promptTemplate?: {
    templateType: string;
    variables: string[];
    validated: boolean;
  };
  /** Dynamic content analysis */
  dynamicContent?: {
    hasInterpolation: boolean;
    injectionSafe: boolean;
    escapingApplied: string[];
  };
}

export interface PromptAssessment {
  promptsTested: number;
  aupViolations: number;
  injectionVulnerabilities: number;
  argumentValidationIssues: number;
  results: PromptTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Issue #197: Stage B enrichment data for Claude validation */
  enrichmentData?: PromptEnrichmentData;
}

// ============================================================================
// Prompt Stage B Enrichment Types (Issue #197)
// ============================================================================

/**
 * Prompt inventory item for Stage B validation
 */
export interface PromptInventoryItem {
  name: string;
  description?: string;
  /** Number of arguments */
  argumentCount: number;
  /** Required argument names */
  requiredArgs: string[];
  /** Optional argument names */
  optionalArgs: string[];
  /** Inferred prompt category */
  category: PromptCategory;
  /** Security flags based on analysis */
  securityFlags: PromptSecurityFlag[];
}

/**
 * Prompt category classifications
 */
export type PromptCategory =
  | "code_generation" // Code-related prompts
  | "data_query" // Database/data queries
  | "content_creation" // Text/content generation
  | "system_control" // System/admin operations
  | "user_interaction" // User-facing interactions
  | "templating" // Template-based prompts
  | "unknown"; // Cannot determine

/**
 * Security flags for prompts
 */
export type PromptSecurityFlag =
  | "aup_violation" // Contains AUP-violating content
  | "injection_vulnerable" // Vulnerable to injection
  | "missing_validation" // Arguments not validated
  | "sensitive_data" // References sensitive data
  | "dynamic_content" // Has dynamic interpolation
  | "system_access" // References system operations
  | "code_execution"; // Can trigger code execution

/**
 * Security pattern coverage for prompts
 */
export interface PromptPatternCoverage {
  /** Total injection patterns checked */
  injectionPatternsChecked: number;
  /** AUP patterns checked */
  aupPatternsChecked: number;
  /** Argument validation checks performed */
  argumentValidationChecks: number;
  /** Sample patterns tested */
  samplePatterns: string[];
}

/**
 * Flag for prompts that warrant review
 */
export interface PromptFlagForReview {
  promptName: string;
  /** Reason for flagging */
  reason: string;
  /** Security flags that triggered the flag */
  flags: PromptSecurityFlag[];
  /** Risk level */
  riskLevel: "critical" | "high" | "medium" | "low";
}

/**
 * Prompt enrichment data for Stage B Claude validation (Issue #197)
 */
export interface PromptEnrichmentData {
  /** Prompt inventory with security analysis */
  promptInventory: PromptInventoryItem[];
  /** Pattern coverage showing what was tested */
  patternCoverage: PromptPatternCoverage;
  /** Prompts flagged for review */
  flagsForReview: PromptFlagForReview[];
  /** Summary metrics */
  metrics: {
    totalPrompts: number;
    aupViolations: number;
    injectionVulnerabilities: number;
    argumentValidationIssues: number;
    promptsWithDynamicContent: number;
  };
}

// ============================================================================
// Cross-Capability Security Assessment Types
// Tests interactions between tools, resources, and prompts
// ============================================================================

export interface CrossCapabilityTestResult {
  testType:
    | "tool_to_resource"
    | "prompt_to_tool"
    | "resource_to_tool"
    | "privilege_escalation";
  sourceCapability: string;
  targetCapability: string;
  vulnerable: boolean;
  evidence?: string;
  riskLevel: SecurityRiskLevel;
  description: string;
  // NEW: Enriched fields for Claude analysis alignment (Issue #9)
  /** Specific privilege escalation vector if detected */
  privilegeEscalationVector?: string;
  /** Data exfiltration risk details */
  dataExfiltrationRisk?: {
    sensitiveFields: string[];
    exfiltrationMethod: string;
  };
  /** Chain of capabilities that could be exploited together */
  attackChain?: string[];
  /** Confidence level in the detection */
  confidence?: "high" | "medium" | "low";
}

export interface CrossCapabilitySecurityAssessment {
  testsRun: number;
  vulnerabilitiesFound: number;
  privilegeEscalationRisks: number;
  dataFlowViolations: number;
  results: CrossCapabilityTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Protocol Conformance Assessment Types
// Validates MCP protocol-level compliance (error format, content types, etc.)
// Complements ErrorHandlingAssessor (application-level) with protocol-level checks
// ============================================================================

/**
 * Result of a single protocol conformance check
 */
export interface ProtocolCheck {
  /** Whether the check passed */
  passed: boolean;
  /** Confidence level of the check result */
  confidence: "high" | "medium" | "low";
  /** Human-readable evidence of the check result */
  evidence: string;
  /** URL to the MCP specification section this check validates */
  specReference: string;
  /** Additional details about the check (e.g., raw responses, validation results) */
  details?: Record<string, unknown>;
  /** Warnings that don't fail the check but should be noted */
  warnings?: string[];
}

/**
 * Protocol Conformance Assessment Results
 * Tests MCP protocol-level compliance including error response format,
 * content type support, and initialization handshake validation.
 */
export interface ProtocolConformanceAssessment {
  /** Individual protocol checks */
  checks: {
    /** Validates error responses follow MCP format (isError flag, content array structure) */
    errorResponseFormat: ProtocolCheck;
    /** Validates content types are valid (text, image, audio, resource) */
    contentTypeSupport: ProtocolCheck;
    /** Validates server completed proper initialization handshake */
    initializationHandshake: ProtocolCheck;
    /** Optional: Validates progress notification format (if tools support progress) */
    progressNotifications?: ProtocolCheck;
    /** Optional: Validates log notification format (if tools support logging) */
    logNotifications?: ProtocolCheck;
  };
  /** Overall conformance score (0-100) */
  score: number;
  /** Assessment status based on score and critical check failures */
  status: AssessmentStatus;
  /** Human-readable explanation of the assessment result */
  explanation: string;
  /** Recommendations for improving protocol conformance */
  recommendations: string[];
}

// ============================================================================
// File Modularization Assessment Types (Issue #104)
// Detects large monolithic tool files and recommends modularization
// ============================================================================

/**
 * Severity level for file modularization issues
 */
export type FileSeverity = "HIGH" | "MEDIUM" | "LOW" | "INFO";

/**
 * Information about a large file detected in the codebase
 */
export interface LargeFileInfo {
  /** Relative path to the file */
  path: string;
  /** Total line count */
  lines: number;
  /** Number of tool definitions detected */
  toolCount: number;
  /** Severity of the modularization issue */
  severity: FileSeverity;
  /** Specific recommendation for this file */
  recommendation: string;
}

/**
 * Result of a single modularization check
 */
export interface ModularizationCheck {
  /** Name of the check (e.g., "file_line_count", "tool_per_file") */
  checkName: string;
  /** Whether the check passed */
  passed: boolean;
  /** Severity if failed */
  severity: FileSeverity;
  /** Evidence explaining the result */
  evidence?: string;
  /** Threshold that was checked against */
  threshold?: number;
  /** Actual value measured */
  actualValue?: number;
}

/**
 * Aggregated metrics about file modularization
 */
export interface FileModularizationMetrics {
  /** Total number of source files analyzed */
  totalSourceFiles: number;
  /** Total lines across all source files */
  totalLines: number;
  /** Files exceeding thresholds, sorted by size */
  largestFiles: LargeFileInfo[];
  /** Count of files over 1,000 lines (warning threshold) */
  filesOver1000Lines: number;
  /** Count of files over 2,000 lines (error threshold) */
  filesOver2000Lines: number;
  /** Count of files with more than 10 tools */
  filesWithOver10Tools: number;
  /** Count of files with more than 20 tools */
  filesWithOver20Tools: number;
  /** Whether the codebase has modular structure (tools/ dir, multiple files) */
  hasModularStructure: boolean;
  /** Overall modularization score (0-100) */
  modularizationScore: number;
}

/**
 * Complete file modularization assessment result
 */
export interface FileModularizationAssessment {
  /** Aggregated metrics */
  metrics: FileModularizationMetrics;
  /** Individual check results */
  checks: ModularizationCheck[];
  /** Overall assessment status */
  status: AssessmentStatus;
  /** Human-readable explanation of the assessment */
  explanation: string;
  /** Specific recommendations for improvement */
  recommendations: string[];
}

// ============================================================================
// MCP Conformance Types (Official MCP Protocol Conformance)
// Integration with @modelcontextprotocol/conformance package
// ============================================================================

/**
 * Individual conformance check result
 */
export interface ConformanceCheck {
  /** Name of the conformance check */
  name: string;
  /** Whether the check passed */
  status: "pass" | "fail" | "skip";
  /** Human-readable message explaining the result */
  message: string;
  /** Reference to MCP specification section */
  specReference?: string;
  /** Timestamp when check was executed */
  timestamp?: string;
}

/**
 * Result of a conformance scenario (group of related checks)
 */
export interface ConformanceScenario {
  /** Scenario name (e.g., "server-initialize", "tools-list") */
  name: string;
  /** Overall scenario status */
  status: "pass" | "fail" | "skip";
  /** Individual checks within this scenario */
  checks: ConformanceCheck[];
  /** Execution time in milliseconds */
  executionTime?: number;
}

/**
 * Complete MCP conformance assessment result
 * Uses official @modelcontextprotocol/conformance package
 */
export interface ConformanceAssessment {
  /** Overall assessment status */
  status: AssessmentStatus;
  /** Version of the conformance package used */
  conformanceVersion: string;
  /** MCP protocol version tested against */
  protocolVersion: string;
  /** Scenario results from official conformance tests */
  scenarios: ConformanceScenario[];
  /** All individual checks (flattened from scenarios) */
  officialChecks: ConformanceCheck[];
  /** Number of checks that passed */
  passedChecks: number;
  /** Total number of checks run */
  totalChecks: number;
  /** Compliance score (0-100) */
  complianceScore: number;
  /** Human-readable explanation */
  explanation: string;
  /** Recommendations for improving conformance */
  recommendations: string[];
  /** Whether conformance tests were skipped (e.g., server unavailable) */
  skipped?: boolean;
  /** Reason for skipping if applicable */
  skipReason?: string;
}

// ============================================================================
// Developer Experience Assessment Types (Issue #124)
// Combined documentation + usability assessment for v2.0.0 transition
// ============================================================================

// Import result types for composition (circular import avoided via import type)
import type {
  DocumentationAssessment,
  UsabilityAssessment,
} from "./resultTypes";

/**
 * Combined Developer Experience Assessment
 * Merges documentation and usability assessments into a single logical grouping.
 *
 * Added in v1.32.0 for backward-compatible transition.
 * In v2.0.0, this will replace the separate `documentation` and `usability` keys
 * in MCPDirectoryAssessment.
 *
 * @since 1.32.0
 */
export interface DeveloperExperienceAssessment {
  /** Documentation assessment results */
  documentation: DocumentationAssessment;
  /** Usability assessment results */
  usability: UsabilityAssessment;
  /** Overall status based on both assessments */
  status: AssessmentStatus;
  /** Combined score (average of documentation and usability scores, 0-100) */
  score: number;
  /** Namespace detection results (Issue #142) - helps identify intentional naming patterns */
  namespaceDetection?: import("./coreTypes").NamespaceDetectionResult;
}
