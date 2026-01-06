/**
 * Extended Assessment Types
 *
 * Types for extended assessment modules including AUP compliance,
 * tool annotations, temporal detection, and capability assessors.
 *
 * @module assessment/extendedTypes
 */

import type {
  AssessmentStatus,
  SecurityRiskLevel,
  InferenceConfidence,
  AlignmentStatus,
} from "./coreTypes";

// ============================================================================
// AUP (Acceptable Use Policy) Compliance Types
// Based on Anthropic's 14 AUP categories (A-N)
// ============================================================================

export type AUPCategory =
  | "A" // Child Sexual Abuse Material
  | "B" // Weapons of Mass Destruction
  | "C" // Malware & Cyberweapons
  | "D" // Disinformation & Election Interference
  | "E" // Fraud & Deception
  | "F" // Harassment & Abuse
  | "G" // Privacy Violations
  | "H" // Unauthorized Practice
  | "I" // Copyright Circumvention
  | "J" // High-Risk Decisions
  | "K" // Critical Infrastructure
  | "L" // Adult Content
  | "M" // Illegal Activities
  | "N"; // Other Prohibited Uses

export type AUPSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "FLAG";

export interface AUPViolation {
  category: AUPCategory;
  categoryName: string;
  severity: AUPSeverity;
  pattern: string;
  matchedText: string;
  location: "tool_name" | "tool_description" | "readme" | "source_code";
  filePath?: string;
  lineNumber?: number;
  confidence: "high" | "medium" | "low";
  requiresHumanReview: boolean;
  reviewGuidance?: string;
}

export interface AUPComplianceAssessment {
  violations: AUPViolation[];
  highRiskDomains: string[];
  scannedLocations: {
    toolNames: boolean;
    toolDescriptions: boolean;
    readme: boolean;
    sourceCode: boolean;
  };
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Tool Annotation Types (Policy #17)
// Verifies readOnlyHint, destructiveHint presence
// ============================================================================

/**
 * Source of tool annotations
 */
export type AnnotationSource = "mcp" | "source-code" | "inferred" | "none";

export interface ToolAnnotationResult {
  toolName: string;
  hasAnnotations: boolean;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    title?: string;
    description?: string;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  /** Where the annotations were extracted from */
  annotationSource?: AnnotationSource;
  inferredBehavior?: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
    /** Confidence level of the inference */
    confidence: InferenceConfidence;
    /** True if the tool name matches an ambiguous pattern */
    isAmbiguous: boolean;
  };
  /** Alignment status between annotations and inferred behavior */
  alignmentStatus?: AlignmentStatus;
  issues: string[];
  recommendations: string[];
  /** Description poisoning detection (Issue #8) */
  descriptionPoisoning?: {
    detected: boolean;
    patterns: Array<{
      name: string;
      pattern: string;
      severity: "LOW" | "MEDIUM" | "HIGH";
      category: string;
      evidence: string;
    }>;
    riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  };
}

export interface ToolAnnotationAssessment {
  toolResults: ToolAnnotationResult[];
  annotatedCount: number;
  missingAnnotationsCount: number;
  /** Count of high-confidence misalignments only (excludes REVIEW_RECOMMENDED) */
  misalignedAnnotationsCount: number;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Detailed metrics for annotation quality */
  metrics?: {
    /** Percentage of tools with any annotations (0-100) */
    coverage: number;
    /** Percentage of tools without contradictions (0-100) */
    consistency: number;
    /** Percentage of high-confidence alignments (0-100) */
    correctness: number;
    /** Count of tools needing manual review */
    reviewRequired: number;
  };
  /** Breakdown of tools by alignment status */
  alignmentBreakdown?: {
    aligned: number;
    misaligned: number;
    reviewRecommended: number;
    unknown: number;
  };
  /** Summary of where annotations were extracted from */
  annotationSources?: {
    /** Count from MCP protocol (tools/list response) */
    mcp: number;
    /** Count from source code analysis */
    sourceCode: number;
    /** Count where behavior was inferred from patterns */
    inferred: number;
    /** Count with no annotations found */
    none: number;
  };
  /** Count of tools with poisoned descriptions detected (Issue #8) */
  poisonedDescriptionsDetected?: number;
}

// ============================================================================
// Prohibited Libraries Types (Policy #28-30)
// Detects financial and media processing libraries
// ============================================================================

export type ProhibitedLibraryCategory =
  | "financial"
  | "media"
  | "payments"
  | "banking";

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
}

export interface ProhibitedLibrariesAssessment {
  matches: ProhibitedLibraryMatch[];
  scannedFiles: string[];
  hasFinancialLibraries: boolean;
  hasMediaLibraries: boolean;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// MCPB Manifest Validation Types
// Based on manifest_version 0.3 spec
// ============================================================================

export interface ManifestJsonSchema {
  manifest_version: string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  repository?: string;
  license?: string;
  mcp_config: {
    command: string;
    args?: string[];
    env?: Record<string, string>;
  };
  icon?: string;
  homepage?: string;
  keywords?: string[];
  privacy_policies?: string[]; // URLs to privacy policy documents
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

// ============================================================================
// External API Scanner Types
// ============================================================================

export interface DetectedAPI {
  url: string;
  service: string; // 'github' | 'slack' | 'aws' | 'openai' | 'anthropic' | 'unknown'
  filePath: string;
}

export interface ExternalAPIScannerAssessment {
  detectedAPIs: DetectedAPI[];
  uniqueServices: string[];
  affiliationWarning?: string; // If server name suggests unverified affiliation
  scannedFiles: number;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Authentication Assessment Types
// ============================================================================

export type AuthMethod = "oauth" | "api_key" | "none" | "unknown";

export interface AuthAppropriateness {
  isAppropriate: boolean;
  concerns: string[];
  explanation: string;
}

export interface TransportSecurityAnalysis {
  usesTLS: boolean;
  tlsEnforced: boolean;
  hasInsecurePatterns: boolean;
  insecurePatterns: string[];
  hasSecurePatterns: boolean;
  securePatterns: string[];
  corsConfigured: boolean;
  corsPermissive: boolean;
  sessionSecure: boolean;
  recommendations: string[];
}

export interface AuthenticationAssessment {
  authMethod: AuthMethod;
  hasLocalDependencies: boolean;
  transportType: string;
  appropriateness: AuthAppropriateness;
  recommendation: string;
  detectedPatterns: {
    oauthIndicators: string[];
    localResourceIndicators: string[];
    apiKeyIndicators: string[];
  };
  transportSecurity?: TransportSecurityAnalysis;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Temporal/Rug Pull Assessment Types
// Detects tools that change behavior after N invocations
// ============================================================================

export interface TemporalToolResult {
  tool: string;
  vulnerable: boolean;
  totalInvocations: number;
  firstDeviationAt: number | null;
  deviationCount: number;
  errorCount: number; // Track errors during invocations (subset of deviationCount)
  pattern: "RUG_PULL_TEMPORAL" | "RUG_PULL_DEFINITION" | null;
  severity: "HIGH" | "MEDIUM" | "NONE";
  reducedInvocations?: boolean; // True if destructive tool detection applied
  note?: string; // Additional context (e.g., stateful tool with expected variation)
  evidence?: {
    safeResponseExample: unknown;
    maliciousResponseExample: unknown;
  };
  // Definition mutation tracking (Issue #7)
  definitionMutated?: boolean; // True if tool description/schema changed during invocations
  definitionMutationAt?: number | null; // Invocation number where mutation was detected
  definitionEvidence?: {
    baselineDescription?: string;
    mutatedDescription?: string;
    baselineSchema?: unknown;
    mutatedSchema?: unknown;
  };
}

export interface TemporalAssessment {
  toolsTested: number;
  invocationsPerTool: number;
  rugPullsDetected: number;
  definitionMutationsDetected: number; // Tools that changed description/schema during invocations
  details: TemporalToolResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

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
}

export interface ResourceAssessment {
  resourcesTested: number;
  resourceTemplatesTested: number;
  accessibleResources: number;
  securityIssuesFound: number;
  pathTraversalVulnerabilities: number;
  sensitiveDataExposures: number;
  promptInjectionVulnerabilities: number;
  results: ResourceTestResult[];
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
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
