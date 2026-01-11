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
  /** Extended metadata extraction (Issue #54) */
  extendedMetadata?: {
    /** Rate limiting configuration */
    rateLimit?: {
      windowMs?: number;
      maxRequests?: number;
      requestsPerMinute?: number;
      requestsPerSecond?: number;
    };
    /** Permission/scope requirements */
    permissions?: {
      required?: string[];
      scopes?: string[];
    };
    /** Return schema presence */
    returnSchema?: {
      hasSchema: boolean;
      schema?: object;
    };
    /** Bulk operation support */
    bulkOperations?: {
      supported: boolean;
      maxBatchSize?: number;
    };
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
  /** Extended metadata coverage metrics (Issue #54) */
  extendedMetadataMetrics?: {
    toolsWithRateLimits: number;
    toolsWithPermissions: number;
    toolsWithReturnSchema: number;
    toolsWithBulkSupport: number;
  };
  /** Server architecture analysis (Issue #57) */
  architectureAnalysis?: ArchitectureAnalysis;
  /** Enhanced behavior inference metrics (Issue #57) */
  behaviorInferenceMetrics?: {
    /** Count of tools matched by name patterns */
    namePatternMatches: number;
    /** Count of tools matched by description analysis */
    descriptionMatches: number;
    /** Count of tools matched by schema analysis */
    schemaMatches: number;
    /** Average aggregated confidence across all tools (0-100) */
    aggregatedConfidenceAvg: number;
  };
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

// ============================================================================
// Authentication Configuration Types (Issue #62)
// Detects env-dependent auth, fail-open patterns, and dev mode warnings
// ============================================================================

/** Type of authentication configuration finding */
export type AuthConfigFindingType =
  | "ENV_DEPENDENT_AUTH" // Auth depends on env var that may be missing
  | "FAIL_OPEN_PATTERN" // Auth bypassed when config missing (env var fallback)
  | "FAIL_OPEN_LOGIC" // Auth bypassed due to logic flaw (error handling grants access)
  | "DEV_MODE_WARNING" // Dev mode weakens security
  | "HARDCODED_SECRET"; // Secret hardcoded instead of env var

/** Severity of auth configuration finding */
export type AuthConfigSeverity = "HIGH" | "MEDIUM" | "LOW";

/** Context lines surrounding a finding (Issue #66) */
export interface AuthConfigFindingContext {
  /** Line before the finding (undefined if finding is on first line) */
  before?: string;
  /** Line after the finding (undefined if finding is on last line) */
  after?: string;
}

/** Single auth configuration finding */
export interface AuthConfigFinding {
  type: AuthConfigFindingType;
  severity: AuthConfigSeverity;
  message: string;
  evidence: string;
  file?: string;
  lineNumber?: number;
  recommendation?: string;
  /** Issue #66: Surrounding context lines for better understanding */
  context?: AuthConfigFindingContext;
}

/** Auth configuration analysis results */
export interface AuthConfigAnalysis {
  /** Total findings detected */
  totalFindings: number;
  /** Findings by type */
  envDependentAuthCount: number;
  failOpenPatternCount: number;
  failOpenLogicCount: number;
  devModeWarningCount: number;
  hardcodedSecretCount: number;
  /** Detailed findings */
  findings: AuthConfigFinding[];
  /** Has any HIGH severity findings */
  hasHighSeverity: boolean;
  /** Environment variables detected for auth */
  envVarsDetected: string[];
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
  /** Issue #62: Auth configuration analysis for env-dependent auth and fail-open patterns */
  authConfigAnalysis?: AuthConfigAnalysis;
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
  /** Issue #69: Variance classification for reduced false positives */
  varianceClassification?: VarianceClassification;
  /** Issue #69: Per-invocation variance details for transparency */
  varianceDetails?: Array<{
    invocation: number;
    classification: VarianceClassification;
  }>;
  /**
   * Issue #119, Challenge #2: Detection phase tracking
   * Indicates when the deviation was first detected
   * - "baseline" (invocations 1-5): Deviation during safe behavior establishment
   * - "monitoring" (invocations 6-15): Deviation during threshold monitoring
   * - null: No deviation detected
   */
  detectionPhase?: "baseline" | "monitoring" | null;
}

// ============================================================================
// Variance Classification Types (Issue #69)
// Distinguishes legitimate response variance from suspicious behavioral changes
// ============================================================================

/**
 * Classification of temporal variance between tool invocations.
 * Used to reduce false positives while maintaining detection capability.
 *
 * - LEGITIMATE: Expected variance (IDs, timestamps, search results, pagination)
 * - SUSPICIOUS: Concerning changes (capabilities, permissions, schema structure)
 * - BEHAVIORAL: Semantic changes (promotional keywords, error injection)
 */
export type VarianceType = "LEGITIMATE" | "SUSPICIOUS" | "BEHAVIORAL";

/**
 * Result of variance classification analysis.
 * Provides transparency into why a response difference was classified.
 */
export interface VarianceClassification {
  /** Type of variance detected */
  type: VarianceType;
  /** Confidence in the classification */
  confidence: "high" | "medium" | "low";
  /** Human-readable reasons for the classification */
  reasons: string[];
  /** Field paths that varied between invocations */
  variedFields?: string[];
  /** Suspicious patterns detected (if type is SUSPICIOUS or BEHAVIORAL) */
  suspiciousPatterns?: string[];
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

// ============================================================================
// Architecture Detection Types (Issue #57)
// Detects database backends, server types, and transport capabilities
// ============================================================================

/**
 * Database backend types detected from patterns
 */
export type DatabaseBackend =
  | "neo4j"
  | "mongodb"
  | "sqlite"
  | "postgresql"
  | "mysql"
  | "redis"
  | "dynamodb"
  | "firestore"
  | "supabase"
  | "cassandra"
  | "elasticsearch"
  | "unknown";

/**
 * Transport mode capabilities
 */
export type TransportMode = "stdio" | "http" | "sse";

/**
 * Server architecture classification
 */
export type ServerArchitectureType = "local" | "hybrid" | "remote";

/**
 * Result of architecture analysis
 * Provides insights into server infrastructure and dependencies
 */
export interface ArchitectureAnalysis {
  /** Classification of server architecture */
  serverType: ServerArchitectureType;
  /** Primary detected database backend (if any) */
  databaseBackend?: DatabaseBackend;
  /** All detected database backends (may include multiple) */
  databaseBackends: DatabaseBackend[];
  /** Detected transport modes the server supports */
  transportModes: TransportMode[];
  /** External services detected (e.g., GitHub, AWS, OpenAI) */
  externalDependencies: string[];
  /** Whether the server requires network/internet access */
  requiresNetworkAccess: boolean;
  /** Confidence level of the analysis */
  confidence: "high" | "medium" | "low";
  /** Evidence supporting the analysis */
  evidence: {
    /** Strings matched that indicate database usage */
    databaseIndicators: string[];
    /** Strings matched that indicate transport modes */
    transportIndicators: string[];
    /** Strings matched that indicate network requirements */
    networkIndicators: string[];
  };
}

// ============================================================================
// Enhanced Behavior Inference Types (Issue #57)
// Multi-signal behavior inference with aggregated confidence
// ============================================================================

/**
 * Signal from a single inference source (name, description, or schema)
 */
export interface InferenceSignal {
  /** Whether this signal indicates read-only behavior */
  expectedReadOnly: boolean;
  /** Whether this signal indicates destructive behavior */
  expectedDestructive: boolean;
  /** Confidence level (0-100) */
  confidence: number;
  /** Evidence explaining why this signal was detected */
  evidence: string[];
}

/**
 * Enhanced behavior inference result with multi-signal analysis
 * Aggregates signals from name patterns, descriptions, and schemas
 */
export interface EnhancedBehaviorInferenceResult {
  /** Final inferred behavior */
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  /** Primary reason for the inference */
  reason: string;
  /** Overall confidence level */
  confidence: "high" | "medium" | "low";
  /** Whether the inference is ambiguous */
  isAmbiguous: boolean;
  /** Individual signals from each source */
  signals: {
    /** Signal from tool name pattern matching */
    namePatternSignal?: InferenceSignal;
    /** Signal from description keyword analysis */
    descriptionSignal?: InferenceSignal;
    /** Signal from input schema analysis */
    inputSchemaSignal?: InferenceSignal;
    /** Signal from output schema analysis */
    outputSchemaSignal?: InferenceSignal;
  };
  /** Aggregated confidence from all signals (0-100) */
  aggregatedConfidence: number;
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
}
