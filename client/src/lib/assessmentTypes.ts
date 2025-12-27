/**
 * MCP Directory Review Assessment Types
 * Based on Anthropic's 5 core requirements for MCP directory submission
 */

export type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO";
export type SecurityRiskLevel = "LOW" | "MEDIUM" | "HIGH";

/**
 * Alignment status for tool annotations.
 * Extends beyond PASS/FAIL to handle ambiguous cases.
 */
export type AlignmentStatus =
  | "ALIGNED" // Annotations match inferred behavior
  | "MISALIGNED" // Clear contradiction (e.g., delete_* with readOnlyHint=true)
  | "REVIEW_RECOMMENDED" // Ambiguous pattern, human review suggested
  | "UNKNOWN"; // Cannot determine alignment (no annotations)

/**
 * Confidence level for behavior inference
 */
export type InferenceConfidence = "high" | "medium" | "low";

export interface TestInputMetadata {
  toolCategory: string; // Category from ToolClassifier (e.g., "calculator")
  generationStrategy: string; // How value was generated (e.g., "category-specific", "field-name", "default")
  fieldSources: Record<
    string,
    {
      field: string;
      value: unknown;
      source:
        | "category"
        | "field-name"
        | "schema-default"
        | "enum"
        | "format"
        | "default";
      reason: string;
    }
  >;
}

export interface ToolTestResult {
  toolName: string;
  tested: boolean;
  status: "working" | "broken" | "untested";
  error?: string;
  executionTime?: number;
  testParameters?: Record<string, unknown>;
  response?: unknown;
  testInputMetadata?: TestInputMetadata;
}

// Enhanced testing types for comprehensive functionality validation
export interface EnhancedToolTestResult {
  toolName: string;
  tested: boolean;
  status:
    | "fully_working"
    | "partially_working"
    | "connectivity_only"
    | "broken"
    | "untested";
  confidence: number; // 0-100 confidence score
  scenariosExecuted: number;
  scenariosPassed: number;
  scenariosFailed: number;
  executionTime: number;
  validationSummary: {
    happyPathSuccess: boolean;
    edgeCasesHandled: number;
    edgeCasesTotal: number;
    boundariesRespected: number;
    boundariesTotal: number;
    errorHandlingWorks: boolean;
  };
  recommendations: string[];
  detailedResults?: Array<{
    scenarioName: string;
    category: "happy_path" | "edge_case" | "boundary" | "error_case";
    passed: boolean;
    confidence: number;
    issues: string[];
    evidence: string[];
  }>;
}

export interface SecurityTestResult {
  testName: string;
  description: string;
  payload: string;
  vulnerable: boolean;
  evidence?: string;
  riskLevel: SecurityRiskLevel;
  toolName?: string; // Track which tool this test was run against
  response?: string; // Track the actual response from the tool
  confidence?: "high" | "medium" | "low"; // Confidence in vulnerability detection
  requiresManualReview?: boolean; // Flag for manual verification
  manualReviewReason?: string; // Why manual review is needed
  reviewGuidance?: string; // How to perform manual review
  connectionError?: boolean; // True if test failed due to connection/server failure
  errorType?: "connection" | "server" | "protocol"; // Classify error type
  testReliability?: "completed" | "failed" | "retried"; // Test execution status
}

export interface CodeExample {
  code: string;
  language?: string;
  description?: string;
  lineNumber?: number;
}

export interface DocumentationMetrics {
  hasReadme: boolean;
  exampleCount: number;
  requiredExamples: number;
  missingExamples: string[];
  hasInstallInstructions: boolean;
  hasUsageGuide: boolean;
  hasAPIReference: boolean;
  extractedExamples?: CodeExample[];
  installInstructions?: string;
  usageInstructions?: string;
}

export interface ErrorTestDetail {
  toolName: string;
  testType: string; // "invalid_params", "missing_required", "wrong_type", etc.
  testInput: Record<string, unknown>;
  testDescription?: string; // Human-readable description of what's being tested
  expectedError: string;
  actualResponse: {
    isError: boolean;
    errorCode?: string | number;
    errorMessage?: string;
    rawResponse: unknown;
  };
  passed: boolean;
  reason?: string;
}

export interface ErrorHandlingMetrics {
  mcpComplianceScore: number; // 0-100
  errorResponseQuality: "excellent" | "good" | "fair" | "poor";
  hasProperErrorCodes: boolean;
  hasDescriptiveMessages: boolean;
  validatesInputs: boolean;
  validationCoverage?: {
    wrongType: number; // % of wrong type tests that passed
    wrongTypeCount?: { passed: number; total: number }; // Detailed count
    extraParams: number; // % of extra parameter tests that passed
    extraParamsCount?: { passed: number; total: number }; // Detailed count
    missingRequired: number; // % of missing required tests that passed
    missingRequiredCount?: { passed: number; total: number }; // Detailed count
    nullValues: number; // % of null value tests that passed
    nullValuesCount?: { passed: number; total: number }; // Detailed count
    totalTests: number; // Total number of tests run
    overallPassRate?: number; // Overall percentage of tests that passed
  };
  testDetails?: ErrorTestDetail[]; // Detailed test results
}

export interface UsabilityMetrics {
  toolNamingConvention: "consistent" | "inconsistent";
  parameterClarity: "clear" | "unclear" | "mixed";
  hasHelpfulDescriptions: boolean;
  followsBestPractices: boolean;
  // Detailed visibility into scoring decisions
  detailedAnalysis?: {
    tools: Array<{
      toolName: string;
      namingPattern: string;
      description?: string;
      descriptionLength: number;
      hasDescription: boolean;
      parameterCount: number;
      hasRequiredParams: boolean;
      hasSchema: boolean;
      schemaQuality: string;
      parameters?: Array<{
        name: string;
        type?: string;
        required: boolean;
        description?: string;
        hasDescription: boolean;
      }>;
    }>;
    naming: {
      patterns: string[];
      breakdown: Record<string, number>;
      dominant: string;
    };
    descriptions: {
      withDescriptions: number;
      withoutDescriptions: number;
      averageLength: number;
      tooShort: Array<{
        toolName: string;
        namingPattern: string;
        description?: string;
        descriptionLength: number;
        hasDescription: boolean;
        parameterCount: number;
        hasRequiredParams: boolean;
        hasSchema: boolean;
        schemaQuality: string;
        parameters?: Array<{
          name: string;
          type?: string;
          required: boolean;
          description?: string;
          hasDescription: boolean;
        }>;
      }>;
      adequate: Array<{
        toolName: string;
        namingPattern: string;
        description?: string;
        descriptionLength: number;
        hasDescription: boolean;
        parameterCount: number;
        hasRequiredParams: boolean;
        hasSchema: boolean;
        schemaQuality: string;
        parameters?: Array<{
          name: string;
          type?: string;
          required: boolean;
          description?: string;
          hasDescription: boolean;
        }>;
      }>;
      detailed: Array<{
        toolName: string;
        namingPattern: string;
        description?: string;
        descriptionLength: number;
        hasDescription: boolean;
        parameterCount: number;
        hasRequiredParams: boolean;
        hasSchema: boolean;
        schemaQuality: string;
        parameters?: Array<{
          name: string;
          type?: string;
          required: boolean;
          description?: string;
          hasDescription: boolean;
        }>;
      }>;
    };
    parameterIssues: string[];
    bestPracticeScore: {
      naming: number;
      descriptions: number;
      schemas: number;
      clarity: number;
      total: number;
    };
    overallScore: number;
  };
}

/** Tool definition with schema from MCP tools/list response */
export interface DiscoveredTool {
  name: string;
  description?: string;
  inputSchema?: {
    type: string;
    properties?: Record<string, unknown>;
    required?: string[];
  };
}

export interface FunctionalityAssessment {
  totalTools: number;
  testedTools: number;
  workingTools: number;
  brokenTools: string[];
  coveragePercentage: number;
  status: AssessmentStatus;
  explanation: string;
  toolResults: ToolTestResult[];
  /** Raw tool definitions with inputSchema from MCP server */
  tools?: DiscoveredTool[];
}

export interface SecurityAssessment {
  promptInjectionTests: SecurityTestResult[];
  vulnerabilities: string[];
  overallRiskLevel: SecurityRiskLevel;
  status: AssessmentStatus;
  explanation: string;
}

export interface DocumentationAssessment {
  metrics: DocumentationMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

export interface ErrorHandlingAssessment {
  metrics: ErrorHandlingMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

export interface UsabilityAssessment {
  metrics: UsabilityMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// Structured recommendation with confidence metadata
export interface StructuredRecommendation {
  id: string;
  title: string;
  severity: "critical" | "warning" | "enhancement";
  confidence: "high" | "medium" | "low";
  detectionMethod: "automated" | "manual-required";
  category: string;
  description: string;
  requiresManualVerification: boolean;
  manualVerificationSteps?: string[];
  contextNote?: string;
  actionItems: string[];
}

// MCP Specification Compliance Assessment - Hybrid Structure
// Separates protocol-verified checks from metadata-based hints

/**
 * Individual protocol check result with evidence
 */
export interface ProtocolCheckResult {
  passed: boolean;
  confidence: "high" | "medium" | "low";
  evidence?: string;
  warnings?: string[];
  rawResponse?: unknown;
}

/**
 * Protocol checks that are actually tested via MCP calls
 * HIGH CONFIDENCE - these are verified through actual protocol interaction
 */
export interface ProtocolChecks {
  jsonRpcCompliance: ProtocolCheckResult;
  serverInfoValidity: ProtocolCheckResult;
  schemaCompliance: ProtocolCheckResult; // May have false positives from Zod/TypeBox
  errorResponseCompliance: ProtocolCheckResult;
  structuredOutputSupport: ProtocolCheckResult;
}

/**
 * Metadata-based hints parsed from serverInfo
 * LOW CONFIDENCE - these are NOT tested, just parsed from metadata
 */
export interface MetadataHints {
  confidence: "low"; // Always low - these are just hints
  requiresManualVerification: true;

  transportHints?: {
    detectedTransport?: string;
    supportsStdio: boolean;
    supportsHTTP: boolean;
    supportsSSE: boolean;
    detectionMethod: "metadata" | "assumed";
  };

  oauthHints?: {
    hasOAuthConfig: boolean;
    supportsOAuth: boolean;
    supportsPKCE: boolean;
    resourceIndicators?: string[];
  };

  annotationHints?: {
    supportsReadOnlyHint: boolean;
    supportsDestructiveHint: boolean;
    supportsTitleAnnotation: boolean;
    customAnnotations?: string[];
  };

  streamingHints?: {
    supportsStreaming: boolean;
    streamingProtocol?: "http-streaming" | "sse" | "websocket";
  };

  manualVerificationSteps: string[];
}

/**
 * MCP Spec Compliance Assessment - Hybrid Structure
 * Clearly separates verified protocol checks from unverified metadata hints
 */
export interface MCPSpecComplianceAssessment {
  protocolVersion: string;

  // HIGH CONFIDENCE: Actually tested via protocol
  protocolChecks: ProtocolChecks;

  // LOW CONFIDENCE: Parsed from metadata (not tested)
  metadataHints?: MetadataHints;

  // Overall assessment based on protocol checks only
  status: AssessmentStatus;
  complianceScore: number; // Based only on protocolChecks (0-100)
  explanation: string;
  recommendations: string[]; // Simplified - no structured recommendations

  // Legacy fields - deprecated but kept for backward compatibility
  /** @deprecated Use protocolChecks and metadataHints instead */
  transportCompliance?: TransportComplianceMetrics;
  /** @deprecated Use metadataHints.oauthHints instead */
  oauthImplementation?: OAuthComplianceMetrics;
  /** @deprecated Use metadataHints.annotationHints instead */
  annotationSupport?: AnnotationSupportMetrics;
  /** @deprecated Use metadataHints.streamingHints instead */
  streamingSupport?: StreamingSupportMetrics;
}

export interface TransportComplianceMetrics {
  supportsStreamableHTTP: boolean;
  deprecatedSSE: boolean;
  transportValidation: "passed" | "failed" | "partial";
  errors?: string[];
  // Added missing properties that UI expects
  supportsStdio?: boolean;
  supportsSSE?: boolean;

  // Detection metadata
  confidence?: "high" | "medium" | "low";
  detectionMethod?: "automated" | "manual-required";
  requiresManualCheck?: boolean;
  manualVerificationSteps?: string[];
}

export interface OAuthComplianceMetrics {
  implementsResourceServer: boolean;
  supportsRFC8707: boolean;
  resourceIndicators: string[];
  tokenValidation: boolean;
  scopeEnforcement: boolean;
  errors?: string[];
  // Added missing properties that UI expects
  supportsOAuth?: boolean;
  supportsPKCE?: boolean;
}

export interface AnnotationSupportMetrics {
  supportsReadOnlyHint: boolean;
  supportsDestructiveHint: boolean;
  supportsTitleAnnotation: boolean;
  customAnnotations?: string[];
}

export interface StreamingSupportMetrics {
  supportsStreaming: boolean;
  streamingProtocol?: "http-streaming" | "sse" | "websocket";
  performanceMetrics?: {
    latency: number;
    throughput: number;
  };
}

// Supply Chain Security Assessment - REMOVED (out of scope for Anthropic requirements)
// export interface SupplyChainAssessment {
//   dependencies: DependencyAnalysis;
//   vulnerabilities: VulnerabilityReport[];
//   sbom?: SoftwareBillOfMaterials;
//   packageIntegrity: PackageIntegrityMetrics;
//   status: AssessmentStatus;
//   explanation: string;
//   recommendations: string[];
// }

export interface DependencyAnalysis {
  totalDependencies: number;
  directDependencies: number;
  transitiveDependencies: number;
  outdatedPackages: number;
  abandonedPackages: number;
  riskyLicenses: string[];
  // Added missing property that UI expects
  licenseCompliance?: boolean;
}

export interface VulnerabilityReport {
  packageName: string;
  version: string;
  vulnerability: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cve?: string;
  fixAvailable: boolean;
  fixVersion?: string;
  // Added missing property that UI expects
  package?: string;
}

export interface SoftwareBillOfMaterials {
  format: "SPDX" | "CycloneDX";
  components: number;
  licenses: string[];
  attestations?: string[];
}

export interface PackageIntegrityMetrics {
  signedPackages: number;
  verifiedPublishers: number;
  integrityChecksPassed: boolean;
  integrityScore: number; // Added missing property that UI expects
  squattingRisk: "HIGH" | "MEDIUM" | "LOW";
}

// Dynamic Security Assessment - REMOVED (merged into SecurityAssessor)
// export interface DynamicSecurityAssessment {
//   runtimeTests: RuntimeTestResult[];
//   fuzzingResults: FuzzingReport;
//   sandboxTests: SandboxTestResult[];
//   behaviorAnalysis: BehaviorAnalysisReport;
//   status: AssessmentStatus;
//   explanation: string;
//   recommendations: string[];
// }

export interface RuntimeTestResult {
  testName: string;
  category: "memory" | "filesystem" | "network" | "process";
  passed: boolean;
  findings?: string[];
  severity?: SecurityRiskLevel;
}

export interface FuzzingReport {
  totalInputsTested: number;
  crashesFound: number;
  hangsDetected: number;
  memoryLeaks: number;
  unexpectedBehaviors: string[];
  coveragePercentage: number;
  // Added missing properties that UI expects
  passed: number;
  failed: number;
}

export interface SandboxTestResult {
  escapeTechnique: string;
  successful: boolean;
  containmentLevel: "full" | "partial" | "none";
  details?: string;
}

export interface BehaviorAnalysisReport {
  suspiciousBehaviors: string[];
  networkConnections: string[];
  fileSystemAccess: string[];
  processSpawning: boolean;
  anomalyScore: number;
}

// Privacy Compliance Assessment
// Bloat interfaces removed: PrivacyComplianceAssessment, HumanInLoopAssessment
// and all related metric interfaces (DataHandling, Consent, Regulatory, PII, Review, Override, Transparency, AuditTrail)
// These are outside Anthropic's 5 core MCP directory criteria

export interface MCPDirectoryAssessment {
  serverName: string;
  assessmentDate: string;
  assessorVersion: string;

  // Core assessment areas (Original 5)
  functionality: FunctionalityAssessment;
  security: SecurityAssessment;
  documentation: DocumentationAssessment;
  errorHandling: ErrorHandlingAssessment;
  usability: UsabilityAssessment;

  // Extended assessment areas (MCP Spec Compliance)
  mcpSpecCompliance?: MCPSpecComplianceAssessment;

  // New assessment areas (MCP Directory Compliance Gaps)
  aupCompliance?: AUPComplianceAssessment;
  toolAnnotations?: ToolAnnotationAssessment;
  prohibitedLibraries?: ProhibitedLibrariesAssessment;
  manifestValidation?: ManifestValidationAssessment;
  portability?: PortabilityAssessment;
  externalAPIScanner?: ExternalAPIScannerAssessment;
  authentication?: AuthenticationAssessment;

  // Overall assessment
  overallStatus: AssessmentStatus;
  summary: string;
  recommendations: string[];

  // Metadata
  executionTime: number;
  totalTestsRun: number;
  evidenceFiles?: string[];
  mcpProtocolVersion?: string;
}

// ============================================================================
// NEW ASSESSOR TYPES - MCP Directory Compliance Gaps
// ============================================================================

/**
 * AUP (Acceptable Use Policy) Compliance Types
 * Based on Anthropic's 14 AUP categories (A-N)
 */
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

/**
 * Tool Annotation Types (Policy #17)
 * Verifies readOnlyHint, destructiveHint presence
 */
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
}

/**
 * Prohibited Libraries Types (Policy #28-30)
 * Detects financial and media processing libraries
 */
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

/**
 * MCPB Manifest Validation Types
 * Based on manifest_version 0.3 spec
 */
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

/**
 * Portability Assessment Types
 * Detects hardcoded paths, platform-specific code
 */
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
}

// External API Scanner Types
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

// Authentication Assessment Types
export type AuthMethod = "oauth" | "api_key" | "none" | "unknown";

export interface AuthAppropriateness {
  isAppropriate: boolean;
  concerns: string[];
  explanation: string;
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
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// END NEW ASSESSOR TYPES
// ============================================================================

// Backend API security patterns (8 total) - tests API security, not LLM behaviors
export const PROMPT_INJECTION_TESTS: Omit<
  SecurityTestResult,
  "vulnerable" | "evidence"
>[] = [
  // Critical Injection (3)
  {
    testName: "Command Injection",
    description: "Test if tool executes system commands",
    payload: "; rm -rf /; echo 'test'",
    riskLevel: "HIGH",
  },
  {
    testName: "SQL Injection",
    description: "Test if tool properly escapes SQL commands",
    payload: "'; DROP TABLE users;--",
    riskLevel: "HIGH",
  },
  {
    testName: "Path Traversal",
    description:
      "Test if tool allows access to files outside intended directory",
    payload: "../../../etc/passwd",
    riskLevel: "HIGH",
  },
  // Input Validation (3)
  {
    testName: "Type Safety",
    description: "Test if tool validates parameter types correctly",
    payload: "not_a_number",
    riskLevel: "MEDIUM",
  },
  {
    testName: "Boundary Testing",
    description: "Test edge cases and boundary conditions",
    payload: "",
    riskLevel: "LOW",
  },
  {
    testName: "Required Fields",
    description: "Test if tool validates required parameters",
    payload: "MISSING_REQUIRED",
    riskLevel: "MEDIUM",
  },
  // Protocol Compliance (2)
  {
    testName: "MCP Error Format",
    description: "Verify errors follow MCP protocol specification",
    payload: "INVALID_TRIGGER_ERROR",
    riskLevel: "LOW",
  },
  {
    testName: "Timeout Handling",
    description: "Test if tool handles long operations gracefully",
    payload: "SIMULATE_LONG_OPERATION",
    riskLevel: "LOW",
  },
];

/**
 * Claude Code Bridge Configuration
 * Enables integration with Claude Code CLI for intelligent analysis
 */
export interface ClaudeCodeConfig {
  enabled: boolean;
  features: {
    intelligentTestGeneration: boolean; // Use Claude for test parameter generation
    aupSemanticAnalysis: boolean; // Semantic analysis of AUP violations
    annotationInference: boolean; // Infer tool behavior from descriptions
    documentationQuality: boolean; // Assess documentation quality
  };
  timeout: number; // Per-call timeout in milliseconds
  workingDir?: string; // Optional working directory for Claude
  maxRetries?: number; // Max retries on failure (default 1)
}

export interface AssessmentConfiguration {
  testTimeout: number; // milliseconds
  delayBetweenTests?: number; // milliseconds to wait between tests to avoid rate limiting
  skipBrokenTools: boolean;
  // Reviewer mode: simplify testing for Anthropic review workflow
  reviewerMode?: boolean;
  // Extended configuration for new categories
  enableExtendedAssessment?: boolean;
  parallelTesting?: boolean;
  maxParallelTests?: number;
  // Testing configuration (always uses comprehensive multi-scenario testing)
  scenariosPerTool?: number; // Max scenarios per tool (default 5-20 based on complexity)
  maxToolsToTestForErrors?: number; // @deprecated Use selectedToolsForTesting instead. Max number of tools to test for error handling (default -1 for all, use positive number to limit)
  selectedToolsForTesting?: string[]; // Array of tool names to test for functionality, security, and error handling. Empty array = test none, undefined = test all tools
  securityPatternsToTest?: number; // Number of security patterns to test (default all 8, reviewer mode uses 3)
  // Security testing mode: Basic (3 patterns) or Advanced (8 patterns)
  enableDomainTesting?: boolean; // Enable advanced security testing with all 8 backend patterns (default true)
  mcpProtocolVersion?: string;
  // Enable source code analysis (requires sourceCodePath in context)
  enableSourceCodeAnalysis?: boolean;
  // Path to custom annotation pattern JSON file (for ToolAnnotationAssessor)
  patternConfigPath?: string;
  // Claude Code integration for intelligent analysis
  claudeCode?: ClaudeCodeConfig;
  assessmentCategories?: {
    functionality: boolean;
    security: boolean;
    documentation: boolean;
    errorHandling: boolean;
    usability: boolean;
    mcpSpecCompliance?: boolean;
    // New assessment categories for MCP Directory compliance gaps
    aupCompliance?: boolean; // AUP 14 categories violation scanning
    toolAnnotations?: boolean; // Policy #17 - readOnlyHint/destructiveHint
    prohibitedLibraries?: boolean; // Policy #28-30 - Financial/Media libs
    manifestValidation?: boolean; // MCPB manifest.json compliance
    portability?: boolean; // Hardcoded paths, platform-specific code
    externalAPIScanner?: boolean; // External API detection and affiliation check
    authentication?: boolean; // OAuth appropriateness evaluation
  };
}

// ============================================================================
// Progress Event Types - For real-time test progress tracking
// ============================================================================

/**
 * Progress callback for assessment modules to report test execution progress.
 * Used by CLI to emit batched JSONL events.
 */
export interface ProgressCallback {
  (event: ProgressEvent): void;
}

/**
 * Union type for all progress events emitted during assessment.
 */
export type ProgressEvent =
  | ModuleStartedProgress
  | TestBatchProgress
  | ModuleCompleteProgress
  | VulnerabilityFoundProgress
  | AnnotationMissingProgress
  | AnnotationMisalignedProgress
  | AnnotationReviewRecommendedProgress;

/**
 * Emitted when an assessment module begins execution.
 */
export interface ModuleStartedProgress {
  type: "module_started";
  module: string;
  estimatedTests: number;
  toolCount: number;
}

/**
 * Emitted periodically during module execution with batched test results.
 * Batching reduces event volume for large assessments.
 */
export interface TestBatchProgress {
  type: "test_batch";
  module: string;
  completed: number;
  total: number;
  batchSize: number;
  elapsed: number;
}

/**
 * Emitted when an assessment module completes with final stats.
 */
export interface ModuleCompleteProgress {
  type: "module_complete";
  module: string;
  status: AssessmentStatus;
  score: number;
  testsRun: number;
  duration: number;
}

/**
 * Emitted when a security vulnerability is detected during assessment.
 * Provides real-time alerts for security findings.
 */
export interface VulnerabilityFoundProgress {
  type: "vulnerability_found";
  tool: string;
  pattern: string;
  confidence: "high" | "medium" | "low";
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
  requiresReview: boolean;
  payload?: string;
}

/**
 * Tool parameter metadata for annotation events.
 * Reusable type matching jsonl-events.ts ToolParam.
 */
export interface ToolParamProgress {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

/**
 * Emitted when a tool is missing required annotations.
 * Provides real-time alerts during annotation assessment.
 */
export interface AnnotationMissingProgress {
  type: "annotation_missing";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  inferredBehavior: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
  };
}

/**
 * Emitted when tool annotations don't match inferred behavior.
 * Provides real-time alerts during annotation assessment.
 */
export interface AnnotationMisalignedProgress {
  type: "annotation_misaligned";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  expected: boolean;
  confidence: number;
  reason: string;
}

/**
 * Emitted when annotation alignment cannot be confidently determined.
 * Used for ambiguous patterns like store_*, queue_*, cache_* where behavior
 * varies by implementation context. Does not indicate a failure - just flags
 * for human review.
 */
export interface AnnotationReviewRecommendedProgress {
  type: "annotation_review_recommended";
  tool: string;
  title?: string;
  description?: string;
  parameters: ToolParamProgress[];
  field: "readOnlyHint" | "destructiveHint";
  actual: boolean | undefined;
  inferred: boolean;
  confidence: InferenceConfidence;
  isAmbiguous: boolean;
  reason: string;
}

// ============================================================================
// End Progress Event Types
// ============================================================================

export const DEFAULT_ASSESSMENT_CONFIG: AssessmentConfiguration = {
  testTimeout: 30000, // 30 seconds per tool
  delayBetweenTests: 0, // No delay by default
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true, // Enable MCP Spec Compliance assessment by default
  parallelTesting: false,
  maxParallelTests: 5,
  maxToolsToTestForErrors: -1, // Default to test ALL tools for comprehensive compliance
  securityPatternsToTest: 8, // Test all security patterns by default
  enableDomainTesting: true, // Enable advanced security testing by default (all 8 backend patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: false, // Source code analysis disabled by default (requires sourceCodePath)
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false,
    // New assessors - disabled by default, enable for MCP Directory compliance audits
    aupCompliance: false,
    toolAnnotations: false,
    prohibitedLibraries: false,
    manifestValidation: false,
    portability: false,
    externalAPIScanner: false,
    authentication: false,
  },
};

// Reviewer mode configuration: optimized for fast, human-assisted reviews
// Focuses on Anthropic's 5 core requirements only
export const REVIEWER_MODE_CONFIG: AssessmentConfiguration = {
  testTimeout: 10000, // 10 seconds per tool (faster)
  delayBetweenTests: 100, // Small delay for rate limiting
  skipBrokenTools: true, // Skip broken tools to save time
  reviewerMode: true,
  enableExtendedAssessment: false, // Disable extended assessments (not required for directory approval)
  parallelTesting: true, // Faster execution
  maxParallelTests: 5,
  scenariosPerTool: 1, // Single realistic test per tool
  maxToolsToTestForErrors: 3, // Test only first 3 tools for error handling
  securityPatternsToTest: 3, // Test only 3 critical security patterns
  enableDomainTesting: false, // Use basic security testing for speed (3 patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: false,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false, // Not part of Anthropic's 5 core requirements
    // New assessors - disabled in reviewer mode for speed
    aupCompliance: false,
    toolAnnotations: false,
    prohibitedLibraries: false,
    manifestValidation: false,
    portability: false,
    externalAPIScanner: false,
    authentication: false,
  },
};

// Developer mode configuration: comprehensive testing for debugging
export const DEVELOPER_MODE_CONFIG: AssessmentConfiguration = {
  testTimeout: 30000, // 30 seconds per tool
  delayBetweenTests: 500, // Moderate delay for thorough testing
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true,
  parallelTesting: false, // Sequential for easier debugging
  maxParallelTests: 5,
  maxToolsToTestForErrors: -1, // Test ALL tools
  securityPatternsToTest: 8, // Test all security patterns
  enableDomainTesting: true, // Enable advanced security testing (all 8 backend patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true, // Enable source code analysis if path provided
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // Include extended assessments
    // New assessors - enabled in developer mode for comprehensive testing
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: true,
    portability: true,
    externalAPIScanner: true,
    authentication: true,
  },
};

// MCP Directory Audit mode: focuses on compliance gap assessors
// Use for pre-submission validation to Anthropic MCP Directory
export const AUDIT_MODE_CONFIG: AssessmentConfiguration = {
  testTimeout: 30000,
  delayBetweenTests: 100,
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true,
  parallelTesting: true, // Parallel for faster audits
  maxParallelTests: 5,
  maxToolsToTestForErrors: -1,
  securityPatternsToTest: 8,
  enableDomainTesting: true,
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true, // Deep analysis for audits
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true,
    // All new assessors enabled for audit mode
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: true,
    portability: true,
    externalAPIScanner: true,
    authentication: true,
  },
};

// Claude-enhanced audit mode: uses Claude Code for intelligent analysis
// Reduces false positives in AUP scanning and improves test quality
export const CLAUDE_ENHANCED_AUDIT_CONFIG: AssessmentConfiguration = {
  testTimeout: 30000,
  delayBetweenTests: 100,
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true,
  parallelTesting: false, // Sequential when using Claude to avoid rate limiting
  maxParallelTests: 1,
  maxToolsToTestForErrors: -1,
  securityPatternsToTest: 8,
  enableDomainTesting: true,
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true,
  // Claude Code integration enabled
  claudeCode: {
    enabled: true,
    features: {
      intelligentTestGeneration: true, // Generate semantically meaningful test params
      aupSemanticAnalysis: true, // Reduce false positives in AUP scanning
      annotationInference: true, // Detect annotation misalignments
      documentationQuality: true, // Assess documentation quality semantically
    },
    timeout: 90000, // 90 seconds for Claude calls
    maxRetries: 2,
  },
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true,
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: true,
    portability: true,
    externalAPIScanner: true,
    authentication: true,
  },
};
