/**
 * Assessment Result Types
 *
 * Core assessment result interfaces including MCPDirectoryAssessment
 * and all module-specific assessment types.
 *
 * @module assessment/resultTypes
 */

import type {
  AssessmentStatus,
  SecurityRiskLevel,
  NamespaceDetectionResult,
} from "./coreTypes";

// Re-export NamespaceDetectionResult for backward compatibility (moved to coreTypes.ts in Issue #147)
export type { NamespaceDetectionResult };

// Import extended types for MCPDirectoryAssessment composition
import type {
  AUPComplianceAssessment,
  ToolAnnotationAssessment,
  ProhibitedLibrariesAssessment,
  ManifestValidationAssessment,
  PortabilityAssessment,
  ExternalAPIScannerAssessment,
  AuthenticationAssessment,
  TemporalAssessment,
  ResourceAssessment,
  PromptAssessment,
  CrossCapabilitySecurityAssessment,
  ProtocolConformanceAssessment,
  FileModularizationAssessment,
  ConformanceAssessment,
  DeveloperExperienceAssessment,
} from "./extendedTypes";

// ============================================================================
// Test Input/Output Types
// ============================================================================

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

/**
 * Metadata about the response content types and structure.
 * Tracks what type of content the tool returns for better categorization.
 */
export interface ResponseMetadata {
  /** Content types present in the response */
  contentTypes: Array<
    "text" | "image" | "resource" | "resource_link" | "audio"
  >;
  /** True if response includes structuredContent property */
  hasStructuredContent: boolean;
  /** True if response includes _meta property */
  hasMeta: boolean;
  /** Number of text content blocks */
  textBlockCount: number;
  /** Number of image content blocks */
  imageCount: number;
  /** Number of resource/resource_link content blocks */
  resourceCount: number;
  /** Output schema validation result (if tool has outputSchema) */
  outputSchemaValidation?: {
    hasOutputSchema: boolean;
    isValid: boolean;
    error?: string;
  };
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
  /** Metadata about response content types and structure (optional, backward compatible) */
  responseMetadata?: ResponseMetadata;
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
  // Issue #56: Sanitization detection fields for false positive reduction
  sanitizationDetected?: boolean; // Whether sanitization was detected in tool/response
  sanitizationLibraries?: string[]; // Specific libraries detected (e.g., "DOMPurify")
  // Claude semantic analysis results for false positive reduction (progressive enhancement)
  semanticAnalysis?: {
    originalConfidence: "high" | "medium" | "low";
    refinedConfidence: "high" | "medium" | "low";
    reasoning: string;
    source: "claude-refined";
  };
  // Issue #75: Auth bypass detection fields for fail-open vulnerability detection
  authBypassDetected?: boolean; // Whether fail-open auth bypass was detected
  authFailureMode?: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN"; // Classification of auth behavior
  authBypassEvidence?: string; // Evidence text that triggered detection
  // Issue #110: Blacklist bypass detection fields for Challenge #11
  blacklistBypassDetected?: boolean; // Whether blacklist bypass was detected
  blacklistBypassType?: "BLACKLIST_BYPASS" | "ALLOWLIST_BLOCKED" | "UNKNOWN";
  blacklistBypassMethod?: string; // e.g., "python3", "perl", "wget"
  blacklistBypassEvidence?: string; // Evidence text that triggered detection
  // Issue #110: Output injection detection fields for Challenge #8
  outputInjectionDetected?: boolean; // Whether output injection vulnerability was detected
  outputInjectionType?:
    | "LLM_INJECTION_MARKERS"
    | "RAW_CONTENT_INCLUDED"
    | "SANITIZED"
    | "UNKNOWN";
  outputInjectionMarkers?: string[]; // Which markers were found (e.g., ["<IMPORTANT>", "[INST]"])
  outputInjectionEvidence?: string; // Evidence text that triggered detection
  // Issue #111: Session management detection fields for Challenge #12
  sessionManagementDetected?: boolean; // Whether session management vulnerability was detected
  sessionVulnerabilityType?:
    | "SESSION_FIXATION" // CWE-384: External session ID accepted
    | "PREDICTABLE_TOKEN" // CWE-330: Pattern like session_{user}_{timestamp}_{counter}
    | "NO_TIMEOUT" // CWE-613: expires_at null, timeout_checked false
    | "ID_IN_URL" // CWE-200: session_id in URL parameter
    | "NO_REGENERATION" // CWE-384: session_regenerated: false after auth
    | "UNKNOWN";
  sessionCweIds?: string[]; // e.g., ["CWE-384", "CWE-330"]
  sessionManagementEvidence?: string; // Evidence text that triggered detection
  // Issue #112: Cryptographic failure detection fields for Challenge #13
  // OWASP A02:2021 - Cryptographic Failures
  cryptoFailureDetected?: boolean; // Whether cryptographic failure was detected
  cryptoVulnerabilityType?:
    | "WEAK_HASH" // CWE-328: MD5/SHA1 for password hashing
    | "STATIC_SALT" // CWE-916: Static salt like "static_salt_123"
    | "PREDICTABLE_RNG" // CWE-330: random.random() with timestamp seed
    | "TIMING_ATTACK" // CWE-208: Non-constant-time comparison
    | "ECB_MODE" // CWE-327: AES-ECB mode (pattern leakage)
    | "HARDCODED_KEY" // CWE-321: key_source: "hardcoded"
    | "WEAK_KDF" // CWE-916: MD5 for key derivation
    | "WEAK_KEY_LENGTH" // CWE-326: key_length < 16 bytes
    | "UNKNOWN";
  cryptoCweIds?: string[]; // e.g., ["CWE-328", "CWE-916"]
  cryptoFailureEvidence?: string; // Evidence text that triggered detection
  // Issue #144: Excessive permissions scope detection fields for Challenge #22
  // CWE-250: Execution with Unnecessary Privileges
  // CWE-269: Improper Privilege Management
  excessivePermissionsDetected?: boolean; // Whether scope violation was detected
  scopeViolationType?:
    | "SCOPE_VIOLATION" // Tool performed write/delete/execute despite readOnlyHint=True
    | "SCOPE_ESCALATION" // Keyword triggered hidden admin mode
    | "SAFE" // Tool properly enforced scope restrictions
    | "UNKNOWN";
  scopeDeclared?: string; // e.g., "readOnlyHint=True, destructiveHint=False"
  scopeActual?: string; // e.g., "write", "delete", "execute", "network"
  scopeTriggerPayload?: string; // e.g., "admin", "sudo", "write_file"
  scopeCweIds?: string[]; // e.g., ["CWE-250", "CWE-269"]
  excessivePermissionsEvidence?: string; // Evidence text that triggered detection
  // Issue #146: Execution context classification for false positive reduction
  // Distinguishes between actual execution and payload reflection in errors
  executionContext?: "CONFIRMED" | "LIKELY_FALSE_POSITIVE" | "SUSPECTED";
  contextEvidence?: string; // Evidence supporting the context classification
  operationSucceeded?: boolean; // Whether the operation succeeded or failed
}

// ============================================================================
// Documentation Types
// ============================================================================

export interface CodeExample {
  code: string;
  language?: string;
  description?: string;
  lineNumber?: number;
  // NEW: Classification fields for downstream analysis
  lineCount?: number;
  exampleType?: "functional" | "install" | "config" | "implementation";
}

/**
 * Represents a tool with missing or inadequate documentation.
 * Used to identify documentation gaps for tool descriptions.
 */
export interface ToolDocGap {
  toolName: string;
  issue: "missing" | "too_short";
  descriptionLength: number;
  documentedInReadme: boolean;
}

/**
 * Issue #55: Documentation quality checks with point-based scoring
 * Used to assess README quality, installation docs, config docs, examples, and license
 */
export interface DocumentationQualityChecks {
  hasReadme: boolean;
  /** Size-based quality tier: minimal (<5KB), adequate (5-15KB), comprehensive (>15KB) */
  readmeQuality: "minimal" | "adequate" | "comprehensive";
  hasInstallation: boolean;
  hasConfiguration: boolean;
  hasExamples: boolean;
  hasLicense: boolean;
  licenseType?: string;
}

/**
 * Issue #55: Point-based documentation quality score breakdown
 * Max 100 points total
 */
export interface DocumentationQualityScore {
  /** Total points earned out of 100 */
  total: number;
  /** Points breakdown by check */
  breakdown: {
    /** README exists: 10 points */
    readmeExists: number;
    /** README size bonus: >5KB +10, >15KB +20 total */
    readmeComprehensive: number;
    /** Installation section present: 20 points */
    installation: number;
    /** Configuration/env vars documented: 20 points */
    configuration: number;
    /** Usage examples present: 20 points */
    examples: number;
    /** License file present: 10 points */
    license: number;
  };
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
  // NEW: Lightweight metadata (standard+ verbosity)
  readmeLength?: number;
  readmeWordCount?: number;
  sectionHeadings?: string[];
  // NEW: Tool documentation status (standard+ verbosity)
  toolDocumentation?: Array<{
    name: string;
    hasDescription: boolean;
    descriptionLength: number;
    documentedInReadme: boolean;
    /** Actual description text (truncated to 200 chars) for Claude analysis */
    description?: string;
  }>;
  // NEW: Full content (verbose mode only, truncated to 5000 chars)
  readmeContent?: string;
  // NEW: Always computed aggregates (not gated by verbosity)
  /** Count of tools with descriptions >= 50 characters */
  toolsWithDescriptions: number;
  /** Total number of tools analyzed */
  toolsTotal: number;
  /** Tools with missing or inadequate (<50 chars) descriptions */
  toolDocGaps: ToolDocGap[];
  // Issue #55: Documentation quality scoring
  /** Point-based quality checks (Issue #55) */
  qualityChecks?: DocumentationQualityChecks;
  /** Point-based quality score breakdown (Issue #55) */
  qualityScore?: DocumentationQualityScore;
  /** README size in bytes for quality tier calculation */
  readmeSizeBytes?: number;
}

// ============================================================================
// Error Handling Types
// ============================================================================

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

// ============================================================================
// Usability Types
// ============================================================================

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

// ============================================================================
// Namespace Detection Types (Issue #142)
// NOTE: NamespaceDetectionResult moved to coreTypes.ts (Issue #147)
// Re-exported above for backward compatibility
// ============================================================================

// ============================================================================
// Core Assessment Types
// ============================================================================

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

/**
 * Test validity warning when responses are suspiciously uniform.
 * Indicates tests may not have reached security-relevant code paths.
 * Issue #134: Detect identical security test responses
 * Issue #135: Enhanced data for Stage B Claude analysis
 */
export interface TestValidityWarning {
  /** Number of responses that match the most common pattern */
  identicalResponseCount: number;
  /** Total number of test responses analyzed */
  totalResponses: number;
  /** Percentage of identical responses (0-100) */
  percentageIdentical: number;
  /** Sample of the most common response (truncated) */
  sampleResponse: string;
  /** Detected pattern category */
  detectedPattern:
    | "configuration_error"
    | "connection_error"
    | "timeout"
    | "empty_response"
    | "generic_error"
    | "unknown";
  /** Human-readable explanation */
  explanation: string;

  // Issue #135: Enhanced fields for Stage B semantic analysis

  /** Response diversity metrics for Claude analysis */
  responseDiversity?: {
    /** Number of unique normalized responses */
    uniqueResponses: number;
    /** Shannon entropy (0=uniform, 1=max diversity) */
    entropyScore: number;
    /** Top response distribution by frequency */
    distribution: Array<{
      response: string;
      count: number;
      percentage: number;
    }>;
  };

  /** Per-tool uniformity breakdown */
  toolUniformity?: Record<
    string,
    {
      identicalCount: number;
      totalCount: number;
      percentageIdentical: number;
    }
  >;

  /** Attack pattern correlation for semantic analysis */
  attackPatternCorrelation?: Record<
    string,
    {
      testCount: number;
      uniqueResponses: number;
      samplePayload?: string;
      sampleResponse?: string;
    }
  >;

  /** Sample payload-response pairs for Claude analysis */
  samplePairs?: Array<{
    attackCategory: string;
    payload: string;
    response: string;
    vulnerable: boolean;
  }>;

  /** Response metadata statistics */
  responseMetadata?: {
    avgLength: number;
    minLength: number;
    maxLength: number;
    emptyCount: number;
    errorCount: number;
  };
}

export interface SecurityAssessment {
  promptInjectionTests: SecurityTestResult[];
  vulnerabilities: string[];
  overallRiskLevel: SecurityRiskLevel;
  status: AssessmentStatus;
  explanation: string;
  // Issue #75: Auth bypass summary for fail-open vulnerability detection
  authBypassSummary?: {
    toolsWithAuthBypass: string[];
    failOpenCount: number;
    failClosedCount: number;
    unknownCount: number;
  };
  // Issue #134: Test validity warning for response uniformity detection
  testValidityWarning?: TestValidityWarning;
  /** Overall confidence level (may be reduced by test validity issues) */
  overallConfidence?: "high" | "medium" | "low";
  // Issue #152: Test execution metadata for score validation
  // Prevents high scores when tests fail to execute
  testExecutionMetadata?: {
    /** Total tests that were supposed to run */
    totalTestsAttempted: number;
    /** Tests that completed successfully */
    validTestsCompleted: number;
    /** Tests that failed due to connection/server errors */
    connectionErrorCount: number;
    /** Percentage of tests that completed: validTestsCompleted / totalTestsAttempted * 100 */
    testCoveragePercent: number;
  };
}

export interface DocumentationAssessment {
  metrics: DocumentationMetrics;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

export interface ErrorHandlingAssessment {
  metrics: ErrorHandlingMetrics;
  /** Raw error handling test results for downstream analysis */
  errorTests?: ErrorTestDetail[];
  status: AssessmentStatus;
  /** Module-level score (0-100) derived from metrics.mcpComplianceScore (Issue #28) */
  score: number;
  explanation: string;
  recommendations: string[];
  // Issue #153: Test execution metadata for score validation
  // Prevents high scores when tests fail to execute
  testExecutionMetadata?: {
    /** Total tests that were supposed to run */
    totalTestsAttempted: number;
    /** Tests that completed successfully */
    validTestsCompleted: number;
    /** Tests that failed due to connection/server errors */
    connectionErrorCount: number;
    /** Percentage of tests that completed: validTestsCompleted / totalTestsAttempted * 100 */
    testCoveragePercent: number;
  };
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

// ============================================================================
// MCP Spec Compliance Types
// ============================================================================

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

// ============================================================================
// Output Schema Coverage Types (Issue #64)
// ============================================================================

/**
 * Coverage metrics for outputSchema presence across tools.
 * Tracks how many tools define outputSchema for client-side response validation.
 */
export interface OutputSchemaCoverage {
  /** Total number of tools analyzed */
  totalTools: number;
  /** Number of tools with outputSchema defined */
  withOutputSchema: number;
  /** Number of tools without outputSchema */
  withoutOutputSchema: number;
  /** Coverage percentage (0-100) */
  coveragePercent: number;
  /** List of tool names that are missing outputSchema */
  toolsWithoutSchema: string[];
  /** Status: PASS if 100% coverage, INFO otherwise */
  status: "PASS" | "INFO";
  /** Recommendation for improving coverage (present when < 100%) */
  recommendation?: string;
}

/**
 * Per-tool outputSchema analysis result.
 * Provides detailed information about each tool's outputSchema status.
 */
export interface ToolOutputSchemaResult {
  /** Tool name */
  toolName: string;
  /** Whether the tool has outputSchema defined */
  hasOutputSchema: boolean;
  /** The actual outputSchema if present */
  outputSchema?: Record<string, unknown>;
  /** Validation result if outputSchema was validated against response */
  validationResult?: {
    /** Whether the response matched the outputSchema */
    isValid: boolean;
    /** Validation error message if invalid */
    error?: string;
  };
}

/**
 * Extended protocol check result that includes outputSchema coverage.
 * Used specifically for structuredOutputSupport checks.
 */
export interface StructuredOutputCheckResult extends ProtocolCheckResult {
  /** Detailed coverage metrics for outputSchema */
  coverage?: OutputSchemaCoverage;
  /** Per-tool outputSchema analysis results */
  toolResults?: ToolOutputSchemaResult[];
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
  /** Structured output support check with detailed coverage metrics (Issue #64) */
  structuredOutputSupport: StructuredOutputCheckResult;
  capabilitiesCompliance?: ProtocolCheckResult; // Validates declared capabilities match actual behavior
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

// ============================================================================
// Legacy Supply Chain / Dynamic Security Types (kept for backward compatibility)
// ============================================================================

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

// ============================================================================
// Main Assessment Result Interface
// ============================================================================

export interface MCPDirectoryAssessment {
  serverName: string;
  assessmentDate: string;
  assessorVersion: string;

  // Core assessment areas (Original 5)
  functionality: FunctionalityAssessment;
  security: SecurityAssessment;
  /** @deprecated Use `developerExperience.documentation` instead. Will be removed in v2.0.0. */
  documentation: DocumentationAssessment;
  errorHandling: ErrorHandlingAssessment;
  /** @deprecated Use `developerExperience.usability` instead. Will be removed in v2.0.0. */
  usability: UsabilityAssessment;

  // NEW: Combined developer experience assessment (v1.32.0+, Issue #124)
  /** Combined documentation + usability assessment. Replaces separate documentation/usability keys in v2.0.0. */
  developerExperience?: DeveloperExperienceAssessment;

  // Extended assessment areas (MCP Spec Compliance)
  /** @deprecated Use `protocolCompliance` instead. Will be removed in v2.0.0. */
  mcpSpecCompliance?: MCPSpecComplianceAssessment;

  // NEW: Unified protocol compliance (v1.32.0+, Issue #124)
  /** Unified protocol compliance assessment. Replaces mcpSpecCompliance in v2.0.0. */
  protocolCompliance?: MCPSpecComplianceAssessment;

  // New assessment areas (MCP Directory Compliance Gaps)
  aupCompliance?: AUPComplianceAssessment;
  toolAnnotations?: ToolAnnotationAssessment;
  prohibitedLibraries?: ProhibitedLibrariesAssessment;
  manifestValidation?: ManifestValidationAssessment;
  portability?: PortabilityAssessment;
  externalAPIScanner?: ExternalAPIScannerAssessment;
  authentication?: AuthenticationAssessment;
  temporal?: TemporalAssessment;

  // New capability assessors (resources, prompts, cross-capability)
  /** MCP Resources capability assessment results */
  resources?: ResourceAssessment;
  /** MCP Prompts capability assessment results */
  prompts?: PromptAssessment;
  /** Cross-capability security assessment (resources x prompts x tools interactions) */
  crossCapability?: CrossCapabilitySecurityAssessment;

  // Protocol conformance assessment
  /**
   * MCP protocol-level compliance (error format, content types, initialization handshake)
   * @deprecated Use `protocolCompliance` instead. Merged with mcpSpecCompliance. Will be removed in v2.0.0.
   */
  protocolConformance?: ProtocolConformanceAssessment;

  // Code quality assessors
  /** File modularization assessment - detects large monolithic tool files (Issue #104) */
  fileModularization?: FileModularizationAssessment;

  // Official MCP conformance testing
  /** Official MCP conformance tests via @modelcontextprotocol/conformance (opt-in) */
  conformance?: ConformanceAssessment;

  // Overall assessment
  overallStatus: AssessmentStatus;
  summary: string;
  recommendations: string[];

  // Metadata
  executionTime: number;
  totalTestsRun: number;
  evidenceFiles?: string[];
  mcpProtocolVersion?: string;

  // Assessment context metadata (for policy compliance evaluation)
  assessmentMetadata?: {
    /** Whether source code was available during assessment */
    sourceCodeAvailable: boolean;
    /** Transport type used for the assessment */
    transportType?: "stdio" | "sse" | "streamable-http";
  };
}
