/**
 * MCP Directory Review Assessment Types
 * Based on Anthropic's 5 core requirements for MCP directory submission
 */

export type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO";
export type SecurityRiskLevel = "LOW" | "MEDIUM" | "HIGH";

export interface ToolTestResult {
  toolName: string;
  tested: boolean;
  status: "working" | "broken" | "untested";
  error?: string;
  executionTime?: number;
  testParameters?: Record<string, unknown>;
  response?: unknown;
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

export interface FunctionalityAssessment {
  totalTools: number;
  testedTools: number;
  workingTools: number;
  brokenTools: string[];
  coveragePercentage: number;
  status: AssessmentStatus;
  explanation: string;
  toolResults: ToolTestResult[];
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
  assessmentCategories?: {
    functionality: boolean;
    security: boolean;
    documentation: boolean;
    errorHandling: boolean;
    usability: boolean;
    mcpSpecCompliance?: boolean;
  };
}

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
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false,
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
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false, // Not part of Anthropic's 5 core requirements
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
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // Include extended assessments
  },
};
