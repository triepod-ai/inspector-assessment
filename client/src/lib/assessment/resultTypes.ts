/**
 * Assessment Result Types
 *
 * Core assessment result interfaces including MCPDirectoryAssessment
 * and all module-specific assessment types.
 *
 * @module assessment/resultTypes
 */

import type { AssessmentStatus, SecurityRiskLevel } from "./coreTypes";

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
  /** Raw error handling test results for downstream analysis */
  errorTests?: ErrorTestDetail[];
  status: AssessmentStatus;
  /** Module-level score (0-100) derived from metrics.mcpComplianceScore (Issue #28) */
  score: number;
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
  temporal?: TemporalAssessment;

  // New capability assessors (resources, prompts, cross-capability)
  /** MCP Resources capability assessment results */
  resources?: ResourceAssessment;
  /** MCP Prompts capability assessment results */
  prompts?: PromptAssessment;
  /** Cross-capability security assessment (resources x prompts x tools interactions) */
  crossCapability?: CrossCapabilitySecurityAssessment;

  // Protocol conformance assessment
  /** MCP protocol-level compliance (error format, content types, initialization handshake) */
  protocolConformance?: ProtocolConformanceAssessment;

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
