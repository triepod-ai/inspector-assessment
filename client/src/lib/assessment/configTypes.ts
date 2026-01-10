/**
 * Assessment Configuration Types
 *
 * Configuration interfaces and preset configurations for assessments.
 *
 * @module assessment/configTypes
 */

import {
  LoggingConfig,
  LogLevel,
  DEFAULT_LOGGING_CONFIG,
} from "@/services/assessment/lib/logger";

// Re-export logging types for convenience
export type { LoggingConfig, LogLevel };
export { DEFAULT_LOGGING_CONFIG };

/**
 * HTTP transport configuration for connecting to mcp-auditor API
 */
export interface HttpTransportConfig {
  baseUrl: string; // e.g., "http://localhost:8085"
  apiKey?: string; // Optional API key for authentication
  headers?: Record<string, string>; // Additional headers
}

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
  transport?: "cli" | "http"; // Transport method (default: "cli")
  httpConfig?: HttpTransportConfig; // Required when transport is "http"
}

export interface AssessmentConfiguration {
  testTimeout: number; // milliseconds
  /** Security-specific test timeout in ms (default: 5000). Lower than testTimeout for fast payload testing. */
  securityTestTimeout?: number;
  delayBetweenTests?: number; // milliseconds to wait between tests to avoid rate limiting
  skipBrokenTools: boolean;
  // Reviewer mode: simplify testing for Anthropic review workflow
  reviewerMode?: boolean;
  // Extended configuration for new categories
  enableExtendedAssessment?: boolean;
  // Documentation output verbosity level
  documentationVerbosity?: "minimal" | "standard" | "verbose";
  // minimal: Only boolean flags (legacy behavior)
  // standard: + metadata (readmeLength, sectionHeadings, toolDocumentation) [DEFAULT]
  // verbose: + readmeContent (truncated to 5000 chars)
  parallelTesting?: boolean;
  maxParallelTests?: number;
  // Testing configuration (always uses comprehensive multi-scenario testing)
  scenariosPerTool?: number; // Max scenarios per tool (default 5-20 based on complexity)
  maxToolsToTestForErrors?: number; // @deprecated Use selectedToolsForTesting instead. Max number of tools to test for error handling (default -1 for all, use positive number to limit)
  selectedToolsForTesting?: string[]; // Array of tool names to test for functionality, security, and error handling. Empty array = test none, undefined = test all tools
  securityPatternsToTest?: number; // Number of security patterns to test (default all 8, reviewer mode uses 3)
  // Security testing mode: Basic (3 patterns) or Advanced (8 patterns)
  enableDomainTesting?: boolean; // Enable advanced security testing with all 8 backend patterns (default true)
  /** Enable cross-tool sequence testing for privilege escalation (Issue #92, default true) */
  enableSequenceTesting?: boolean;
  mcpProtocolVersion?: string;
  // Enable source code analysis (requires sourceCodePath in context)
  enableSourceCodeAnalysis?: boolean;
  // Path to custom annotation pattern JSON file (for ToolAnnotationAssessor)
  patternConfigPath?: string;
  // Claude Code integration for intelligent analysis
  claudeCode?: ClaudeCodeConfig;
  // Temporal/rug pull detection configuration
  temporalInvocations?: number; // Number of invocations per tool for rug pull detection (default 25)
  /** Logging configuration for diagnostic output */
  logging?: LoggingConfig;
  assessmentCategories?: {
    functionality: boolean;
    security: boolean;
    documentation: boolean;
    errorHandling: boolean;
    usability: boolean;
    /** @deprecated Use protocolCompliance instead. Will be removed in v2.0.0. */
    mcpSpecCompliance?: boolean;
    // New unified protocol compliance flag (replaces mcpSpecCompliance + protocolConformance)
    protocolCompliance?: boolean;
    // New assessment categories for MCP Directory compliance gaps
    aupCompliance?: boolean; // AUP 14 categories violation scanning
    toolAnnotations?: boolean; // Policy #17 - readOnlyHint/destructiveHint
    prohibitedLibraries?: boolean; // Policy #28-30 - Financial/Media libs
    manifestValidation?: boolean; // MCPB manifest.json compliance
    portability?: boolean; // Hardcoded paths, platform-specific code
    externalAPIScanner?: boolean; // External API detection and affiliation check
    authentication?: boolean; // OAuth appropriateness evaluation
    temporal?: boolean; // Temporal/rug pull vulnerability detection
    // New capability assessors
    resources?: boolean; // Resource path traversal, sensitive data exposure
    prompts?: boolean; // Prompt AUP compliance, injection vulnerabilities
    crossCapability?: boolean; // Cross-capability security (tool→resource, prompt→tool)
    // Protocol conformance assessment
    /** @deprecated Use protocolCompliance instead. Will be removed in v2.0.0. */
    protocolConformance?: boolean; // MCP protocol-level compliance (error format, content types, initialization)
    // Code quality assessors
    fileModularization?: boolean; // Code quality - detects large monolithic tool files (Issue #104)
  };
}

// ============================================================================
// Configuration Presets
// ============================================================================

export const DEFAULT_ASSESSMENT_CONFIG: AssessmentConfiguration = {
  testTimeout: 30000, // 30 seconds per tool
  delayBetweenTests: 0, // No delay by default
  skipBrokenTools: false,
  reviewerMode: false,
  enableExtendedAssessment: true, // Enable MCP Spec Compliance assessment by default
  parallelTesting: false,
  maxParallelTests: 5,
  securityPatternsToTest: 8, // Test all security patterns by default
  enableDomainTesting: true, // Enable advanced security testing by default (all 8 backend patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: false, // Source code analysis disabled by default (requires sourceCodePath)
  logging: { level: "info" }, // Standard verbosity
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false, // @deprecated
    protocolCompliance: false, // Unified protocol compliance (replaces mcpSpecCompliance + protocolConformance)
    // New assessors - disabled by default, enable for MCP Directory compliance audits
    aupCompliance: false,
    toolAnnotations: false,
    prohibitedLibraries: false,
    manifestValidation: false,
    portability: false,
    externalAPIScanner: false,
    authentication: false,
    // New capability assessors - disabled by default
    resources: false,
    prompts: false,
    crossCapability: false,
    // Protocol conformance - disabled by default
    protocolConformance: false,
    // Code quality - disabled by default (requires source code analysis)
    fileModularization: false,
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
  securityPatternsToTest: 3, // Test only 3 critical security patterns
  enableDomainTesting: false, // Use basic security testing for speed (3 patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: false,
  logging: { level: "warn" }, // Minimal noise for fast reviews
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: false, // @deprecated - Not part of Anthropic's 5 core requirements
    protocolCompliance: false, // Unified protocol compliance
    // New assessors - disabled in reviewer mode for speed
    aupCompliance: false,
    toolAnnotations: false,
    prohibitedLibraries: false,
    manifestValidation: false,
    portability: false,
    externalAPIScanner: false,
    authentication: false,
    // New capability assessors - disabled in reviewer mode for speed
    resources: false,
    prompts: false,
    crossCapability: false,
    // Protocol conformance - disabled in reviewer mode for speed
    protocolConformance: false,
    // Code quality - disabled in reviewer mode for speed
    fileModularization: false,
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
  securityPatternsToTest: 8, // Test all security patterns
  enableDomainTesting: true, // Enable advanced security testing (all 8 backend patterns)
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true, // Enable source code analysis if path provided
  logging: { level: "debug" }, // Full diagnostic output for debugging
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // @deprecated - Include extended assessments
    protocolCompliance: true, // Unified protocol compliance (replaces mcpSpecCompliance + protocolConformance)
    // New assessors - enabled in developer mode for comprehensive testing
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: false, // MCPB bundle-specific, disabled by default
    portability: false, // MCPB bundle-specific, disabled by default
    externalAPIScanner: true,
    authentication: true,
    // New capability assessors - enabled in developer mode
    resources: true,
    prompts: true,
    crossCapability: true,
    // Protocol conformance - enabled in developer mode for comprehensive testing
    protocolConformance: true,
    // Code quality - enabled in developer mode for comprehensive testing
    fileModularization: true,
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
  securityPatternsToTest: 8,
  enableDomainTesting: true,
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true, // Deep analysis for audits
  logging: { level: "info" }, // Standard verbosity for audits
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // @deprecated
    protocolCompliance: true, // Unified protocol compliance
    // All new assessors enabled for audit mode
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: false, // MCPB bundle-specific, disabled by default
    portability: false, // MCPB bundle-specific, disabled by default
    externalAPIScanner: true,
    authentication: true,
    // New capability assessors - enabled in audit mode
    resources: true,
    prompts: true,
    crossCapability: true,
    // Protocol conformance - enabled in audit mode for compliance validation
    protocolConformance: true,
    // Code quality - enabled in audit mode for compliance validation
    fileModularization: true,
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
  securityPatternsToTest: 8,
  enableDomainTesting: true,
  mcpProtocolVersion: "2025-06",
  enableSourceCodeAnalysis: true,
  logging: { level: "info" }, // Standard verbosity (Claude output is already verbose)
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
    mcpSpecCompliance: true, // @deprecated
    protocolCompliance: true, // Unified protocol compliance
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
    manifestValidation: false, // MCPB bundle-specific, disabled by default
    portability: false, // MCPB bundle-specific, disabled by default
    externalAPIScanner: true,
    authentication: true,
    // New capability assessors - enabled in Claude mode
    resources: true,
    prompts: true,
    crossCapability: true,
    // Protocol conformance - enabled in Claude mode for comprehensive validation (@deprecated)
    protocolConformance: true,
    // Code quality - enabled in Claude mode for comprehensive validation
    fileModularization: true,
  },
};
