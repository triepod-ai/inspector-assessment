/**
 * External Services Types
 *
 * Types for external API scanner and authentication assessment.
 * Includes detection of external service dependencies, auth methods,
 * transport security, and auth configuration analysis.
 *
 * @module assessment/externalServicesTypes
 */

import type { AssessmentStatus } from "./coreTypes";

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
  /** Issue #195: Stage B enrichment data for Claude validation */
  enrichmentData?: AuthEnrichmentData;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
}

// ============================================================================
// Authentication Stage B Enrichment Types (Issue #195)
// ============================================================================

/**
 * Tool item with auth-related capabilities for Stage B validation
 */
export interface AuthToolInventoryItem {
  name: string;
  description: string;
  /** Inferred auth-related capabilities */
  authCapabilities: AuthToolCapability[];
  /** Whether this tool handles sensitive auth operations */
  isSensitive: boolean;
}

/**
 * Auth-specific capability categories
 */
export type AuthToolCapability =
  | "oauth" // OAuth flow operations
  | "api_key" // API key handling
  | "session" // Session management
  | "credential" // Credential storage/retrieval
  | "token" // Token management
  | "encryption" // Credential encryption
  | "none"; // No auth capabilities detected

/**
 * OAuth pattern coverage showing what was checked
 */
export interface OAuthPatternCoverage {
  /** Total OAuth patterns checked */
  totalPatterns: number;
  /** Patterns that matched */
  matchedPatterns: string[];
  /** Summary of OAuth flow detected */
  flowType:
    | "authorization_code"
    | "client_credentials"
    | "pkce"
    | "unknown"
    | "none";
  /** Whether PKCE is implemented (security best practice) */
  pkceDetected: boolean;
}

/**
 * API key pattern coverage
 */
export interface APIKeyPatternCoverage {
  /** Total API key patterns checked */
  totalPatterns: number;
  /** Patterns that matched */
  matchedPatterns: string[];
  /** Whether keys appear to be properly managed via env vars */
  envVarManaged: boolean;
}

/**
 * Transport security summary for Stage B context
 */
export interface TransportSecuritySummary {
  /** Transport type (stdio, http, sse, streamable-http) */
  transportType: string;
  /** Whether TLS is enforced */
  tlsEnforced: boolean;
  /** Whether CORS is configured */
  corsConfigured: boolean;
  /** Whether session cookies are secure */
  sessionSecure: boolean;
  /** Count of insecure patterns detected */
  insecurePatternCount: number;
  /** Count of secure patterns detected */
  securePatternCount: number;
}

/**
 * Flag for auth tools that warrant review
 */
export interface AuthFlagForReview {
  toolName: string;
  /** Reason for flagging */
  reason: string;
  /** Auth capabilities that triggered the flag */
  capabilities: AuthToolCapability[];
  /** Risk level based on capabilities */
  riskLevel: "high" | "medium" | "low";
}

/**
 * Authentication enrichment data for Stage B Claude validation (Issue #195)
 * Provides context for Claude to validate authentication findings
 */
export interface AuthEnrichmentData {
  /** Tool inventory with auth-related capabilities */
  toolInventory: AuthToolInventoryItem[];
  /** OAuth pattern coverage */
  oauthPatternCoverage: OAuthPatternCoverage;
  /** API key pattern coverage */
  apiKeyPatternCoverage: APIKeyPatternCoverage;
  /** Transport security summary */
  transportSecurity: TransportSecuritySummary;
  /** Tools flagged for auth-related review */
  flagsForReview: AuthFlagForReview[];
  /** Summary metrics for quick assessment */
  metrics: {
    totalTools: number;
    authSensitiveTools: number;
    oauthIndicators: number;
    apiKeyIndicators: number;
    localDependencyIndicators: number;
  };
}
