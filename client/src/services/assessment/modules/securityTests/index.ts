/**
 * Security Assessment Module
 *
 * Exports all security-related components for testing MCP servers.
 * Includes payload generation, testing, and response analysis.
 *
 * @public
 * @module assessment/security
 */

export {
  SecurityResponseAnalyzer,
  type ConfidenceResult,
  type AnalysisResult,
  type ErrorClassification,
  // Re-exported from extracted analyzers (Issue #179)
  type AuthBypassResult,
  type StateBasedAuthResult,
  type SecretLeakageResult,
  type ChainExploitationAnalysis,
  type ChainExecutionType,
  type ChainVulnerabilityCategory,
  type ExcessivePermissionsScopeResult,
  type BlacklistBypassResult,
  type OutputInjectionResult,
  type SessionManagementResult,
  type CryptoFailureResult,
} from "./SecurityResponseAnalyzer";

// Direct analyzer exports for advanced usage (Issue #179)
export {
  AuthBypassAnalyzer,
  StateBasedAuthAnalyzer,
  SecretLeakageDetector,
  ChainExploitationAnalyzer,
  ExcessivePermissionsAnalyzer,
  BlacklistBypassAnalyzer,
  OutputInjectionAnalyzer,
  SessionManagementAnalyzer,
  CryptographicFailureAnalyzer,
} from "./analyzers";

export {
  SecurityPayloadTester,
  type TestProgressCallback,
  type PayloadTestConfig,
  type TestLogger,
} from "./SecurityPayloadTester";

export { SecurityPayloadGenerator } from "./SecurityPayloadGenerator";

export {
  CrossToolStateTester,
  type CrossToolTestResult,
  type ToolPair,
  type CallToolFunction,
  type CrossToolTestConfig,
} from "./CrossToolStateTester";

export {
  ChainExecutionTester,
  type ChainExecutionTestResult,
  type ChainExploitationSummary,
  type ChainExecutionTesterConfig,
  type ChainTestReason,
} from "./ChainExecutionTester";

export {
  TestValidityAnalyzer,
  type TestValidityConfig,
  type TestValidityResult,
} from "./TestValidityAnalyzer";

export {
  adjustSeverityForAnnotations,
  type SeverityAdjustment,
} from "./AnnotationAwareSeverity";

// Factory pattern for dependency injection (Issue #200 - V2 Refactoring)
export {
  createSecurityTesters,
  createSecurityTestersWithOverrides,
  type SecurityTesters,
  type SecurityTestersConfig,
} from "./factory";
