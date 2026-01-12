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
  type StateBasedAuthResult,
  type ChainExploitationAnalysis,
  type ChainExecutionType,
  type ChainVulnerabilityCategory,
} from "./SecurityResponseAnalyzer";

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
