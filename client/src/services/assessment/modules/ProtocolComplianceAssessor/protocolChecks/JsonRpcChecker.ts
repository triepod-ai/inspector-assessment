/**
 * JSON-RPC 2.0 Compliance Checker
 *
 * Validates that MCP server responses follow JSON-RPC 2.0 format.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/JsonRpcChecker
 * @see GitHub Issue #188
 */

import type {
  ProtocolCheckResult,
  CallToolFunction,
  Logger,
  AssessmentConfiguration,
} from "../types";

/**
 * Checks JSON-RPC 2.0 compliance via actual tool calls.
 */
export class JsonRpcChecker {
  constructor(_config: AssessmentConfiguration, _logger: Logger) {}

  /**
   * Check JSON-RPC 2.0 compliance by making an actual call.
   * Validates response structure includes proper content array or isError flag.
   */
  async check(callTool: CallToolFunction): Promise<ProtocolCheckResult> {
    try {
      const result = await callTool("list", {});
      const hasValidStructure =
        result !== null &&
        (Array.isArray(result.content) || result.isError !== undefined);

      return {
        passed: hasValidStructure,
        confidence: "high",
        evidence: "Verified via actual tool call",
        rawResponse: result,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);

      // Structured MCP errors are acceptable - they follow JSON-RPC format
      const isStructuredError =
        errorMessage.includes("MCP error") ||
        errorMessage.includes("jsonrpc") ||
        errorMessage.includes("-32");

      return {
        passed: isStructuredError,
        confidence: "high",
        evidence: isStructuredError
          ? "Error follows JSON-RPC 2.0 format"
          : "Non-standard error response",
        rawResponse: error,
      };
    }
  }
}
