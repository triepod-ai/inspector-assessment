/**
 * Capabilities Compliance Checker
 *
 * Validates that declared server capabilities match actual implementation.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/CapabilitiesChecker
 * @see GitHub Issue #188
 */

import type { AssessmentContext } from "../../../AssessmentOrchestrator";
import type {
  ProtocolCheckResult,
  Logger,
  AssessmentConfiguration,
} from "../types";

/**
 * Checks that declared capabilities have corresponding implementations.
 */
export class CapabilitiesChecker {
  constructor(_config: AssessmentConfiguration, _logger: Logger) {}

  /**
   * Check capabilities compliance.
   * Validates declared vs actual capabilities.
   */
  check(
    context: AssessmentContext,
  ): ProtocolCheckResult & { testCount: number } {
    const warnings: string[] = [];
    const capabilities = context.serverCapabilities;
    let testCount = 0;

    if (!capabilities) {
      return {
        passed: true,
        confidence: "medium",
        evidence: "No server capabilities declared (optional)",
        rawResponse: undefined,
        testCount: 0,
      };
    }

    // Check tools capability
    if (capabilities.tools) {
      testCount++;
      if (context.tools.length === 0) {
        warnings.push("Declared tools capability but no tools registered");
      }
    }

    // Check resources capability
    if (capabilities.resources) {
      testCount++;
      if (!context.resources || context.resources.length === 0) {
        if (!context.readResource) {
          warnings.push(
            "Declared resources capability but no resources data provided for validation",
          );
        }
      }
    }

    // Check prompts capability
    if (capabilities.prompts) {
      testCount++;
      if (!context.prompts || context.prompts.length === 0) {
        if (!context.getPrompt) {
          warnings.push(
            "Declared prompts capability but no prompts data provided for validation",
          );
        }
      }
    }

    const passed = warnings.length === 0;
    const confidence = warnings.length === 0 ? "high" : "medium";

    return {
      passed,
      confidence,
      evidence: passed
        ? "All declared capabilities have corresponding implementations"
        : `Capability validation issues: ${warnings.join("; ")}`,
      warnings: warnings.length > 0 ? warnings : undefined,
      rawResponse: capabilities,
      testCount,
    };
  }
}
