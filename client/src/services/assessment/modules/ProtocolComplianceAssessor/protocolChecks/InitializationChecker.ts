/**
 * Initialization Handshake Checker
 *
 * Validates that server provides required initialization data.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/InitializationChecker
 * @see GitHub Issue #188
 */

import type { AssessmentContext } from "../../../AssessmentOrchestrator";
import type {
  ProtocolCheckResult,
  Logger,
  AssessmentConfiguration,
} from "../types";

/**
 * Validates initialization handshake completeness.
 */
export class InitializationChecker {
  constructor(_config: AssessmentConfiguration, _logger: Logger) {}

  // Note: getSpecVersion/getSpecBaseUrl reserved for future use with dynamic spec URLs

  /**
   * Check initialization handshake.
   */
  check(context: AssessmentContext): ProtocolCheckResult {
    const serverInfo = context.serverInfo;
    const serverCapabilities = context.serverCapabilities;

    const validations = {
      hasServerInfo: serverInfo !== undefined && serverInfo !== null,
      hasServerName:
        typeof serverInfo?.name === "string" && serverInfo.name.length > 0,
      hasServerVersion:
        typeof serverInfo?.version === "string" &&
        serverInfo.version.length > 0,
      hasCapabilities: serverCapabilities !== undefined,
    };

    const passedValidations = Object.values(validations).filter((v) => v);
    const allPassed =
      passedValidations.length === Object.keys(validations).length;
    const hasMinimumInfo =
      validations.hasServerInfo && validations.hasServerName;

    const warnings: string[] = [];
    if (!validations.hasServerVersion) {
      warnings.push(
        "Server should provide version for better compatibility tracking",
      );
    }
    if (!validations.hasCapabilities) {
      warnings.push(
        "Server should declare capabilities for feature negotiation",
      );
    }

    return {
      passed: hasMinimumInfo,
      confidence: allPassed ? "high" : "medium",
      evidence: `${passedValidations.length}/${Object.keys(validations).length} initialization checks passed`,
      details: {
        validations,
        serverInfo: {
          name: serverInfo?.name,
          version: serverInfo?.version,
          hasCapabilities: !!serverCapabilities,
        },
      },
      warnings: warnings.length > 0 ? warnings : undefined,
    };
  }
}
