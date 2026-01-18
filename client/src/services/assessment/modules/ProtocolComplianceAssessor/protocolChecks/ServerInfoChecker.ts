/**
 * Server Info Validity Checker
 *
 * Validates server info structure during initialization.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/ServerInfoChecker
 * @see GitHub Issue #188
 */

import type { ServerInfo } from "@/lib/assessmentTypes";
import type {
  ProtocolCheckResult,
  Logger,
  AssessmentConfiguration,
} from "../types";

/**
 * Validates server info structure and types.
 */
export class ServerInfoChecker {
  constructor(
    _config: AssessmentConfiguration,
    private readonly logger: Logger,
  ) {}

  /**
   * Check if server info is valid and properly formatted.
   * Server info is optional, but if present must have valid types.
   */
  check(serverInfo: ServerInfo | undefined): ProtocolCheckResult {
    if (!serverInfo) {
      return {
        passed: true,
        confidence: "medium",
        evidence: "No server info provided (optional)",
        rawResponse: undefined,
      };
    }

    // Validate name field
    if (serverInfo.name !== undefined && serverInfo.name !== null) {
      if (typeof serverInfo.name !== "string") {
        this.logger.info("Server info name is not a string");
        return {
          passed: false,
          confidence: "high",
          evidence: "Server info name must be a string",
          rawResponse: serverInfo,
        };
      }
    }

    // Validate metadata field
    if (serverInfo.metadata !== undefined && serverInfo.metadata !== null) {
      if (typeof serverInfo.metadata !== "object") {
        this.logger.info("Server info metadata is not an object");
        return {
          passed: false,
          confidence: "high",
          evidence: "Server info metadata must be an object",
          rawResponse: serverInfo,
        };
      }
    }

    return {
      passed: true,
      confidence: "high",
      evidence: "Server info structure is valid",
      rawResponse: serverInfo,
    };
  }
}
