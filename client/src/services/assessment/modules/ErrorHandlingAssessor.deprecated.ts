/**
 * Error Handling Assessor - Deprecated Wrapper
 *
 * @deprecated Use ProtocolComplianceAssessor instead.
 * ErrorHandlingAssessor has been merged into ProtocolComplianceAssessor (Issue #188).
 * This wrapper delegates to ProtocolComplianceAssessor and extracts the errorHandling result.
 *
 * This export will be removed in v2.0.0.
 *
 * @module assessment/modules/ErrorHandlingAssessor
 */

import { ErrorHandlingAssessment } from "@/lib/assessmentTypes";
import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { ProtocolComplianceAssessor } from "./ProtocolComplianceAssessor";

/**
 * @deprecated Use ProtocolComplianceAssessor instead.
 *
 * This is a thin wrapper that delegates to ProtocolComplianceAssessor
 * and extracts the errorHandling result for backward compatibility.
 */
export class ErrorHandlingAssessor extends BaseAssessor<ErrorHandlingAssessment> {
  private protocolComplianceAssessor: ProtocolComplianceAssessor;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.protocolComplianceAssessor = new ProtocolComplianceAssessor(config);
    this.logger.warn(
      "ErrorHandlingAssessor is deprecated. Use ProtocolComplianceAssessor instead. " +
        "This wrapper will be removed in v2.0.0.",
    );
  }

  /**
   * Delegates to ProtocolComplianceAssessor and extracts errorHandling result.
   */
  async assess(context: AssessmentContext): Promise<ErrorHandlingAssessment> {
    this.logger.info(
      "ErrorHandlingAssessor.assess() delegating to ProtocolComplianceAssessor",
    );

    // Run the unified protocol compliance assessment
    const unifiedResult = await this.protocolComplianceAssessor.assess(context);

    // Extract and return just the errorHandling portion
    return unifiedResult.errorHandling;
  }
}
