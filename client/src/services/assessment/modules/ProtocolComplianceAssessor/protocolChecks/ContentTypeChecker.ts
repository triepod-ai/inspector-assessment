/**
 * Content Type Support Checker
 *
 * Validates that tool responses use valid MCP content types.
 * Valid types: text, image, audio, resource, resource_link.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/ContentTypeChecker
 * @see GitHub Issue #188
 */

import type { AssessmentContext } from "../../../AssessmentOrchestrator";
import type {
  ProtocolCheckResult,
  Logger,
  AssessmentConfiguration,
  ContentItem,
} from "../types";

// Valid MCP content types
const VALID_TYPES = [
  "text",
  "image",
  "audio",
  "resource",
  "resource_link",
] as const;

type ValidContentType = (typeof VALID_TYPES)[number];

/**
 * Validates content type usage in tool responses.
 */
export class ContentTypeChecker {
  private config: AssessmentConfiguration;

  constructor(config: AssessmentConfiguration, _logger: Logger) {
    this.config = config;
  }

  // Note: getSpecVersion/getSpecBaseUrl reserved for future use with dynamic spec URLs

  /**
   * Execute with timeout helper.
   */
  private async executeWithTimeout<T>(
    promise: Promise<T>,
    timeout: number,
  ): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) =>
        setTimeout(() => reject(new Error("Timeout")), timeout),
      ),
    ]);
  }

  /**
   * Check content type support.
   */
  async check(context: AssessmentContext): Promise<ProtocolCheckResult> {
    try {
      const testTool = context.tools[0];
      if (!testTool) {
        return {
          passed: false,
          confidence: "low",
          evidence: "No tools available to test content types",
        };
      }

      const schema = testTool.inputSchema;
      const hasRequiredParams =
        schema?.required &&
        Array.isArray(schema.required) &&
        schema.required.length > 0;

      // Cannot test content types if tool has required parameters
      if (hasRequiredParams) {
        return {
          passed: true,
          confidence: "low",
          evidence:
            "Cannot test content types without knowing valid parameters - tool has required params",
          warnings: ["Content type validation requires valid tool parameters"],
        };
      }

      const result = await this.executeWithTimeout(
        context.callTool(testTool.name, {}),
        this.config.testTimeout ?? 5000,
      );

      const contentArray = Array.isArray(result.content) ? result.content : [];
      const validations = {
        hasContentArray: Array.isArray(result.content),
        contentNotEmpty: contentArray.length > 0,
        allContentHasType: (contentArray as ContentItem[]).every(
          (c) => c.type !== undefined,
        ),
        validContentTypes: (contentArray as ContentItem[]).every((c) =>
          VALID_TYPES.includes(c.type as ValidContentType),
        ),
      };

      const passedValidations = Object.values(validations).filter((v) => v);
      const allPassed =
        passedValidations.length === Object.keys(validations).length;

      const detectedTypes = (contentArray as ContentItem[]).map((c) => c.type);
      const invalidTypes = detectedTypes.filter(
        (t) => !VALID_TYPES.includes(t as ValidContentType),
      );

      return {
        passed: allPassed,
        confidence: allPassed ? "high" : "medium",
        evidence: `${passedValidations.length}/${Object.keys(validations).length} content type checks passed`,
        details: {
          validations,
          detectedContentTypes: detectedTypes,
          invalidContentTypes:
            invalidTypes.length > 0 ? invalidTypes : undefined,
        },
        warnings:
          invalidTypes.length > 0
            ? [`Invalid content types found: ${invalidTypes.join(", ")}`]
            : undefined,
      };
    } catch (error) {
      return {
        passed: false,
        confidence: "medium",
        evidence: "Could not test content types due to error",
        details: {
          error: error instanceof Error ? error.message : String(error),
        },
      };
    }
  }
}
