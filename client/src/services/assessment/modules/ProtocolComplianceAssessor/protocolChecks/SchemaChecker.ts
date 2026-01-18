/**
 * JSON Schema Compliance Checker
 *
 * Validates that all tool input schemas follow JSON Schema specification.
 * Uses AJV for schema validation.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/SchemaChecker
 * @see GitHub Issue #188
 */

import Ajv from "ajv";
import type { Ajv as AjvInstance } from "ajv";
import type {
  ProtocolCheckResult,
  Tool,
  Logger,
  AssessmentConfiguration,
} from "../types";

/**
 * Validates tool input schemas against JSON Schema specification.
 */
export class SchemaChecker {
  private ajv: AjvInstance;
  private logger: Logger;

  constructor(_config: AssessmentConfiguration, logger: Logger) {
    this.ajv = new Ajv({ allErrors: true });
    this.logger = logger;
  }

  /**
   * Check schema compliance for all tools.
   * Returns low confidence if validation errors detected (may be Zod/TypeBox conversion issues).
   */
  check(tools: Tool[]): ProtocolCheckResult {
    try {
      let hasErrors = false;
      const errors: string[] = [];

      for (const tool of tools) {
        if (tool.inputSchema) {
          const isValid = this.ajv.validateSchema(tool.inputSchema);
          if (!isValid) {
            hasErrors = true;
            const errorMsg = `${tool.name}: ${JSON.stringify(this.ajv.errors)}`;
            errors.push(errorMsg);
            this.logger.warn(`Invalid schema for tool ${tool.name}`, {
              errors: this.ajv.errors,
            });
          }
        }
      }

      return {
        passed: !hasErrors,
        confidence: hasErrors ? "low" : "high",
        evidence: hasErrors
          ? "Schema validation errors detected (may be Zod/TypeBox conversion)"
          : "All tool schemas follow JSON Schema specification",
        warnings: hasErrors ? errors : undefined,
        rawResponse: tools.map((t) => ({
          name: t.name,
          inputSchema: t.inputSchema,
        })),
      };
    } catch (error) {
      this.logger.error("Schema compliance check failed", {
        error: String(error),
      });
      return {
        passed: false,
        confidence: "low",
        evidence: String(error),
        warnings: [String(error)],
      };
    }
  }
}
