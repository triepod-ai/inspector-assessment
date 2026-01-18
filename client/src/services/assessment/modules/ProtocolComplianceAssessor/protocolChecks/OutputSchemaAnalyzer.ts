/**
 * Output Schema Coverage Analyzer
 *
 * Analyzes outputSchema coverage across all tools.
 * Issue #64: Detailed coverage metrics instead of just boolean.
 *
 * @module assessment/modules/ProtocolComplianceAssessor/protocolChecks/OutputSchemaAnalyzer
 * @see GitHub Issue #64, #188
 */

import type {
  OutputSchemaCoverage,
  ToolOutputSchemaResult,
} from "@/lib/assessmentTypes";
import type { Tool, Logger, AssessmentConfiguration } from "../types";

/**
 * Result of output schema analysis.
 */
export interface OutputSchemaAnalysisResult {
  coverage: OutputSchemaCoverage;
  toolResults: ToolOutputSchemaResult[];
}

/**
 * Analyzes structured output (outputSchema) coverage.
 */
export class OutputSchemaAnalyzer {
  private logger: Logger;

  constructor(_config: AssessmentConfiguration, logger: Logger) {
    this.logger = logger;
  }

  /**
   * Analyze outputSchema coverage across all tools.
   * Returns detailed coverage metrics per tool.
   */
  analyze(tools: Tool[]): OutputSchemaAnalysisResult {
    const toolResults: ToolOutputSchemaResult[] = [];
    const toolsWithoutSchema: string[] = [];
    let withOutputSchema = 0;
    let withoutOutputSchema = 0;

    for (const tool of tools) {
      const hasOutputSchema = !!tool.outputSchema;

      if (hasOutputSchema) {
        withOutputSchema++;
      } else {
        withoutOutputSchema++;
        toolsWithoutSchema.push(tool.name);
      }

      toolResults.push({
        toolName: tool.name,
        hasOutputSchema,
        outputSchema: tool.outputSchema as Record<string, unknown> | undefined,
      });
    }

    const totalTools = tools.length;
    const coveragePercent =
      totalTools > 0 ? Math.round((withOutputSchema / totalTools) * 100) : 0;

    this.logger.info(
      `Structured output support: ${withOutputSchema}/${totalTools} tools (${coveragePercent}%)`,
    );

    const coverage: OutputSchemaCoverage = {
      totalTools,
      withOutputSchema,
      withoutOutputSchema,
      coveragePercent,
      toolsWithoutSchema,
      status: coveragePercent === 100 ? "PASS" : "INFO",
      recommendation:
        coveragePercent < 100
          ? "Add outputSchema to tools for client-side response validation"
          : undefined,
    };

    return { coverage, toolResults };
  }
}
