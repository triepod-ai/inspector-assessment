/**
 * Report Formatters
 *
 * Factory module for creating report formatters in different output formats.
 *
 * @module reportFormatters
 */

import type { MCPDirectoryAssessment } from "../assessmentTypes";
import type { PolicyComplianceReport } from "../policyMapping";
import {
  MarkdownReportFormatter,
  type MarkdownReportOptions,
} from "./MarkdownReportFormatter";

/**
 * Supported output formats
 */
export type ReportFormat = "json" | "markdown";

/**
 * Base formatter interface
 */
export interface ReportFormatter {
  /** Format the assessment results */
  format(assessment: MCPDirectoryAssessment): string;
  /** Get the file extension for this format */
  getFileExtension(): string;
}

/**
 * Options for creating a formatter
 */
export interface FormatterOptions {
  /** Output format */
  format: ReportFormat;
  /** Include policy compliance mapping */
  includePolicyMapping?: boolean;
  /** Policy compliance report (generated separately) */
  policyReport?: PolicyComplianceReport;
  /** Server name override */
  serverName?: string;
  /** Include detailed results */
  includeDetails?: boolean;
  /** Pretty print JSON */
  prettyPrint?: boolean;
}

/**
 * JSON formatter implementation
 */
class JSONReportFormatter implements ReportFormatter {
  private options: FormatterOptions;

  constructor(options: FormatterOptions) {
    this.options = options;
  }

  format(assessment: MCPDirectoryAssessment): string {
    const output: Record<string, unknown> = {
      ...assessment,
    };

    // Add policy compliance if included
    if (this.options.includePolicyMapping && this.options.policyReport) {
      output.policyCompliance = this.options.policyReport;
    }

    // Override server name if provided
    if (this.options.serverName) {
      output.serverName = this.options.serverName;
    }

    const indent = this.options.prettyPrint !== false ? 2 : undefined;
    return JSON.stringify(output, null, indent);
  }

  getFileExtension(): string {
    return ".json";
  }
}

/**
 * Markdown formatter wrapper
 */
class MarkdownFormatterWrapper implements ReportFormatter {
  private formatter: MarkdownReportFormatter;

  constructor(options: FormatterOptions) {
    const mdOptions: MarkdownReportOptions = {
      includePolicy: options.includePolicyMapping,
      policyReport: options.policyReport,
      includeDetails: options.includeDetails ?? true,
      includeRecommendations: true,
      serverName: options.serverName,
    };
    this.formatter = new MarkdownReportFormatter(mdOptions);
  }

  format(assessment: MCPDirectoryAssessment): string {
    return this.formatter.format(assessment);
  }

  getFileExtension(): string {
    return ".md";
  }
}

/**
 * Create a formatter based on options
 */
export function createFormatter(options: FormatterOptions): ReportFormatter {
  switch (options.format) {
    case "markdown":
      return new MarkdownFormatterWrapper(options);
    case "json":
    default:
      return new JSONReportFormatter(options);
  }
}

/**
 * Quick format utility
 */
export function formatAssessmentReport(
  assessment: MCPDirectoryAssessment,
  format: ReportFormat = "json",
  options?: Partial<FormatterOptions>,
): string {
  const formatter = createFormatter({
    format,
    ...options,
  });
  return formatter.format(assessment);
}

// Re-export types and classes
export { MarkdownReportFormatter, type MarkdownReportOptions };
