/**
 * Assessment Summarizer Module
 *
 * Generates tiered output for large assessment results to fit within
 * LLM context windows.
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @module assessment/summarizer
 */

// Types
export type {
  OutputFormat,
  ToolRiskLevel,
  ExecutiveSummary,
  ToolSummary,
  ToolSummariesCollection,
  ToolDetailReference,
  TieredOutput,
  SummarizerConfig,
} from "./types";

export { DEFAULT_SUMMARIZER_CONFIG } from "./types";

// Token estimation utilities
export {
  estimateTokens,
  estimateJsonFileTokens,
  shouldAutoTier,
  formatTokenEstimate,
  estimateSectionTokens,
  getTopSections,
} from "./tokenEstimator";

// Main summarizer class
export { AssessmentSummarizer } from "./AssessmentSummarizer";
