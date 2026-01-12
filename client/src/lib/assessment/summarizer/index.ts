/**
 * Assessment Summarizer Module
 *
 * Generates tiered output for large assessment results to fit within
 * LLM context windows.
 *
 * Issue #136: Tiered output strategy for large assessments
 * Issue #137: Stage B enrichment for Claude semantic analysis
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

// Stage B Types (Issue #137)
export type {
  FindingEvidence,
  PayloadCorrelation,
  ToolSummaryStageBEnrichment,
  ToolDetailStageBEnrichment,
  StageBEnrichment,
} from "./stageBTypes";

export {
  STAGE_B_ENRICHMENT_VERSION,
  DEFAULT_TIER2_MAX_SAMPLES,
  DEFAULT_TIER3_MAX_CORRELATIONS,
  MAX_RESPONSE_LENGTH,
  MAX_CONTEXT_WINDOW,
} from "./stageBTypes";

// Stage B Enrichment Builders (Issue #137)
export {
  buildToolSummaryStageBEnrichment,
  buildToolDetailStageBEnrichment,
} from "./stageBEnrichmentBuilder";

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
