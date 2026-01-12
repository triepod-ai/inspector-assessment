/**
 * Tiered Output Types
 *
 * Type definitions for the tiered output strategy that generates
 * LLM-consumable summaries from large assessment results.
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @module assessment/summarizer/types
 */

import type { AssessmentStatus } from "../coreTypes";
import type { ToolSummaryStageBEnrichment } from "./stageBTypes";

// ============================================================================
// Output Format Types
// ============================================================================

/**
 * Output format for assessment results.
 * - "full": Complete JSON output (default, existing behavior)
 * - "tiered": Directory structure with executive summary, tool summaries, and per-tool details
 * - "summary-only": Only executive summary and tool summaries (no per-tool detail files)
 */
export type OutputFormat = "full" | "tiered" | "summary-only";

/**
 * Risk level categorization for tools based on security assessment results.
 */
export type ToolRiskLevel = "HIGH" | "MEDIUM" | "LOW" | "SAFE";

// ============================================================================
// Tier 1: Executive Summary (~5K tokens)
// ============================================================================

/**
 * Executive Summary - Tier 1 output.
 * Always generated, always fits in LLM context window.
 * Provides high-level overview for quick assessment understanding.
 */
export interface ExecutiveSummary {
  /** Server name from assessment */
  serverName: string;

  /** Overall assessment status (PASS/FAIL/NEED_MORE_INFO) */
  overallStatus: AssessmentStatus;

  /** Calculated overall score (0-100) */
  overallScore: number;

  /** Total number of tools discovered */
  toolCount: number;

  /** Total number of tests executed */
  testCount: number;

  /** Total execution time in milliseconds */
  executionTime: number;

  /**
   * Per-module status and score summary.
   * Key is module name (e.g., "security", "functionality")
   */
  modulesSummary: Record<
    string,
    {
      status: AssessmentStatus;
      score: number;
    }
  >;

  /** Critical findings aggregated from all modules */
  criticalFindings: {
    /** Number of security vulnerabilities detected */
    securityVulnerabilities: number;
    /** Number of AUP violations detected */
    aupViolations: number;
    /** Number of broken/non-functional tools */
    brokenTools: number;
    /** Number of tools missing required annotations */
    missingAnnotations: number;
  };

  /**
   * Distribution of tools by risk level.
   * Helps quickly understand overall risk profile.
   */
  toolRiskDistribution: {
    high: number;
    medium: number;
    low: number;
    safe: number;
  };

  /** Top recommendations aggregated from all modules */
  recommendations: string[];

  /** Estimated token count for this summary */
  estimatedTokens: number;

  /** ISO timestamp when summary was generated */
  generatedAt: string;
}

// ============================================================================
// Tier 2: Tool Summaries (~500 tokens per tool)
// ============================================================================

/**
 * Tool Summary - Tier 2 output.
 * Per-tool digest without individual test results.
 * Enables focused analysis on specific tools without full detail.
 */
export interface ToolSummary {
  /** Tool name from MCP server */
  toolName: string;

  /** Calculated risk level based on security findings */
  riskLevel: ToolRiskLevel;

  /** Number of vulnerabilities found for this tool */
  vulnerabilityCount: number;

  /**
   * Top vulnerability patterns detected.
   * Limited to top 5 for token efficiency.
   */
  topPatterns: string[];

  /** Total number of tests run on this tool */
  testCount: number;

  /** Percentage of tests that passed (0-100) */
  passRate: number;

  /** Tool-specific recommendations */
  recommendations: string[];

  /** Estimated token count for this summary */
  estimatedTokens: number;

  /** Whether the tool has proper annotations */
  hasAnnotations: boolean;

  /** Annotation alignment status if available */
  annotationStatus?: "ALIGNED" | "MISALIGNED" | "MISSING";

  /** Stage B enrichment for Claude semantic analysis (Issue #137) */
  stageBEnrichment?: ToolSummaryStageBEnrichment;
}

/**
 * Collection of tool summaries with aggregate metadata.
 */
export interface ToolSummariesCollection {
  /** Individual tool summaries */
  tools: ToolSummary[];

  /** Total number of tools */
  totalTools: number;

  /** Aggregate statistics */
  aggregate: {
    /** Total vulnerabilities across all tools */
    totalVulnerabilities: number;
    /** Average pass rate across all tools */
    averagePassRate: number;
    /** Tools with misaligned annotations */
    misalignedAnnotations: number;
  };

  /** Estimated total tokens for all summaries */
  estimatedTokens: number;

  /** ISO timestamp */
  generatedAt: string;
}

// ============================================================================
// Tier 3: Per-Tool Detail References
// ============================================================================

/**
 * Reference to a per-tool detail file (Tier 3).
 * Full test results stored in separate files for deep-dive analysis.
 */
export interface ToolDetailReference {
  /** Tool name */
  toolName: string;

  /** Relative path to detail file (e.g., "tools/my_tool.json") */
  relativePath: string;

  /** Absolute path to detail file */
  absolutePath: string;

  /** File size in bytes */
  fileSizeBytes: number;

  /** Estimated token count for full detail */
  estimatedTokens: number;
}

// ============================================================================
// Complete Tiered Output
// ============================================================================

/**
 * Complete tiered output structure.
 * Contains all tiers with paths to generated files.
 */
export interface TieredOutput {
  /** Tier 1: Executive summary */
  executiveSummary: ExecutiveSummary;

  /** Tier 2: Tool summaries */
  toolSummaries: ToolSummariesCollection;

  /** Tier 3: References to per-tool detail files */
  toolDetailRefs: ToolDetailReference[];

  /** Output directory path */
  outputDir: string;

  /** File paths for each tier */
  paths: {
    executiveSummary: string;
    toolSummaries: string;
    toolDetailsDir: string;
  };
}

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Configuration options for the summarizer.
 */
export interface SummarizerConfig {
  /** Maximum number of recommendations to include in executive summary */
  maxRecommendations?: number;

  /** Maximum number of top patterns per tool in tool summaries */
  maxPatternsPerTool?: number;

  /** Token threshold for auto-tiering (default: 100,000) */
  autoTierThreshold?: number;

  /** Whether to include tool detail files (Tier 3) */
  includeToolDetails?: boolean;

  /** Enable Stage B enrichment for Claude semantic analysis (Issue #137) */
  stageBVerbose?: boolean;
}

/**
 * Default summarizer configuration values.
 */
export const DEFAULT_SUMMARIZER_CONFIG: Required<SummarizerConfig> = {
  maxRecommendations: 10,
  maxPatternsPerTool: 5,
  autoTierThreshold: 100_000,
  includeToolDetails: true,
  stageBVerbose: false,
};
