/**
 * Stage B Enrichment Types
 *
 * Type definitions for Stage B (Claude semantic analysis) data enrichment.
 * These types extend the tiered output with evidence, correlations, and
 * confidence details for better LLM semantic analysis.
 *
 * Issue #137: Stage A data enrichment for Stage B Claude analysis
 * Issue #194: AUP module enrichment for Claude validation
 *
 * @module assessment/summarizer/stageBTypes
 */

import type { ToolCapability, AUPCategory } from "../aupComplianceTypes";

// ============================================================================
// Base Evidence Types
// ============================================================================

/**
 * Evidence structure for individual findings.
 * Provides raw data and context for Claude to analyze.
 */
export interface FindingEvidence {
  /** Actual data that triggered the finding (payload or matched text) */
  raw: string;
  /** Surrounding context for better understanding */
  context: string;
  /** Location in response (e.g., "response.content[0].text", "description") */
  location: string;
}

/**
 * Payload correlation linking input to output.
 * Enables Claude to understand cause-effect relationships.
 */
export interface PayloadCorrelation {
  /** The test payload that was sent */
  inputPayload: string;
  /** The response received (may be truncated) */
  outputResponse: string;
  /** Classification of the result */
  classification: "vulnerable" | "safe" | "error" | "timeout";
  /** Patterns that matched this response */
  matchedPatterns: string[];
  /** Tool this correlation belongs to */
  toolName: string;
  /** Test name/pattern that triggered this */
  testName: string;
  /** Confidence level of the detection */
  confidence?: "high" | "medium" | "low";
}

// ============================================================================
// Tier 2: Tool Summary Enrichment
// ============================================================================

/**
 * Stage B enrichment for Tier 2 tool summaries.
 * Provides sampled evidence for quick Claude analysis.
 */
export interface ToolSummaryStageBEnrichment {
  /** Top evidence samples for this tool (limited for token efficiency) */
  sampleEvidence: FindingEvidence[];

  /** Confidence breakdown by pattern type */
  confidenceBreakdown: {
    high: number;
    medium: number;
    low: number;
  };

  /** Highest risk correlation for this tool (if vulnerable) */
  highestRiskCorrelation?: PayloadCorrelation;

  /** Pattern distribution showing which attack types were detected */
  patternDistribution: Record<string, number>;

  /** Whether this tool has sanitization detected */
  sanitizationDetected?: boolean;

  /** Auth bypass mode if detected */
  authFailureMode?: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN";
}

// ============================================================================
// Tier 3: Tool Detail Enrichment
// ============================================================================

/**
 * Stage B enrichment for Tier 3 per-tool detail files.
 * Provides comprehensive evidence for deep-dive analysis.
 */
export interface ToolDetailStageBEnrichment {
  /** All payload correlations for this tool */
  payloadCorrelations: PayloadCorrelation[];

  /** Full pattern distribution with counts */
  patternDistribution: Record<string, number>;

  /** Context windows for key locations */
  contextWindows: Record<string, string>;

  /** Detailed confidence breakdown */
  confidenceDetails: {
    /** Overall confidence score (0-100) */
    overall: number;
    /** Confidence by attack category */
    byCategory: Record<string, number>;
    /** Number of tests with manual review recommended */
    requiresManualReview: number;
  };

  /** Security-specific details */
  securityDetails: {
    /** Total vulnerabilities found */
    vulnerableCount: number;
    /** Total safe tests */
    safeCount: number;
    /** Tests with connection errors */
    errorCount: number;
    /** Sanitization libraries detected */
    sanitizationLibraries: string[];
    /** Auth bypass evidence if detected */
    authBypassEvidence?: string;
  };

  /** Annotation alignment details (if available) */
  annotationDetails?: {
    /** Whether tool has annotations */
    hasAnnotations: boolean;
    /** Alignment status */
    alignmentStatus?: "ALIGNED" | "MISALIGNED" | "MISSING";
    /** Inferred behavior from patterns */
    inferredBehavior?: {
      expectedReadOnly: boolean;
      expectedDestructive: boolean;
      reason: string;
    };
    /** Description poisoning if detected */
    descriptionPoisoning?: {
      detected: boolean;
      patterns: Array<{
        name: string;
        evidence: string;
        severity: "LOW" | "MEDIUM" | "HIGH";
      }>;
    };
  };

  /** AUP violations for this tool (if any) */
  aupViolations?: Array<{
    pattern: string;
    matchedText: string;
    severity: string;
    location: string;
  }>;
}

// ============================================================================
// Aggregated Enrichment
// ============================================================================

/**
 * Combined Stage B enrichment that can be attached to results.
 */
export interface StageBEnrichment {
  /** Enrichment version for compatibility tracking */
  version: number;

  /** Whether enrichment was enabled */
  enabled: boolean;

  /** Generation timestamp */
  generatedAt: string;

  /** Tier 2 enrichment (tool summary level) */
  tier2?: ToolSummaryStageBEnrichment;

  /** Tier 3 enrichment (tool detail level) */
  tier3?: ToolDetailStageBEnrichment;
}

// ============================================================================
// AUP Module Enrichment (Issue #194)
// ============================================================================

/**
 * Stage B enrichment for the AUP compliance module.
 * Provides tool inventory, pattern coverage, and flags for Claude validation.
 */
export interface AUPModuleStageBEnrichment {
  /** Tool inventory with names, descriptions, and inferred capabilities */
  toolInventory: Array<{
    name: string;
    description: string;
    capabilities: ToolCapability[];
  }>;

  /** Pattern coverage showing what AUP patterns were checked */
  patternCoverage: {
    totalPatterns: number;
    categoriesCovered: AUPCategory[];
    samplePatterns: string[];
    severityBreakdown: {
      critical: number;
      high: number;
      medium: number;
      flag: number;
    };
  };

  /** Tools flagged for review based on sensitive capabilities */
  flagsForReview: Array<{
    toolName: string;
    reason: string;
    capabilities: ToolCapability[];
    confidence: "low";
  }>;

  /** Summary counts for quick reference */
  summary: {
    totalTools: number;
    toolsWithSensitiveCapabilities: number;
    capabilityBreakdown: Record<string, number>;
  };
}

// ============================================================================
// Constants
// ============================================================================

/** Current Stage B enrichment version */
export const STAGE_B_ENRICHMENT_VERSION = 1;

/** Default maximum samples for Tier 2 evidence */
export const DEFAULT_TIER2_MAX_SAMPLES = 3;

/** Default maximum correlations for Tier 3 */
export const DEFAULT_TIER3_MAX_CORRELATIONS = 50;

/** Maximum response length to include (prevents token explosion) */
export const MAX_RESPONSE_LENGTH = 500;

/** Maximum context window size (chars before/after) */
export const MAX_CONTEXT_WINDOW = 200;

/** Maximum tools to include in inventory (for token efficiency) */
export const MAX_TOOL_INVENTORY_ITEMS = 50;
