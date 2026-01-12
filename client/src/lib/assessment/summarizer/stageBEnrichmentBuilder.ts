/**
 * Stage B Enrichment Builder
 *
 * Functions to build Stage B enrichment data from assessment results.
 * Extracts evidence, correlations, and confidence details for Claude
 * semantic analysis.
 *
 * Issue #137: Stage A data enrichment for Stage B Claude analysis
 *
 * @module assessment/summarizer/stageBEnrichmentBuilder
 */

import type { SecurityTestResult } from "../resultTypes";
import type { AUPViolation } from "../extendedTypes";
import type { EnhancedToolAnnotationResult } from "../../../services/assessment/modules/annotations/types";
import {
  type FindingEvidence,
  type PayloadCorrelation,
  type ToolSummaryStageBEnrichment,
  type ToolDetailStageBEnrichment,
  DEFAULT_TIER2_MAX_SAMPLES,
  DEFAULT_TIER3_MAX_CORRELATIONS,
  MAX_RESPONSE_LENGTH,
  MAX_CONTEXT_WINDOW,
} from "./stageBTypes";

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Truncate a string to a maximum length, adding ellipsis if truncated.
 */
function truncate(str: string | undefined, maxLength: number): string {
  if (!str) return "";
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + "...";
}

/**
 * Map test result to classification.
 */
function classifyTestResult(
  test: SecurityTestResult,
): "vulnerable" | "safe" | "error" | "timeout" {
  if (test.connectionError) return "error";
  if (test.testReliability === "failed") return "error";
  if (test.vulnerable) return "vulnerable";
  return "safe";
}

/**
 * Convert SecurityTestResult to PayloadCorrelation.
 */
function testToCorrelation(test: SecurityTestResult): PayloadCorrelation {
  return {
    inputPayload: truncate(test.payload, MAX_RESPONSE_LENGTH),
    outputResponse: truncate(test.response, MAX_RESPONSE_LENGTH),
    classification: classifyTestResult(test),
    matchedPatterns: test.vulnerable ? [test.testName] : [],
    toolName: test.toolName || "unknown",
    testName: test.testName,
    confidence: test.confidence,
  };
}

/**
 * Convert test result to finding evidence.
 */
function testToEvidence(test: SecurityTestResult): FindingEvidence {
  const contextSource = test.evidence || test.response;
  const location = test.evidence
    ? "evidence"
    : test.response
      ? "response"
      : "unknown";
  return {
    raw: truncate(test.payload, MAX_RESPONSE_LENGTH),
    context: truncate(contextSource, MAX_CONTEXT_WINDOW),
    location,
  };
}

/**
 * Calculate confidence distribution from tests.
 */
function calculateConfidenceBreakdown(tests: SecurityTestResult[]): {
  high: number;
  medium: number;
  low: number;
} {
  const breakdown = { high: 0, medium: 0, low: 0 };

  for (const test of tests) {
    if (test.vulnerable) {
      const confidence = test.confidence || "medium";
      breakdown[confidence]++;
    }
  }

  return breakdown;
}

/**
 * Calculate pattern distribution from tests.
 */
function calculatePatternDistribution(
  tests: SecurityTestResult[],
): Record<string, number> {
  const distribution: Record<string, number> = {};

  for (const test of tests) {
    if (test.vulnerable) {
      const pattern = test.testName;
      distribution[pattern] = (distribution[pattern] || 0) + 1;
    }
  }

  return distribution;
}

/**
 * Find the highest risk test (most concerning vulnerability).
 */
function findHighestRiskTest(
  tests: SecurityTestResult[],
): SecurityTestResult | undefined {
  const vulnerableTests = tests.filter((t) => t.vulnerable);
  if (vulnerableTests.length === 0) return undefined;

  // Prioritize by risk level, then by confidence
  const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const confidenceOrder = { high: 0, medium: 1, low: 2 };

  return vulnerableTests.sort((a, b) => {
    const riskDiff =
      (riskOrder[a.riskLevel] ?? 4) - (riskOrder[b.riskLevel] ?? 4);
    if (riskDiff !== 0) return riskDiff;
    return (
      (confidenceOrder[a.confidence || "medium"] ?? 1) -
      (confidenceOrder[b.confidence || "medium"] ?? 1)
    );
  })[0];
}

// ============================================================================
// Tier 2: Tool Summary Enrichment Builder
// ============================================================================

/**
 * Build Stage B enrichment for Tier 2 tool summaries.
 *
 * @param toolName - Name of the tool
 * @param tests - Security test results for this tool
 * @param maxSamples - Maximum evidence samples to include
 * @returns Tool summary Stage B enrichment
 */
export function buildToolSummaryStageBEnrichment(
  toolName: string,
  tests: SecurityTestResult[],
  maxSamples: number = DEFAULT_TIER2_MAX_SAMPLES,
): ToolSummaryStageBEnrichment {
  // Filter to only tests for this tool
  const toolTests = tests.filter((t) => t.toolName === toolName);

  // Get vulnerable tests for evidence sampling
  const vulnerableTests = toolTests.filter((t) => t.vulnerable);

  // Sample evidence from highest-risk vulnerabilities
  const sortedVulnerable = [...vulnerableTests].sort((a, b) => {
    const riskOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return (riskOrder[a.riskLevel] ?? 4) - (riskOrder[b.riskLevel] ?? 4);
  });

  const sampleEvidence = sortedVulnerable
    .slice(0, maxSamples)
    .map(testToEvidence);

  // Calculate confidence breakdown
  const confidenceBreakdown = calculateConfidenceBreakdown(toolTests);

  // Find highest risk correlation
  const highestRiskTest = findHighestRiskTest(toolTests);
  const highestRiskCorrelation = highestRiskTest
    ? testToCorrelation(highestRiskTest)
    : undefined;

  // Calculate pattern distribution
  const patternDistribution = calculatePatternDistribution(toolTests);

  // Check for sanitization detection
  const sanitizationDetected = toolTests.some((t) => t.sanitizationDetected);

  // Check auth failure mode
  const authTests = toolTests.filter((t) => t.authFailureMode);
  const authFailureMode =
    authTests.length > 0 ? authTests[0].authFailureMode : undefined;

  return {
    sampleEvidence,
    confidenceBreakdown,
    highestRiskCorrelation,
    patternDistribution,
    sanitizationDetected: sanitizationDetected || undefined,
    authFailureMode,
  };
}

// ============================================================================
// Tier 3: Tool Detail Enrichment Builder
// ============================================================================

/**
 * Build Stage B enrichment for Tier 3 per-tool detail files.
 *
 * @param toolName - Name of the tool
 * @param tests - Security test results for this tool
 * @param annotationResult - Tool annotation result (if available)
 * @param aupViolations - AUP violations for this tool (if any)
 * @param maxCorrelations - Maximum correlations to include
 * @returns Tool detail Stage B enrichment
 */
export function buildToolDetailStageBEnrichment(
  toolName: string,
  tests: SecurityTestResult[],
  annotationResult?: EnhancedToolAnnotationResult,
  aupViolations?: AUPViolation[],
  maxCorrelations: number = DEFAULT_TIER3_MAX_CORRELATIONS,
): ToolDetailStageBEnrichment {
  // Filter to only tests for this tool
  const toolTests = tests.filter((t) => t.toolName === toolName);

  // Build payload correlations (prioritize vulnerable, then errors, then safe)
  const sortedTests = [...toolTests].sort((a, b) => {
    if (a.vulnerable && !b.vulnerable) return -1;
    if (!a.vulnerable && b.vulnerable) return 1;
    if (a.connectionError && !b.connectionError) return -1;
    if (!a.connectionError && b.connectionError) return 1;
    return 0;
  });

  const payloadCorrelations = sortedTests
    .slice(0, maxCorrelations)
    .map(testToCorrelation);

  // Pattern distribution
  const patternDistribution = calculatePatternDistribution(toolTests);

  // Build context windows from evidence
  const contextWindows: Record<string, string> = {};
  for (const test of toolTests.filter((t) => t.vulnerable && t.evidence)) {
    const key = `${test.testName}:${test.payload.slice(0, 30)}`;
    if (!contextWindows[key]) {
      contextWindows[key] = truncate(test.evidence, MAX_CONTEXT_WINDOW);
    }
  }

  // Calculate confidence details
  const confidenceBreakdown = calculateConfidenceBreakdown(toolTests);
  const totalVulnerable =
    confidenceBreakdown.high +
    confidenceBreakdown.medium +
    confidenceBreakdown.low;
  const overallConfidence =
    totalVulnerable > 0
      ? Math.round(
          ((confidenceBreakdown.high * 100 +
            confidenceBreakdown.medium * 70 +
            confidenceBreakdown.low * 40) /
            totalVulnerable /
            100) *
            100,
        )
      : 100; // 100% confidence if no vulnerabilities

  const confidenceDetails = {
    overall: overallConfidence,
    byCategory: patternDistribution,
    requiresManualReview: toolTests.filter((t) => t.requiresManualReview)
      .length,
  };

  // Security details
  const vulnerableCount = toolTests.filter((t) => t.vulnerable).length;
  const safeCount = toolTests.filter(
    (t) => !t.vulnerable && !t.connectionError,
  ).length;
  const errorCount = toolTests.filter((t) => t.connectionError).length;

  // Collect sanitization libraries
  const sanitizationLibraries = [
    ...new Set(
      toolTests.flatMap((t) => t.sanitizationLibraries || []).filter(Boolean),
    ),
  ];

  // Auth bypass evidence
  const authBypassTest = toolTests.find((t) => t.authBypassDetected);
  const authBypassEvidence = authBypassTest?.authBypassEvidence;

  const securityDetails = {
    vulnerableCount,
    safeCount,
    errorCount,
    sanitizationLibraries,
    authBypassEvidence,
  };

  // Annotation details
  let annotationDetails: ToolDetailStageBEnrichment["annotationDetails"];
  if (annotationResult) {
    annotationDetails = {
      hasAnnotations: annotationResult.hasAnnotations,
      alignmentStatus: annotationResult.alignmentStatus as
        | "ALIGNED"
        | "MISALIGNED"
        | "MISSING"
        | undefined,
      inferredBehavior: annotationResult.inferredBehavior
        ? {
            expectedReadOnly:
              annotationResult.inferredBehavior.expectedReadOnly,
            expectedDestructive:
              annotationResult.inferredBehavior.expectedDestructive,
            reason: annotationResult.inferredBehavior.reason,
          }
        : undefined,
      descriptionPoisoning: annotationResult.descriptionPoisoning
        ? {
            detected: annotationResult.descriptionPoisoning.detected,
            patterns: annotationResult.descriptionPoisoning.patterns.map(
              (p: {
                name: string;
                evidence: string;
                severity: "LOW" | "MEDIUM" | "HIGH";
              }) => ({
                name: p.name,
                evidence: truncate(p.evidence, MAX_CONTEXT_WINDOW),
                severity: p.severity,
              }),
            ),
          }
        : undefined,
    };
  }

  // AUP violations for this tool
  const toolAupViolations = aupViolations
    ?.filter((v) => v.location?.includes(toolName))
    .map((v) => ({
      pattern: v.pattern,
      matchedText: truncate(v.matchedText, MAX_CONTEXT_WINDOW),
      severity: v.severity,
      location: v.location,
    }));

  return {
    payloadCorrelations,
    patternDistribution,
    contextWindows,
    confidenceDetails,
    securityDetails,
    annotationDetails,
    aupViolations:
      toolAupViolations && toolAupViolations.length > 0
        ? toolAupViolations
        : undefined,
  };
}
