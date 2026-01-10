/**
 * Explanation Generator Module
 * Generates explanations and recommendations for annotation assessment results
 *
 * Extracted from ToolAnnotationAssessor.ts as part of Issue #105 refactoring.
 */

import type { ToolAnnotationResult } from "@/lib/assessmentTypes";
import type { EnhancedToolAnnotationResult } from "./types";

/**
 * Generate basic explanation for annotation assessment
 */
export function generateExplanation(
  annotatedCount: number,
  missingCount: number,
  misalignedCount: number,
  totalTools: number,
): string {
  const parts: string[] = [];

  if (totalTools === 0) {
    return "No tools found to assess for annotations.";
  }

  parts.push(
    `Tool annotation coverage: ${annotatedCount}/${totalTools} tools have annotations.`,
  );

  if (missingCount > 0) {
    parts.push(
      `${missingCount} tool(s) are missing required annotations (readOnlyHint, destructiveHint).`,
    );
  }

  if (misalignedCount > 0) {
    parts.push(
      `${misalignedCount} tool(s) have potentially misaligned annotations based on naming patterns.`,
    );
  }

  if (missingCount === 0 && misalignedCount === 0) {
    parts.push("All tools are properly annotated.");
  }

  return parts.join(" ");
}

/**
 * Generate enhanced explanation with Claude analysis
 */
export function generateEnhancedExplanation(
  annotatedCount: number,
  missingCount: number,
  highConfidenceMisalignments: number,
  totalTools: number,
): string {
  const parts: string[] = [];

  if (totalTools === 0) {
    return "No tools found to assess for annotations.";
  }

  parts.push(
    `Tool annotation coverage: ${annotatedCount}/${totalTools} tools have annotations.`,
  );

  if (missingCount > 0) {
    parts.push(
      `${missingCount} tool(s) are missing required annotations (readOnlyHint, destructiveHint).`,
    );
  }

  if (highConfidenceMisalignments > 0) {
    parts.push(
      `Claude analysis identified ${highConfidenceMisalignments} high-confidence annotation misalignment(s).`,
    );
  }

  parts.push("Analysis enhanced with Claude semantic behavior inference.");

  return parts.join(" ");
}

/**
 * Generate recommendations for annotation issues
 */
export function generateRecommendations(
  results: ToolAnnotationResult[],
): string[] {
  const recommendations: string[] = [];
  const allRecs = new Set<string>();

  for (const result of results) {
    for (const rec of result.recommendations) {
      allRecs.add(rec);
    }
  }

  const destructiveRecs = Array.from(allRecs).filter((r) =>
    r.includes("destructive"),
  );
  const otherRecs = Array.from(allRecs).filter(
    (r) => !r.includes("destructive"),
  );

  if (destructiveRecs.length > 0) {
    recommendations.push(
      "PRIORITY: The following tools appear to perform destructive operations but lack proper destructiveHint annotation:",
    );
    recommendations.push(...destructiveRecs.slice(0, 5));
  }

  if (otherRecs.length > 0) {
    recommendations.push(...otherRecs.slice(0, 5));
  }

  if (recommendations.length === 0) {
    recommendations.push(
      "All tools have proper annotations. No action required.",
    );
  } else {
    recommendations.push(
      "Reference: MCP Directory Policy #17 requires tools to have readOnlyHint and destructiveHint annotations.",
    );
  }

  return recommendations;
}

/**
 * Generate enhanced recommendations with Claude analysis
 */
export function generateEnhancedRecommendations(
  results: EnhancedToolAnnotationResult[],
): string[] {
  const recommendations: string[] = [];

  const claudeMisalignments = results.filter(
    (r) =>
      r.claudeInference &&
      r.claudeInference.source === "claude-inferred" &&
      r.claudeInference.confidence >= 70 &&
      r.claudeInference.misalignmentDetected,
  );

  if (claudeMisalignments.length > 0) {
    recommendations.push(
      "HIGH CONFIDENCE: Claude analysis identified the following annotation issues:",
    );
    for (const result of claudeMisalignments.slice(0, 5)) {
      if (result.claudeInference) {
        recommendations.push(
          `  - ${result.toolName}: ${result.claudeInference.reasoning}`,
        );
      }
    }
  }

  const claudeSuggestions = results
    .filter(
      (r) =>
        r.claudeInference &&
        r.claudeInference.source === "claude-inferred" &&
        r.claudeInference.confidence >= 60,
    )
    .flatMap((r) => r.recommendations.filter((rec) => rec.includes("Claude")));

  if (claudeSuggestions.length > 0) {
    recommendations.push(...claudeSuggestions.slice(0, 5));
  }

  const patternRecs = new Set<string>();
  for (const result of results) {
    for (const rec of result.recommendations) {
      if (!rec.includes("Claude")) {
        patternRecs.add(rec);
      }
    }
  }

  const destructiveRecs = Array.from(patternRecs).filter((r) =>
    r.includes("destructive"),
  );
  const otherRecs = Array.from(patternRecs).filter(
    (r) => !r.includes("destructive"),
  );

  if (destructiveRecs.length > 0) {
    recommendations.push(
      "PRIORITY: Potential destructive tools without proper hints:",
    );
    recommendations.push(...destructiveRecs.slice(0, 3));
  }

  if (otherRecs.length > 0 && recommendations.length < 10) {
    recommendations.push(...otherRecs.slice(0, 3));
  }

  if (recommendations.length === 0) {
    recommendations.push(
      "All tools have proper annotations. No action required.",
    );
  } else {
    recommendations.push(
      "Reference: MCP Directory Policy #17 requires tools to have readOnlyHint and destructiveHint annotations.",
    );
  }

  return recommendations;
}
