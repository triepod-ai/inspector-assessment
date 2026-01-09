/**
 * Comparison Handler Module
 *
 * Handles assessment comparison/diff logic for comparing
 * current results against a baseline.
 *
 * @module cli/lib/comparison-handler
 */

import * as fs from "fs";

import type { MCPDirectoryAssessment } from "../../../client/lib/lib/assessmentTypes.js";
import {
  compareAssessments,
  type AssessmentDiff,
} from "../../../client/lib/lib/assessmentDiffer.js";
import { formatDiffAsMarkdown } from "../../../client/lib/lib/reportFormatters/DiffReportFormatter.js";

import type { AssessmentOptions } from "./cli-parser.js";

// ============================================================================
// Types
// ============================================================================

/**
 * Result from comparison handling
 */
export interface ComparisonResult {
  /** The assessment diff */
  diff: AssessmentDiff;
  /** Exit code based on comparison result */
  exitCode: number;
  /** If diff-only mode, the path to the output file */
  diffOutputPath?: string;
}

// ============================================================================
// Comparison Functions
// ============================================================================

/**
 * Handle comparison mode - compare current results against a baseline.
 *
 * @param results - Current assessment results
 * @param options - CLI options including comparePath and diffOnly
 * @returns ComparisonResult if comparison was performed, null if no comparison
 */
export function handleComparison(
  results: MCPDirectoryAssessment,
  options: AssessmentOptions,
): ComparisonResult | null {
  if (!options.comparePath) {
    return null;
  }

  if (!fs.existsSync(options.comparePath)) {
    console.error(`Error: Baseline file not found: ${options.comparePath}`);
    // Return null to indicate comparison failed - caller handles null returns
    return null;
  }

  const baselineData = JSON.parse(
    fs.readFileSync(options.comparePath, "utf-8"),
  );

  // Validate baseline has expected structure
  if (!baselineData.functionality || !baselineData.security) {
    console.warn(
      "Warning: Baseline file may be incomplete (missing functionality or security)",
    );
  }

  const baseline: MCPDirectoryAssessment = baselineData;

  const diff = compareAssessments(baseline, results);

  // Handle diff-only mode
  if (options.diffOnly) {
    let diffPath: string;

    if (options.format === "markdown") {
      diffPath =
        options.outputPath || `/tmp/inspector-diff-${options.serverName}.md`;
      fs.writeFileSync(diffPath, formatDiffAsMarkdown(diff));
    } else {
      diffPath =
        options.outputPath || `/tmp/inspector-diff-${options.serverName}.json`;
      fs.writeFileSync(diffPath, JSON.stringify(diff, null, 2));
    }

    const exitCode = diff.summary.overallChange === "regressed" ? 1 : 0;
    return { diff, exitCode, diffOutputPath: diffPath };
  }

  // Return comparison result for normal mode
  const exitCode = diff.summary.overallChange === "regressed" ? 1 : 0;
  return { diff, exitCode };
}

/**
 * Display comparison summary to console.
 *
 * @param diff - Assessment diff to display
 */
export function displayComparisonSummary(diff: AssessmentDiff): void {
  console.log("\n" + "=".repeat(70));
  console.log("VERSION COMPARISON");
  console.log("=".repeat(70));
  console.log(
    `Baseline: ${diff.baseline.version || "N/A"} (${diff.baseline.date})`,
  );
  console.log(
    `Current:  ${diff.current.version || "N/A"} (${diff.current.date})`,
  );
  console.log(`Overall Change: ${diff.summary.overallChange.toUpperCase()}`);
  console.log(`Modules Improved: ${diff.summary.modulesImproved}`);
  console.log(`Modules Regressed: ${diff.summary.modulesRegressed}`);

  if (diff.securityDelta.newVulnerabilities.length > 0) {
    console.log(
      `\n⚠️  NEW VULNERABILITIES: ${diff.securityDelta.newVulnerabilities.length}`,
    );
  }
  if (diff.securityDelta.fixedVulnerabilities.length > 0) {
    console.log(
      `✅ FIXED VULNERABILITIES: ${diff.securityDelta.fixedVulnerabilities.length}`,
    );
  }
  if (diff.functionalityDelta.newBrokenTools.length > 0) {
    console.log(
      `❌ NEW BROKEN TOOLS: ${diff.functionalityDelta.newBrokenTools.length}`,
    );
  }
  if (diff.functionalityDelta.fixedTools.length > 0) {
    console.log(`✅ FIXED TOOLS: ${diff.functionalityDelta.fixedTools.length}`);
  }
}
