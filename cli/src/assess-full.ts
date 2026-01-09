#!/usr/bin/env node

/**
 * Full Assessment Runner CLI
 *
 * Runs comprehensive MCP server assessment using AssessmentOrchestrator
 * with all 17 assessor modules and optional Claude Code integration.
 *
 * Usage:
 *   mcp-assess-full --server <server-name> [--claude-enabled] [--full]
 *   mcp-assess-full my-server --source ./my-server --output ./results.json
 */

import { ScopedListenerConfig } from "./lib/event-config.js";

// Import from extracted modules
import { parseArgs } from "./lib/cli-parser.js";
import { runFullAssessment } from "./lib/assessment-runner.js";
import { saveResults, displaySummary } from "./lib/result-output.js";
import {
  handleComparison,
  displayComparisonSummary,
} from "./lib/comparison-handler.js";

// ============================================================================
// Main Entry Point
// ============================================================================

/**
 * Main execution
 */
async function main() {
  // Use scoped listener configuration instead of global modification
  // See GitHub Issue #33 for rationale
  const listenerConfig = new ScopedListenerConfig(50);

  try {
    const options = parseArgs();

    if (options.helpRequested) {
      return;
    }

    // Apply scoped listener configuration for assessment
    listenerConfig.apply();

    const results = await runFullAssessment(options);

    // Pre-flight mode handles its own output and exit
    if (options.preflightOnly) {
      return;
    }

    // Handle comparison mode
    const comparison = handleComparison(results, options);

    // If comparison was requested but returned null, baseline file was not found
    if (options.comparePath && !comparison) {
      setTimeout(() => process.exit(1), 10);
      return;
    }

    if (comparison?.diffOutputPath) {
      // Diff-only mode: output path and exit
      console.log(comparison.diffOutputPath);
      setTimeout(() => process.exit(comparison.exitCode), 10);
      return;
    }

    // Display comparison summary if in comparison mode (not diff-only)
    if (comparison && !options.jsonOnly) {
      displayComparisonSummary(comparison.diff);
    }

    // Display results summary
    if (!options.jsonOnly) {
      displaySummary(results);
    }

    // Save results to file
    const outputPath = saveResults(options.serverName, results, options);

    if (options.jsonOnly) {
      console.log(outputPath);
    } else {
      console.log(`📄 Results saved to: ${outputPath}\n`);
    }

    // Exit with appropriate code
    const exitCode = results.overallStatus === "FAIL" ? 1 : 0;
    setTimeout(() => process.exit(exitCode), 10);
  } catch (error) {
    console.error(
      "\n❌ Error:",
      error instanceof Error ? error.message : String(error),
    );
    if (error instanceof Error && error.stack && process.env.DEBUG) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    setTimeout(() => process.exit(1), 10);
  } finally {
    // Restore original listener configuration
    listenerConfig.restore();
  }
}

main();
