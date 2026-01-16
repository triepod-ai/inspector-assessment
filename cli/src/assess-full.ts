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
import { runFullAssessment, runSingleModule } from "./lib/assessment-runner.js";
import {
  saveResults,
  saveTieredResults,
  saveSummaryOnly,
  displaySummary,
  saveSingleModuleResults,
  displaySingleModuleSummary,
} from "./lib/result-output.js";
import {
  handleComparison,
  displayComparisonSummary,
} from "./lib/comparison-handler.js";
import {
  shouldAutoTier,
  formatTokenEstimate,
} from "../../client/lib/lib/assessment/summarizer/index.js";

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

    if (
      options.helpRequested ||
      options.versionRequested ||
      options.listModules
    ) {
      return;
    }

    // Apply scoped listener configuration for assessment
    listenerConfig.apply();

    // Single module mode - bypass orchestrator for lightweight execution (Issue #184)
    if (options.singleModule) {
      const result = await runSingleModule(options.singleModule, options);

      if (!options.jsonOnly) {
        displaySingleModuleSummary(result);
      }

      const outputPath = saveSingleModuleResults(
        options.serverName,
        options.singleModule,
        result,
        options,
      );

      if (options.jsonOnly) {
        console.log(outputPath);
      } else {
        console.log(`\n📄 Results saved to: ${outputPath}\n`);
      }

      const exitCode = result.status === "FAIL" ? 1 : 0;
      setTimeout(() => process.exit(exitCode), 10);
      return;
    }

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

    // Determine output format (Issue #136: Tiered output strategy)
    let effectiveFormat = options.outputFormat || "full";

    // Auto-tier if requested and results exceed threshold
    if (
      effectiveFormat === "full" &&
      options.autoTier &&
      shouldAutoTier(results)
    ) {
      effectiveFormat = "tiered";
      if (!options.jsonOnly) {
        const estimate = formatTokenEstimate(
          Math.ceil(JSON.stringify(results).length / 4),
        );
        console.log(
          `\n📊 Auto-tiering enabled: ${estimate.tokens} tokens (${estimate.recommendation})`,
        );
      }
    }

    // Save results in appropriate format
    let outputPath: string;

    if (effectiveFormat === "tiered") {
      const tieredOutput = saveTieredResults(
        options.serverName,
        results,
        options,
      );
      outputPath = tieredOutput.outputDir;

      if (options.jsonOnly) {
        console.log(outputPath);
      } else {
        console.log(`\n📁 Tiered output saved to: ${outputPath}/`);
        console.log(`   📋 Executive Summary: executive-summary.json`);
        console.log(`   📋 Tool Summaries: tool-summaries.json`);
        console.log(
          `   📋 Tool Details: tools/ (${tieredOutput.toolDetailRefs.length} files)`,
        );
        console.log(
          `   📊 Total tokens: ~${tieredOutput.executiveSummary.estimatedTokens + tieredOutput.toolSummaries.estimatedTokens} (summaries only)\n`,
        );
      }
    } else if (effectiveFormat === "summary-only") {
      outputPath = saveSummaryOnly(options.serverName, results, options);

      if (options.jsonOnly) {
        console.log(outputPath);
      } else {
        console.log(`\n📁 Summary output saved to: ${outputPath}/`);
        console.log(`   📋 Executive Summary: executive-summary.json`);
        console.log(`   📋 Tool Summaries: tool-summaries.json\n`);
      }
    } else {
      // Default: full output
      outputPath = saveResults(options.serverName, results, options);

      if (options.jsonOnly) {
        console.log(outputPath);
      } else {
        console.log(`📄 Results saved to: ${outputPath}\n`);
      }
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
