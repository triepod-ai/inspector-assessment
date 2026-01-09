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

import * as fs from "fs";

import {
  MCPDirectoryAssessment,
  ASSESSMENT_CATEGORY_METADATA,
} from "../../client/lib/lib/assessmentTypes.js";
import { createFormatter } from "../../client/lib/lib/reportFormatters/index.js";
import { generatePolicyComplianceReport } from "../../client/lib/services/assessment/PolicyComplianceGenerator.js";
import { compareAssessments } from "../../client/lib/lib/assessmentDiffer.js";
import { formatDiffAsMarkdown } from "../../client/lib/lib/reportFormatters/DiffReportFormatter.js";
import { ScopedListenerConfig } from "./lib/event-config.js";

// Import from extracted modules
import { parseArgs, type AssessmentOptions } from "./lib/cli-parser.js";
import { runFullAssessment } from "./lib/assessment-runner.js";

// ============================================================================
// Result Output
// ============================================================================

/**
 * Save results to file with appropriate format
 */
function saveResults(
  serverName: string,
  results: MCPDirectoryAssessment,
  options: AssessmentOptions,
): string {
  const format = options.format || "json";

  // Generate policy compliance report if requested
  const policyReport = options.includePolicy
    ? generatePolicyComplianceReport(results, serverName)
    : undefined;

  // Create formatter with options
  const formatter = createFormatter({
    format,
    includePolicyMapping: options.includePolicy,
    policyReport,
    serverName,
    includeDetails: true,
    prettyPrint: true,
  });

  const fileExtension = formatter.getFileExtension();
  const defaultPath = `/tmp/inspector-full-assessment-${serverName}${fileExtension}`;
  const finalPath = options.outputPath || defaultPath;

  // For JSON format, add metadata wrapper
  if (format === "json") {
    // Filter out undefined/skipped modules from results (--skip-modules support)
    const filteredResults = Object.fromEntries(
      Object.entries(results).filter(([_, v]) => v !== undefined),
    );

    const output = {
      timestamp: new Date().toISOString(),
      assessmentType: "full",
      ...filteredResults,
      ...(policyReport ? { policyCompliance: policyReport } : {}),
    };
    fs.writeFileSync(finalPath, JSON.stringify(output, null, 2));
  } else {
    // For other formats (markdown), use the formatter
    const content = formatter.format(results);
    fs.writeFileSync(finalPath, content);
  }

  return finalPath;
}

// ============================================================================
// Summary Display
// ============================================================================

/**
 * Display summary to console
 */
function displaySummary(results: MCPDirectoryAssessment) {
  const {
    overallStatus,
    summary,
    totalTestsRun,
    executionTime,
    // Destructuring order matches display order below
    functionality,
    security,
    documentation,
    errorHandling,
    usability,
    mcpSpecCompliance,
    aupCompliance,
    toolAnnotations,
    prohibitedLibraries,
    manifestValidation,
    portability,
    externalAPIScanner,
    authentication,
    temporal,
    resources,
    prompts,
    crossCapability,
  } = results;

  console.log("\n" + "=".repeat(70));
  console.log("FULL ASSESSMENT RESULTS");
  console.log("=".repeat(70));
  console.log(`Server: ${results.serverName}`);
  console.log(`Overall Status: ${overallStatus}`);
  console.log(`Total Tests Run: ${totalTestsRun}`);
  console.log(`Execution Time: ${executionTime}ms`);
  console.log("-".repeat(70));

  console.log("\n📊 MODULE STATUS:");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const modules: [string, any, string][] = [
    ["Functionality", functionality, "functionality"],
    ["Security", security, "security"],
    ["Documentation", documentation, "documentation"],
    ["Error Handling", errorHandling, "errorHandling"],
    ["Usability", usability, "usability"],
    ["MCP Spec Compliance", mcpSpecCompliance, "mcpSpecCompliance"],
    ["AUP Compliance", aupCompliance, "aupCompliance"],
    ["Tool Annotations", toolAnnotations, "toolAnnotations"],
    ["Prohibited Libraries", prohibitedLibraries, "prohibitedLibraries"],
    ["Manifest Validation", manifestValidation, "manifestValidation"],
    ["Portability", portability, "portability"],
    ["External API Scanner", externalAPIScanner, "externalAPIScanner"],
    ["Authentication", authentication, "authentication"],
    ["Temporal", temporal, "temporal"],
    ["Resources", resources, "resources"],
    ["Prompts", prompts, "prompts"],
    ["Cross-Capability", crossCapability, "crossCapability"],
  ];

  for (const [name, module, categoryKey] of modules) {
    if (module) {
      const metadata = ASSESSMENT_CATEGORY_METADATA[categoryKey];
      const optionalMarker = metadata?.tier === "optional" ? " (optional)" : "";
      const icon =
        module.status === "PASS"
          ? "✅"
          : module.status === "FAIL"
            ? "❌"
            : "⚠️";
      console.log(`   ${icon} ${name}${optionalMarker}: ${module.status}`);
    }
  }

  console.log("\n📋 KEY FINDINGS:");
  console.log(`   ${summary}`);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const securityModule = security as any;
  if (securityModule?.vulnerabilities?.length > 0) {
    const vulns = securityModule.vulnerabilities;
    console.log(`\n🔒 SECURITY VULNERABILITIES (${vulns.length}):`);
    for (const vuln of vulns.slice(0, 5)) {
      console.log(`   • ${vuln}`);
    }
    if (vulns.length > 5) {
      console.log(`   ... and ${vulns.length - 5} more`);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const aupModule = aupCompliance as any;
  if (aupModule?.violations?.length > 0) {
    const violations = aupModule.violations;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const critical = violations.filter((v: any) => v.severity === "CRITICAL");
    console.log(`\n⚖️  AUP FINDINGS:`);
    console.log(`   Total flagged: ${violations.length}`);
    if (critical.length > 0) {
      console.log(`   🚨 CRITICAL violations: ${critical.length}`);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const annotationsModule = toolAnnotations as any;
  if (annotationsModule) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const funcModule = functionality as any;
    console.log(`\n🏷️  TOOL ANNOTATIONS:`);
    console.log(
      `   Annotated: ${annotationsModule.annotatedCount || 0}/${funcModule?.workingTools || 0}`,
    );
    if (annotationsModule.missingAnnotationsCount > 0) {
      console.log(`   Missing: ${annotationsModule.missingAnnotationsCount}`);
    }
    if (annotationsModule.misalignedAnnotationsCount > 0) {
      console.log(
        `   ⚠️  Misalignments: ${annotationsModule.misalignedAnnotationsCount}`,
      );
    }
  }

  if (results.recommendations?.length > 0) {
    console.log("\n💡 RECOMMENDATIONS:");
    for (const rec of results.recommendations.slice(0, 5)) {
      console.log(`   • ${rec}`);
    }
  }

  console.log("\n" + "=".repeat(70));
}

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
    if (options.comparePath) {
      if (!fs.existsSync(options.comparePath)) {
        console.error(`Error: Baseline file not found: ${options.comparePath}`);
        setTimeout(() => process.exit(1), 10);
        return;
      }

      const baselineData = JSON.parse(
        fs.readFileSync(options.comparePath, "utf-8"),
      );
      const baseline: MCPDirectoryAssessment =
        baselineData.functionality && baselineData.security
          ? baselineData
          : baselineData;

      const diff = compareAssessments(baseline, results);

      if (options.diffOnly) {
        // Only output diff, not full assessment
        if (options.format === "markdown") {
          const diffPath =
            options.outputPath ||
            `/tmp/inspector-diff-${options.serverName}.md`;
          fs.writeFileSync(diffPath, formatDiffAsMarkdown(diff));
          console.log(diffPath);
        } else {
          const diffPath =
            options.outputPath ||
            `/tmp/inspector-diff-${options.serverName}.json`;
          fs.writeFileSync(diffPath, JSON.stringify(diff, null, 2));
          console.log(diffPath);
        }
        const exitCode = diff.summary.overallChange === "regressed" ? 1 : 0;
        setTimeout(() => process.exit(exitCode), 10);
        return;
      }

      // Include diff in output alongside full assessment
      if (!options.jsonOnly) {
        console.log("\n" + "=".repeat(70));
        console.log("VERSION COMPARISON");
        console.log("=".repeat(70));
        console.log(
          `Baseline: ${diff.baseline.version || "N/A"} (${diff.baseline.date})`,
        );
        console.log(
          `Current:  ${diff.current.version || "N/A"} (${diff.current.date})`,
        );
        console.log(
          `Overall Change: ${diff.summary.overallChange.toUpperCase()}`,
        );
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
          console.log(
            `✅ FIXED TOOLS: ${diff.functionalityDelta.fixedTools.length}`,
          );
        }
      }
    }

    if (!options.jsonOnly) {
      displaySummary(results);
    }

    const outputPath = saveResults(options.serverName, results, options);

    if (options.jsonOnly) {
      console.log(outputPath);
    } else {
      console.log(`📄 Results saved to: ${outputPath}\n`);
    }

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
