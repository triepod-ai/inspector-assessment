/**
 * Result Output Module
 *
 * Handles saving assessment results to files and displaying
 * summaries to the console.
 *
 * @module cli/lib/result-output
 */

import * as fs from "fs";
import * as path from "path";

import {
  MCPDirectoryAssessment,
  ASSESSMENT_CATEGORY_METADATA,
} from "../../../client/lib/lib/assessmentTypes.js";
import { createFormatter } from "../../../client/lib/lib/reportFormatters/index.js";
import { generatePolicyComplianceReport } from "../../../client/lib/services/assessment/PolicyComplianceGenerator.js";
import {
  AssessmentSummarizer,
  estimateTokens,
  type TieredOutput,
  type ToolDetailReference,
} from "../../../client/lib/lib/assessment/summarizer/index.js";
import { emitTieredOutput } from "./jsonl-events.js";

import type { AssessmentOptions } from "./cli-parser.js";

// ============================================================================
// Result Output
// ============================================================================

/**
 * Save results to file with appropriate format
 */
export function saveResults(
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

/**
 * Save results in tiered format for LLM consumption.
 * Creates a directory with executive summary, tool summaries, and per-tool details.
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @param serverName - Server name for output directory
 * @param results - Full assessment results
 * @param options - Assessment options
 * @returns Path to output directory
 */
export function saveTieredResults(
  serverName: string,
  results: MCPDirectoryAssessment,
  options: AssessmentOptions,
): TieredOutput {
  // Issue #137: Pass stageBVerbose option to summarizer for Stage B enrichment
  const summarizer = new AssessmentSummarizer({
    stageBVerbose: options.stageBVerbose,
  });

  // Determine output directory
  const defaultDir = `/tmp/inspector-full-assessment-${serverName}`;
  const outputDir = options.outputPath || defaultDir;

  // Create directory structure
  fs.mkdirSync(outputDir, { recursive: true });
  fs.mkdirSync(path.join(outputDir, "tools"), { recursive: true });

  // Tier 1: Executive Summary
  const executiveSummary = summarizer.generateExecutiveSummary(results);
  const executivePath = path.join(outputDir, "executive-summary.json");
  fs.writeFileSync(executivePath, JSON.stringify(executiveSummary, null, 2));

  // Tier 2: Tool Summaries
  const toolSummaries = summarizer.generateToolSummaries(results);
  const toolSummariesPath = path.join(outputDir, "tool-summaries.json");
  fs.writeFileSync(toolSummariesPath, JSON.stringify(toolSummaries, null, 2));

  // Tier 3: Per-Tool Details
  const toolDetailRefs: ToolDetailReference[] = [];
  const toolNames = summarizer.getAllToolNames(results);

  for (const toolName of toolNames) {
    const detail = summarizer.extractToolDetail(toolName, results);
    const safeFileName = toolName.replace(/[^a-zA-Z0-9_-]/g, "_");
    const relativePath = `tools/${safeFileName}.json`;
    const absolutePath = path.join(outputDir, relativePath);

    fs.writeFileSync(absolutePath, JSON.stringify(detail, null, 2));

    const stats = fs.statSync(absolutePath);
    toolDetailRefs.push({
      toolName,
      relativePath,
      absolutePath,
      fileSizeBytes: stats.size,
      estimatedTokens: estimateTokens(detail),
    });
  }

  // Create index file with all paths
  const tieredOutput: TieredOutput = {
    executiveSummary,
    toolSummaries,
    toolDetailRefs,
    outputDir,
    paths: {
      executiveSummary: executivePath,
      toolSummaries: toolSummariesPath,
      toolDetailsDir: path.join(outputDir, "tools"),
    },
  };

  // Save index file
  const indexPath = path.join(outputDir, "index.json");
  fs.writeFileSync(
    indexPath,
    JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        serverName,
        outputFormat: "tiered",
        paths: tieredOutput.paths,
        toolCount: toolDetailRefs.length,
        totalEstimatedTokens: {
          executiveSummary: executiveSummary.estimatedTokens,
          toolSummaries: toolSummaries.estimatedTokens,
          toolDetails: toolDetailRefs.reduce(
            (sum, r) => sum + r.estimatedTokens,
            0,
          ),
        },
      },
      null,
      2,
    ),
  );

  // Emit JSONL event for tiered output (Issue #136)
  emitTieredOutput(outputDir, "tiered", {
    executiveSummary: {
      path: executivePath,
      estimatedTokens: executiveSummary.estimatedTokens,
    },
    toolSummaries: {
      path: toolSummariesPath,
      estimatedTokens: toolSummaries.estimatedTokens,
      toolCount: toolSummaries.tools.length,
    },
    toolDetails: {
      directory: path.join(outputDir, "tools"),
      fileCount: toolDetailRefs.length,
      totalEstimatedTokens: toolDetailRefs.reduce(
        (sum, r) => sum + r.estimatedTokens,
        0,
      ),
    },
  });

  return tieredOutput;
}

/**
 * Save results in summary-only format (Tier 1 + Tier 2, no per-tool details).
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @param serverName - Server name for output
 * @param results - Full assessment results
 * @param options - Assessment options
 * @returns Path to output directory
 */
export function saveSummaryOnly(
  serverName: string,
  results: MCPDirectoryAssessment,
  options: AssessmentOptions,
): string {
  // Issue #137: Pass stageBVerbose option to summarizer for Stage B enrichment
  const summarizer = new AssessmentSummarizer({
    stageBVerbose: options.stageBVerbose,
  });

  // Determine output directory
  const defaultDir = `/tmp/inspector-full-assessment-${serverName}`;
  const outputDir = options.outputPath || defaultDir;

  // Create directory
  fs.mkdirSync(outputDir, { recursive: true });

  // Tier 1: Executive Summary
  const executiveSummary = summarizer.generateExecutiveSummary(results);
  const executivePath = path.join(outputDir, "executive-summary.json");
  fs.writeFileSync(executivePath, JSON.stringify(executiveSummary, null, 2));

  // Tier 2: Tool Summaries
  const toolSummaries = summarizer.generateToolSummaries(results);
  const toolSummariesPath = path.join(outputDir, "tool-summaries.json");
  fs.writeFileSync(toolSummariesPath, JSON.stringify(toolSummaries, null, 2));

  // Create index file
  const indexPath = path.join(outputDir, "index.json");
  fs.writeFileSync(
    indexPath,
    JSON.stringify(
      {
        timestamp: new Date().toISOString(),
        serverName,
        outputFormat: "summary-only",
        paths: {
          executiveSummary: executivePath,
          toolSummaries: toolSummariesPath,
        },
        totalEstimatedTokens: {
          executiveSummary: executiveSummary.estimatedTokens,
          toolSummaries: toolSummaries.estimatedTokens,
        },
      },
      null,
      2,
    ),
  );

  // Emit JSONL event for summary-only output (Issue #136)
  emitTieredOutput(outputDir, "summary-only", {
    executiveSummary: {
      path: executivePath,
      estimatedTokens: executiveSummary.estimatedTokens,
    },
    toolSummaries: {
      path: toolSummariesPath,
      estimatedTokens: toolSummaries.estimatedTokens,
      toolCount: toolSummaries.tools.length,
    },
  });

  return outputDir;
}

// ============================================================================
// Summary Display
// ============================================================================

/**
 * Display summary to console
 */
export function displaySummary(results: MCPDirectoryAssessment): void {
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
