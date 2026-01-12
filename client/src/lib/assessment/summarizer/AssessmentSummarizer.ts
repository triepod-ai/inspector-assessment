/**
 * Assessment Summarizer
 *
 * Generates tiered output for large assessment results to fit within
 * LLM context windows. Creates executive summaries and per-tool digests.
 *
 * Issue #136: Tiered output strategy for large assessments
 *
 * @module assessment/summarizer/AssessmentSummarizer
 */

import type {
  MCPDirectoryAssessment,
  SecurityTestResult,
} from "../resultTypes";
import type { AssessmentStatus } from "../coreTypes";
import { calculateModuleScore } from "../../moduleScoring";
import { estimateTokens } from "./tokenEstimator";
import {
  type ExecutiveSummary,
  type ToolSummary,
  type ToolSummariesCollection,
  type ToolRiskLevel,
  type SummarizerConfig,
  DEFAULT_SUMMARIZER_CONFIG,
} from "./types";
import {
  buildToolSummaryStageBEnrichment,
  buildToolDetailStageBEnrichment,
} from "./stageBEnrichmentBuilder";

// ============================================================================
// Assessment Summarizer Class
// ============================================================================

/**
 * Generates tiered summaries from assessment results.
 *
 * @example
 * ```typescript
 * const summarizer = new AssessmentSummarizer();
 * const executive = summarizer.generateExecutiveSummary(results);
 * const toolSummaries = summarizer.generateToolSummaries(results);
 * ```
 */
export class AssessmentSummarizer {
  private config: Required<SummarizerConfig>;

  constructor(config: SummarizerConfig = {}) {
    this.config = { ...DEFAULT_SUMMARIZER_CONFIG, ...config };
  }

  // ==========================================================================
  // Tier 1: Executive Summary
  // ==========================================================================

  /**
   * Generate executive summary (Tier 1) from assessment results.
   * Targets ~5K tokens for guaranteed LLM context fit.
   *
   * @param results - Full assessment results
   * @returns Executive summary
   */
  generateExecutiveSummary(results: MCPDirectoryAssessment): ExecutiveSummary {
    const modulesSummary = this.extractModulesSummary(results);
    const criticalFindings = this.extractCriticalFindings(results);
    const toolRiskDistribution = this.calculateToolRiskDistribution(results);
    const recommendations = this.aggregateRecommendations(results);

    const summary: ExecutiveSummary = {
      serverName: results.serverName,
      overallStatus: results.overallStatus,
      overallScore: this.calculateOverallScore(results),
      toolCount: results.functionality?.totalTools ?? 0,
      testCount: results.totalTestsRun ?? 0,
      executionTime: results.executionTime ?? 0,
      modulesSummary,
      criticalFindings,
      toolRiskDistribution,
      recommendations: recommendations.slice(0, this.config.maxRecommendations),
      estimatedTokens: 0, // Will be calculated after construction
      generatedAt: new Date().toISOString(),
    };

    // Calculate actual token estimate
    summary.estimatedTokens = estimateTokens(summary);

    return summary;
  }

  /**
   * Extract per-module status and scores.
   */
  private extractModulesSummary(
    results: MCPDirectoryAssessment,
  ): Record<string, { status: AssessmentStatus; score: number }> {
    const summary: Record<string, { status: AssessmentStatus; score: number }> =
      {};

    const moduleKeys = [
      "functionality",
      "security",
      "errorHandling",
      "aupCompliance",
      "toolAnnotations",
      "temporal",
      "resources",
      "prompts",
      "crossCapability",
      "protocolCompliance",
      "developerExperience",
      "prohibitedLibraries",
      "manifestValidation",
      "authentication",
      "portability",
      "externalAPIScanner",
      // Legacy keys for backwards compatibility
      "mcpSpecCompliance",
      "documentation",
      "usability",
    ] as const;

    for (const key of moduleKeys) {
      const module = results[key as keyof MCPDirectoryAssessment] as
        | { status?: AssessmentStatus }
        | undefined;

      if (module && module.status) {
        const score = calculateModuleScore(module) ?? 50;
        summary[key] = {
          status: module.status,
          score,
        };
      }
    }

    return summary;
  }

  /**
   * Extract critical findings counts from all modules.
   */
  private extractCriticalFindings(results: MCPDirectoryAssessment): {
    securityVulnerabilities: number;
    aupViolations: number;
    brokenTools: number;
    missingAnnotations: number;
  } {
    return {
      securityVulnerabilities: results.security?.vulnerabilities?.length ?? 0,
      aupViolations: results.aupCompliance?.violations?.length ?? 0,
      brokenTools: results.functionality?.brokenTools?.length ?? 0,
      missingAnnotations: results.toolAnnotations?.missingAnnotationsCount ?? 0,
    };
  }

  /**
   * Calculate tool risk distribution from security test results.
   */
  private calculateToolRiskDistribution(results: MCPDirectoryAssessment): {
    high: number;
    medium: number;
    low: number;
    safe: number;
  } {
    const distribution = { high: 0, medium: 0, low: 0, safe: 0 };

    const tests = results.security?.promptInjectionTests ?? [];
    const toolVulnCounts = new Map<string, number>();

    // Count vulnerabilities per tool
    for (const test of tests) {
      if (test.vulnerable && test.toolName) {
        const current = toolVulnCounts.get(test.toolName) ?? 0;
        toolVulnCounts.set(test.toolName, current + 1);
      }
    }

    // Get all tool names
    const allTools = new Set<string>();
    for (const test of tests) {
      if (test.toolName) {
        allTools.add(test.toolName);
      }
    }

    // Categorize each tool
    for (const toolName of allTools) {
      const vulnCount = toolVulnCounts.get(toolName) ?? 0;
      const riskLevel = this.calculateToolRiskLevel(vulnCount);

      switch (riskLevel) {
        case "HIGH":
          distribution.high++;
          break;
        case "MEDIUM":
          distribution.medium++;
          break;
        case "LOW":
          distribution.low++;
          break;
        case "SAFE":
          distribution.safe++;
          break;
      }
    }

    return distribution;
  }

  /**
   * Calculate risk level based on vulnerability count.
   */
  private calculateToolRiskLevel(vulnCount: number): ToolRiskLevel {
    if (vulnCount >= 5) return "HIGH";
    if (vulnCount >= 2) return "MEDIUM";
    if (vulnCount >= 1) return "LOW";
    return "SAFE";
  }

  /**
   * Aggregate recommendations from all modules.
   */
  private aggregateRecommendations(results: MCPDirectoryAssessment): string[] {
    const recommendations: string[] = [];

    // Top-level recommendations
    if (results.recommendations) {
      recommendations.push(...results.recommendations);
    }

    // Module-specific recommendations
    const modulesWithRecs = [
      results.errorHandling,
      results.aupCompliance,
      results.toolAnnotations,
      results.developerExperience,
      results.documentation,
      results.usability,
      results.prohibitedLibraries,
      results.portability,
    ] as Array<{ recommendations?: string[] } | undefined>;

    for (const module of modulesWithRecs) {
      if (module?.recommendations) {
        recommendations.push(...module.recommendations);
      }
    }

    // Deduplicate
    return [...new Set(recommendations)];
  }

  /**
   * Calculate overall score from module scores.
   */
  private calculateOverallScore(results: MCPDirectoryAssessment): number {
    const scores: number[] = [];

    const coreModules = [
      results.functionality,
      results.security,
      results.errorHandling,
    ];

    for (const module of coreModules) {
      const score = calculateModuleScore(module);
      if (score !== null) {
        scores.push(score);
      }
    }

    if (scores.length === 0) {
      return results.overallStatus === "PASS" ? 100 : 0;
    }

    return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  }

  // ==========================================================================
  // Tier 2: Tool Summaries
  // ==========================================================================

  /**
   * Generate tool summaries (Tier 2) from assessment results.
   * Targets ~500 tokens per tool for efficient LLM processing.
   *
   * @param results - Full assessment results
   * @returns Collection of tool summaries
   */
  generateToolSummaries(
    results: MCPDirectoryAssessment,
  ): ToolSummariesCollection {
    const tools: ToolSummary[] = [];

    // Get all unique tool names from security tests
    const toolNames = this.extractToolNames(results);

    for (const toolName of toolNames) {
      const summary = this.generateSingleToolSummary(toolName, results);
      tools.push(summary);
    }

    // Sort by risk level (highest first)
    tools.sort((a, b) => {
      const riskOrder: Record<ToolRiskLevel, number> = {
        HIGH: 0,
        MEDIUM: 1,
        LOW: 2,
        SAFE: 3,
      };
      return riskOrder[a.riskLevel] - riskOrder[b.riskLevel];
    });

    const aggregate = this.calculateAggregate(tools);
    const collection: ToolSummariesCollection = {
      tools,
      totalTools: tools.length,
      aggregate,
      estimatedTokens: 0,
      generatedAt: new Date().toISOString(),
    };

    collection.estimatedTokens = estimateTokens(collection);

    return collection;
  }

  /**
   * Extract all unique tool names from assessment results.
   */
  private extractToolNames(results: MCPDirectoryAssessment): string[] {
    const toolNames = new Set<string>();

    // From security tests
    const tests = results.security?.promptInjectionTests ?? [];
    for (const test of tests) {
      if (test.toolName) {
        toolNames.add(test.toolName);
      }
    }

    // From functionality results
    const funcResults = results.functionality?.toolResults ?? [];
    for (const result of funcResults) {
      if (result.toolName) {
        toolNames.add(result.toolName);
      }
    }

    // From annotation results
    const annotationResults = results.toolAnnotations?.toolResults ?? [];
    for (const result of annotationResults) {
      if (result.toolName) {
        toolNames.add(result.toolName);
      }
    }

    return [...toolNames].sort();
  }

  /**
   * Generate summary for a single tool.
   */
  private generateSingleToolSummary(
    toolName: string,
    results: MCPDirectoryAssessment,
  ): ToolSummary {
    const tests = this.getToolTests(toolName, results);
    const vulnCount = tests.filter((t) => t.vulnerable).length;
    const patterns = this.extractTopPatterns(tests);
    const passRate = this.calculatePassRate(tests);
    const annotationInfo = this.getToolAnnotationInfo(toolName, results);

    const summary: ToolSummary = {
      toolName,
      riskLevel: this.calculateToolRiskLevel(vulnCount),
      vulnerabilityCount: vulnCount,
      topPatterns: patterns.slice(0, this.config.maxPatternsPerTool),
      testCount: tests.length,
      passRate,
      recommendations: this.generateToolRecommendations(
        toolName,
        vulnCount,
        annotationInfo,
      ),
      estimatedTokens: 0,
      hasAnnotations: annotationInfo.hasAnnotations,
      annotationStatus: annotationInfo.status,
    };

    // Issue #137: Add Stage B enrichment if enabled
    if (this.config.stageBVerbose) {
      const allTests = results.security?.promptInjectionTests ?? [];
      summary.stageBEnrichment = buildToolSummaryStageBEnrichment(
        toolName,
        allTests,
        3, // Max samples for Tier 2
      );
    }

    summary.estimatedTokens = estimateTokens(summary);

    return summary;
  }

  /**
   * Get all security tests for a specific tool.
   */
  private getToolTests(
    toolName: string,
    results: MCPDirectoryAssessment,
  ): SecurityTestResult[] {
    const tests = results.security?.promptInjectionTests ?? [];
    return tests.filter((t) => t.toolName === toolName);
  }

  /**
   * Extract top vulnerability patterns from tests.
   */
  private extractTopPatterns(tests: SecurityTestResult[]): string[] {
    const patternCounts = new Map<string, number>();

    for (const test of tests) {
      if (test.vulnerable && test.testName) {
        const current = patternCounts.get(test.testName) ?? 0;
        patternCounts.set(test.testName, current + 1);
      }
    }

    // Sort by count and return names
    return [...patternCounts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([name]) => name);
  }

  /**
   * Calculate pass rate for tests.
   */
  private calculatePassRate(tests: SecurityTestResult[]): number {
    if (tests.length === 0) return 100;
    const passed = tests.filter((t) => !t.vulnerable).length;
    return Math.round((passed / tests.length) * 100);
  }

  /**
   * Get annotation info for a tool.
   */
  private getToolAnnotationInfo(
    toolName: string,
    results: MCPDirectoryAssessment,
  ): {
    hasAnnotations: boolean;
    status?: "ALIGNED" | "MISALIGNED" | "MISSING";
  } {
    const annotationResults = results.toolAnnotations?.toolResults ?? [];
    const toolResult = annotationResults.find((r) => r.toolName === toolName);

    if (!toolResult) {
      return { hasAnnotations: false, status: "MISSING" };
    }

    const hasAnnotations =
      toolResult.annotations?.readOnlyHint !== undefined ||
      toolResult.annotations?.destructiveHint !== undefined;

    let status: "ALIGNED" | "MISALIGNED" | "MISSING" | undefined;
    if (!hasAnnotations) {
      status = "MISSING";
    } else if (toolResult.alignmentStatus === "ALIGNED") {
      status = "ALIGNED";
    } else if (toolResult.alignmentStatus === "MISALIGNED") {
      status = "MISALIGNED";
    }

    return { hasAnnotations, status };
  }

  /**
   * Generate recommendations for a specific tool.
   */
  private generateToolRecommendations(
    toolName: string,
    vulnCount: number,
    annotationInfo: { hasAnnotations: boolean; status?: string },
  ): string[] {
    const recommendations: string[] = [];

    if (vulnCount >= 5) {
      recommendations.push(
        `Critical: ${toolName} has ${vulnCount} vulnerabilities - requires immediate security review`,
      );
    } else if (vulnCount >= 2) {
      recommendations.push(
        `${toolName} has ${vulnCount} vulnerabilities - review input validation`,
      );
    } else if (vulnCount >= 1) {
      recommendations.push(
        `${toolName} has a vulnerability - investigate and patch`,
      );
    }

    if (!annotationInfo.hasAnnotations) {
      recommendations.push(
        `Add readOnlyHint/destructiveHint annotations to ${toolName}`,
      );
    } else if (annotationInfo.status === "MISALIGNED") {
      recommendations.push(`Review annotation alignment for ${toolName}`);
    }

    return recommendations;
  }

  /**
   * Calculate aggregate statistics across all tool summaries.
   */
  private calculateAggregate(tools: ToolSummary[]): {
    totalVulnerabilities: number;
    averagePassRate: number;
    misalignedAnnotations: number;
  } {
    const totalVulns = tools.reduce((sum, t) => sum + t.vulnerabilityCount, 0);
    const avgPassRate =
      tools.length > 0
        ? Math.round(
            tools.reduce((sum, t) => sum + t.passRate, 0) / tools.length,
          )
        : 100;
    const misaligned = tools.filter(
      (t) => t.annotationStatus === "MISALIGNED",
    ).length;

    return {
      totalVulnerabilities: totalVulns,
      averagePassRate: avgPassRate,
      misalignedAnnotations: misaligned,
    };
  }

  // ==========================================================================
  // Tier 3: Per-Tool Details (extraction helpers)
  // ==========================================================================

  /**
   * Extract full detail data for a specific tool.
   * Used when generating Tier 3 per-tool detail files.
   *
   * @param toolName - Tool name to extract
   * @param results - Full assessment results
   * @returns Tool-specific detail data
   */
  extractToolDetail(
    toolName: string,
    results: MCPDirectoryAssessment,
  ): Record<string, unknown> {
    const securityTests = this.getToolTests(toolName, results);
    const functionalityResult = results.functionality?.toolResults?.find(
      (r) => r.toolName === toolName,
    );
    const annotationResult = results.toolAnnotations?.toolResults?.find(
      (r) => r.toolName === toolName,
    );

    const detail: Record<string, unknown> = {
      toolName,
      extractedAt: new Date().toISOString(),
      security: {
        tests: securityTests,
        vulnerableCount: securityTests.filter((t) => t.vulnerable).length,
        totalTests: securityTests.length,
      },
      functionality: functionalityResult ?? null,
      annotations: annotationResult ?? null,
      estimatedTokens: estimateTokens({
        security: { tests: securityTests },
        functionality: functionalityResult,
        annotations: annotationResult,
      }),
    };

    // Issue #137: Add Stage B enrichment for Tier 3 if enabled
    if (this.config.stageBVerbose) {
      const allTests = results.security?.promptInjectionTests ?? [];
      const aupViolations = results.aupCompliance?.violations;
      detail.stageBEnrichment = buildToolDetailStageBEnrichment(
        toolName,
        allTests,
        annotationResult,
        aupViolations,
        50, // Max correlations for Tier 3
      );
    }

    return detail;
  }

  /**
   * Get all tool names for Tier 3 file generation.
   */
  getAllToolNames(results: MCPDirectoryAssessment): string[] {
    return this.extractToolNames(results);
  }
}
