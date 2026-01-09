/**
 * AUP Compliance Assessor
 * Scans MCP server for Acceptable Use Policy violations
 *
 * Checks:
 * - Tool names and descriptions
 * - README content
 * - Source code (if sourceCodePath provided)
 *
 * Based on Anthropic's 14 AUP categories (A-N)
 *
 * Supports optional Claude Code integration for semantic analysis
 * to reduce false positives (e.g., security tools, disclaimers).
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  AUPComplianceAssessment,
  AUPViolation,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import {
  checkTextForAUPViolations,
  checkTextForHighRiskDomains,
} from "@/lib/aupPatterns";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";

/**
 * Extended AUP violation with semantic analysis results
 */
export interface EnhancedAUPViolation extends AUPViolation {
  semanticAnalysis?: {
    isConfirmedViolation: boolean;
    confidence: number;
    reasoning: string;
    source: "claude-verified" | "pattern-only";
  };
}

/**
 * Extended AUP compliance assessment with semantic analysis
 */
export interface EnhancedAUPComplianceAssessment extends AUPComplianceAssessment {
  confirmedViolations: EnhancedAUPViolation[];
  flaggedForReview: EnhancedAUPViolation[];
  semanticAnalysisEnabled: boolean;
  falsePositivesFiltered: number;
}

export class AUPComplianceAssessor extends BaseAssessor {
  // Optional Claude Code bridge for semantic analysis
  private claudeBridge: ClaudeCodeBridge | null = null;

  /**
   * Set the Claude Code bridge for semantic violation analysis
   */
  setClaudeBridge(bridge: ClaudeCodeBridge | null): void {
    this.claudeBridge = bridge;
  }

  /**
   * Check if Claude semantic analysis is enabled
   */
  private isSemanticAnalysisEnabled(): boolean {
    return (
      this.claudeBridge !== null &&
      this.claudeBridge.isFeatureEnabled("aupSemanticAnalysis")
    );
  }
  /**
   * Run AUP compliance assessment
   * If Claude semantic analysis is enabled, violations are verified to reduce false positives.
   */
  async assess(
    context: AssessmentContext,
  ): Promise<AUPComplianceAssessment | EnhancedAUPComplianceAssessment> {
    this.logger.info("Starting AUP compliance assessment");
    this.testCount = 0;

    const violations: AUPViolation[] = [];
    const highRiskDomains: string[] = [];
    const scannedLocations = {
      toolNames: false,
      toolDescriptions: false,
      readme: false,
      sourceCode: false,
    };

    // Build a map of tool descriptions for semantic analysis context
    const toolDescriptionMap = new Map<string, string>();
    for (const tool of context.tools) {
      toolDescriptionMap.set(tool.name, tool.description || "");
    }

    // Scan tool names
    this.logger.info("Scanning tool names...");
    scannedLocations.toolNames = true;
    for (const tool of context.tools) {
      this.testCount++;
      const toolViolations = this.scanToolName(tool.name);
      violations.push(...toolViolations);

      // Check for high-risk domains
      const domains = checkTextForHighRiskDomains(tool.name);
      for (const domain of domains) {
        if (!highRiskDomains.includes(domain.domain)) {
          highRiskDomains.push(domain.domain);
        }
      }
    }

    // Scan tool descriptions
    this.logger.info("Scanning tool descriptions...");
    scannedLocations.toolDescriptions = true;
    for (const tool of context.tools) {
      if (tool.description) {
        this.testCount++;
        const descViolations = this.scanToolDescription(
          tool.name,
          tool.description,
        );
        violations.push(...descViolations);

        const domains = checkTextForHighRiskDomains(tool.description);
        for (const domain of domains) {
          if (!highRiskDomains.includes(domain.domain)) {
            highRiskDomains.push(domain.domain);
          }
        }
      }
    }

    // Scan README content
    if (context.readmeContent) {
      this.logger.info("Scanning README content...");
      scannedLocations.readme = true;
      this.testCount++;
      const readmeViolations = this.scanReadme(context.readmeContent);
      violations.push(...readmeViolations);

      const domains = checkTextForHighRiskDomains(context.readmeContent);
      for (const domain of domains) {
        if (!highRiskDomains.includes(domain.domain)) {
          highRiskDomains.push(domain.domain);
        }
      }
    }

    // Scan source code if available
    if (context.sourceCodeFiles && context.config.enableSourceCodeAnalysis) {
      this.logger.info("Scanning source code files...");
      scannedLocations.sourceCode = true;

      for (const [filePath, content] of context.sourceCodeFiles) {
        // Skip non-relevant files
        if (this.shouldSkipFile(filePath)) continue;

        this.testCount++;
        const sourceViolations = this.scanSourceFile(filePath, content);
        violations.push(...sourceViolations);
      }
    }

    // If Claude semantic analysis is enabled, verify violations to reduce false positives
    if (this.isSemanticAnalysisEnabled() && violations.length > 0) {
      this.logger.info(
        `Running semantic analysis on ${violations.length} potential violations...`,
      );
      return await this.runSemanticAnalysis(
        violations,
        highRiskDomains,
        scannedLocations,
        toolDescriptionMap,
      );
    }

    // Standard assessment without semantic analysis
    const status = this.determineAUPStatus(violations);
    const explanation = this.generateExplanation(
      violations,
      highRiskDomains,
      scannedLocations,
    );
    const recommendations = this.generateRecommendations(
      violations,
      highRiskDomains,
    );

    this.logger.info(
      `Assessment complete: ${violations.length} violations found, ${highRiskDomains.length} high-risk domains`,
    );

    return {
      violations,
      highRiskDomains,
      scannedLocations,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Run Claude semantic analysis on flagged violations
   * Separates confirmed violations from likely false positives
   */
  private async runSemanticAnalysis(
    violations: AUPViolation[],
    highRiskDomains: string[],
    scannedLocations: AUPComplianceAssessment["scannedLocations"],
    toolDescriptionMap: Map<string, string>,
  ): Promise<EnhancedAUPComplianceAssessment> {
    const confirmedViolations: EnhancedAUPViolation[] = [];
    const flaggedForReview: EnhancedAUPViolation[] = [];
    let falsePositivesFiltered = 0;

    // Analyze each violation with Claude
    for (const violation of violations) {
      try {
        // Get tool description for context
        const toolDescription =
          violation.location === "tool_name" ||
          violation.location === "tool_description"
            ? toolDescriptionMap.get(violation.matchedText.split(" ")[0]) || ""
            : "";

        const analysis = await this.claudeBridge!.analyzeAUPViolation(
          violation.matchedText,
          {
            toolName:
              violation.location === "tool_name"
                ? violation.matchedText
                : "unknown",
            toolDescription,
            category: violation.category,
            categoryName: violation.categoryName,
            location: violation.location,
          },
        );

        // Handle null result (Claude unavailable or error)
        if (!analysis) {
          flaggedForReview.push({
            ...violation,
            semanticAnalysis: {
              isConfirmedViolation: true,
              confidence: 50,
              reasoning:
                "Claude analysis unavailable. Flagged for manual review.",
              source: "pattern-only",
            },
          });
          continue;
        }

        const enhancedViolation: EnhancedAUPViolation = {
          ...violation,
          semanticAnalysis: {
            isConfirmedViolation: analysis.isViolation,
            confidence: analysis.confidence,
            reasoning: analysis.reasoning,
            source: "claude-verified",
          },
        };

        // High confidence confirmed violations
        if (analysis.isViolation && analysis.confidence >= 70) {
          confirmedViolations.push(enhancedViolation);
        }
        // Uncertain - flag for human review
        else if (analysis.isViolation || analysis.confidence >= 40) {
          flaggedForReview.push(enhancedViolation);
        }
        // Low confidence - likely false positive
        else {
          falsePositivesFiltered++;
          this.logger.info(
            `Filtered likely false positive: "${violation.matchedText}" - ${analysis.reasoning}`,
          );
        }
      } catch (error) {
        // On analysis error, conservatively add to flagged for review
        flaggedForReview.push({
          ...violation,
          semanticAnalysis: {
            isConfirmedViolation: true,
            confidence: 50,
            reasoning: `Analysis error: ${error}. Flagged for manual review.`,
            source: "pattern-only",
          },
        });
      }
    }

    // Determine status based on confirmed violations only
    const status = this.determineAUPStatus(confirmedViolations);
    const explanation = this.generateSemanticExplanation(
      confirmedViolations,
      flaggedForReview,
      falsePositivesFiltered,
      highRiskDomains,
      scannedLocations,
    );
    const recommendations = this.generateSemanticRecommendations(
      confirmedViolations,
      flaggedForReview,
      highRiskDomains,
    );

    this.logger.info(
      `Semantic analysis complete: ${confirmedViolations.length} confirmed, ${flaggedForReview.length} flagged, ${falsePositivesFiltered} filtered`,
    );

    return {
      violations: [...confirmedViolations, ...flaggedForReview],
      confirmedViolations,
      flaggedForReview,
      highRiskDomains,
      scannedLocations,
      status,
      explanation,
      recommendations,
      semanticAnalysisEnabled: true,
      falsePositivesFiltered,
    };
  }

  /**
   * Generate explanation for semantic analysis results
   */
  private generateSemanticExplanation(
    confirmed: EnhancedAUPViolation[],
    flagged: EnhancedAUPViolation[],
    filtered: number,
    highRiskDomains: string[],
    scannedLocations: AUPComplianceAssessment["scannedLocations"],
  ): string {
    const parts: string[] = [];

    parts.push(
      `Semantic analysis enabled (Claude-verified). ${filtered} likely false positives filtered.`,
    );

    if (confirmed.length === 0 && flagged.length === 0) {
      parts.push("No AUP violations confirmed after semantic analysis.");
    } else {
      if (confirmed.length > 0) {
        const criticalCount = confirmed.filter(
          (v) => v.severity === "CRITICAL",
        ).length;
        const highCount = confirmed.filter((v) => v.severity === "HIGH").length;

        if (criticalCount > 0) {
          parts.push(
            `CRITICAL: ${criticalCount} confirmed critical violation(s).`,
          );
        }
        if (highCount > 0) {
          parts.push(
            `HIGH: ${highCount} confirmed high-severity violation(s).`,
          );
        }
      }

      if (flagged.length > 0) {
        parts.push(`${flagged.length} item(s) flagged for manual review.`);
      }
    }

    if (highRiskDomains.length > 0) {
      parts.push(
        `High-risk domains: ${highRiskDomains.join(", ")}. Additional review recommended.`,
      );
    }

    const scannedList = Object.entries(scannedLocations)
      .filter(([, scanned]) => scanned)
      .map(([location]) => location);
    parts.push(`Scanned: ${scannedList.join(", ")}.`);

    return parts.join(" ");
  }

  /**
   * Generate recommendations for semantic analysis results
   */
  private generateSemanticRecommendations(
    confirmed: EnhancedAUPViolation[],
    flagged: EnhancedAUPViolation[],
    highRiskDomains: string[],
  ): string[] {
    const recommendations: string[] = [];

    // Confirmed violations
    if (confirmed.length > 0) {
      const criticalViolations = confirmed.filter(
        (v) => v.severity === "CRITICAL",
      );
      if (criticalViolations.length > 0) {
        recommendations.push(
          "CRITICAL (Claude-verified): This MCP server contains content that violates Anthropic's Acceptable Use Policy:",
        );
        for (const v of criticalViolations) {
          recommendations.push(
            `- Category ${v.category} (${v.categoryName}): "${v.matchedText}" - ${v.semanticAnalysis?.reasoning || ""}`,
          );
        }
      }

      const highViolations = confirmed.filter((v) => v.severity === "HIGH");
      if (highViolations.length > 0) {
        recommendations.push(
          "HIGH (Claude-verified): Confirmed AUP violations:",
        );
        for (const v of highViolations) {
          recommendations.push(
            `- Category ${v.category} (${v.categoryName}): "${v.matchedText}" - ${v.semanticAnalysis?.reasoning || ""}`,
          );
        }
      }
    }

    // Flagged for review
    if (flagged.length > 0) {
      recommendations.push(
        "MANUAL REVIEW REQUIRED: The following items need human verification:",
      );
      for (const v of flagged) {
        recommendations.push(
          `- Category ${v.category}: "${v.matchedText}" (${v.semanticAnalysis?.confidence || 50}% confidence) - ${v.semanticAnalysis?.reasoning || ""}`,
        );
      }
    }

    // High-risk domains
    if (highRiskDomains.length > 0) {
      recommendations.push(
        `This server operates in high-risk domain(s): ${highRiskDomains.join(", ")}. Ensure appropriate safeguards.`,
      );
    }

    // If no issues
    if (recommendations.length === 0) {
      recommendations.push(
        "No AUP compliance issues confirmed after semantic analysis. Server appears compliant with Anthropic's Acceptable Use Policy.",
      );
    }

    return recommendations;
  }

  /**
   * Scan a tool name for AUP violations
   */
  private scanToolName(toolName: string): AUPViolation[] {
    const matches = checkTextForAUPViolations(toolName);

    return matches.map((match) => ({
      category: match.category,
      categoryName: match.categoryName,
      severity: match.severity,
      pattern: match.matchedPattern,
      matchedText: match.matchedText,
      location: "tool_name" as const,
      confidence: "high" as const,
      requiresHumanReview: match.requiresHumanReview,
      reviewGuidance: match.reviewGuidance,
    }));
  }

  /**
   * Scan a tool description for AUP violations
   */
  private scanToolDescription(
    toolName: string,
    description: string,
  ): AUPViolation[] {
    const matches = checkTextForAUPViolations(description);

    return matches.map((match) => ({
      category: match.category,
      categoryName: match.categoryName,
      severity: match.severity,
      pattern: match.matchedPattern,
      matchedText: match.matchedText,
      location: "tool_description" as const,
      confidence: "medium" as const, // Descriptions can have legitimate context
      requiresHumanReview: match.requiresHumanReview,
      reviewGuidance: `Tool: ${toolName}. ${match.reviewGuidance || ""}`,
    }));
  }

  /**
   * Scan README content for AUP violations
   */
  private scanReadme(content: string): AUPViolation[] {
    const matches = checkTextForAUPViolations(content);

    return matches.map((match) => ({
      category: match.category,
      categoryName: match.categoryName,
      severity: match.severity,
      pattern: match.matchedPattern,
      matchedText: match.matchedText,
      location: "readme" as const,
      confidence: "low" as const, // READMEs often discuss what NOT to do
      requiresHumanReview: true,
      reviewGuidance: `README match - verify context. ${match.reviewGuidance || ""}`,
    }));
  }

  /**
   * Scan a source file for AUP violations
   */
  private scanSourceFile(filePath: string, content: string): AUPViolation[] {
    const violations: AUPViolation[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const matches = checkTextForAUPViolations(line);

      for (const match of matches) {
        violations.push({
          category: match.category,
          categoryName: match.categoryName,
          severity: match.severity,
          pattern: match.matchedPattern,
          matchedText: match.matchedText,
          location: "source_code" as const,
          filePath,
          lineNumber: i + 1,
          confidence: "medium" as const,
          requiresHumanReview: match.requiresHumanReview,
          reviewGuidance: match.reviewGuidance,
        });
      }
    }

    return violations;
  }

  /**
   * Check if a file should be skipped for AUP scanning
   */
  private shouldSkipFile(filePath: string): boolean {
    const skipPatterns = [
      /node_modules/,
      /\.test\.(ts|js|tsx|jsx)$/,
      /\.spec\.(ts|js|tsx|jsx)$/,
      /\.d\.ts$/,
      /package-lock\.json$/,
      /yarn\.lock$/,
      /\.map$/,
      /\.min\.(js|css)$/,
    ];

    return skipPatterns.some((pattern) => pattern.test(filePath));
  }

  /**
   * Determine overall status based on violations
   */
  private determineAUPStatus(violations: AUPViolation[]): AssessmentStatus {
    // CRITICAL violations = automatic FAIL
    const criticalViolations = violations.filter(
      (v) => v.severity === "CRITICAL",
    );
    if (criticalViolations.length > 0) {
      return "FAIL";
    }

    // HIGH violations = FAIL unless all low confidence
    const highViolations = violations.filter((v) => v.severity === "HIGH");
    const highConfidenceHigh = highViolations.filter(
      (v) => v.confidence === "high" || v.confidence === "medium",
    );
    if (highConfidenceHigh.length > 0) {
      return "FAIL";
    }

    // MEDIUM/FLAG violations = NEED_MORE_INFO
    if (violations.length > 0) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation text
   */
  private generateExplanation(
    violations: AUPViolation[],
    highRiskDomains: string[],
    scannedLocations: AUPComplianceAssessment["scannedLocations"],
  ): string {
    const parts: string[] = [];

    // Summary
    if (violations.length === 0 && highRiskDomains.length === 0) {
      parts.push("No AUP violations detected.");
    } else {
      const criticalCount = violations.filter(
        (v) => v.severity === "CRITICAL",
      ).length;
      const highCount = violations.filter((v) => v.severity === "HIGH").length;
      const mediumCount = violations.filter(
        (v) => v.severity === "MEDIUM",
      ).length;

      if (criticalCount > 0) {
        parts.push(
          `CRITICAL: ${criticalCount} critical AUP violation(s) detected that require immediate review.`,
        );
      }
      if (highCount > 0) {
        parts.push(`HIGH: ${highCount} high-severity violation(s) detected.`);
      }
      if (mediumCount > 0) {
        parts.push(
          `MEDIUM: ${mediumCount} medium-severity item(s) flagged for review.`,
        );
      }
    }

    // High-risk domains
    if (highRiskDomains.length > 0) {
      parts.push(
        `High-risk domains detected: ${highRiskDomains.join(", ")}. Additional review recommended.`,
      );
    }

    // Coverage
    const scannedList = Object.entries(scannedLocations)
      .filter(([, scanned]) => scanned)
      .map(([location]) => location);
    parts.push(`Scanned: ${scannedList.join(", ")}.`);

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    violations: AUPViolation[],
    highRiskDomains: string[],
  ): string[] {
    const recommendations: string[] = [];

    // Critical violations
    const criticalViolations = violations.filter(
      (v) => v.severity === "CRITICAL",
    );
    if (criticalViolations.length > 0) {
      recommendations.push(
        "CRITICAL: This MCP server contains content that violates Anthropic's Acceptable Use Policy and cannot be approved for the directory.",
      );
      for (const v of criticalViolations) {
        recommendations.push(
          `- Category ${v.category} (${v.categoryName}): "${v.matchedText}" in ${v.location}`,
        );
      }
    }

    // High violations
    const highViolations = violations.filter((v) => v.severity === "HIGH");
    if (highViolations.length > 0) {
      recommendations.push(
        "HIGH: Review the following items for potential AUP violations:",
      );
      for (const v of highViolations) {
        recommendations.push(
          `- Category ${v.category} (${v.categoryName}): "${v.matchedText}" in ${v.location}`,
        );
      }
    }

    // High-risk domains
    if (highRiskDomains.length > 0) {
      recommendations.push(
        `This server operates in high-risk domain(s): ${highRiskDomains.join(", ")}. Ensure appropriate safeguards and human oversight are in place.`,
      );
    }

    // If no issues
    if (recommendations.length === 0) {
      recommendations.push(
        "No AUP compliance issues detected. Server appears compliant with Anthropic's Acceptable Use Policy.",
      );
    }

    return recommendations;
  }
}
