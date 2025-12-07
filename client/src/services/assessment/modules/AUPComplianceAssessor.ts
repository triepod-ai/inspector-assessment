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
  AUP_PATTERNS,
} from "@/lib/aupPatterns";

export class AUPComplianceAssessor extends BaseAssessor {
  /**
   * Run AUP compliance assessment
   */
  async assess(context: AssessmentContext): Promise<AUPComplianceAssessment> {
    this.log("Starting AUP compliance assessment");
    this.testCount = 0;

    const violations: AUPViolation[] = [];
    const highRiskDomains: string[] = [];
    const scannedLocations = {
      toolNames: false,
      toolDescriptions: false,
      readme: false,
      sourceCode: false,
    };

    // Scan tool names
    this.log("Scanning tool names...");
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
    this.log("Scanning tool descriptions...");
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
      this.log("Scanning README content...");
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
      this.log("Scanning source code files...");
      scannedLocations.sourceCode = true;

      for (const [filePath, content] of context.sourceCodeFiles) {
        // Skip non-relevant files
        if (this.shouldSkipFile(filePath)) continue;

        this.testCount++;
        const sourceViolations = this.scanSourceFile(filePath, content);
        violations.push(...sourceViolations);
      }
    }

    // Determine status
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

    this.log(
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
