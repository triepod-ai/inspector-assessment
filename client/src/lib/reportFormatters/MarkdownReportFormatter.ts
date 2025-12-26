/**
 * Markdown Report Formatter
 *
 * Generates human-readable markdown reports from MCP assessment results.
 * Designed for reviewers, auditors, and developers.
 *
 * @module MarkdownReportFormatter
 */

import type {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "../assessmentTypes";
import type {
  PolicyComplianceReport,
  ComplianceStatus,
} from "../policyMapping";

/**
 * Options for markdown report generation
 */
export interface MarkdownReportOptions {
  /** Include policy compliance section */
  includePolicy?: boolean;
  /** Policy compliance report (required if includePolicy is true) */
  policyReport?: PolicyComplianceReport;
  /** Include detailed module results */
  includeDetails?: boolean;
  /** Include recommendations */
  includeRecommendations?: boolean;
  /** Server name override */
  serverName?: string;
}

/**
 * Formats assessment results as Markdown
 */
export class MarkdownReportFormatter {
  private options: MarkdownReportOptions;

  constructor(options: MarkdownReportOptions = {}) {
    this.options = {
      includeDetails: true,
      includeRecommendations: true,
      ...options,
    };
  }

  /**
   * Format assessment results as markdown
   */
  format(assessment: MCPDirectoryAssessment): string {
    const sections: string[] = [];

    // Header
    sections.push(this.formatHeader(assessment));

    // Executive Summary
    sections.push(this.formatExecutiveSummary(assessment));

    // Module Status Table
    sections.push(this.formatModuleStatusTable(assessment));

    // Key Findings
    sections.push(this.formatKeyFindings(assessment));

    // Policy Compliance (if enabled)
    if (this.options.includePolicy && this.options.policyReport) {
      sections.push(this.formatPolicyCompliance(this.options.policyReport));
    }

    // Recommendations
    if (this.options.includeRecommendations) {
      sections.push(this.formatRecommendations(assessment));
    }

    // Detailed Results (if enabled)
    if (this.options.includeDetails) {
      sections.push(this.formatDetailedResults(assessment));
    }

    // Footer
    sections.push(this.formatFooter(assessment));

    return sections.filter(Boolean).join("\n\n---\n\n");
  }

  /**
   * Format header section
   */
  private formatHeader(assessment: MCPDirectoryAssessment): string {
    const serverName = this.options.serverName || assessment.serverName;
    const statusEmoji = this.getStatusEmoji(assessment.overallStatus);

    return `# MCP Server Assessment Report

**Server**: ${serverName}
**Date**: ${new Date(assessment.assessmentDate).toLocaleString()}
**Status**: ${statusEmoji} ${assessment.overallStatus}
**Version**: ${assessment.assessorVersion}`;
  }

  /**
   * Format executive summary
   */
  private formatExecutiveSummary(assessment: MCPDirectoryAssessment): string {
    const lines: string[] = ["## Executive Summary", ""];
    lines.push("| Metric | Value |");
    lines.push("|--------|-------|");

    // Tools count
    const workingCount = assessment.functionality?.workingTools ?? 0;
    const brokenCount = assessment.functionality?.brokenTools?.length ?? 0;
    lines.push(`| Tools Tested | ${workingCount + brokenCount} |`);

    // Success rate
    const successRate =
      assessment.functionality?.coveragePercentage ??
      (workingCount > 0
        ? Math.round((workingCount / (workingCount + brokenCount)) * 100)
        : 0);
    lines.push(`| Tool Success Rate | ${successRate}% |`);

    // Vulnerabilities
    const vulnCount = assessment.security?.vulnerabilities?.length ?? 0;
    lines.push(
      `| Security Vulnerabilities | ${vulnCount === 0 ? "None" : vulnCount} |`,
    );

    // Total tests
    lines.push(`| Total Tests Run | ${assessment.totalTestsRun} |`);

    // Execution time
    const execTime = (assessment.executionTime / 1000).toFixed(1);
    lines.push(`| Execution Time | ${execTime}s |`);

    return lines.join("\n");
  }

  /**
   * Format module status table
   */
  private formatModuleStatusTable(assessment: MCPDirectoryAssessment): string {
    const lines: string[] = ["## Module Status", ""];
    lines.push("| Module | Status | Key Finding |");
    lines.push("|--------|--------|-------------|");

    // Core modules
    lines.push(
      this.formatModuleRow(
        "Functionality",
        assessment.functionality?.status,
        this.getFunctionalityFinding(assessment),
      ),
    );

    lines.push(
      this.formatModuleRow(
        "Security",
        assessment.security?.status,
        this.getSecurityFinding(assessment),
      ),
    );

    lines.push(
      this.formatModuleRow(
        "Error Handling",
        assessment.errorHandling?.status,
        this.getErrorHandlingFinding(assessment),
      ),
    );

    lines.push(
      this.formatModuleRow(
        "Documentation",
        assessment.documentation?.status,
        this.getDocumentationFinding(assessment),
      ),
    );

    lines.push(
      this.formatModuleRow(
        "Usability",
        assessment.usability?.status,
        this.getUsabilityFinding(assessment),
      ),
    );

    // Extended modules (if present)
    if (assessment.mcpSpecCompliance) {
      lines.push(
        this.formatModuleRow(
          "MCP Spec Compliance",
          assessment.mcpSpecCompliance.status,
          this.getMCPSpecFinding(assessment),
        ),
      );
    }

    if (assessment.aupCompliance) {
      lines.push(
        this.formatModuleRow(
          "AUP Compliance",
          assessment.aupCompliance.status,
          this.getAUPFinding(assessment),
        ),
      );
    }

    if (assessment.toolAnnotations) {
      lines.push(
        this.formatModuleRow(
          "Tool Annotations",
          assessment.toolAnnotations.status,
          this.getAnnotationFinding(assessment),
        ),
      );
    }

    return lines.join("\n");
  }

  /**
   * Format a single module row
   */
  private formatModuleRow(
    name: string,
    status: AssessmentStatus | undefined,
    finding: string,
  ): string {
    const statusEmoji = this.getStatusEmoji(status);
    const displayStatus = status || "NOT_RUN";
    return `| ${name} | ${statusEmoji} ${displayStatus} | ${finding} |`;
  }

  /**
   * Format key findings section
   */
  private formatKeyFindings(assessment: MCPDirectoryAssessment): string {
    const lines: string[] = ["## Key Findings", ""];

    // Critical Issues
    const criticalIssues = this.getCriticalIssues(assessment);
    if (criticalIssues.length > 0) {
      lines.push("### Critical Issues");
      for (const issue of criticalIssues) {
        lines.push(`- ${issue}`);
      }
      lines.push("");
    }

    // Warnings
    const warnings = this.getWarnings(assessment);
    if (warnings.length > 0) {
      lines.push("### Warnings");
      for (const warning of warnings) {
        lines.push(`- ${warning}`);
      }
      lines.push("");
    }

    // Positive findings
    const positives = this.getPositiveFindings(assessment);
    if (positives.length > 0) {
      lines.push("### Positive Findings");
      for (const positive of positives) {
        lines.push(`- ${positive}`);
      }
    }

    return lines.join("\n");
  }

  /**
   * Format policy compliance section
   */
  private formatPolicyCompliance(report: PolicyComplianceReport): string {
    const lines: string[] = ["## Policy Compliance", ""];

    // Summary
    lines.push("### Compliance Summary");
    lines.push("");
    lines.push("| Metric | Value |");
    lines.push("|--------|-------|");
    lines.push(`| Total Requirements | ${report.summary.totalRequirements} |`);
    lines.push(`| Passed | ${report.summary.passed} |`);
    lines.push(`| Failed | ${report.summary.failed} |`);
    lines.push(`| Needs Review | ${report.summary.needsReview} |`);
    lines.push(`| Compliance Score | ${report.summary.complianceScore}% |`);
    lines.push(
      `| Overall Status | ${this.getStatusEmoji(this.complianceToAssessment(report.summary.overallStatus))} ${report.summary.overallStatus} |`,
    );
    lines.push("");

    // Category breakdown
    lines.push("### By Category");
    lines.push("");
    lines.push("| Category | Status | Passed | Failed |");
    lines.push("|----------|--------|--------|--------|");

    for (const [, category] of Object.entries(report.byCategory)) {
      const statusEmoji = this.getComplianceStatusEmoji(category.status);
      lines.push(
        `| ${category.categoryName} | ${statusEmoji} ${category.status} | ${category.passed}/${category.total} | ${category.failed} |`,
      );
    }
    lines.push("");

    // Critical issues from policy
    if (report.criticalIssues.length > 0) {
      lines.push("### Critical Policy Issues");
      lines.push("");
      for (const issue of report.criticalIssues.slice(0, 5)) {
        lines.push(
          `- **${issue.requirement.id}**: ${issue.requirement.name} - ${issue.status}`,
        );
        if (issue.recommendation) {
          lines.push(`  - ${issue.recommendation}`);
        }
      }
      lines.push("");
    }

    // Action items
    if (report.actionItems.length > 0) {
      lines.push("### Action Items");
      lines.push("");
      for (const item of report.actionItems) {
        lines.push(`- ${item}`);
      }
    }

    return lines.join("\n");
  }

  /**
   * Format recommendations section
   */
  private formatRecommendations(assessment: MCPDirectoryAssessment): string {
    const lines: string[] = ["## Recommendations", ""];

    const recs = assessment.recommendations || [];

    if (recs.length === 0) {
      lines.push("No recommendations at this time.");
      return lines.join("\n");
    }

    // Group by priority
    const high = recs.filter(
      (r) =>
        r.toLowerCase().includes("critical") ||
        r.toLowerCase().includes("security"),
    );
    const medium = recs.filter(
      (r) =>
        !high.includes(r) &&
        (r.toLowerCase().includes("required") ||
          r.toLowerCase().includes("must")),
    );
    const low = recs.filter((r) => !high.includes(r) && !medium.includes(r));

    if (high.length > 0) {
      lines.push("### High Priority");
      for (const rec of high) {
        lines.push(`1. ${rec}`);
      }
      lines.push("");
    }

    if (medium.length > 0) {
      lines.push("### Medium Priority");
      for (const rec of medium) {
        lines.push(`1. ${rec}`);
      }
      lines.push("");
    }

    if (low.length > 0) {
      lines.push("### Other");
      for (const rec of low.slice(0, 5)) {
        lines.push(`1. ${rec}`);
      }
    }

    return lines.join("\n");
  }

  /**
   * Format detailed results section
   */
  private formatDetailedResults(assessment: MCPDirectoryAssessment): string {
    const lines: string[] = ["## Detailed Results", ""];

    // Functionality details
    if (assessment.functionality) {
      lines.push("### Functionality");
      lines.push("");
      lines.push(`**Status**: ${assessment.functionality.status}`);
      lines.push("");

      const workingCount = assessment.functionality.workingTools ?? 0;
      const brokenTools = assessment.functionality.brokenTools || [];

      if (workingCount > 0) {
        lines.push(
          `**Working Tools**: ${workingCount} tool(s) functioning correctly`,
        );
      }

      if (brokenTools.length > 0) {
        lines.push("");
        lines.push(`**Broken Tools** (${brokenTools.length}):`);
        for (const tool of brokenTools.slice(0, 5)) {
          lines.push(`- ${tool}`);
        }
      }
      lines.push("");
    }

    // Security details
    if (assessment.security) {
      lines.push("### Security");
      lines.push("");
      lines.push(`**Status**: ${assessment.security.status}`);
      lines.push("");

      const vulns = assessment.security.vulnerabilities || [];
      if (vulns.length > 0) {
        lines.push(`**Vulnerabilities Found** (${vulns.length}):`);
        for (const vuln of vulns.slice(0, 5)) {
          lines.push(`- ${vuln}`);
        }
      } else {
        lines.push("No vulnerabilities detected.");
      }
      lines.push("");
    }

    // Tool Annotations details
    if (assessment.toolAnnotations) {
      lines.push("### Tool Annotations");
      lines.push("");
      lines.push(`**Status**: ${assessment.toolAnnotations.status}`);
      lines.push(
        `**Coverage**: ${assessment.toolAnnotations.annotatedCount} annotated, ${assessment.toolAnnotations.missingAnnotationsCount} missing`,
      );

      if (assessment.toolAnnotations.annotationSources) {
        const sources = assessment.toolAnnotations.annotationSources;
        lines.push("");
        lines.push("**Annotation Sources**:");
        lines.push(`- MCP Protocol: ${sources.mcp}`);
        lines.push(`- Source Code: ${sources.sourceCode}`);
        lines.push(`- Inferred: ${sources.inferred}`);
        lines.push(`- None: ${sources.none}`);
      }
      lines.push("");
    }

    return lines.join("\n");
  }

  /**
   * Format footer section
   */
  private formatFooter(assessment: MCPDirectoryAssessment): string {
    return `## Report Metadata

- **Generated**: ${new Date().toISOString()}
- **Assessor Version**: ${assessment.assessorVersion}
- **MCP Protocol Version**: ${assessment.mcpProtocolVersion || "N/A"}
- **Total Tests**: ${assessment.totalTestsRun}
- **Execution Time**: ${(assessment.executionTime / 1000).toFixed(2)}s

---

*Generated by MCP Inspector Assessment CLI*`;
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private getStatusEmoji(status: AssessmentStatus | undefined): string {
    switch (status) {
      case "PASS":
        return "✅";
      case "FAIL":
        return "❌";
      case "NEED_MORE_INFO":
        return "⚠️";
      default:
        return "❓";
    }
  }

  private getComplianceStatusEmoji(status: ComplianceStatus): string {
    switch (status) {
      case "PASS":
        return "✅";
      case "FAIL":
        return "❌";
      case "FLAG":
        return "🚩";
      case "REVIEW":
        return "🔍";
      case "NOT_APPLICABLE":
        return "➖";
      case "NOT_TESTED":
        return "❓";
      default:
        return "❓";
    }
  }

  private complianceToAssessment(
    status: "COMPLIANT" | "NON_COMPLIANT" | "NEEDS_REVIEW",
  ): AssessmentStatus {
    switch (status) {
      case "COMPLIANT":
        return "PASS";
      case "NON_COMPLIANT":
        return "FAIL";
      case "NEEDS_REVIEW":
        return "NEED_MORE_INFO";
    }
  }

  private getFunctionalityFinding(assessment: MCPDirectoryAssessment): string {
    const working = assessment.functionality?.workingTools ?? 0;
    const broken = assessment.functionality?.brokenTools?.length ?? 0;
    const total = working + broken;
    if (total === 0) return "No tools tested";
    if (broken === 0) return `All ${total} tools working`;
    return `${working}/${total} tools working, ${broken} failing`;
  }

  private getSecurityFinding(assessment: MCPDirectoryAssessment): string {
    const vulns = assessment.security?.vulnerabilities?.length ?? 0;
    if (vulns === 0) return "No vulnerabilities detected";
    return `${vulns} vulnerability(ies) detected`;
  }

  private getErrorHandlingFinding(assessment: MCPDirectoryAssessment): string {
    const metrics = assessment.errorHandling?.metrics;
    if (!metrics) return "Not tested";
    const passRate = metrics.validationCoverage?.overallPassRate ?? 0;
    return `${passRate}% pass rate`;
  }

  private getDocumentationFinding(assessment: MCPDirectoryAssessment): string {
    const status = assessment.documentation?.status;
    if (!status) return "Not assessed";
    return status === "PASS"
      ? "Documentation adequate"
      : "Documentation needs improvement";
  }

  private getUsabilityFinding(assessment: MCPDirectoryAssessment): string {
    const status = assessment.usability?.status;
    if (!status) return "Not assessed";
    return status === "PASS" ? "Good usability" : "Usability issues found";
  }

  private getMCPSpecFinding(assessment: MCPDirectoryAssessment): string {
    const status = assessment.mcpSpecCompliance?.status;
    if (!status) return "Not tested";
    return status === "PASS" ? "Protocol compliant" : "Protocol issues found";
  }

  private getAUPFinding(assessment: MCPDirectoryAssessment): string {
    const violations = assessment.aupCompliance?.violations?.length ?? 0;
    if (violations === 0) return "No AUP violations";
    return `${violations} AUP violation(s) detected`;
  }

  private getAnnotationFinding(assessment: MCPDirectoryAssessment): string {
    const annotated = assessment.toolAnnotations?.annotatedCount ?? 0;
    const missing = assessment.toolAnnotations?.missingAnnotationsCount ?? 0;
    if (annotated === 0 && missing === 0) return "No tools assessed";
    if (missing === 0) return `All ${annotated} tools annotated`;
    return `${annotated} annotated, ${missing} missing`;
  }

  private getCriticalIssues(assessment: MCPDirectoryAssessment): string[] {
    const issues: string[] = [];

    // Security vulnerabilities
    const vulns = assessment.security?.vulnerabilities || [];
    if (vulns.length > 0) {
      issues.push(`${vulns.length} security vulnerability(ies) detected`);
    }

    // AUP violations
    const aupViolations = assessment.aupCompliance?.violations || [];
    const critical = aupViolations.filter(
      (v) =>
        typeof v === "object" &&
        v !== null &&
        (v as { severity?: string }).severity === "CRITICAL",
    );
    if (critical.length > 0) {
      issues.push(`${critical.length} critical AUP violation(s)`);
    }

    // Broken tools
    const broken = assessment.functionality?.brokenTools || [];
    if (broken.length > 0) {
      issues.push(`${broken.length} tool(s) not functioning correctly`);
    }

    return issues;
  }

  private getWarnings(assessment: MCPDirectoryAssessment): string[] {
    const warnings: string[] = [];

    // Missing annotations
    const missing = assessment.toolAnnotations?.missingAnnotationsCount ?? 0;
    if (missing > 0) {
      warnings.push(`${missing} tool(s) missing required annotations`);
    }

    // Misaligned annotations
    const misaligned =
      assessment.toolAnnotations?.misalignedAnnotationsCount ?? 0;
    if (misaligned > 0) {
      warnings.push(
        `${misaligned} tool(s) with potentially misaligned annotations`,
      );
    }

    // Error handling issues
    const errorMetrics = assessment.errorHandling?.metrics;
    const passRate = errorMetrics?.validationCoverage?.overallPassRate ?? 100;
    if (errorMetrics && passRate < 80) {
      warnings.push(`Low error handling pass rate (${passRate}%)`);
    }

    return warnings;
  }

  private getPositiveFindings(assessment: MCPDirectoryAssessment): string[] {
    const positives: string[] = [];

    // All tools working
    const working = assessment.functionality?.workingTools ?? 0;
    const broken = assessment.functionality?.brokenTools?.length ?? 0;
    if (working > 0 && broken === 0) {
      positives.push(`All ${working} tools functioning correctly`);
    }

    // No security vulnerabilities
    const vulns = assessment.security?.vulnerabilities?.length ?? 0;
    if (vulns === 0) {
      positives.push("No security vulnerabilities detected");
    }

    // Full annotation coverage
    const annotated = assessment.toolAnnotations?.annotatedCount ?? 0;
    const missingAnnotations =
      assessment.toolAnnotations?.missingAnnotationsCount ?? 0;
    if (annotated > 0 && missingAnnotations === 0) {
      positives.push(`All ${annotated} tools have required annotations`);
    }

    // Good error handling
    const errorMetrics2 = assessment.errorHandling?.metrics;
    const passRate2 = errorMetrics2?.validationCoverage?.overallPassRate ?? 0;
    if (errorMetrics2 && passRate2 >= 90) {
      positives.push("Excellent error handling coverage");
    }

    return positives;
  }
}

/**
 * Create a markdown formatter with options
 */
export function createMarkdownFormatter(
  options?: MarkdownReportOptions,
): MarkdownReportFormatter {
  return new MarkdownReportFormatter(options);
}
