/**
 * Prohibited Libraries Assessor
 * Detects financial and media processing libraries per Policy #28-30
 *
 * Checks:
 * - package.json dependencies
 * - requirements.txt (Python)
 * - Source code imports (if sourceCodePath provided)
 *
 * Reference: Anthropic MCP Directory Policy #28-30
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  ProhibitedLibrariesAssessment,
  ProhibitedLibraryMatch,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import {
  checkPackageJsonDependencies,
  checkRequirementsTxt,
  checkSourceImports,
} from "@/lib/prohibitedLibraries";

export class ProhibitedLibrariesAssessor extends BaseAssessor {
  /**
   * Run prohibited libraries assessment
   */
  async assess(
    context: AssessmentContext,
  ): Promise<ProhibitedLibrariesAssessment> {
    this.log("Starting prohibited libraries assessment");
    this.testCount = 0;

    const matches: ProhibitedLibraryMatch[] = [];
    const scannedFiles: string[] = [];
    let hasFinancialLibraries = false;
    let hasMediaLibraries = false;

    // Check package.json dependencies
    if (context.packageJson) {
      this.log("Scanning package.json dependencies...");
      this.testCount++;
      scannedFiles.push("package.json");

      const packageJson = context.packageJson as any;
      const depMatches = checkPackageJsonDependencies(packageJson);

      for (const match of depMatches) {
        matches.push({
          name: match.library.name,
          category: match.library.category,
          location: "package.json",
          severity: match.library.severity,
          reason: match.library.reason,
          policyReference: match.library.policyReference,
        });

        if (
          match.library.category === "financial" ||
          match.library.category === "payments" ||
          match.library.category === "banking"
        ) {
          hasFinancialLibraries = true;
        }
        if (match.library.category === "media") {
          hasMediaLibraries = true;
        }
      }
    }

    // Check source code files if available
    if (context.sourceCodeFiles && context.config.enableSourceCodeAnalysis) {
      this.log("Scanning source code files...");

      for (const [filePath, content] of context.sourceCodeFiles) {
        // Check Python requirements files
        if (
          filePath.endsWith("requirements.txt") ||
          filePath.endsWith("requirements-dev.txt")
        ) {
          this.testCount++;
          scannedFiles.push(filePath);

          const reqMatches = checkRequirementsTxt(content);
          for (const match of reqMatches) {
            matches.push({
              name: match.library.name,
              category: match.library.category,
              location: "requirements.txt",
              filePath,
              lineNumber: match.lineNumber,
              severity: match.library.severity,
              reason: match.library.reason,
              policyReference: match.library.policyReference,
            });

            if (
              match.library.category === "financial" ||
              match.library.category === "payments" ||
              match.library.category === "banking"
            ) {
              hasFinancialLibraries = true;
            }
            if (match.library.category === "media") {
              hasMediaLibraries = true;
            }
          }
        }

        // Check source code imports
        if (this.isSourceFile(filePath)) {
          this.testCount++;
          scannedFiles.push(filePath);

          const importMatches = checkSourceImports(content);
          for (const match of importMatches) {
            matches.push({
              name: match.library.name,
              category: match.library.category,
              location: "source_import",
              filePath,
              lineNumber: match.lineNumber,
              severity: match.library.severity,
              reason: match.library.reason,
              policyReference: match.library.policyReference,
            });

            if (
              match.library.category === "financial" ||
              match.library.category === "payments" ||
              match.library.category === "banking"
            ) {
              hasFinancialLibraries = true;
            }
            if (match.library.category === "media") {
              hasMediaLibraries = true;
            }
          }
        }
      }
    }

    // De-duplicate matches by library name
    const uniqueMatches = this.deduplicateMatches(matches);

    const status = this.calculateStatusFromMatches(uniqueMatches);
    const explanation = this.generateExplanation(
      uniqueMatches,
      hasFinancialLibraries,
      hasMediaLibraries,
      scannedFiles,
    );
    const recommendations = this.generateRecommendations(uniqueMatches);

    this.log(
      `Assessment complete: ${uniqueMatches.length} prohibited libraries found`,
    );

    return {
      matches: uniqueMatches,
      scannedFiles,
      hasFinancialLibraries,
      hasMediaLibraries,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Check if file is a source file worth scanning
   */
  private isSourceFile(filePath: string): boolean {
    const sourceExtensions = [
      ".ts",
      ".tsx",
      ".js",
      ".jsx",
      ".mjs",
      ".cjs",
      ".py",
      ".rs",
      ".go",
    ];

    // Skip test files and node_modules
    if (
      filePath.includes("node_modules") ||
      filePath.includes(".test.") ||
      filePath.includes(".spec.") ||
      filePath.includes("__tests__")
    ) {
      return false;
    }

    return sourceExtensions.some((ext) => filePath.endsWith(ext));
  }

  /**
   * De-duplicate matches, keeping the most severe
   */
  private deduplicateMatches(
    matches: ProhibitedLibraryMatch[],
  ): ProhibitedLibraryMatch[] {
    const byName = new Map<string, ProhibitedLibraryMatch>();

    for (const match of matches) {
      const existing = byName.get(match.name);
      if (!existing) {
        byName.set(match.name, match);
      } else {
        // Keep the more severe match
        const severityOrder = { BLOCKING: 3, HIGH: 2, MEDIUM: 1 };
        if (severityOrder[match.severity] > severityOrder[existing.severity]) {
          byName.set(match.name, match);
        }
      }
    }

    return Array.from(byName.values());
  }

  /**
   * Calculate overall status from matches
   */
  private calculateStatusFromMatches(
    matches: ProhibitedLibraryMatch[],
  ): AssessmentStatus {
    // Any BLOCKING library = FAIL
    const blockingMatches = matches.filter((m) => m.severity === "BLOCKING");
    if (blockingMatches.length > 0) {
      return "FAIL";
    }

    // HIGH severity = NEED_MORE_INFO (requires justification)
    const highMatches = matches.filter((m) => m.severity === "HIGH");
    if (highMatches.length > 0) {
      return "NEED_MORE_INFO";
    }

    // MEDIUM severity = PASS with notes
    if (matches.length > 0) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    matches: ProhibitedLibraryMatch[],
    hasFinancial: boolean,
    hasMedia: boolean,
    scannedFiles: string[],
  ): string {
    const parts: string[] = [];

    if (matches.length === 0) {
      parts.push(
        "No prohibited libraries detected. Server appears compliant with Policy #28-30.",
      );
    } else {
      const blockingCount = matches.filter(
        (m) => m.severity === "BLOCKING",
      ).length;
      const highCount = matches.filter((m) => m.severity === "HIGH").length;
      const mediumCount = matches.filter((m) => m.severity === "MEDIUM").length;

      if (blockingCount > 0) {
        parts.push(
          `BLOCKING: ${blockingCount} prohibited library/libraries detected that violate MCP Directory policy.`,
        );
      }
      if (highCount > 0) {
        parts.push(
          `HIGH: ${highCount} library/libraries detected that require justification for MCP server use.`,
        );
      }
      if (mediumCount > 0) {
        parts.push(
          `MEDIUM: ${mediumCount} library/libraries flagged for review.`,
        );
      }

      if (hasFinancial) {
        parts.push(
          "Financial/payment processing libraries detected - violates Policy #28-29.",
        );
      }
      if (hasMedia) {
        parts.push(
          "Media processing libraries detected - may require justification per Policy #30.",
        );
      }
    }

    parts.push(`Scanned ${scannedFiles.length} file(s).`);

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(matches: ProhibitedLibraryMatch[]): string[] {
    const recommendations: string[] = [];

    // Group by severity
    const blocking = matches.filter((m) => m.severity === "BLOCKING");
    const high = matches.filter((m) => m.severity === "HIGH");
    const medium = matches.filter((m) => m.severity === "MEDIUM");

    if (blocking.length > 0) {
      recommendations.push(
        "BLOCKING - The following libraries must be removed for MCP Directory approval:",
      );
      for (const match of blocking) {
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}`,
        );
      }
    }

    if (high.length > 0) {
      recommendations.push(
        "HIGH - The following libraries require strong justification:",
      );
      for (const match of high) {
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}`,
        );
      }
    }

    if (medium.length > 0) {
      recommendations.push(
        "MEDIUM - Review the following libraries for necessity:",
      );
      for (const match of medium.slice(0, 3)) {
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}`,
        );
      }
    }

    if (matches.length === 0) {
      recommendations.push(
        "No prohibited libraries detected. Server is compliant with library restrictions.",
      );
    } else {
      recommendations.push(
        "Reference: MCP Directory Policy #28-30 restricts financial transaction and media processing libraries.",
      );
    }

    return recommendations;
  }
}
