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
  PackageJson,
  ProhibitedLibrariesEnrichmentData,
  LibraryInventoryItem,
  LibrarySecurityFlag,
  LibraryPolicyCoverage,
  LibraryFlagForReview,
} from "@/lib/assessmentTypes";
import {
  checkPackageJsonDependencies,
  checkRequirementsTxt,
  checkSourceImports,
  checkDependencyUsage,
  ALL_PROHIBITED_LIBRARIES,
  type ProhibitedLibrary,
} from "@/lib/prohibitedLibraries";
import type { DependencyUsageStatus } from "@/lib/assessmentTypes";

export class ProhibitedLibrariesAssessor extends BaseAssessor {
  /**
   * Run prohibited libraries assessment
   */
  async assess(
    context: AssessmentContext,
  ): Promise<ProhibitedLibrariesAssessment> {
    this.logger.info("Starting prohibited libraries assessment");
    this.testCount = 0;

    // Issue #154: Check if there are any files to scan
    const hasPackageJson = Boolean(context.packageJson);
    const hasSourceFiles = Boolean(
      context.sourceCodeFiles &&
      context.config.enableSourceCodeAnalysis &&
      context.sourceCodeFiles.size > 0,
    );

    if (!hasPackageJson && !hasSourceFiles) {
      this.logger.info(
        "No package.json or source files available, skipping assessment",
      );
      return this.createSkippedResult(
        "No package.json or source files provided. Enable source code analysis with --source flag.",
      );
    }

    const matches: ProhibitedLibraryMatch[] = [];
    const scannedFiles: string[] = [];
    let hasFinancialLibraries = false;
    let hasMediaLibraries = false;

    // Check package.json dependencies
    if (context.packageJson) {
      this.logger.info("Scanning package.json dependencies...");
      this.testCount++;
      scannedFiles.push("package.json");

      const packageJson = context.packageJson as PackageJson;
      const depMatches = checkPackageJsonDependencies(packageJson);

      for (const match of depMatches) {
        // Issue #63: Check if dependency is actually used in source code
        let usageStatus: DependencyUsageStatus = "UNKNOWN";
        let importCount = 0;
        let importFiles: string[] = [];

        if (
          context.sourceCodeFiles &&
          context.config.enableSourceCodeAnalysis
        ) {
          const usage = checkDependencyUsage(
            match.library.name,
            context.sourceCodeFiles,
          );
          usageStatus = usage.status;
          importCount = usage.importCount;
          importFiles = usage.files;
        }

        matches.push({
          name: match.library.name,
          category: match.library.category,
          location: "package.json",
          severity: match.library.severity,
          reason: match.library.reason,
          policyReference: match.library.policyReference,
          usageStatus,
          importCount,
          importFiles,
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
      this.logger.info("Scanning source code files...");

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

    this.logger.info(
      `Assessment complete: ${uniqueMatches.length} prohibited libraries found`,
    );

    // Issue #198: Build Stage B enrichment data for Claude validation
    const enrichmentData = this.buildEnrichmentData(
      uniqueMatches,
      scannedFiles,
      hasFinancialLibraries,
      hasMediaLibraries,
    );

    return {
      matches: uniqueMatches,
      scannedFiles,
      hasFinancialLibraries,
      hasMediaLibraries,
      status,
      explanation,
      recommendations,
      enrichmentData,
    };
  }

  /**
   * Create result when no files are available to scan (Issue #154)
   * Follows the pattern established by ConformanceAssessor
   */
  private createSkippedResult(reason: string): ProhibitedLibrariesAssessment {
    return {
      matches: [],
      scannedFiles: [],
      hasFinancialLibraries: false,
      hasMediaLibraries: false,
      status: "NEED_MORE_INFO",
      explanation: `Prohibited libraries assessment skipped: ${reason}`,
      recommendations: [
        "Provide --source <path> to enable package.json and source file scanning",
        "Ensure the source path exists and contains package.json or source files",
      ],
      skipped: true,
      skipReason: reason,
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
   *
   * Issue #63: Status now considers dependency usage:
   * - ACTIVE dependencies are actively imported (high risk)
   * - UNUSED dependencies are listed but not imported (lower risk, recommend removal)
   * - UNKNOWN usage falls back to previous behavior
   */
  private calculateStatusFromMatches(
    matches: ProhibitedLibraryMatch[],
  ): AssessmentStatus {
    // Separate matches by usage status
    const activeMatches = matches.filter((m) => m.usageStatus !== "UNUSED");
    const unusedMatches = matches.filter((m) => m.usageStatus === "UNUSED");

    // Only ACTIVE BLOCKING libraries = FAIL (actually imported and dangerous)
    const blockingActive = activeMatches.filter(
      (m) => m.severity === "BLOCKING",
    );
    if (blockingActive.length > 0) {
      return "FAIL";
    }

    // UNUSED BLOCKING = NEED_MORE_INFO (recommend removal, but not actively dangerous)
    if (unusedMatches.some((m) => m.severity === "BLOCKING")) {
      return "NEED_MORE_INFO";
    }

    // ACTIVE HIGH severity = NEED_MORE_INFO (requires justification)
    if (activeMatches.some((m) => m.severity === "HIGH")) {
      return "NEED_MORE_INFO";
    }

    // Any remaining matches = NEED_MORE_INFO (review recommended)
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
   *
   * Issue #63: Recommendations now distinguish between ACTIVE and UNUSED dependencies
   */
  private generateRecommendations(matches: ProhibitedLibraryMatch[]): string[] {
    const recommendations: string[] = [];

    // Issue #63: Separate active vs unused dependencies
    const activeMatches = matches.filter((m) => m.usageStatus !== "UNUSED");
    const unusedMatches = matches.filter((m) => m.usageStatus === "UNUSED");

    // Group active matches by severity
    const blockingActive = activeMatches.filter(
      (m) => m.severity === "BLOCKING",
    );
    const highActive = activeMatches.filter((m) => m.severity === "HIGH");
    const mediumActive = activeMatches.filter((m) => m.severity === "MEDIUM");

    if (blockingActive.length > 0) {
      recommendations.push(
        "BLOCKING (ACTIVE) - The following libraries are imported and must be removed:",
      );
      for (const match of blockingActive) {
        const files =
          match.importFiles && match.importFiles.length > 0
            ? ` (imported in: ${match.importFiles.slice(0, 2).join(", ")})`
            : "";
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}${files}`,
        );
      }
    }

    if (highActive.length > 0) {
      recommendations.push(
        "HIGH (ACTIVE) - The following libraries are imported and require strong justification:",
      );
      for (const match of highActive) {
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}`,
        );
      }
    }

    if (mediumActive.length > 0) {
      recommendations.push(
        "MEDIUM (ACTIVE) - Review the following imported libraries:",
      );
      for (const match of mediumActive.slice(0, 3)) {
        recommendations.push(
          `- ${match.name} (${match.policyReference}): ${match.reason}`,
        );
      }
    }

    // Issue #63: Add recommendations for unused dependencies
    if (unusedMatches.length > 0) {
      recommendations.push(
        "UNUSED - The following libraries are listed but not imported (consider removing):",
      );
      for (const match of unusedMatches) {
        recommendations.push(
          `- npm uninstall ${match.name} (${match.policyReference}): Listed in package.json but not imported`,
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

  // ============================================================================
  // Issue #198: Stage B Enrichment Data for Claude Validation
  // ============================================================================

  /**
   * Build enrichment data for Stage B Claude validation.
   * Provides context for Claude to validate prohibited libraries findings.
   */
  private buildEnrichmentData(
    matches: ProhibitedLibraryMatch[],
    scannedFiles: string[],
    hasFinancialLibraries: boolean,
    hasMediaLibraries: boolean,
  ): ProhibitedLibrariesEnrichmentData {
    // Build library inventory
    const libraryInventory = this.buildLibraryInventory(matches);

    // Build policy coverage
    const policyCoverage = this.buildPolicyCoverage(scannedFiles);

    // Generate flags for review
    const flagsForReview = this.generateLibraryFlags(matches);

    // Calculate metrics
    const metrics = {
      totalMatches: matches.length,
      blockingCount: matches.filter((m) => m.severity === "BLOCKING").length,
      highCount: matches.filter((m) => m.severity === "HIGH").length,
      mediumCount: matches.filter((m) => m.severity === "MEDIUM").length,
      activeCount: matches.filter((m) => m.usageStatus !== "UNUSED").length,
      unusedCount: matches.filter((m) => m.usageStatus === "UNUSED").length,
      hasFinancialLibraries,
      hasMediaLibraries,
    };

    return {
      libraryInventory,
      policyCoverage,
      flagsForReview,
      metrics,
    };
  }

  /**
   * Build library inventory with usage analysis
   */
  private buildLibraryInventory(
    matches: ProhibitedLibraryMatch[],
  ): LibraryInventoryItem[] {
    return matches.slice(0, 50).map((match) => ({
      name: match.name,
      category: match.category,
      severity: match.severity,
      location: match.location,
      usageStatus: match.usageStatus ?? "UNKNOWN",
      importCount: match.importCount ?? 0,
      importFiles: match.importFiles?.slice(0, 5) ?? [],
      policyReference: match.policyReference,
    }));
  }

  /**
   * Build policy coverage showing what was checked
   */
  private buildPolicyCoverage(scannedFiles: string[]): LibraryPolicyCoverage {
    // Get total number of prohibited libraries in checklist
    const totalLibraries =
      typeof ALL_PROHIBITED_LIBRARIES !== "undefined"
        ? ALL_PROHIBITED_LIBRARIES.length
        : 25; // Fallback estimate

    // Sample library names for context
    const sampleLibraries =
      typeof ALL_PROHIBITED_LIBRARIES !== "undefined"
        ? ALL_PROHIBITED_LIBRARIES.slice(0, 5).map(
            (lib: ProhibitedLibrary) => lib.name,
          )
        : ["stripe", "plaid", "ffmpeg", "imagemagick", "braintree"];

    return {
      totalProhibitedLibraries: totalLibraries,
      scannedFiles: scannedFiles.length,
      policiesChecked: ["Policy #28", "Policy #29", "Policy #30"],
      sampleLibraries,
    };
  }

  /**
   * Infer security flags from library match
   */
  private inferSecurityFlags(
    match: ProhibitedLibraryMatch,
  ): LibrarySecurityFlag[] {
    const flags: LibrarySecurityFlag[] = [];

    // Severity + usage combination flags
    if (match.severity === "BLOCKING") {
      if (match.usageStatus !== "UNUSED") {
        flags.push("blocking_active");
      } else {
        flags.push("blocking_unused");
      }
    }

    if (match.severity === "HIGH" && match.usageStatus !== "UNUSED") {
      flags.push("high_active");
    }

    // Category flags
    if (
      match.category === "financial" ||
      match.category === "payments" ||
      match.category === "banking"
    ) {
      flags.push("financial");
    }
    if (match.category === "media") {
      flags.push("media");
    }

    // Needs justification
    if (
      match.severity === "HIGH" ||
      (match.severity === "MEDIUM" && match.usageStatus !== "UNUSED")
    ) {
      flags.push("needs_justification");
    }

    return flags;
  }

  /**
   * Generate flags for libraries that warrant review
   */
  private generateLibraryFlags(
    matches: ProhibitedLibraryMatch[],
  ): LibraryFlagForReview[] {
    const flags: LibraryFlagForReview[] = [];

    for (const match of matches) {
      const securityFlags = this.inferSecurityFlags(match);
      let riskLevel: "critical" | "high" | "medium" | "low" = "low";
      let reason = "";

      // Determine risk level and reason
      if (match.severity === "BLOCKING" && match.usageStatus !== "UNUSED") {
        riskLevel = "critical";
        reason = `BLOCKING library actively imported: ${match.reason}`;
      } else if (
        match.severity === "BLOCKING" &&
        match.usageStatus === "UNUSED"
      ) {
        riskLevel = "high";
        reason = `BLOCKING library in dependencies (not imported): ${match.reason}`;
      } else if (match.severity === "HIGH" && match.usageStatus !== "UNUSED") {
        riskLevel = "high";
        reason = `HIGH severity library actively imported: ${match.reason}`;
      } else if (match.severity === "HIGH") {
        riskLevel = "medium";
        reason = `HIGH severity library in dependencies: ${match.reason}`;
      } else if (match.severity === "MEDIUM") {
        riskLevel = "medium";
        reason = `Library flagged for review: ${match.reason}`;
      }

      if (reason) {
        flags.push({
          libraryName: match.name,
          reason,
          flags: securityFlags,
          riskLevel,
        });
      }
    }

    // Sort by risk level and limit
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    flags.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

    return flags.slice(0, 20);
  }
}
