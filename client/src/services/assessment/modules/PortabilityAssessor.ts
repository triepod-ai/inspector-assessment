/**
 * Portability Assessor
 * Detects hardcoded paths and platform-specific code
 *
 * Checks:
 * - Hardcoded absolute paths
 * - User home directory references
 * - ${BUNDLE_ROOT} anti-pattern (should use ${__dirname})
 * - Platform-specific code without fallbacks
 * - ${__dirname} usage (correct pattern)
 *
 * Reference: MCPB Bundle Portability Requirements
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  PortabilityAssessment,
  PortabilityIssue,
  AssessmentStatus,
} from "@/lib/assessmentTypes";

/**
 * Patterns for detecting portability issues
 */
const ISSUE_PATTERNS = {
  // Absolute Unix paths (not ${__dirname})
  absoluteUnixPath: /(?<!\$\{__dirname\}|['"])\/(?:usr|home|var|etc|opt|tmp|Users|Applications)\/[^\s'"]+/g,

  // Absolute Windows paths
  absoluteWindowsPath: /[A-Z]:\\[^\s'"]+/gi,

  // User home directory references
  userHomePath: /(?:~\/|\/Users\/|\/home\/)[^\s'"]+/g,

  // ${BUNDLE_ROOT} anti-pattern
  bundleRootAntipattern: /\$\{BUNDLE_ROOT\}/g,

  // Platform-specific checks without fallbacks
  platformSpecificDarwin: /process\.platform\s*===?\s*['"]darwin['"]/g,
  platformSpecificWin32: /process\.platform\s*===?\s*['"]win32['"]/g,
  platformSpecificLinux: /process\.platform\s*===?\s*['"]linux['"]/g,

  // Hardcoded config paths
  hardcodedConfigPaths: /['"](?:\/etc\/|~\/\.|\.config\/)[^'"]+['"]/g,
};

/**
 * Patterns for correct usage (positive signals)
 */
const GOOD_PATTERNS = {
  // Correct ${__dirname} usage
  dirname: /\$\{__dirname\}/g,

  // process.cwd() (usually acceptable)
  processCwd: /process\.cwd\(\)/g,

  // Cross-platform path handling
  pathJoin: /path\.join\(/g,
  pathResolve: /path\.resolve\(/g,
};

export class PortabilityAssessor extends BaseAssessor {
  /**
   * Run portability assessment
   */
  async assess(context: AssessmentContext): Promise<PortabilityAssessment> {
    this.log("Starting portability assessment");
    this.testCount = 0;

    const issues: PortabilityIssue[] = [];
    let scannedFiles = 0;
    let platformSpecificCount = 0;
    let hardcodedPathCount = 0;
    let usesDirname = false;
    let usesBundleRoot = false;

    // Check manifest if available
    if (context.manifestRaw) {
      this.testCount++;
      scannedFiles++;
      const manifestIssues = this.scanFile("manifest.json", context.manifestRaw);
      issues.push(...manifestIssues);

      // Check for ${__dirname} and ${BUNDLE_ROOT} in manifest
      if (GOOD_PATTERNS.dirname.test(context.manifestRaw)) {
        usesDirname = true;
      }
      if (ISSUE_PATTERNS.bundleRootAntipattern.test(context.manifestRaw)) {
        usesBundleRoot = true;
      }
    }

    // Check package.json scripts
    if (context.packageJson) {
      this.testCount++;
      scannedFiles++;
      const packageJson = context.packageJson as any;
      if (packageJson.scripts) {
        const scriptsStr = JSON.stringify(packageJson.scripts);
        const scriptIssues = this.scanFile("package.json (scripts)", scriptsStr);
        issues.push(...scriptIssues);
      }
    }

    // Check source code files if available
    if (context.sourceCodeFiles && context.config.enableSourceCodeAnalysis) {
      this.log("Scanning source code files for portability issues...");

      for (const [filePath, content] of context.sourceCodeFiles) {
        // Skip irrelevant files
        if (this.shouldSkipFile(filePath)) continue;

        this.testCount++;
        scannedFiles++;

        const fileIssues = this.scanFile(filePath, content);
        issues.push(...fileIssues);

        // Check for good patterns
        if (GOOD_PATTERNS.dirname.test(content)) {
          usesDirname = true;
        }
        if (ISSUE_PATTERNS.bundleRootAntipattern.test(content)) {
          usesBundleRoot = true;
        }
      }
    }

    // Count issue types
    hardcodedPathCount = issues.filter(
      (i) =>
        i.type === "hardcoded_path" ||
        i.type === "absolute_path" ||
        i.type === "user_home_path"
    ).length;
    platformSpecificCount = issues.filter(
      (i) => i.type === "platform_specific"
    ).length;

    const status = this.determinePortabilityStatus(
      issues,
      usesDirname,
      usesBundleRoot
    );
    const explanation = this.generateExplanation(
      issues,
      usesDirname,
      usesBundleRoot,
      scannedFiles
    );
    const recommendations = this.generateRecommendations(
      issues,
      usesDirname,
      usesBundleRoot
    );

    this.log(`Assessment complete: ${issues.length} portability issues found`);

    return {
      issues,
      scannedFiles,
      platformSpecificCount,
      hardcodedPathCount,
      usesDirname,
      usesBundleRoot,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Scan a file for portability issues
   */
  private scanFile(filePath: string, content: string): PortabilityIssue[] {
    const issues: PortabilityIssue[] = [];
    const lines = content.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNumber = i + 1;

      // Check for ${BUNDLE_ROOT} anti-pattern
      const bundleRootMatches = line.match(ISSUE_PATTERNS.bundleRootAntipattern);
      if (bundleRootMatches) {
        for (const match of bundleRootMatches) {
          issues.push({
            type: "bundle_root_antipattern",
            filePath,
            lineNumber,
            matchedText: match,
            severity: "HIGH",
            recommendation:
              "Replace ${BUNDLE_ROOT} with ${__dirname} - BUNDLE_ROOT is not supported",
          });
        }
      }

      // Check for absolute Unix paths (excluding __dirname prefixed)
      const cleanLine = line.replace(/\$\{__dirname\}/g, ""); // Remove __dirname to avoid false positives
      const unixPathMatches = cleanLine.match(ISSUE_PATTERNS.absoluteUnixPath);
      if (unixPathMatches) {
        for (const match of unixPathMatches) {
          // Skip if it looks like a URL or comment
          if (match.includes("://") || line.trim().startsWith("//") || line.trim().startsWith("*")) {
            continue;
          }
          issues.push({
            type: "absolute_path",
            filePath,
            lineNumber,
            matchedText: match,
            severity: "HIGH",
            recommendation: "Use relative paths or ${__dirname} for bundle portability",
          });
        }
      }

      // Check for absolute Windows paths
      const windowsPathMatches = line.match(ISSUE_PATTERNS.absoluteWindowsPath);
      if (windowsPathMatches) {
        for (const match of windowsPathMatches) {
          issues.push({
            type: "absolute_path",
            filePath,
            lineNumber,
            matchedText: match,
            severity: "HIGH",
            recommendation: "Use relative paths or path.join() for cross-platform support",
          });
        }
      }

      // Check for user home paths
      const homePathMatches = line.match(ISSUE_PATTERNS.userHomePath);
      if (homePathMatches) {
        for (const match of homePathMatches) {
          // Skip if in a comment
          if (line.trim().startsWith("//") || line.trim().startsWith("*") || line.trim().startsWith("#")) {
            continue;
          }
          issues.push({
            type: "user_home_path",
            filePath,
            lineNumber,
            matchedText: match,
            severity: "MEDIUM",
            recommendation:
              "Use os.homedir() or environment variable for user home paths",
          });
        }
      }

      // Check for platform-specific code without apparent fallback
      const platformChecks = [
        ISSUE_PATTERNS.platformSpecificDarwin,
        ISSUE_PATTERNS.platformSpecificWin32,
        ISSUE_PATTERNS.platformSpecificLinux,
      ];

      for (const pattern of platformChecks) {
        const matches = line.match(pattern);
        if (matches) {
          // Check if there's a fallback (else clause or default case)
          const hasElse = content.substring(content.indexOf(line)).includes("else");
          const hasDefault = content.substring(content.indexOf(line)).includes("default:");

          if (!hasElse && !hasDefault) {
            for (const match of matches) {
              issues.push({
                type: "platform_specific",
                filePath,
                lineNumber,
                matchedText: match,
                severity: "LOW",
                recommendation:
                  "Consider adding fallback for other platforms",
              });
            }
          }
        }
      }
    }

    return issues;
  }

  /**
   * Check if file should be skipped
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
      /README\.md$/i,
      /CHANGELOG\.md$/i,
      /LICENSE/i,
    ];

    return skipPatterns.some((pattern) => pattern.test(filePath));
  }

  /**
   * Determine overall status
   */
  private determinePortabilityStatus(
    issues: PortabilityIssue[],
    usesDirname: boolean,
    usesBundleRoot: boolean
  ): AssessmentStatus {
    // ${BUNDLE_ROOT} usage = automatic FAIL
    if (usesBundleRoot) {
      return "FAIL";
    }

    // HIGH severity issues = FAIL
    const highIssues = issues.filter((i) => i.severity === "HIGH");
    if (highIssues.length > 0) {
      return "FAIL";
    }

    // MEDIUM severity issues = NEED_MORE_INFO
    const mediumIssues = issues.filter((i) => i.severity === "MEDIUM");
    if (mediumIssues.length > 0) {
      return "NEED_MORE_INFO";
    }

    // Uses ${__dirname} is a positive signal
    if (usesDirname && issues.length === 0) {
      return "PASS";
    }

    // LOW severity issues only
    if (issues.length > 0) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    issues: PortabilityIssue[],
    usesDirname: boolean,
    usesBundleRoot: boolean,
    scannedFiles: number
  ): string {
    const parts: string[] = [];

    if (usesBundleRoot) {
      parts.push(
        "CRITICAL: Uses ${BUNDLE_ROOT} which is not supported in MCPB bundles."
      );
    }

    if (issues.length === 0) {
      parts.push("No portability issues detected.");
    } else {
      const highCount = issues.filter((i) => i.severity === "HIGH").length;
      const mediumCount = issues.filter((i) => i.severity === "MEDIUM").length;

      if (highCount > 0) {
        parts.push(`${highCount} high-severity portability issue(s) found.`);
      }
      if (mediumCount > 0) {
        parts.push(`${mediumCount} medium-severity issue(s) found.`);
      }
    }

    if (usesDirname) {
      parts.push("Uses ${__dirname} correctly for relative paths.");
    }

    parts.push(`Scanned ${scannedFiles} file(s).`);

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    issues: PortabilityIssue[],
    usesDirname: boolean,
    usesBundleRoot: boolean
  ): string[] {
    const recommendations: string[] = [];

    if (usesBundleRoot) {
      recommendations.push(
        "CRITICAL: Replace all ${BUNDLE_ROOT} with ${__dirname} - BUNDLE_ROOT variable is not supported in MCPB bundles."
      );
    }

    // Group issues by type
    const byType = new Map<string, PortabilityIssue[]>();
    for (const issue of issues) {
      const existing = byType.get(issue.type) || [];
      existing.push(issue);
      byType.set(issue.type, existing);
    }

    // Add recommendations by type
    for (const [type, typeIssues] of byType) {
      if (type === "bundle_root_antipattern") continue; // Already handled

      const first = typeIssues[0];
      if (typeIssues.length === 1) {
        recommendations.push(
          `${first.filePath}:${first.lineNumber}: ${first.recommendation}`
        );
      } else {
        recommendations.push(
          `${typeIssues.length} ${type.replace(/_/g, " ")} issues: ${first.recommendation}`
        );
      }
    }

    if (recommendations.length === 0) {
      if (usesDirname) {
        recommendations.push(
          "Server uses proper relative paths with ${__dirname}. Good portability."
        );
      } else {
        recommendations.push(
          "Consider using ${__dirname} for paths in manifest.json for better portability."
        );
      }
    }

    return recommendations;
  }
}
