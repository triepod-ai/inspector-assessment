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
  PackageJson,
} from "@/lib/assessmentTypes";

/**
 * Patterns for detecting portability issues
 */
const ISSUE_PATTERNS = {
  // Absolute Unix paths (not ${__dirname})
  // Note: /tmp/ excluded as it's a portable Unix standard directory
  absoluteUnixPath:
    /(?<!\$\{__dirname\}|['"])\/(?:usr|home|var|etc|opt|Users|Applications)\/[^\s'"]+/g,

  // Absolute Windows paths (requires valid path chars, excludes escape sequences like \n, \t)
  // Note: Windows drive letters are always uppercase, so /i flag removed to avoid false positives
  // Negative lookahead (?![ntr0'"bfv]) excludes escape sequences in source code strings
  // e.g., "STDOUT:\n" won't match T:\n as a Windows path
  absoluteWindowsPath: /[A-Z]:\\(?![ntr0'"bfv])[a-zA-Z0-9_\-.\\]+/g,

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

/**
 * Shell command patterns for enrichment (Issue #9)
 * Maps shell commands to portability info
 */
const SHELL_COMMAND_PATTERNS: Array<{
  pattern: RegExp;
  command: string;
  isPortable: boolean;
  alternativeCommand?: string;
}> = [
  // Unix-only commands
  {
    pattern: /\brm\s+-rf?\s/g,
    command: "rm -rf",
    isPortable: false,
    alternativeCommand: "Use rimraf or fs-extra.remove()",
  },
  {
    pattern: /\bchmod\s+/g,
    command: "chmod",
    isPortable: false,
    alternativeCommand: "Use fs.chmod() or skip on Windows",
  },
  {
    pattern: /\bchown\s+/g,
    command: "chown",
    isPortable: false,
    alternativeCommand: "Skip on Windows or use icacls",
  },
  {
    pattern: /\bln\s+-s/g,
    command: "ln -s",
    isPortable: false,
    alternativeCommand: "Use fs.symlink() with junction on Windows",
  },
  {
    pattern: /\bsed\s+-[ie]/g,
    command: "sed",
    isPortable: false,
    alternativeCommand: "Use Node.js replace or replace-in-file package",
  },
  {
    pattern: /\bgrep\s+/g,
    command: "grep",
    isPortable: false,
    alternativeCommand: "Use Node.js string methods or glob package",
  },
  {
    pattern: /\bawk\s+/g,
    command: "awk",
    isPortable: false,
    alternativeCommand: "Use Node.js string/regex methods",
  },
  {
    pattern: /\btar\s+-[cxzf]/g,
    command: "tar",
    isPortable: false,
    alternativeCommand: "Use node-tar or archiver package",
  },
  {
    pattern: /\bcurl\s+/g,
    command: "curl",
    isPortable: false,
    alternativeCommand: "Use node-fetch or axios",
  },
  {
    pattern: /\bwget\s+/g,
    command: "wget",
    isPortable: false,
    alternativeCommand: "Use node-fetch or axios",
  },

  // Portable commands
  { pattern: /\bnpx\s+/g, command: "npx", isPortable: true },
  { pattern: /\bnpm\s+run/g, command: "npm run", isPortable: true },
  { pattern: /\bnode\s+/g, command: "node", isPortable: true },
  { pattern: /\bpython3?\s+/g, command: "python", isPortable: true },
];

export class PortabilityAssessor extends BaseAssessor {
  /**
   * Run portability assessment
   */
  async assess(context: AssessmentContext): Promise<PortabilityAssessment> {
    this.logger.info("Starting portability assessment");
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
      const manifestIssues = this.scanFile(
        "manifest.json",
        context.manifestRaw,
      );
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
      const packageJson = context.packageJson as PackageJson;
      if (packageJson.scripts) {
        const scriptsStr = JSON.stringify(packageJson.scripts);
        const scriptIssues = this.scanFile(
          "package.json (scripts)",
          scriptsStr,
        );
        issues.push(...scriptIssues);
      }
    }

    // Check source code files if available
    if (context.sourceCodeFiles && context.config.enableSourceCodeAnalysis) {
      this.logger.info("Scanning source code files for portability issues...");

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
        i.type === "user_home_path",
    ).length;
    platformSpecificCount = issues.filter(
      (i) => i.type === "platform_specific",
    ).length;

    const status = this.determinePortabilityStatus(
      issues,
      usesDirname,
      usesBundleRoot,
    );
    const explanation = this.generateExplanation(
      issues,
      usesDirname,
      usesBundleRoot,
      scannedFiles,
    );
    const recommendations = this.generateRecommendations(
      issues,
      usesDirname,
      usesBundleRoot,
    );

    this.logger.info(
      `Assessment complete: ${issues.length} portability issues found`,
    );

    // NEW: Analyze shell commands and platform coverage (Issue #9)
    const shellCommands = this.analyzeShellCommands(context);
    const platformCoverage = this.analyzePlatformCoverage(issues);

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
      // NEW: Enrichment fields (Issue #9)
      shellCommands,
      platformCoverage,
    };
  }

  /**
   * Analyze shell commands in source files for enrichment (Issue #9)
   */
  private analyzeShellCommands(context: AssessmentContext): Array<{
    command: string;
    isPortable: boolean;
    alternativeCommand?: string;
  }> {
    const commands: Map<
      string,
      { command: string; isPortable: boolean; alternativeCommand?: string }
    > = new Map();

    // Collect all source content to scan
    const contentsToScan: string[] = [];

    if (context.manifestRaw) {
      contentsToScan.push(context.manifestRaw);
    }

    if (context.packageJson) {
      const packageJson = context.packageJson as PackageJson;
      if (packageJson.scripts) {
        contentsToScan.push(JSON.stringify(packageJson.scripts));
      }
    }

    if (context.sourceCodeFiles && context.config.enableSourceCodeAnalysis) {
      for (const [, content] of context.sourceCodeFiles) {
        contentsToScan.push(content);
      }
    }

    // Scan content for shell commands with early termination per pattern
    for (const patternDef of SHELL_COMMAND_PATTERNS) {
      for (const content of contentsToScan) {
        // Reset lastIndex for global patterns
        patternDef.pattern.lastIndex = 0;
        if (patternDef.pattern.test(content)) {
          commands.set(patternDef.command, {
            command: patternDef.command,
            isPortable: patternDef.isPortable,
            alternativeCommand: patternDef.alternativeCommand,
          });
          break; // Found once, no need to check other content pieces
        }
      }
    }

    return Array.from(commands.values());
  }

  /**
   * Analyze platform coverage from detected issues (Issue #9)
   */
  private analyzePlatformCoverage(issues: PortabilityIssue[]): {
    supported: "all" | "windows" | "macos" | "linux";
    missing: string[];
  } {
    const missing: string[] = [];

    // Check for platform-specific issues
    const hasDarwinSpecific = issues.some(
      (i) => i.type === "platform_specific" && i.matchedText.includes("darwin"),
    );
    const hasWin32Specific = issues.some(
      (i) => i.type === "platform_specific" && i.matchedText.includes("win32"),
    );
    const hasLinuxSpecific = issues.some(
      (i) => i.type === "platform_specific" && i.matchedText.includes("linux"),
    );

    // Check for Unix-only paths
    const hasUnixPaths = issues.some(
      (i) =>
        (i.type === "absolute_path" || i.type === "user_home_path") &&
        (i.matchedText.startsWith("/") || i.matchedText.includes("~/")),
    );

    // Check for Windows-only paths
    const hasWindowsPaths = issues.some(
      (i) => i.type === "absolute_path" && /^[A-Z]:\\/.test(i.matchedText),
    );

    // Determine missing platforms
    if (hasUnixPaths && !hasWindowsPaths) {
      missing.push("windows");
    }
    if (hasWindowsPaths && !hasUnixPaths) {
      missing.push("macos", "linux");
    }
    if (hasDarwinSpecific && !hasWin32Specific && !hasLinuxSpecific) {
      if (!missing.includes("windows")) missing.push("windows");
      if (!missing.includes("linux")) missing.push("linux");
    }
    if (hasWin32Specific && !hasDarwinSpecific && !hasLinuxSpecific) {
      if (!missing.includes("macos")) missing.push("macos");
      if (!missing.includes("linux")) missing.push("linux");
    }
    if (hasLinuxSpecific && !hasDarwinSpecific && !hasWin32Specific) {
      if (!missing.includes("windows")) missing.push("windows");
      if (!missing.includes("macos")) missing.push("macos");
    }

    // Determine supported platforms with explicit precedence
    let supported: "all" | "windows" | "macos" | "linux" = "all";
    if (missing.length > 0) {
      // Determine the primary supported platform (explicit precedence)
      if (hasDarwinSpecific) {
        supported = "macos";
      } else if (hasLinuxSpecific) {
        supported = "linux";
      } else if (hasWin32Specific || hasWindowsPaths) {
        supported = "windows";
      } else if (hasUnixPaths) {
        // Unix paths without platform-specific code default to linux
        supported = "linux";
      }
    }

    return {
      supported,
      missing,
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
      const bundleRootMatches = line.match(
        ISSUE_PATTERNS.bundleRootAntipattern,
      );
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
          // Skip if it looks like a URL, comment, or shebang
          if (
            match.includes("://") ||
            line.trim().startsWith("//") ||
            line.trim().startsWith("*") ||
            line.trim().startsWith("#!")
          ) {
            continue;
          }
          issues.push({
            type: "absolute_path",
            filePath,
            lineNumber,
            matchedText: match,
            severity: "HIGH",
            recommendation:
              "Use relative paths or ${__dirname} for bundle portability",
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
            recommendation:
              "Use relative paths or path.join() for cross-platform support",
          });
        }
      }

      // Check for user home paths
      const homePathMatches = line.match(ISSUE_PATTERNS.userHomePath);
      if (homePathMatches) {
        for (const match of homePathMatches) {
          // Skip if in a comment
          if (
            line.trim().startsWith("//") ||
            line.trim().startsWith("*") ||
            line.trim().startsWith("#")
          ) {
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
          const hasElse = content
            .substring(content.indexOf(line))
            .includes("else");
          const hasDefault = content
            .substring(content.indexOf(line))
            .includes("default:");

          if (!hasElse && !hasDefault) {
            for (const match of matches) {
              issues.push({
                type: "platform_specific",
                filePath,
                lineNumber,
                matchedText: match,
                severity: "LOW",
                recommendation: "Consider adding fallback for other platforms",
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
    usesBundleRoot: boolean,
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
    scannedFiles: number,
  ): string {
    const parts: string[] = [];

    if (usesBundleRoot) {
      parts.push(
        "CRITICAL: Uses ${BUNDLE_ROOT} which is not supported in MCPB bundles.",
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
    usesBundleRoot: boolean,
  ): string[] {
    const recommendations: string[] = [];

    if (usesBundleRoot) {
      recommendations.push(
        "CRITICAL: Replace all ${BUNDLE_ROOT} with ${__dirname} - BUNDLE_ROOT variable is not supported in MCPB bundles.",
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
          `${first.filePath}:${first.lineNumber}: ${first.recommendation}`,
        );
      } else {
        recommendations.push(
          `${typeIssues.length} ${type.replace(/_/g, " ")} issues: ${first.recommendation}`,
        );
      }
    }

    if (recommendations.length === 0) {
      if (usesDirname) {
        recommendations.push(
          "Server uses proper relative paths with ${__dirname}. Good portability.",
        );
      } else {
        recommendations.push(
          "Consider using ${__dirname} for paths in manifest.json for better portability.",
        );
      }
    }

    return recommendations;
  }
}
