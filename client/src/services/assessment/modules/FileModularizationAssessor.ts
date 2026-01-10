/**
 * File Modularization Assessor (Issue #104)
 * Detects large monolithic tool files and recommends modularization
 *
 * Checks:
 * - Single file >1,000 lines (WARNING, MEDIUM severity)
 * - Single file >2,000 lines (ERROR, HIGH severity)
 * - Tool file with >10 tools (WARNING, MEDIUM severity)
 * - Tool file with >20 tools (ERROR, HIGH severity)
 * - No modular structure (INFO, LOW severity)
 *
 * Scoring:
 * - Starts at 100 points
 * - -15 per file >2,000 lines
 * - -8 per file 1,000-2,000 lines
 * - -12 per file with >20 tools
 * - -6 per file with 10-20 tools
 * - -10 for no modular structure
 * - +5 for tools/ subdirectory
 * - +3 for multiple tool files (>3)
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  FileModularizationAssessment,
  FileModularizationMetrics,
  LargeFileInfo,
  ModularizationCheck,
  FileSeverity,
  AssessmentStatus,
} from "@/lib/assessmentTypes";

/**
 * Tool detection patterns by language
 */
const TOOL_PATTERNS: Record<string, RegExp[]> = {
  python: [
    /@mcp\.tool/g, // FastMCP decorator
    /(?<!async\s)def\s+\w+_tool\s*\(/g, // Convention: *_tool functions (not async)
    /async\s+def\s+\w+_tool\s*\(/g, // Async tool functions
    /@server\.tool/g, // MCP server decorator
    /@app\.tool/g, // Alternative app-based decorator
  ],
  typescript: [
    /server\.tool\s*\(/g, // MCP SDK tool registration
    /\.setRequestHandler\s*\(/g, // Request handler pattern
    /tools\.push\s*\(/g, // Array-based registration
    /registerTool\s*\(/g, // Common pattern
    /\.addTool\s*\(/g, // Add tool pattern
  ],
  javascript: [
    /server\.tool\s*\(/g,
    /\.setRequestHandler\s*\(/g,
    /tools\.push\s*\(/g,
    /registerTool\s*\(/g,
    /\.addTool\s*\(/g,
  ],
  go: [
    /func\s+\w*Tool\s*\(/g, // Go tool functions
    /mcp\.NewTool\s*\(/g, // MCP Go SDK
    /tools\.Register\s*\(/g, // Tool registration
  ],
  rust: [
    /fn\s+\w+_tool\s*\(/g, // Rust tool functions
    /#\[tool\]/g, // Attribute macro
    /\.register_tool\s*\(/g, // Registration pattern
  ],
};

/**
 * File extension to language mapping
 */
const EXTENSION_TO_LANGUAGE: Record<string, string> = {
  ".py": "python",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".go": "go",
  ".rs": "rust",
};

/**
 * Thresholds for modularization checks
 */
const THRESHOLDS = {
  LINE_WARNING: 1000,
  LINE_ERROR: 2000,
  TOOL_COUNT_WARNING: 10,
  TOOL_COUNT_ERROR: 20,
};

export class FileModularizationAssessor extends BaseAssessor<FileModularizationAssessment> {
  /**
   * Run file modularization assessment
   */
  async assess(
    context: AssessmentContext,
  ): Promise<FileModularizationAssessment> {
    this.logger.info("Starting file modularization assessment");
    this.testCount = 0;

    // Check if source code analysis is enabled
    if (!context.sourceCodeFiles || !context.config.enableSourceCodeAnalysis) {
      this.logger.info(
        "Source code analysis not enabled, returning NEED_MORE_INFO",
      );
      return this.createSkippedResult();
    }

    // Analyze each source file
    const fileAnalyses = this.analyzeFiles(context.sourceCodeFiles);

    // Calculate metrics
    const metrics = this.calculateMetrics(fileAnalyses);

    // Run checks against thresholds
    const checks = this.runChecks(metrics, fileAnalyses);

    // Determine status based on checks
    const status = this.determineStatusFromChecks(checks);

    // Generate explanation and recommendations
    const explanation = this.generateExplanation(metrics, checks);
    const recommendations = this.generateRecommendations(metrics, fileAnalyses);

    this.logger.info(
      `Assessment complete: score=${metrics.modularizationScore}, status=${status}`,
    );

    return {
      metrics,
      checks,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Create result when source code is not available
   */
  private createSkippedResult(): FileModularizationAssessment {
    return {
      metrics: {
        totalSourceFiles: 0,
        totalLines: 0,
        largestFiles: [],
        filesOver1000Lines: 0,
        filesOver2000Lines: 0,
        filesWithOver10Tools: 0,
        filesWithOver20Tools: 0,
        hasModularStructure: false,
        modularizationScore: 0,
      },
      checks: [],
      status: "NEED_MORE_INFO",
      explanation:
        "Source code analysis not enabled. Enable enableSourceCodeAnalysis in config to run file modularization checks.",
      recommendations: [
        "Enable source code analysis by setting enableSourceCodeAnalysis: true in assessment config",
        "Provide sourceCodePath in assessment context to analyze file structure",
      ],
    };
  }

  /**
   * Analyze all source files
   */
  private analyzeFiles(
    sourceCodeFiles: Map<string, string>,
  ): Map<
    string,
    { lines: number; toolCount: number; language: string | null }
  > {
    const analyses = new Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >();

    for (const [filePath, content] of sourceCodeFiles) {
      if (!this.isSourceFile(filePath)) {
        continue;
      }

      this.testCount++;

      const lines = content.split("\n").length;
      const language = this.detectLanguage(filePath);
      const toolCount = this.countToolsInFile(content, language);

      analyses.set(filePath, { lines, toolCount, language });
    }

    return analyses;
  }

  /**
   * Check if file is a source file worth scanning
   */
  private isSourceFile(filePath: string): boolean {
    const sourceExtensions = Object.keys(EXTENSION_TO_LANGUAGE);

    // Skip test files, node_modules, and build artifacts
    // Check for paths containing these directories or starting with them
    if (
      filePath.includes("node_modules") ||
      filePath.includes(".test.") ||
      filePath.includes(".spec.") ||
      filePath.includes("__tests__") ||
      filePath.includes("__pycache__") ||
      filePath.includes("/dist/") ||
      filePath.includes("/build/") ||
      filePath.includes("/.venv/") ||
      filePath.includes("/venv/") ||
      filePath.startsWith("dist/") ||
      filePath.startsWith("build/") ||
      filePath.startsWith(".venv/") ||
      filePath.startsWith("venv/")
    ) {
      return false;
    }

    return sourceExtensions.some((ext) => filePath.endsWith(ext));
  }

  /**
   * Detect language from file extension
   */
  private detectLanguage(filePath: string): string | null {
    for (const [ext, lang] of Object.entries(EXTENSION_TO_LANGUAGE)) {
      if (filePath.endsWith(ext)) {
        return lang;
      }
    }
    return null;
  }

  /**
   * Count tool definitions in a file
   */
  private countToolsInFile(content: string, language: string | null): number {
    if (!language) return 0;

    const patterns = TOOL_PATTERNS[language] || [];
    let count = 0;

    for (const pattern of patterns) {
      // Reset lastIndex since we're using global flags
      pattern.lastIndex = 0;
      const matches = content.match(pattern);
      if (matches) {
        count += matches.length;
      }
    }

    return count;
  }

  /**
   * Calculate aggregated metrics
   */
  private calculateMetrics(
    fileAnalyses: Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >,
  ): FileModularizationMetrics {
    const largestFiles: LargeFileInfo[] = [];
    let totalLines = 0;
    let filesOver1000Lines = 0;
    let filesOver2000Lines = 0;
    let filesWithOver10Tools = 0;
    let filesWithOver20Tools = 0;

    for (const [filePath, analysis] of fileAnalyses) {
      totalLines += analysis.lines;

      // Check line count thresholds
      if (analysis.lines > THRESHOLDS.LINE_ERROR) {
        filesOver2000Lines++;
        filesOver1000Lines++; // Also counts for 1000+ threshold
      } else if (analysis.lines > THRESHOLDS.LINE_WARNING) {
        filesOver1000Lines++;
      }

      // Check tool count thresholds
      if (analysis.toolCount > THRESHOLDS.TOOL_COUNT_ERROR) {
        filesWithOver20Tools++;
        filesWithOver10Tools++; // Also counts for 10+ threshold
      } else if (analysis.toolCount > THRESHOLDS.TOOL_COUNT_WARNING) {
        filesWithOver10Tools++;
      }

      // Track large files for reporting
      if (
        analysis.lines > THRESHOLDS.LINE_WARNING ||
        analysis.toolCount > THRESHOLDS.TOOL_COUNT_WARNING
      ) {
        const severity = this.determineSeverity(
          analysis.lines,
          analysis.toolCount,
        );
        const recommendation = this.generateFileRecommendation(
          filePath,
          analysis.lines,
          analysis.toolCount,
        );

        largestFiles.push({
          path: filePath,
          lines: analysis.lines,
          toolCount: analysis.toolCount,
          severity,
          recommendation,
        });
      }
    }

    // Sort by lines descending
    largestFiles.sort((a, b) => b.lines - a.lines);

    // Check for modular structure
    const hasModularStructure = this.checkModularStructure(fileAnalyses);

    // Calculate modularization score
    const modularizationScore = this.calculateScore(
      filesOver1000Lines,
      filesOver2000Lines,
      filesWithOver10Tools,
      filesWithOver20Tools,
      hasModularStructure,
      fileAnalyses,
    );

    return {
      totalSourceFiles: fileAnalyses.size,
      totalLines,
      largestFiles,
      filesOver1000Lines,
      filesOver2000Lines,
      filesWithOver10Tools,
      filesWithOver20Tools,
      hasModularStructure,
      modularizationScore,
    };
  }

  /**
   * Determine severity for a file
   */
  private determineSeverity(lines: number, toolCount: number): FileSeverity {
    // HIGH if either threshold is exceeded at error level
    if (
      lines > THRESHOLDS.LINE_ERROR ||
      toolCount > THRESHOLDS.TOOL_COUNT_ERROR
    ) {
      return "HIGH";
    }
    // MEDIUM if warning thresholds are exceeded
    if (
      lines > THRESHOLDS.LINE_WARNING ||
      toolCount > THRESHOLDS.TOOL_COUNT_WARNING
    ) {
      return "MEDIUM";
    }
    return "LOW";
  }

  /**
   * Generate recommendation for a specific file
   */
  private generateFileRecommendation(
    filePath: string,
    lines: number,
    toolCount: number,
  ): string {
    const fileName = filePath.split("/").pop() || filePath;
    const parts: string[] = [];

    if (lines > THRESHOLDS.LINE_ERROR) {
      parts.push(
        `Split ${fileName} (${lines} lines) into smaller modules of <500 lines each`,
      );
    } else if (lines > THRESHOLDS.LINE_WARNING) {
      parts.push(
        `Consider splitting ${fileName} (${lines} lines) to improve maintainability`,
      );
    }

    if (toolCount > THRESHOLDS.TOOL_COUNT_ERROR) {
      parts.push(
        `Separate ${toolCount} tools into category-based modules (e.g., tools/auth/, tools/data/)`,
      );
    } else if (toolCount > THRESHOLDS.TOOL_COUNT_WARNING) {
      parts.push(
        `Consider grouping ${toolCount} tools into logical categories`,
      );
    }

    return parts.join(". ");
  }

  /**
   * Check if codebase has modular structure
   */
  private checkModularStructure(
    fileAnalyses: Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >,
  ): boolean {
    const filePaths = Array.from(fileAnalyses.keys());

    // Check for tools/ subdirectory pattern
    const hasToolsDir = filePaths.some(
      (f) => f.includes("/tools/") || f.includes("\\tools\\"),
    );

    // Check for multiple tool files (not all tools in one file)
    const toolFiles = Array.from(fileAnalyses.entries()).filter(
      ([, analysis]) => analysis.toolCount > 0,
    );

    // Has modular structure if: has tools/ dir OR has 3+ tool files
    return hasToolsDir || toolFiles.length >= 3;
  }

  /**
   * Calculate modularization score (0-100)
   */
  private calculateScore(
    filesOver1000Lines: number,
    filesOver2000Lines: number,
    filesWithOver10Tools: number,
    filesWithOver20Tools: number,
    hasModularStructure: boolean,
    fileAnalyses: Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >,
  ): number {
    let score = 100;

    // Deductions
    score -= filesOver2000Lines * 15; // -15 per file >2000 lines
    score -= (filesOver1000Lines - filesOver2000Lines) * 8; // -8 per file 1000-2000 lines
    score -= filesWithOver20Tools * 12; // -12 per file with >20 tools
    score -= (filesWithOver10Tools - filesWithOver20Tools) * 6; // -6 per file 10-20 tools

    if (!hasModularStructure) {
      score -= 10; // -10 for no modular structure
    }

    // Positive signals (bonuses)
    const filePaths = Array.from(fileAnalyses.keys());
    const hasToolsDir = filePaths.some(
      (f) => f.includes("/tools/") || f.includes("\\tools\\"),
    );
    const hasSharedUtils = filePaths.some(
      (f) =>
        f.includes("_common.") ||
        f.includes("shared.") ||
        f.includes("utils.") ||
        f.includes("helpers."),
    );
    const toolFilesCount = Array.from(fileAnalyses.values()).filter(
      (a) => a.toolCount > 0,
    ).length;

    if (hasToolsDir) score += 5; // +5 for tools/ subdirectory
    if (toolFilesCount > 3) score += 3; // +3 for multiple tool files
    if (hasSharedUtils) score += 2; // +2 for shared utilities

    // Clamp to 0-100
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Run threshold checks
   */
  private runChecks(
    metrics: FileModularizationMetrics,
    _fileAnalyses: Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >,
  ): ModularizationCheck[] {
    const checks: ModularizationCheck[] = [];

    // Check 1: Files over 2000 lines (HIGH severity)
    checks.push({
      checkName: "file_line_count_error",
      passed: metrics.filesOver2000Lines === 0,
      severity: "HIGH",
      evidence:
        metrics.filesOver2000Lines > 0
          ? `${metrics.filesOver2000Lines} file(s) exceed 2000 lines`
          : "No files exceed 2000 lines",
      threshold: THRESHOLDS.LINE_ERROR,
      actualValue: metrics.filesOver2000Lines,
    });

    // Check 2: Files over 1000 lines (MEDIUM severity)
    const filesOnlyOver1000 =
      metrics.filesOver1000Lines - metrics.filesOver2000Lines;
    checks.push({
      checkName: "file_line_count_warning",
      passed: filesOnlyOver1000 === 0,
      severity: "MEDIUM",
      evidence:
        filesOnlyOver1000 > 0
          ? `${filesOnlyOver1000} file(s) exceed 1000 lines`
          : "No additional files exceed 1000 lines",
      threshold: THRESHOLDS.LINE_WARNING,
      actualValue: filesOnlyOver1000,
    });

    // Check 3: Files with >20 tools (HIGH severity)
    checks.push({
      checkName: "tool_count_error",
      passed: metrics.filesWithOver20Tools === 0,
      severity: "HIGH",
      evidence:
        metrics.filesWithOver20Tools > 0
          ? `${metrics.filesWithOver20Tools} file(s) contain more than 20 tools`
          : "No files contain more than 20 tools",
      threshold: THRESHOLDS.TOOL_COUNT_ERROR,
      actualValue: metrics.filesWithOver20Tools,
    });

    // Check 4: Files with >10 tools (MEDIUM severity)
    const filesOnlyOver10Tools =
      metrics.filesWithOver10Tools - metrics.filesWithOver20Tools;
    checks.push({
      checkName: "tool_count_warning",
      passed: filesOnlyOver10Tools === 0,
      severity: "MEDIUM",
      evidence:
        filesOnlyOver10Tools > 0
          ? `${filesOnlyOver10Tools} file(s) contain more than 10 tools`
          : "No additional files contain more than 10 tools",
      threshold: THRESHOLDS.TOOL_COUNT_WARNING,
      actualValue: filesOnlyOver10Tools,
    });

    // Check 5: Modular structure (LOW severity, info)
    checks.push({
      checkName: "modular_structure",
      passed: metrics.hasModularStructure,
      severity: "LOW",
      evidence: metrics.hasModularStructure
        ? "Codebase has modular structure (tools/ directory or multiple tool files)"
        : "No modular structure detected - all tools appear to be in single file",
    });

    return checks;
  }

  /**
   * Determine status from checks
   */
  private determineStatusFromChecks(
    checks: ModularizationCheck[],
  ): AssessmentStatus {
    // FAIL if any HIGH severity check fails
    const highSeverityFailed = checks.some(
      (c) => !c.passed && c.severity === "HIGH",
    );
    if (highSeverityFailed) {
      return "FAIL";
    }

    // NEED_MORE_INFO if any MEDIUM severity check fails
    const mediumSeverityFailed = checks.some(
      (c) => !c.passed && c.severity === "MEDIUM",
    );
    if (mediumSeverityFailed) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    metrics: FileModularizationMetrics,
    checks: ModularizationCheck[],
  ): string {
    const parts: string[] = [];

    parts.push(
      `Analyzed ${metrics.totalSourceFiles} source files (${metrics.totalLines} total lines).`,
    );
    parts.push(`Modularization score: ${metrics.modularizationScore}/100.`);

    const failedChecks = checks.filter((c) => !c.passed);
    if (failedChecks.length === 0) {
      parts.push(
        "All modularization checks passed. Code structure appears well-organized.",
      );
    } else {
      const highFailed = failedChecks.filter((c) => c.severity === "HIGH");
      const mediumFailed = failedChecks.filter((c) => c.severity === "MEDIUM");

      if (highFailed.length > 0) {
        parts.push(
          `ERROR: ${highFailed.length} high-severity issue(s) - files are too large or contain too many tools.`,
        );
      }
      if (mediumFailed.length > 0) {
        parts.push(
          `WARNING: ${mediumFailed.length} medium-severity issue(s) - consider refactoring for better maintainability.`,
        );
      }
    }

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    metrics: FileModularizationMetrics,
    _fileAnalyses: Map<
      string,
      { lines: number; toolCount: number; language: string | null }
    >,
  ): string[] {
    const recommendations: string[] = [];

    // Add specific file recommendations
    for (const file of metrics.largestFiles) {
      if (file.severity === "HIGH") {
        recommendations.push(`HIGH: ${file.recommendation}`);
      }
    }

    // Add general recommendations based on checks
    if (metrics.filesOver2000Lines > 0) {
      recommendations.push(
        "Split large files (>2000 lines) into smaller modules to improve maintainability and IDE performance.",
      );
    }

    if (metrics.filesWithOver20Tools > 0) {
      recommendations.push(
        "Group tools by category (e.g., auth tools, data tools, utility tools) into separate modules.",
      );
    }

    if (!metrics.hasModularStructure) {
      recommendations.push(
        "Create a tools/ subdirectory to organize tool implementations by category.",
      );
      recommendations.push(
        "Extract shared utilities into a common module (e.g., _common.py, shared.ts).",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Code structure is well-modularized. Continue following current patterns.",
      );
    }

    return recommendations;
  }
}
