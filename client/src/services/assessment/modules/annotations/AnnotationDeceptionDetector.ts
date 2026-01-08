/**
 * Annotation Deception Detector
 * High-confidence deception detection for obvious annotation misalignments
 *
 * Extracted from ToolAnnotationAssessor.ts for maintainability.
 * Handles keyword-based misalignment detection.
 */

/**
 * Keywords that contradict readOnlyHint=true (these tools modify state)
 */
export const READONLY_CONTRADICTION_KEYWORDS = [
  // Execution keywords - tools that execute code/commands are never read-only
  "exec",
  "execute",
  "run",
  "shell",
  "command",
  "cmd",
  "spawn",
  "invoke",
  // Write/modify keywords
  "write",
  "create",
  "delete",
  "remove",
  "modify",
  "update",
  "edit",
  "change",
  "set",
  "put",
  "patch",
  // Deployment/installation keywords
  "install",
  "deploy",
  "upload",
  "push",
  // Communication keywords (sending data)
  "send",
  "post",
  "submit",
  "publish",
  // Destructive keywords
  "destroy",
  "drop",
  "purge",
  "wipe",
  "clear",
  "truncate",
  "reset",
  "kill",
  "terminate",
];

/**
 * Suffixes that exempt "run" from readOnlyHint contradiction detection.
 * Tools matching "run" + these suffixes are legitimately read-only (fetch analysis data).
 * Issue #18: browser-tools-mcp uses runAccessibilityAudit, runSEOAudit, etc.
 */
export const RUN_READONLY_EXEMPT_SUFFIXES = [
  "audit", // runAccessibilityAudit, runPerformanceAudit, runSEOAudit
  "check", // runHealthCheck, runSecurityCheck
  "mode", // runAuditMode, runDebuggerMode
  "test", // runTest, runUnitTest (analysis, not execution)
  "scan", // runSecurityScan, runVulnerabilityScan
  "analyze", // runAnalyze, runCodeAnalyze
  "report", // runReport, runStatusReport
  "status", // runStatus, runHealthStatus
  "validate", // runValidate, runSchemaValidate
  "verify", // runVerify, runIntegrityVerify
  "inspect", // runInspect, runCodeInspect
  "lint", // runLint, runEslint
  "benchmark", // runBenchmark, runPerfBenchmark
  "diagnostic", // runDiagnostic
];

/**
 * Keywords that contradict destructiveHint=false (these tools delete/destroy data)
 */
export const DESTRUCTIVE_CONTRADICTION_KEYWORDS = [
  "delete",
  "remove",
  "drop",
  "destroy",
  "purge",
  "wipe",
  "erase",
  "truncate",
  "clear",
  "reset",
  "kill",
  "terminate",
  "revoke",
  "cancel",
  "force",
];

/**
 * Deception detection result
 */
export interface DeceptionResult {
  field: "readOnlyHint" | "destructiveHint";
  matchedKeyword: string;
  reason: string;
}

/**
 * Check if a tool name contains any of the given keywords (case-insensitive)
 * Uses word segment matching to avoid false positives (e.g., "put" in "output")
 * Issue #25: Substring matching caused false positives for words like "output", "input", "compute"
 *
 * Handles: camelCase (putFile), snake_case (put_file), kebab-case (put-file), PascalCase (PutFile)
 */
export function containsKeyword(
  toolName: string,
  keywords: string[],
): string | null {
  // Normalize camelCase/PascalCase by inserting separator before uppercase letters
  // "putFile" → "put_File", "updateUser" → "update_User", "GetOutput" → "Get_Output"
  const normalized = toolName.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();

  // Split by common separators (underscore, hyphen)
  const segments = normalized.split(/[_-]/);

  for (const keyword of keywords) {
    for (const segment of segments) {
      // Match if segment equals keyword or starts with keyword
      // This handles: "exec" matches "exec" segment, "exec_command" segment starts with "exec"
      if (segment === keyword || segment.startsWith(keyword)) {
        return keyword;
      }
    }
  }
  return null;
}

/**
 * Check if a tool name with "run" keyword is exempt from readOnlyHint contradiction.
 * Tools like "runAccessibilityAudit" are genuinely read-only (fetch analysis data).
 * Issue #18: Prevents false positives for analysis/audit tools.
 */
export function isRunKeywordExempt(toolName: string): boolean {
  const lowerName = toolName.toLowerCase();
  // Only applies when "run" is detected
  if (!lowerName.includes("run")) {
    return false;
  }
  // Check if any exempt suffix is present
  return RUN_READONLY_EXEMPT_SUFFIXES.some((suffix) =>
    lowerName.includes(suffix),
  );
}

/**
 * Type guard for confidence levels that warrant event emission or status changes.
 * Uses positive check for acceptable levels (safer than !== "low" if new levels added).
 */
export function isActionableConfidence(confidence: string): boolean {
  return confidence === "high" || confidence === "medium";
}

/**
 * Detect high-confidence annotation deception
 * Returns misalignment info if obvious deception detected, null otherwise
 */
export function detectAnnotationDeception(
  toolName: string,
  annotations: { readOnlyHint?: boolean; destructiveHint?: boolean },
): DeceptionResult | null {
  // Check readOnlyHint=true contradiction
  if (annotations.readOnlyHint === true) {
    const keyword = containsKeyword(toolName, READONLY_CONTRADICTION_KEYWORDS);
    if (keyword) {
      // Issue #18: Skip deception flagging for "run" + analysis suffix combinations
      // Tools like "runAccessibilityAudit" are genuinely read-only
      if (keyword === "run" && isRunKeywordExempt(toolName)) {
        // Tool matches "run" but has an analysis suffix - not deceptive
        // Fall through to normal pattern-based inference
      } else {
        return {
          field: "readOnlyHint",
          matchedKeyword: keyword,
          reason: `Tool name contains '${keyword}' but claims readOnlyHint=true - this is likely deceptive`,
        };
      }
    }
  }

  // Check destructiveHint=false contradiction
  if (annotations.destructiveHint === false) {
    const keyword = containsKeyword(
      toolName,
      DESTRUCTIVE_CONTRADICTION_KEYWORDS,
    );
    if (keyword) {
      return {
        field: "destructiveHint",
        matchedKeyword: keyword,
        reason: `Tool name contains '${keyword}' but claims destructiveHint=false - this is likely deceptive`,
      };
    }
  }

  return null;
}
