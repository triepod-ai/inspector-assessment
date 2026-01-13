/**
 * Module Scoring Helpers
 *
 * Shared utilities for calculating module scores and normalizing module names.
 * Used by both the AssessmentOrchestrator (client) and CLI runners (scripts).
 */

import packageJson from "../../package.json" with { type: "json" };

/**
 * Normalize module name to snake_case key for consistent machine parsing.
 * Examples: "Functionality" -> "functionality", "Error Handling" -> "error_handling"
 */
export function normalizeModuleKey(moduleName: string): string {
  return moduleName.toLowerCase().replace(/ /g, "_");
}

/**
 * Calculate module score from assessment result.
 * Handles different result shapes from different assessors.
 * This centralizes score calculation logic used by the orchestrator.
 *
 * Returns null for undefined/missing results (e.g., skipped modules via --skip-modules).
 * Callers should check for null and skip emission/display for skipped modules.
 */
export function calculateModuleScore(result: unknown): number | null {
  if (!result || typeof result !== "object") return null;
  const r = result as Record<string, unknown>;

  // Issue #154: Handle skipped modules - return null to exclude from scoring
  // Modules that couldn't execute (e.g., prohibitedLibraries without source files)
  // should not contribute to overall score calculations
  if (r.skipped === true) {
    return null;
  }

  // ErrorHandling module - validate test execution before scoring (Issue #153)
  const metrics = r.metrics as Record<string, unknown> | undefined;
  if (metrics?.mcpComplianceScore !== undefined) {
    const metadata = r.testExecutionMetadata as
      | {
          totalTestsAttempted?: number;
          validTestsCompleted?: number;
          connectionErrorCount?: number;
          testCoveragePercent?: number;
        }
      | undefined;

    // If we have metadata, validate test execution
    if (metadata) {
      const {
        validTestsCompleted = 0,
        connectionErrorCount = 0,
        testCoveragePercent = 0,
      } = metadata;

      // Case 1: All tests failed due to connection errors
      // Return 0 score - can't verify error handling without successful test execution
      // Note: validTestsCompleted=0 with connectionErrorCount=0 is allowed
      // (e.g., no tools selected for testing - uses normal scoring)
      if (validTestsCompleted === 0 && connectionErrorCount > 0) {
        return 0;
      }

      // Case 2: Significant connection errors (>50% failure)
      // Cap score at 50 - partial coverage means partial confidence
      if (testCoveragePercent < 50 && connectionErrorCount > 0) {
        const baseScore = Math.round(metrics.mcpComplianceScore as number);
        return Math.min(50, baseScore);
      }
    }

    return Math.round(metrics.mcpComplianceScore as number);
  }
  // MCPSpecCompliance module - uses complianceScore
  if (r.complianceScore !== undefined) {
    return Math.round(r.complianceScore as number);
  }
  // Functionality module - uses coveragePercentage
  if (r.coveragePercentage !== undefined) {
    return Math.round(r.coveragePercentage as number);
  }
  // Security module - validate test execution before scoring (Issue #152)
  if (Array.isArray(r.vulnerabilities)) {
    const vulnCount = r.vulnerabilities.length;
    const metadata = r.testExecutionMetadata as
      | {
          totalTestsAttempted?: number;
          validTestsCompleted?: number;
          connectionErrorCount?: number;
          testCoveragePercent?: number;
        }
      | undefined;

    // If we have metadata, validate test execution
    if (metadata) {
      const {
        validTestsCompleted = 0,
        connectionErrorCount = 0,
        testCoveragePercent = 0,
      } = metadata;

      // Case 1: All tests failed due to connection errors
      // Return 0 score - can't verify security without successful test execution
      // Note: validTestsCompleted=0 with connectionErrorCount=0 is allowed
      // (e.g., server has no security-relevant tools - uses normal scoring)
      if (validTestsCompleted === 0 && connectionErrorCount > 0) {
        return 0;
      }

      // Case 2: Significant connection errors (>50% failure)
      // Cap score at 50 - partial coverage means partial confidence
      if (testCoveragePercent < 50 && connectionErrorCount > 0) {
        const baseScore =
          vulnCount === 0 ? 100 : Math.max(0, 100 - vulnCount * 10);
        return Math.min(50, baseScore);
      }
    }

    // Normal case: good test coverage, calculate based on vulnerabilities
    return vulnCount === 0 ? 100 : Math.max(0, 100 - vulnCount * 10);
  }
  // AUP module - 100% if no violations, lower based on violation count
  if (Array.isArray(r.violations)) {
    const violationCount = r.violations.length;
    return violationCount === 0 ? 100 : Math.max(0, 100 - violationCount * 10);
  }
  // DeveloperExperience module (Issue #124) - uses pre-computed score
  // Also handles any module with a direct score field
  if (typeof r.score === "number") {
    return Math.round(r.score);
  }
  // Default: derive from status field
  return r.status === "PASS" ? 100 : r.status === "FAIL" ? 0 : 50;
}

/**
 * Current inspector-assessment version for event compatibility checking.
 * Dynamically imported from package.json to stay in sync.
 */
export const INSPECTOR_VERSION = packageJson.version;

/**
 * Schema version for JSONL events.
 * Increment when event structure changes to enable consumers to handle
 * schema evolution gracefully.
 *
 * This is the single source of truth - imported by:
 * - scripts/lib/jsonl-events.ts
 * - cli/src/lib/jsonl-events.ts
 * - client/src/services/assessment/orchestratorHelpers.ts
 *
 * Version History:
 * - v1: Initial schema
 * - v2: Added TestValidityWarningEvent (Issue #134)
 * - v3: Added Stage B enrichment for Claude semantic analysis (Issue #137)
 */
export const SCHEMA_VERSION = 3;
