/**
 * Module Scoring Helpers
 *
 * Shared utilities for calculating module scores and normalizing module names.
 * Used by both the AssessmentOrchestrator (client) and CLI runners (scripts).
 */

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
 */
export function calculateModuleScore(result: unknown): number {
  if (!result || typeof result !== "object") return 50;
  const r = result as Record<string, unknown>;

  // ErrorHandling module - uses metrics.mcpComplianceScore
  const metrics = r.metrics as Record<string, unknown> | undefined;
  if (metrics?.mcpComplianceScore !== undefined) {
    return Math.round(metrics.mcpComplianceScore as number);
  }
  // MCPSpecCompliance module - uses complianceScore
  if (r.complianceScore !== undefined) {
    return Math.round(r.complianceScore as number);
  }
  // Functionality module - uses workingPercentage
  if (r.workingPercentage !== undefined) {
    return Math.round(r.workingPercentage as number);
  }
  // Security module - 100% if no vulns, lower based on vuln count
  if (Array.isArray(r.vulnerabilities)) {
    const vulnCount = r.vulnerabilities.length;
    return vulnCount === 0 ? 100 : Math.max(0, 100 - vulnCount * 10);
  }
  // AUP module - 100% if no violations, lower based on violation count
  if (Array.isArray(r.violations)) {
    const violationCount = r.violations.length;
    return violationCount === 0 ? 100 : Math.max(0, 100 - violationCount * 10);
  }
  // Default: derive from status field
  return r.status === "PASS" ? 100 : r.status === "FAIL" ? 0 : 50;
}

/**
 * Current inspector-assessment version for event compatibility checking.
 * This should match the version in package.json.
 */
export const INSPECTOR_VERSION = "1.20.2";
