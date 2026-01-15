/**
 * Annotation-Aware Severity Adjustment
 *
 * Reduces false positives by considering tool annotations when scoring
 * vulnerability severity.
 *
 * Issue #170: Security module should consider tool annotations to reduce
 * false positives for read-only servers.
 *
 * @module securityTests/AnnotationAwareSeverity
 */

import type {
  SecurityAnnotations,
  SecurityRiskLevel,
} from "@/lib/assessment/coreTypes";

/**
 * Attack patterns that should be downgraded for read-only tools.
 * These involve code/command execution which read-only tools cannot perform.
 */
const EXECUTION_TYPE_ATTACKS = [
  "Command Injection", // RCE via shell commands
  "Calculator Injection", // Code evaluation via calculator
  "Code Execution", // Direct code execution
  "Path Traversal", // File system modification
  "Cross-Tool State Bypass", // State manipulation attacks
  "Chained Exploitation", // Multi-tool execution chains
  "Tool Output Injection", // Output tampering
  "Nested Injection", // Recursive injection attacks
  "Auth Bypass", // Authentication manipulation
  "Session Management", // Session state modification
];

/**
 * Attack patterns that should be downgraded for closed-world tools.
 * These involve external network access which closed-world tools don't have.
 */
const EXFILTRATION_TYPE_ATTACKS = [
  "Indirect Prompt Injection", // External content injection
  "Data Exfiltration", // Data leakage to external services
  "Token Theft", // Credential exfiltration
  "Secret Leakage", // Sensitive data exposure
  "SSRF", // Server-side request forgery
];

/**
 * Result of annotation-aware severity adjustment.
 */
export interface SeverityAdjustment {
  /** Adjusted risk level after considering annotations */
  adjustedRiskLevel: SecurityRiskLevel;
  /** Whether an adjustment was made */
  wasAdjusted: boolean;
  /** Reason for adjustment (human-readable) */
  adjustmentReason?: string;
  /** Original risk level before adjustment */
  originalRiskLevel: SecurityRiskLevel;
}

/**
 * Adjust vulnerability severity based on tool annotations.
 *
 * This function implements the false positive reduction logic from Issue #170.
 * Read-only tools (readOnlyHint=true) have execution-type vulnerabilities
 * downgraded to LOW, and closed-world tools (openWorldHint=false) have
 * exfiltration-type vulnerabilities downgraded to LOW.
 *
 * @param attackName - Name of the attack pattern (e.g., "Command Injection")
 * @param originalRiskLevel - Original risk level from payload definition
 * @param toolAnnotations - Extracted annotations for this specific tool
 * @param serverIsReadOnly - Whether ALL server tools are read-only
 * @param serverIsClosed - Whether ALL server tools are closed-world
 * @returns SeverityAdjustment with potentially adjusted risk level
 *
 * @example
 * ```typescript
 * const adjustment = adjustSeverityForAnnotations(
 *   "Command Injection",
 *   "HIGH",
 *   { readOnlyHint: true, source: "mcp" },
 *   true,
 *   false
 * );
 * // adjustment.wasAdjusted === true
 * // adjustment.adjustedRiskLevel === "LOW"
 * ```
 */
export function adjustSeverityForAnnotations(
  attackName: string,
  originalRiskLevel: SecurityRiskLevel,
  toolAnnotations: SecurityAnnotations | undefined,
  serverIsReadOnly: boolean,
  serverIsClosed: boolean,
): SeverityAdjustment {
  // Check if we have valid per-tool annotations
  const hasValidAnnotations =
    toolAnnotations && toolAnnotations.source !== "none";

  // Check 1: Per-tool read-only for execution-type attacks
  // If tool declares readOnlyHint=true, it cannot execute commands
  if (hasValidAnnotations && toolAnnotations.readOnlyHint === true) {
    if (isExecutionTypeAttack(attackName)) {
      return {
        adjustedRiskLevel: "LOW",
        wasAdjusted: true,
        adjustmentReason: `Tool has readOnlyHint=true; ${attackName} downgraded from ${originalRiskLevel} to LOW (cannot execute)`,
        originalRiskLevel,
      };
    }
  }

  // Check 2: Per-tool closed-world for exfiltration-type attacks
  // If tool declares openWorldHint=false, it cannot access external resources
  if (hasValidAnnotations && toolAnnotations.openWorldHint === false) {
    if (isExfiltrationType(attackName)) {
      return {
        adjustedRiskLevel: "LOW",
        wasAdjusted: true,
        adjustmentReason: `Tool has openWorldHint=false; ${attackName} downgraded from ${originalRiskLevel} to LOW (no external access)`,
        originalRiskLevel,
      };
    }
  }

  // Check 3: Server-level read-only flag provides additional context
  // Even if specific tool annotation is missing, server-level flag applies
  if (serverIsReadOnly && isExecutionTypeAttack(attackName)) {
    return {
      adjustedRiskLevel: "LOW",
      wasAdjusted: true,
      adjustmentReason: `Server is 100% read-only; ${attackName} downgraded from ${originalRiskLevel} to LOW`,
      originalRiskLevel,
    };
  }

  // Check 4: Server-level closed flag
  if (serverIsClosed && isExfiltrationType(attackName)) {
    return {
      adjustedRiskLevel: "LOW",
      wasAdjusted: true,
      adjustmentReason: `Server is 100% closed-world; ${attackName} downgraded from ${originalRiskLevel} to LOW`,
      originalRiskLevel,
    };
  }

  // No adjustment needed
  return {
    adjustedRiskLevel: originalRiskLevel,
    wasAdjusted: false,
    originalRiskLevel,
  };
}

/**
 * Check if attack name matches execution-type patterns.
 * Only checks if attackName contains the pattern (not bidirectional)
 * to prevent security bypass (e.g., "command" matching "Command Injection").
 */
function isExecutionTypeAttack(attackName: string): boolean {
  return EXECUTION_TYPE_ATTACKS.some((pattern) =>
    attackName.toLowerCase().includes(pattern.toLowerCase()),
  );
}

/**
 * Check if attack name matches exfiltration-type patterns.
 * Only checks if attackName contains the pattern (not bidirectional)
 * to prevent security bypass.
 */
function isExfiltrationType(attackName: string): boolean {
  return EXFILTRATION_TYPE_ATTACKS.some((pattern) =>
    attackName.toLowerCase().includes(pattern.toLowerCase()),
  );
}
