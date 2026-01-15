/**
 * Security Patterns Module
 *
 * Backend API Security Patterns for MCP server security testing.
 * Modularized from monolithic securityPatterns.ts (2,202 lines).
 * Maintains full backward compatibility via re-exports.
 *
 * @module securityPatterns
 */

// Types
export type { SecurityPayload, AttackPattern } from "./types";

// Pattern collections (for direct access to specific categories)
export { INJECTION_PATTERNS } from "./injectionPatterns";
export { VALIDATION_PATTERNS } from "./validationPatterns";
export { TOOL_SPECIFIC_PATTERNS } from "./toolSpecificPatterns";
export { RESOURCE_EXHAUSTION_PATTERNS } from "./resourceExhaustionPatterns";
export { AUTH_SESSION_PATTERNS } from "./authSessionPatterns";
export { ADVANCED_EXPLOIT_PATTERNS } from "./advancedExploitPatterns";

// Aggregated patterns and utilities (backward compatible)
export {
  SECURITY_ATTACK_PATTERNS,
  getPayloadsForAttack,
  getAllAttackPatterns,
  getPatternStatistics,
} from "./utils";
