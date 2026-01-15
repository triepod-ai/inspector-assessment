/**
 * Security Patterns Utilities
 *
 * Aggregates all pattern modules and provides utility functions
 * for accessing and analyzing security patterns.
 */

import { AttackPattern, SecurityPayload } from "./types";
import { INJECTION_PATTERNS } from "./injectionPatterns";
import { VALIDATION_PATTERNS } from "./validationPatterns";
import { TOOL_SPECIFIC_PATTERNS } from "./toolSpecificPatterns";
import { RESOURCE_EXHAUSTION_PATTERNS } from "./resourceExhaustionPatterns";
import { AUTH_SESSION_PATTERNS } from "./authSessionPatterns";
import { ADVANCED_EXPLOIT_PATTERNS } from "./advancedExploitPatterns";

/**
 * ========================================
 * BACKEND API SECURITY PATTERNS
 * ========================================
 *
 * 32 focused patterns for MCP server API security
 *
 * Architecture: Attack-Type with Specific Payloads
 * - Critical Injection (6 patterns): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
 * - Input Validation (3 patterns): Type Safety, Boundary Testing, Required Fields
 * - Protocol Compliance (2 patterns): MCP Error Format, Timeout Handling
 * - Tool-Specific Vulnerabilities (7 patterns): SSRF, Unicode, Nested, Package, Exfil, Config, Shadow
 * - Resource Exhaustion (2 patterns): DoS/Resource Exhaustion, Insecure Deserialization
 * - Auth & Session (5 patterns): Token Theft, Permission Scope, Code Execution, Auth Bypass, Session Management
 * - Advanced Exploits (7 patterns): State Bypass, Chain, Output Injection, Secret, Blacklist, Crypto, Permissions
 *
 * Scope: Backend API Security ONLY
 * - Tests structured data inputs to API endpoints
 * - Validates server-side security controls
 * - Tests MCP protocol compliance
 * - Tests tool-specific vulnerability patterns with parameter-aware payloads
 *
 * Out of Scope: LLM Prompt Injection
 * - MCP servers are APIs that receive structured data, not prompts
 * - If a server uses an LLM internally, that's the LLM's responsibility
 * - We test the MCP API layer, not the LLM behavior layer
 */
export const SECURITY_ATTACK_PATTERNS: AttackPattern[] = [
  ...INJECTION_PATTERNS,
  ...VALIDATION_PATTERNS,
  ...TOOL_SPECIFIC_PATTERNS,
  ...RESOURCE_EXHAUSTION_PATTERNS,
  ...AUTH_SESSION_PATTERNS,
  ...ADVANCED_EXPLOIT_PATTERNS,
];

/**
 * Get all payloads for an attack type
 */
export function getPayloadsForAttack(
  attackName: string,
  limit?: number,
): SecurityPayload[] {
  const pattern = SECURITY_ATTACK_PATTERNS.find(
    (p) => p.attackName === attackName,
  );
  if (!pattern) return [];

  const payloads = pattern.payloads;
  return limit ? payloads.slice(0, limit) : payloads;
}

/**
 * Get all attack patterns (for testing all tools)
 */
export function getAllAttackPatterns(): AttackPattern[] {
  return SECURITY_ATTACK_PATTERNS;
}

/**
 * Get pattern statistics
 */
export function getPatternStatistics() {
  const totalAttackTypes = SECURITY_ATTACK_PATTERNS.length;
  let totalPayloads = 0;
  let highRiskPayloads = 0;
  let mediumRiskPayloads = 0;
  let lowRiskPayloads = 0;

  const payloadTypeBreakdown: Record<string, number> = {};

  SECURITY_ATTACK_PATTERNS.forEach((pattern) => {
    totalPayloads += pattern.payloads.length;
    pattern.payloads.forEach((payload) => {
      if (payload.riskLevel === "HIGH") highRiskPayloads++;
      else if (payload.riskLevel === "MEDIUM") mediumRiskPayloads++;
      else lowRiskPayloads++;

      payloadTypeBreakdown[payload.payloadType] =
        (payloadTypeBreakdown[payload.payloadType] || 0) + 1;
    });
  });

  return {
    totalAttackTypes,
    totalPayloads,
    highRiskPayloads,
    mediumRiskPayloads,
    lowRiskPayloads,
    payloadTypeBreakdown,
    averagePayloadsPerAttack: Math.round(totalPayloads / totalAttackTypes),
  };
}
