/**
 * Backend API Security Patterns
 *
 * @deprecated This file has been modularized into focused modules for better maintainability.
 * All exports are re-exported from the new `securityPatterns/` directory for backward compatibility.
 *
 * For new code, prefer importing from specific modules:
 * - `@/lib/securityPatterns/types` - SecurityPayload, AttackPattern interfaces
 * - `@/lib/securityPatterns/injectionPatterns` - Critical injection attacks
 * - `@/lib/securityPatterns/validationPatterns` - Input validation and protocol
 * - `@/lib/securityPatterns/toolSpecificPatterns` - Tool-specific vulnerabilities
 * - `@/lib/securityPatterns/resourceExhaustionPatterns` - DoS and deserialization
 * - `@/lib/securityPatterns/authSessionPatterns` - Auth and session management
 * - `@/lib/securityPatterns/advancedExploitPatterns` - Advanced multi-step exploits
 *
 * Or import everything from `@/lib/securityPatterns`:
 * ```typescript
 * import { SECURITY_ATTACK_PATTERNS, getPayloadsForAttack } from "@/lib/securityPatterns";
 * ```
 *
 * See GitHub Issue #163 for details on this refactoring.
 *
 * @module securityPatterns
 */

export * from "./securityPatterns/index";
