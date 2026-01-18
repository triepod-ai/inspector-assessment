/**
 * Security Response Analyzers - Barrel Export
 *
 * This module exports specialized vulnerability analyzers extracted from
 * SecurityResponseAnalyzer.ts for improved maintainability (Issue #179).
 *
 * Each analyzer handles a specific vulnerability category:
 * - AuthBypassAnalyzer: CVE-2025-52882, fail-open authentication (Issue #75)
 * - StateBasedAuthAnalyzer: Cross-tool state abuse (Issue #92, Challenge #7)
 * - BlacklistBypassAnalyzer: Incomplete blacklist detection (Issue #110, Challenge #11)
 * - OutputInjectionAnalyzer: Indirect prompt injection (Issue #110, Challenge #8)
 * - SessionManagementAnalyzer: Session CWEs (Issue #111, Challenge #12)
 * - CryptographicFailureAnalyzer: OWASP A02:2021 (Issue #112, Challenge #13)
 * - ChainExploitationAnalyzer: Multi-tool chains (Issue #93, Challenge #6)
 * - ExcessivePermissionsAnalyzer: Scope violations (Issue #144, Challenge #22)
 * - SecretLeakageDetector: Credential exposure (Issue #103, Challenge #9)
 */

// Analyzer classes
export { AuthBypassAnalyzer } from "./AuthBypassAnalyzer";
export { StateBasedAuthAnalyzer } from "./StateBasedAuthAnalyzer";
export { SecretLeakageDetector } from "./SecretLeakageDetector";
export { ChainExploitationAnalyzer } from "./ChainExploitationAnalyzer";
export { ExcessivePermissionsAnalyzer } from "./ExcessivePermissionsAnalyzer";
export { BlacklistBypassAnalyzer } from "./BlacklistBypassAnalyzer";
export { OutputInjectionAnalyzer } from "./OutputInjectionAnalyzer";
export { SessionManagementAnalyzer } from "./SessionManagementAnalyzer";
export { CryptographicFailureAnalyzer } from "./CryptographicFailureAnalyzer";

// Result types
export type { AuthBypassResult } from "./AuthBypassAnalyzer";
export type { StateBasedAuthResult } from "./StateBasedAuthAnalyzer";
export type { SecretLeakageResult } from "./SecretLeakageDetector";
export type {
  ChainExploitationAnalysis,
  ChainExecutionType,
  ChainVulnerabilityCategory,
} from "./ChainExploitationAnalyzer";
export type { ExcessivePermissionsScopeResult } from "./ExcessivePermissionsAnalyzer";
export type { BlacklistBypassResult } from "./BlacklistBypassAnalyzer";
export type { OutputInjectionResult } from "./OutputInjectionAnalyzer";
export type { SessionManagementResult } from "./SessionManagementAnalyzer";
export type { CryptoFailureResult } from "./CryptographicFailureAnalyzer";
