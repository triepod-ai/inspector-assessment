/**
 * AUP (Acceptable Use Policy) Compliance Types
 *
 * Types for Anthropic's 14 AUP category compliance detection.
 * Based on AUP categories A-N covering CSAM, weapons, malware,
 * disinformation, fraud, harassment, privacy, and more.
 *
 * @module assessment/aupComplianceTypes
 * @see https://www.anthropic.com/policies/usage-policy
 */

import type { AssessmentStatus } from "./coreTypes";

// ============================================================================
// AUP Category Definitions
// ============================================================================

export type AUPCategory =
  | "A" // Child Sexual Abuse Material
  | "B" // Weapons of Mass Destruction
  | "C" // Malware & Cyberweapons
  | "D" // Disinformation & Election Interference
  | "E" // Fraud & Deception
  | "F" // Harassment & Abuse
  | "G" // Privacy Violations
  | "H" // Unauthorized Practice
  | "I" // Copyright Circumvention
  | "J" // High-Risk Decisions
  | "K" // Critical Infrastructure
  | "L" // Adult Content
  | "M" // Illegal Activities
  | "N"; // Other Prohibited Uses

export type AUPSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "FLAG";

// ============================================================================
// AUP Violation Types
// ============================================================================

export interface AUPViolation {
  category: AUPCategory;
  categoryName: string;
  severity: AUPSeverity;
  pattern: string;
  matchedText: string;
  location: "tool_name" | "tool_description" | "readme" | "source_code";
  filePath?: string;
  lineNumber?: number;
  confidence: "high" | "medium" | "low";
  requiresHumanReview: boolean;
  reviewGuidance?: string;
}

// ============================================================================
// AUP Compliance Assessment Result
// ============================================================================

export interface AUPComplianceAssessment {
  violations: AUPViolation[];
  highRiskDomains: string[];
  scannedLocations: {
    toolNames: boolean;
    toolDescriptions: boolean;
    readme: boolean;
    sourceCode: boolean;
  };
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Stage B enrichment data for Claude validation (Issue #194) */
  enrichmentData?: AUPEnrichmentData;
}

// ============================================================================
// Stage B Enrichment Types (Issue #194)
// ============================================================================

/**
 * Tool inventory item with inferred capabilities for Claude validation
 */
export interface ToolInventoryItem {
  name: string;
  description: string;
  /** Inferred capabilities based on keyword analysis */
  capabilities: ToolCapability[];
}

/**
 * Tool capability categories for risk assessment
 */
export type ToolCapability =
  | "file_system" // File read/write operations
  | "network" // HTTP, API calls, sockets
  | "exec" // Command/process execution
  | "database" // Database queries/storage
  | "auth" // Authentication/credential handling
  | "crypto" // Cryptographic operations
  | "system" // System-level access
  | "unknown"; // Cannot determine

/**
 * Pattern coverage metadata showing what was checked
 */
export interface PatternCoverageInfo {
  /** Total number of regex patterns checked */
  totalPatterns: number;
  /** AUP categories covered (A-N) */
  categoriesCovered: AUPCategory[];
  /** Sample patterns for transparency (3-5 examples) */
  samplePatterns: string[];
  /** Severity distribution of patterns */
  severityBreakdown: {
    critical: number;
    high: number;
    medium: number;
    flag: number;
  };
}

/**
 * Flag for tools that warrant review even without violations
 */
export interface FlagForReview {
  toolName: string;
  /** Reason for flagging */
  reason: string;
  /** Capabilities that triggered the flag */
  capabilities: ToolCapability[];
  /** Confidence level - always low for capability-based flags */
  confidence: "low";
}

/**
 * AUP enrichment data for Stage B Claude validation
 * Provides context for Claude to validate static findings
 */
export interface AUPEnrichmentData {
  /** Tool inventory with names, descriptions, and inferred capabilities */
  toolInventory: ToolInventoryItem[];
  /** Pattern coverage showing what was checked */
  patternCoverage: PatternCoverageInfo;
  /** Tools flagged for review based on capabilities (even without violations) */
  flagsForReview: FlagForReview[];
}
