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
}
