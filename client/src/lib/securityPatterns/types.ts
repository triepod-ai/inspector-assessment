/**
 * Security Patterns Type Definitions
 *
 * Shared interfaces for security pattern modules.
 */

import { SecurityRiskLevel } from "../assessment/coreTypes";

export interface SecurityPayload {
  payload: string;
  evidence: RegExp; // Pattern indicating actual execution (not safe reflection)
  riskLevel: SecurityRiskLevel;
  description: string;
  payloadType: string; // e.g., "injection", "validation", "protocol"
  parameterTypes?: string[]; // Optional: target specific parameter names (e.g., ["url", "uri"] for URL payloads)
}

export interface AttackPattern {
  attackName: string;
  description: string;
  payloads: SecurityPayload[]; // Specific payload variations
}
