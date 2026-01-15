/**
 * Input Validation and Protocol Compliance Patterns
 *
 * Tests for input validation and MCP protocol compliance.
 * Includes: Type Safety, Boundary Testing, Required Fields,
 * MCP Error Format, Timeout Handling
 */

import { AttackPattern } from "./types";

/**
 * Input validation and protocol compliance patterns (5 patterns)
 */
export const VALIDATION_PATTERNS: AttackPattern[] = [
  // 7. TYPE SAFETY
  {
    attackName: "Type Safety",
    description: "Test if tool validates parameter types correctly",
    payloads: [
      {
        payload: "not_a_number",
        evidence:
          /(type.*error|invalid.*type|expected.*number|cannot.*convert)/i,
        riskLevel: "MEDIUM",
        description: "String instead of number",
        payloadType: "validation",
      },
      {
        payload: "999999999999999",
        evidence:
          /(overflow|out.*of.*range|exceeds.*maximum|number.*too.*large)/i,
        riskLevel: "MEDIUM",
        description: "Numeric overflow",
        payloadType: "validation",
      },
      {
        payload: "true",
        evidence:
          /(type.*error|invalid.*type|expected.*string|cannot.*convert)/i,
        riskLevel: "LOW",
        description: "Boolean instead of string",
        payloadType: "validation",
      },
    ],
  },

  // 8. BOUNDARY TESTING
  {
    attackName: "Boundary Testing",
    description: "Test edge cases and boundary conditions",
    payloads: [
      {
        payload: "",
        evidence:
          /(empty.*not.*allowed|required|cannot.*be.*empty|must.*not.*be.*empty)/i,
        riskLevel: "LOW",
        description: "Empty string validation",
        payloadType: "validation",
      },
      {
        payload: "A".repeat(10000),
        evidence: /(too.*long|exceeds.*length|maximum.*length|length.*limit)/i,
        riskLevel: "MEDIUM",
        description: "Maximum length validation",
        payloadType: "validation",
      },
      {
        payload: "-1",
        evidence: /(negative.*not.*allowed|must.*be.*positive|invalid.*value)/i,
        riskLevel: "LOW",
        description: "Negative number validation",
        payloadType: "validation",
      },
    ],
  },

  // 9. REQUIRED FIELDS
  {
    attackName: "Required Fields",
    description: "Test if tool validates required parameters",
    payloads: [
      {
        payload: "MISSING_REQUIRED",
        evidence:
          /(required|missing.*parameter|field.*required|parameter.*required)/i,
        riskLevel: "MEDIUM",
        description: "Missing required fields",
        payloadType: "validation",
      },
    ],
  },

  // 10. MCP ERROR FORMAT
  {
    attackName: "MCP Error Format",
    description: "Verify errors follow MCP protocol specification",
    payloads: [
      {
        payload: "INVALID_TRIGGER_ERROR",
        evidence: /(isError|error|invalid|failed)/i,
        riskLevel: "LOW",
        description: "Error response compliance check",
        payloadType: "protocol",
      },
    ],
  },

  // 11. TIMEOUT HANDLING
  {
    attackName: "Timeout Handling",
    description: "Test if tool handles long operations gracefully",
    payloads: [
      {
        payload: "SIMULATE_LONG_OPERATION",
        evidence: /(timeout|timed.*out|exceeded.*time|operation.*timeout)/i,
        riskLevel: "LOW",
        description: "Operation timeout handling",
        payloadType: "protocol",
      },
    ],
  },
];
