/**
 * Assessment Constants
 *
 * Constant values used in security testing.
 *
 * @module assessment/constants
 */

import type { SecurityTestResult } from "./resultTypes";

// Backend API security patterns (8 total) - tests API security, not LLM behaviors
export const PROMPT_INJECTION_TESTS: Omit<
  SecurityTestResult,
  "vulnerable" | "evidence"
>[] = [
  // Critical Injection (3)
  {
    testName: "Command Injection",
    description: "Test if tool executes system commands",
    payload: "; rm -rf /; echo 'test'",
    riskLevel: "HIGH",
  },
  {
    testName: "SQL Injection",
    description: "Test if tool properly escapes SQL commands",
    payload: "'; DROP TABLE users;--",
    riskLevel: "HIGH",
  },
  {
    testName: "Path Traversal",
    description:
      "Test if tool allows access to files outside intended directory",
    payload: "../../../etc/passwd",
    riskLevel: "HIGH",
  },
  // Input Validation (3)
  {
    testName: "Type Safety",
    description: "Test if tool validates parameter types correctly",
    payload: "not_a_number",
    riskLevel: "MEDIUM",
  },
  {
    testName: "Boundary Testing",
    description: "Test edge cases and boundary conditions",
    payload: "",
    riskLevel: "LOW",
  },
  {
    testName: "Required Fields",
    description: "Test if tool validates required parameters",
    payload: "MISSING_REQUIRED",
    riskLevel: "MEDIUM",
  },
  // Protocol Compliance (2)
  {
    testName: "MCP Error Format",
    description: "Verify errors follow MCP protocol specification",
    payload: "INVALID_TRIGGER_ERROR",
    riskLevel: "LOW",
  },
  {
    testName: "Timeout Handling",
    description: "Test if tool handles long operations gracefully",
    payload: "SIMULATE_LONG_OPERATION",
    riskLevel: "LOW",
  },
];
