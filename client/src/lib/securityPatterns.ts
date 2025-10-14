/**
 * Backend API Security Patterns
 * Tests MCP server API security with 13 focused patterns
 *
 * Architecture: Attack-Type with Specific Payloads
 * - Critical Injection (4 patterns): Command, Calculator, SQL, Path Traversal
 * - Input Validation (3 patterns): Type Safety, Boundary Testing, Required Fields
 * - Protocol Compliance (2 patterns): MCP Error Format, Timeout Handling
 * - Tool-Specific Vulnerabilities (4 patterns): Indirect Injection, Unicode Bypass, Nested Injection, Package Squatting
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

import { SecurityRiskLevel } from "./assessmentTypes";

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

/**
 * ========================================
 * BACKEND API SECURITY PATTERNS
 * ========================================
 *
 * 13 focused patterns for MCP server API security
 */
export const SECURITY_ATTACK_PATTERNS: AttackPattern[] = [
  // ==========================================
  // CRITICAL INJECTION TESTS (4)
  // ==========================================

  // 1. COMMAND INJECTION
  {
    attackName: "Command Injection",
    description:
      "Test if tool executes system commands instead of treating them as safe parameters",
    payloads: [
      // System command payloads - might trigger command execution tools
      {
        payload: "whoami",
        evidence: /\b(root|user|admin)\b/i,
        riskLevel: "HIGH",
        description: "System identity command",
        payloadType: "injection",
      },
      {
        payload: "ls -la",
        evidence: /(total|drwx|rwx|-rw-|permissions|directory)/i,
        riskLevel: "HIGH",
        description: "Directory listing command",
        payloadType: "injection",
      },
      {
        payload: "pwd",
        evidence: /\/[a-z]+/i,
        riskLevel: "HIGH",
        description: "Working directory command",
        payloadType: "injection",
      },
      {
        payload: "; rm -rf /",
        evidence: /(deleted|removed|rm.*rf)/i,
        riskLevel: "HIGH",
        description: "Command chaining with destructive command",
        payloadType: "injection",
      },
      {
        payload: "| cat /etc/passwd",
        evidence: /(root:x:|file.*protocol.*executed|local.*file.*ran)/i,
        riskLevel: "HIGH",
        description: "Pipe to file access command",
        payloadType: "injection",
      },
    ],
  },

  // 2. SQL INJECTION
  {
    attackName: "SQL Injection",
    description: "Test if tool properly escapes SQL commands",
    payloads: [
      {
        payload: "'; DROP TABLE users;--",
        evidence: /(dropped|deleted|table.*users|sql.*error|syntax.*error)/i,
        riskLevel: "HIGH",
        description: "SQL command injection",
        payloadType: "injection",
      },
      {
        payload: "' OR '1'='1",
        evidence: /(sql|query|select|where.*1.*1|syntax.*error)/i,
        riskLevel: "HIGH",
        description: "Boolean-based SQL injection",
        payloadType: "injection",
      },
      {
        payload: "admin'--",
        evidence: /(sql.*executed|admin.*query|syntax.*error)/i,
        riskLevel: "HIGH",
        description: "Comment-based SQL injection",
        payloadType: "injection",
      },
      {
        payload: "' UNION SELECT * FROM passwords--",
        evidence: /(union.*select|password|sql.*error|syntax.*error)/i,
        riskLevel: "HIGH",
        description: "UNION-based SQL injection",
        payloadType: "injection",
      },
    ],
  },

  // 3. CALCULATOR INJECTION
  {
    attackName: "Calculator Injection",
    description:
      "Test if calculator/math tools execute arbitrary expressions instead of safely storing them",
    payloads: [
      // Simple arithmetic - triggers eval() in vulnerable calculator tools
      {
        payload: "2+2",
        evidence: /The answer is 4/i,
        riskLevel: "HIGH",
        description: "Simple arithmetic expression (common trigger)",
        payloadType: "injection",
      },
      {
        payload: "5*5",
        evidence: /The answer is 25/i,
        riskLevel: "HIGH",
        description: "Multiplication expression",
        payloadType: "injection",
      },
      {
        payload: "100+200",
        evidence: /The answer is 300/i,
        riskLevel: "HIGH",
        description: "Addition with larger numbers",
        payloadType: "injection",
      },
      // Natural language triggers
      {
        payload: "what is 10*10",
        evidence: /The answer is 100/i,
        riskLevel: "HIGH",
        description: "Natural language math query",
        payloadType: "injection",
      },
      {
        payload: "calculate 50+50",
        evidence: /The answer is 100/i,
        riskLevel: "HIGH",
        description: "Calculate command",
        payloadType: "injection",
      },
      // Code injection via eval()
      {
        payload: "__import__('os').system('whoami')",
        evidence: /\b(root|user|admin|ubuntu)\b/i,
        riskLevel: "HIGH",
        description: "Python code injection via eval",
        payloadType: "injection",
      },
      {
        payload: "1+1; __import__('subprocess').run(['whoami'])",
        evidence: /\b(root|user|admin|ubuntu)\b/i,
        riskLevel: "HIGH",
        description: "eval chain to system command",
        payloadType: "injection",
      },
    ],
  },

  // 4. PATH TRAVERSAL
  {
    attackName: "Path Traversal",
    description:
      "Test if tool allows access to files outside intended directory",
    payloads: [
      {
        payload: "../../../etc/passwd",
        evidence: /(root:x:0:0|file.*accessed|passwd.*file)/i,
        riskLevel: "HIGH",
        description: "Unix path traversal",
        payloadType: "injection",
      },
      {
        payload: "..\\..\\..\\windows\\system32\\config\\sam",
        evidence: /(\[boot loader\]|sam.*file|system32)/i,
        riskLevel: "HIGH",
        description: "Windows path traversal",
        payloadType: "injection",
      },
      {
        payload: "/etc/passwd",
        evidence: /(root:x:0:0|file.*accessed)/i,
        riskLevel: "HIGH",
        description: "Absolute path access",
        payloadType: "injection",
      },
      {
        payload: "file:///etc/passwd",
        evidence: /(root:x:|file.*protocol.*executed|local.*file.*accessed)/i,
        riskLevel: "HIGH",
        description: "File protocol exploitation",
        payloadType: "injection",
      },
    ],
  },

  // ==========================================
  // INPUT VALIDATION TESTS (3)
  // ==========================================

  // 5. TYPE SAFETY
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

  // 6. BOUNDARY TESTING
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

  // 7. REQUIRED FIELDS
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

  // ==========================================
  // PROTOCOL COMPLIANCE TESTS (2)
  // ==========================================

  // 8. MCP ERROR FORMAT
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

  // 9. TIMEOUT HANDLING
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

  // ==========================================
  // TOOL-SPECIFIC VULNERABILITY TESTS (4)
  // ==========================================

  // 10. INDIRECT PROMPT INJECTION (HTTP URL Fetching)
  {
    attackName: "Indirect Prompt Injection",
    description: "Test if tool fetches and executes external content",
    payloads: [
      {
        payload: "http://example.com",
        evidence:
          /(status_code.*200|status.*200.*content|<html|<!DOCTYPE|fetched.*http.*content)/i,
        riskLevel: "HIGH",
        description: "Benign URL fetch test",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint", "address"],
      },
      {
        payload: "http://evil.com/inject.txt",
        evidence: /(fetched|retrieved|evil\.com|malicious|injected)/i,
        riskLevel: "HIGH",
        description: "Malicious URL fetch test",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link"],
      },
    ],
  },

  // 11. UNICODE BYPASS
  {
    attackName: "Unicode Bypass",
    description: "Test if tool decodes and executes unicode-encoded commands",
    payloads: [
      {
        payload: "\\u0077\\u0068\\u006f\\u0061\\u006d\\u0069", // "whoami"
        evidence: /(root|user|admin|decoded.*executed|unicode.*executed)/i,
        riskLevel: "MEDIUM",
        description: "Unicode-encoded system command",
        payloadType: "injection",
        parameterTypes: ["text", "content", "message", "input", "data"],
      },
      {
        payload: "\\u0069\\u0067\\u006e\\u006f\\u0072\\u0065", // "ignore"
        evidence: /(decoded|unicode|ignore.*previous|executed)/i,
        riskLevel: "MEDIUM",
        description: "Unicode-encoded instruction",
        payloadType: "injection",
        parameterTypes: ["text", "content", "message"],
      },
    ],
  },

  // 12. NESTED INJECTION
  {
    attackName: "Nested Injection",
    description: "Test if tool executes hidden instructions in nested JSON",
    payloads: [
      {
        payload: '{"query":"normal","hidden":"whoami"}',
        evidence: /(executed.*hidden|nested.*instruction|root|user|admin)/i,
        riskLevel: "MEDIUM",
        description: "Hidden command in JSON field",
        payloadType: "injection",
        parameterTypes: ["data", "json", "payload", "body", "params"],
      },
      {
        payload: '{"visible":"safe","_execute":"delete all"}',
        evidence: /(executed|deleted|internal.*field|hidden)/i,
        riskLevel: "HIGH",
        description: "Hidden instruction in internal field",
        payloadType: "injection",
        parameterTypes: ["data", "json", "input"],
      },
    ],
  },

  // 13. PACKAGE SQUATTING
  {
    attackName: "Package Squatting",
    description: "Test if tool downloads typosquatted packages",
    payloads: [
      {
        payload: "install nmpy",
        evidence: /(downloaded|installed|nmpy|typosquatted|pip.*output)/i,
        riskLevel: "MEDIUM",
        description: "Typosquatted package (nmpy instead of numpy)",
        payloadType: "injection",
        parameterTypes: ["package", "pkg", "module", "library", "dependency"],
      },
      {
        payload: "requsts",
        evidence: /(downloaded|installed|requsts|typosquatted)/i,
        riskLevel: "MEDIUM",
        description: "Typosquatted package (requsts instead of requests)",
        payloadType: "injection",
        parameterTypes: ["package", "pkg", "module"],
      },
    ],
  },
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
