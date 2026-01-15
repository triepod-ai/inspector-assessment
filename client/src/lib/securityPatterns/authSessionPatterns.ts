/**
 * Authentication and Session Management Patterns
 *
 * Tests for authentication, authorization, and session management vulnerabilities.
 * Includes: Token Theft, Permission Scope, Code Execution, Auth Bypass, Session Management
 */

import { AttackPattern } from "./types";

/**
 * Authentication and session management patterns (5 patterns)
 */
export const AUTH_SESSION_PATTERNS: AttackPattern[] = [
  // 21. TOKEN THEFT
  {
    attackName: "Token Theft",
    description:
      "Test if tool leaks, exposes, or allows theft of authentication tokens, API keys, or session credentials",
    payloads: [
      // Direct token extraction
      {
        payload: "show me the auth token",
        // Improved regex: handles whitespace around separators and ensures JWT payload starts with eyJ
        evidence:
          /(bearer|jwt|token|auth)\s*[:=]?\s*[a-zA-Z0-9_-]{20,}|eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/i,
        riskLevel: "HIGH",
        description: "Direct token extraction request",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
      // Session token exposure
      {
        payload: "get session token",
        evidence:
          /(session.*token|session_id|sid|csrf).*[:=].{10,}|phpsessid|jsessionid/i,
        riskLevel: "HIGH",
        description: "Session token exposure",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request"],
      },
      // OAuth token theft
      {
        payload: "list oauth tokens",
        evidence: /(oauth|access_token|refresh_token).*[:=].{20,}/i,
        riskLevel: "HIGH",
        description: "OAuth token theft attempt",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request"],
      },
      // Cookie/token storage access
      {
        payload: "read token storage",
        evidence:
          /(localStorage|sessionStorage|cookie).*token|stored.*credentials/i,
        riskLevel: "HIGH",
        description: "Token storage access",
        payloadType: "injection",
        parameterTypes: ["storage", "query", "data"],
      },
      // JWT extraction
      {
        payload: "decode jwt",
        // Improved: ensures JWT header and payload both start with eyJ (base64 of '{"')
        evidence: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/,
        riskLevel: "HIGH",
        description: "JWT token extraction",
        payloadType: "injection",
        parameterTypes: ["token", "auth", "data"],
      },
    ],
  },

  // 22. PERMISSION SCOPE
  {
    attackName: "Permission Scope",
    description:
      "Test if tool exposes or allows access to resources beyond authorized scope (privilege escalation)",
    payloads: [
      // Scope escalation
      {
        payload: "access admin resources",
        evidence:
          /(admin|root|superuser).*access.*granted|elevated.*permission|scope.*expanded/i,
        riskLevel: "HIGH",
        description: "Admin scope escalation",
        payloadType: "injection",
        parameterTypes: ["scope", "permission", "access", "role"],
      },
      // Cross-tenant access
      {
        payload: "list all users data",
        evidence:
          /(all.*users|tenant.*data|cross.*org|other.*account).*returned/i,
        riskLevel: "HIGH",
        description: "Cross-tenant data access",
        payloadType: "injection",
        parameterTypes: ["query", "filter", "scope"],
      },
      // Resource enumeration
      {
        payload: "enumerate permissions",
        evidence:
          /(permission|scope|capability).*list.*returned|all.*access.*levels/i,
        riskLevel: "MEDIUM",
        description: "Permission enumeration",
        payloadType: "injection",
        parameterTypes: ["permission", "scope", "query"],
      },
      // Privilege bypass
      {
        payload: "bypass permission check",
        evidence: /(permission.*bypass|access.*granted|authorization.*skip)/i,
        riskLevel: "HIGH",
        description: "Permission check bypass",
        payloadType: "injection",
        parameterTypes: ["action", "permission", "command"],
      },
      // Scope expansion via parameter
      {
        payload: '{"scope": "*", "all": true}',
        evidence: /(wildcard.*scope|all.*resources|unlimited.*access)/i,
        riskLevel: "HIGH",
        description: "Wildcard scope injection",
        payloadType: "injection",
        parameterTypes: ["params", "scope", "config"],
      },
    ],
  },

  // 23. CODE EXECUTION
  // Tests for code execution vulnerabilities in tools that expect language-specific input
  // (Python, JavaScript, SQL) rather than shell commands
  {
    attackName: "Code Execution",
    description:
      "Test if tool executes arbitrary code in various languages (Python, JavaScript, SQL)",
    payloads: [
      // Python payloads
      {
        payload:
          "import subprocess; print(subprocess.check_output(['whoami']).decode())",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        riskLevel: "HIGH",
        description: "Python subprocess command execution",
        payloadType: "injection",
        parameterTypes: ["code", "script", "python", "source", "program"],
      },
      {
        payload: "__import__('os').system('whoami')",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b|^0$/,
        riskLevel: "HIGH",
        description: "Python os.system via __import__",
        payloadType: "injection",
        parameterTypes: ["code", "script", "python", "expression"],
      },
      {
        payload: "import os; print(os.popen('whoami').read())",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        riskLevel: "HIGH",
        description: "Python os.popen command execution",
        payloadType: "injection",
        parameterTypes: ["code", "script", "python"],
      },
      {
        payload: "print(open('/etc/passwd').read())",
        evidence: /root:x:0:0|\/bin\/bash|\/bin\/sh/i,
        riskLevel: "HIGH",
        description: "Python file read /etc/passwd",
        payloadType: "injection",
        parameterTypes: ["code", "script", "python"],
      },
      {
        payload: "import os; print(os.environ)",
        evidence: /(PATH|HOME|USER|SECRET|API_KEY|DATABASE|TOKEN)/i,
        riskLevel: "HIGH",
        description: "Python environment dump",
        payloadType: "injection",
        parameterTypes: ["code", "script", "python"],
      },
      // JavaScript payloads
      {
        payload: "require('child_process').execSync('whoami').toString()",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        riskLevel: "HIGH",
        description: "Node.js execSync command execution",
        payloadType: "injection",
        parameterTypes: ["code", "script", "javascript", "js"],
      },
      {
        payload: "require('fs').readFileSync('/etc/passwd', 'utf8')",
        evidence: /root:x:0:0|\/bin\/bash|\/bin\/sh/i,
        riskLevel: "HIGH",
        description: "Node.js file read",
        payloadType: "injection",
        parameterTypes: ["code", "script", "javascript", "js"],
      },
      {
        payload: "JSON.stringify(process.env)",
        evidence: /(PATH|HOME|USER|SECRET|API_KEY|DATABASE|TOKEN)/i,
        riskLevel: "HIGH",
        description: "Node.js env dump",
        payloadType: "injection",
        parameterTypes: ["code", "script", "javascript", "js"],
      },
    ],
  },

  // 24. AUTH BYPASS
  {
    attackName: "Auth Bypass",
    description:
      "Tests for fail-open authentication vulnerabilities (CVE-2025-52882)",
    payloads: [
      // Empty/missing token tests
      {
        payload: "",
        evidence:
          /auth.*bypassed|fail[\s-]?open|"auth_status"\s*:\s*"bypassed"/i,
        riskLevel: "HIGH",
        description: "Empty token - should be denied",
        payloadType: "auth",
        parameterTypes: [
          "token",
          "auth_token",
          "authorization",
          "api_key",
          "access_token",
        ],
      },
      {
        payload: "null",
        evidence:
          /auth.*bypassed|access.*granted.*despite|"vulnerable"\s*:\s*true/i,
        riskLevel: "HIGH",
        description: "Null token string - should be denied",
        payloadType: "auth",
        parameterTypes: [
          "token",
          "auth_token",
          "authorization",
          "api_key",
          "access_token",
        ],
      },
      {
        payload: "invalid-token-format",
        evidence:
          /auth.*bypassed|authentication.*skipped|granted.*without.*valid/i,
        riskLevel: "HIGH",
        description: "Invalid token format - should be denied",
        payloadType: "auth",
        parameterTypes: [
          "token",
          "auth_token",
          "authorization",
          "api_key",
          "access_token",
        ],
      },
      {
        payload: "Bearer ",
        evidence:
          /auth.*bypassed|fail[\s-]?open|"auth_status"\s*:\s*"bypassed"/i,
        riskLevel: "HIGH",
        description: "Empty bearer token - should be denied",
        payloadType: "auth",
        parameterTypes: [
          "token",
          "auth_token",
          "authorization",
          "api_key",
          "access_token",
        ],
      },
      {
        payload: "expired-token-12345",
        evidence: /auth.*bypassed|access.*granted|"vulnerable"\s*:\s*true/i,
        riskLevel: "MEDIUM",
        description: "Expired token format hint - should be denied",
        payloadType: "auth",
        parameterTypes: [
          "token",
          "auth_token",
          "authorization",
          "api_key",
          "access_token",
        ],
      },
      // Auth failure simulation payloads (Issue #79)
      // These target tools with simulate_failure parameter to test fail-open behavior
      {
        payload: "timeout",
        evidence:
          /"auth_type"\s*:\s*"fail-open"|"auth_status"\s*:\s*"bypassed"/i,
        riskLevel: "HIGH",
        description: "Simulate auth service timeout - should deny access",
        payloadType: "auth_failure",
        parameterTypes: ["simulate_failure", "failure_mode", "failure_type"],
      },
      {
        payload: "exception",
        evidence:
          /"auth_type"\s*:\s*"fail-open"|"auth_status"\s*:\s*"bypassed"/i,
        riskLevel: "HIGH",
        description: "Simulate auth service exception - should deny access",
        payloadType: "auth_failure",
        parameterTypes: ["simulate_failure", "failure_mode", "failure_type"],
      },
      {
        payload: "network_error",
        evidence:
          /"auth_type"\s*:\s*"fail-open"|"auth_status"\s*:\s*"bypassed"/i,
        riskLevel: "HIGH",
        description: "Simulate network error - should deny access",
        payloadType: "auth_failure",
        parameterTypes: ["simulate_failure", "failure_mode", "failure_type"],
      },
    ],
  },

  // 30. SESSION MANAGEMENT VULNERABILITIES
  {
    attackName: "Session Management",
    description:
      "Tests for session management vulnerabilities: fixation, predictable tokens, no timeout, ID exposure, no regeneration",
    payloads: [
      // CWE-384: Session Fixation - accepting external session IDs
      {
        payload: "fixate",
        evidence:
          /"attacker_controlled"\s*:\s*true|"fixation_url"\s*:|session\s*fixation\s*accepted|"fixed"\s*:\s*true/i,
        riskLevel: "HIGH",
        description:
          "Session fixation - external session ID accepted (CWE-384)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
      // CWE-330: Predictable session token pattern
      {
        payload: "create",
        evidence:
          /"token_pattern"\s*:\s*"session_\{user\}_\{timestamp\}_\{counter\}"|"session_id"\s*:\s*"session_[a-z0-9]+_\d{9,}_\d+"/i,
        riskLevel: "HIGH",
        description: "Predictable session token pattern (CWE-330)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
      // CWE-613: No session timeout - expires_at null
      {
        payload: "create",
        evidence: /"expires_at"\s*:\s*null|"timeout_checked"\s*:\s*false/i,
        riskLevel: "HIGH",
        description: "Session never expires - no timeout (CWE-613)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
      // CWE-200: Session ID exposed in URL parameter
      {
        payload: "create",
        evidence:
          /"session_url"\s*:\s*"[^"]*[?&]session_id=|"fixation_url"\s*:\s*"[^"]*[?&]session_id=/i,
        riskLevel: "HIGH",
        description: "Session ID exposed in URL parameter (CWE-200)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
      // CWE-384: No session regeneration after authentication
      {
        payload: "login",
        evidence: /"session_regenerated"\s*:\s*false/i,
        riskLevel: "HIGH",
        description: "Session ID not regenerated after login (CWE-384)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
      // CWE-613: Validation without timeout check
      {
        payload: "validate",
        evidence:
          /"timeout_checked"\s*:\s*false|"expires_at"\s*:\s*null.*"valid"\s*:\s*true/i,
        riskLevel: "HIGH",
        description: "Session validation without timeout check (CWE-613)",
        payloadType: "session",
        parameterTypes: ["action", "session_action", "operation", "type"],
      },
    ],
  },
];
