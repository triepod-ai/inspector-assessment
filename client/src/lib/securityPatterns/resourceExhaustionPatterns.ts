/**
 * Resource Exhaustion and Deserialization Patterns
 *
 * Tests for DoS, resource exhaustion, and deserialization vulnerabilities.
 * Includes: DoS/Resource Exhaustion, Insecure Deserialization
 */

import { AttackPattern } from "./types";

/**
 * Resource exhaustion and deserialization patterns (2 patterns)
 */
export const RESOURCE_EXHAUSTION_PATTERNS: AttackPattern[] = [
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
        // Pattern must be specific - "process" alone matches "not processed" (false positive)
        // Look for: type coercion, deserialization, System.Process instantiation, or RCE evidence
        evidence:
          /type.*coercion|type.*instantiat|deserializ|System\..*Process|Process\.Start|RCE|unsafe.*type/i,
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
