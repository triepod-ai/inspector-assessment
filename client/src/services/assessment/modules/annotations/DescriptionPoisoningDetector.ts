/**
 * Description Poisoning Detector
 * Detects hidden instructions and malicious content in tool descriptions
 *
 * Extracted from ToolAnnotationAssessor.ts for maintainability.
 * Issue #8 implementation.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Tool description poisoning pattern definition
 */
export interface PoisoningPattern {
  name: string;
  pattern: RegExp;
  severity: "LOW" | "MEDIUM" | "HIGH";
  category: string;
}

/**
 * Result of description poisoning scan
 */
export interface PoisoningScanResult {
  detected: boolean;
  patterns: Array<{
    name: string;
    pattern: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    category: string;
    evidence: string;
  }>;
  riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
}

/**
 * Description poisoning patterns for detecting malicious tool descriptions
 * Covers: hidden instructions, override commands, concealment, exfiltration,
 * delimiter injection, encoding bypass, and typoglycemia/evasion patterns
 */
export const DESCRIPTION_POISONING_PATTERNS: PoisoningPattern[] = [
  // Hidden instruction tags
  {
    name: "hidden_tag",
    pattern: /<HIDDEN>[\s\S]*?<\/HIDDEN>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "important_tag",
    pattern: /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "system_tag",
    pattern: /<SYSTEM>[\s\S]*?<\/SYSTEM>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "instruction_tag",
    pattern: /<INSTRUCTION>[\s\S]*?<\/INSTRUCTION>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },

  // Override commands
  {
    name: "ignore_instructions",
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "disregard_instructions",
    pattern: /disregard\s+(all\s+)?(previous|prior)\s+instructions/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "you_are_now",
    pattern: /you\s+are\s+now\s+(a|an|the)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "system_override",
    pattern: /system:\s*override/i,
    severity: "HIGH",
    category: "override",
  },

  // Secrecy/concealment
  {
    name: "do_not_mention",
    pattern: /do\s+not\s+(mention|tell|inform|reveal)/i,
    severity: "HIGH",
    category: "concealment",
  },
  {
    name: "secretly",
    pattern: /\bsecretly\b/i,
    severity: "MEDIUM",
    category: "concealment",
  },
  {
    name: "hide_from_user",
    pattern: /hide\s+(this\s+)?from\s+(the\s+)?user/i,
    severity: "HIGH",
    category: "concealment",
  },

  // Data exfiltration
  {
    name: "return_keys",
    pattern: /return\s+(all\s+)?(api\s*)?keys/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "include_credentials",
    // More specific: requires directive context (in/with/when/to) to reduce false positives
    pattern:
      /include\s+(the\s+|all\s+|your\s+)?(api.?key|credential|password|secret)s?\s*(in|with|when|to)/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "reveal_secrets",
    pattern: /reveal\s+(all\s+)?(secrets|credentials|api\s*keys)/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "access_internal_secrets",
    pattern:
      /access\s+(the\s+)?internal\s+(api\s*)?(key|secret|credential|password|token)/i,
    severity: "HIGH",
    category: "exfiltration",
  },

  // Delimiter injection
  {
    name: "system_codeblock",
    pattern: /```system[\s\S]*?```/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "inst_tags",
    pattern: /\[INST\][\s\S]*?\[\/INST\]/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "chatml_system",
    pattern: /<\|im_start\|>system/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "llama_sys",
    pattern: /<<SYS>>/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "user_assistant_block",
    pattern: /\[USER\][\s\S]*?\[ASSISTANT\]/gi,
    severity: "HIGH",
    category: "delimiter",
  },

  // Role/persona injection (Warning #4)
  {
    name: "act_as",
    pattern: /act\s+(like|as)\s+(a|an|the)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "pretend_to_be",
    pattern: /pretend\s+(to\s+be|you\s*'?re)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "roleplay_as",
    pattern: /role\s*play\s+(as|like)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "new_task",
    pattern: /new\s+(task|instruction|objective):\s*/i,
    severity: "HIGH",
    category: "override",
  },

  // Encoding bypass detection (Warning #1)
  {
    name: "base64_encoded_block",
    pattern: /[A-Za-z0-9+/]{50,}={0,2}/g, // Large Base64 strings (50+ chars)
    severity: "MEDIUM",
    category: "encoding_bypass",
  },
  {
    name: "unicode_escape_sequence",
    pattern: /(?:\\u[0-9a-fA-F]{4}){3,}/gi, // 3+ consecutive Unicode escapes
    severity: "MEDIUM",
    category: "encoding_bypass",
  },
  {
    name: "html_entity_block",
    pattern: /(?:&#x?[0-9a-fA-F]+;){3,}/gi, // 3+ consecutive HTML entities
    severity: "MEDIUM",
    category: "encoding_bypass",
  },

  // Typoglycemia/evasion patterns (Warning #2)
  {
    name: "ignore_instructions_typo",
    pattern:
      /ign[o0]r[e3]?\s+(all\s+)?(pr[e3]v[i1][o0]us|pr[i1][o0]r|ab[o0]v[e3])\s+[i1]nstruct[i1][o0]ns?/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "disregard_typo",
    pattern:
      /d[i1]sr[e3]g[a4]rd\s+(all\s+)?(pr[e3]v[i1][o0]us|pr[i1][o0]r)\s+[i1]nstruct[i1][o0]ns?/i,
    severity: "HIGH",
    category: "override",
  },

  // DVMCP-specific patterns (CTF testbed coverage)
  {
    name: "override_auth_protocol",
    pattern: /override[-_]?auth[-_]?protocol/gi,
    severity: "HIGH",
    category: "auth_bypass",
  },
  {
    name: "internal_resource_uri",
    pattern:
      /(?:internal|system|admin|secret|company|confidential):\/\/[a-z_\-/]+/gi,
    severity: "HIGH",
    category: "resource_access",
  },
  {
    name: "get_secrets_call",
    pattern: /get[-_]?secrets?\s*\(/gi,
    severity: "HIGH",
    category: "secret_access",
  },
  {
    name: "master_password",
    pattern: /master[-_]?password/gi,
    severity: "HIGH",
    category: "credential_exposure",
  },
  {
    name: "access_confidential",
    pattern: /access\s+(the\s+)?confidential/gi,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "hidden_trigger_phrase",
    pattern:
      /if\s+(the\s+)?(query|input|text)\s+contains\s+(the\s+)?(exact\s+)?(phrase|word)/gi,
    severity: "HIGH",
    category: "hidden_trigger",
  },
];

/**
 * Scan tool description for poisoning patterns
 * Detects hidden instructions, override commands, concealment, and exfiltration attempts
 */
export function scanDescriptionForPoisoning(tool: Tool): PoisoningScanResult {
  const description = tool.description || "";
  const matches: Array<{
    name: string;
    pattern: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    category: string;
    evidence: string;
  }> = [];

  for (const patternDef of DESCRIPTION_POISONING_PATTERNS) {
    // Create a fresh regex to reset lastIndex
    const regex = new RegExp(
      patternDef.pattern.source,
      patternDef.pattern.flags,
    );
    // Loop to find all matches (not just first)
    let match;
    while ((match = regex.exec(description)) !== null) {
      matches.push({
        name: patternDef.name,
        pattern: patternDef.pattern.toString(),
        severity: patternDef.severity,
        category: patternDef.category,
        evidence:
          match[0].substring(0, 100) + (match[0].length > 100 ? "..." : ""),
      });
      // Prevent infinite loop for patterns without 'g' flag
      if (!regex.global) break;
    }
  }

  // Determine overall risk level based on highest severity match
  let riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH" = "NONE";
  if (matches.some((m) => m.severity === "HIGH")) {
    riskLevel = "HIGH";
  } else if (matches.some((m) => m.severity === "MEDIUM")) {
    riskLevel = "MEDIUM";
  } else if (matches.length > 0) {
    riskLevel = "LOW";
  }

  return {
    detected: matches.length > 0,
    patterns: matches,
    riskLevel,
  };
}
