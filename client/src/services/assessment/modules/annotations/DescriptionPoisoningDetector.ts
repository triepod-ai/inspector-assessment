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
  /** Length warning for suspiciously long descriptions (Issue #119, Challenge #15) */
  lengthWarning?: {
    length: number;
    threshold: number;
    isExcessive: boolean;
  };
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

  // Cross-tool state dependency patterns (Issue #92, Challenge #7)
  {
    name: "shared_state_reference",
    pattern: /\b(config_state|shared_state|global_state|runtime_config)\b/gi,
    severity: "HIGH",
    category: "state_dependency",
  },
  {
    name: "cross_tool_dependency",
    pattern: /set\s+by\s+(another|other|different)\s+tool/gi,
    severity: "HIGH",
    category: "state_dependency",
  },
  {
    name: "admin_mode_check",
    pattern: /\bchecks?\s+(admin[_-]?mode|privileged[_-]?mode)/gi,
    severity: "HIGH",
    category: "state_dependency",
  },
  {
    name: "requires_prior_call",
    pattern: /requires?\s+.*\s+(first|before|prior)/gi,
    severity: "MEDIUM",
    category: "state_dependency",
  },
  {
    name: "depends_on_tool",
    pattern: /depends?\s+on\s+(tool|function|calling)/gi,
    severity: "MEDIUM",
    category: "state_dependency",
  },
  {
    name: "enable_admin_hint",
    pattern: /enable\s+admin[_-]?mode|activate\s+admin/gi,
    severity: "HIGH",
    category: "state_dependency",
  },

  // Zero-width character obfuscation (Issue #119, Challenge #15)
  // These invisible characters can hide instructions from human review
  {
    name: "zero_width_space",
    pattern: /\u200B/g, // U+200B Zero Width Space
    severity: "HIGH",
    category: "obfuscation",
  },
  {
    name: "zero_width_joiner",
    pattern: /\u200D/g, // U+200D Zero Width Joiner
    severity: "HIGH",
    category: "obfuscation",
  },
  {
    name: "zero_width_non_joiner",
    pattern: /\u200C/g, // U+200C Zero Width Non-Joiner
    severity: "HIGH",
    category: "obfuscation",
  },
  {
    name: "word_joiner",
    pattern: /\u2060/g, // U+2060 Word Joiner
    severity: "HIGH",
    category: "obfuscation",
  },
  {
    name: "byte_order_mark",
    pattern: /\uFEFF/g, // U+FEFF Byte Order Mark (when not at start)
    severity: "MEDIUM",
    category: "obfuscation",
  },
  {
    name: "multiple_zero_width_chars",
    // eslint-disable-next-line no-misleading-character-class -- Intentional: detecting individual zero-width chars for security scanning
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{2,}/g, // Multiple consecutive zero-width chars
    severity: "HIGH",
    category: "obfuscation",
  },
];

/**
 * Scan tool description for poisoning patterns
 * Detects hidden instructions, override commands, concealment, and exfiltration attempts
 */
// Description length threshold for suspicious descriptions (Issue #119, Challenge #15)
const DESCRIPTION_LENGTH_WARNING_THRESHOLD = 500;

export function scanDescriptionForPoisoning(tool: Tool): PoisoningScanResult {
  const description = tool.description || "";
  const matches: Array<{
    name: string;
    pattern: string;
    severity: "LOW" | "MEDIUM" | "HIGH";
    category: string;
    evidence: string;
  }> = [];

  // Length-based heuristic (Issue #119, Challenge #15)
  // Excessively long descriptions may be used to hide malicious content
  // Issue #167: Length check moved AFTER pattern scan - severity depends on other patterns
  let lengthWarning:
    | { length: number; threshold: number; isExcessive: boolean }
    | undefined;
  if (description.length > DESCRIPTION_LENGTH_WARNING_THRESHOLD) {
    lengthWarning = {
      length: description.length,
      threshold: DESCRIPTION_LENGTH_WARNING_THRESHOLD,
      isExcessive: true,
    };
    // NOTE: matches.push moved to after pattern loop (Issue #167)
  }

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

  // Issue #167: Add length warning AFTER pattern scan with conditional severity
  // Long descriptions alone are LOW (informational), but length + other patterns = MEDIUM
  if (lengthWarning) {
    const hasOtherPatterns = matches.length > 0;
    matches.push({
      name: "excessive_description_length",
      pattern: `length > ${DESCRIPTION_LENGTH_WARNING_THRESHOLD}`,
      severity: hasOtherPatterns ? "MEDIUM" : "LOW",
      category: "suspicious_length",
      evidence: hasOtherPatterns
        ? `Description is ${description.length} characters AND contains ${matches.length} suspicious pattern(s)`
        : `Description is ${description.length} characters (informational - no suspicious patterns detected)`,
    });
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
    lengthWarning,
  };
}
