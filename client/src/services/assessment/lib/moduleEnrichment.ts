/**
 * Module Enrichment Utilities
 *
 * Shared utilities for enriching sparse assessment modules with
 * additional context for Stage B Claude validation.
 *
 * @module assessment/lib/moduleEnrichment
 * @see Issue #194 - Enhance sparse module data for Stage B Claude validation
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type {
  ToolCapability,
  ToolInventoryItem,
  FlagForReview,
  PatternCoverageInfo,
  AUPCategory,
} from "@/lib/assessment/aupComplianceTypes";
import { AUP_PATTERNS } from "@/lib/aupPatterns";

// ============================================================================
// Constants
// ============================================================================

/**
 * Maximum character length for descriptions in enrichment data
 * Helps maintain ~500 token budget per tool
 */
export const MAX_DESCRIPTION_LENGTH = 300;

/**
 * Maximum number of sample patterns to include
 */
export const MAX_SAMPLE_PATTERNS = 5;

/**
 * Keyword patterns for inferring tool capabilities
 * Maps capability types to arrays of keywords/patterns
 */
export const CAPABILITY_KEYWORDS: Record<ToolCapability, RegExp[]> = {
  file_system: [
    /\bfile\b/i,
    /\bread\b/i,
    /\bwrite\b/i,
    /\bpath\b/i,
    /\bdirectory\b/i,
    /\bfolder\b/i,
    /\b(fs|filesystem)\b/i,
    /\bsave\b/i,
    /\bload\b/i,
    /\bdownload\b/i,
    /\bupload\b/i,
    /\bdelete\b/i,
    /\bcreate\b/i,
    /\bremove\b/i,
  ],
  network: [
    /\bhttp\b/i,
    /\bhttps\b/i,
    /\bfetch\b/i,
    /\brequest\b/i,
    /\burl\b/i,
    /\bapi\b/i,
    /\bsocket\b/i,
    /\bwebsocket\b/i,
    /\bweb\b/i,
    /\bremote\b/i,
    /\bdownload\b/i,
    /\bupload\b/i,
    /\bsend\b/i,
    /\bpost\b/i,
    /\bget\b/i,
  ],
  exec: [
    /\bexec\b/i,
    /\bexecute\b/i,
    /\brun\b/i,
    /\bcommand\b/i,
    /\bshell\b/i,
    /\bprocess\b/i,
    /\bspawn\b/i,
    /\bterminal\b/i,
    /\bbash\b/i,
    /\bcmd\b/i,
    /\bscript\b/i,
    /\beval\b/i,
  ],
  database: [
    /\bquery\b/i,
    /\bsql\b/i,
    /\bdb\b/i,
    /\bdatabase\b/i,
    /\bstore\b/i,
    /\bstorage\b/i,
    /\btable\b/i,
    /\binsert\b/i,
    /\bupdate\b/i,
    /\bselect\b/i,
    /\bmongo\b/i,
    /\bredis\b/i,
    /\bpostgres\b/i,
    /\bmysql\b/i,
  ],
  auth: [
    /\bauth\b/i,
    /\bauthenticat/i,
    /\bauthoriz/i,
    /\btoken\b/i,
    /\bcredential\b/i,
    /\bpassword\b/i,
    /\bsecret\b/i,
    /\bkey\b/i,
    /\blogin\b/i,
    /\blogout\b/i,
    /\bsession\b/i,
    /\boauth\b/i,
    /\bjwt\b/i,
    /\bapi.?key\b/i,
  ],
  crypto: [
    /\bcrypt/i,
    /\bencrypt/i,
    /\bdecrypt/i,
    /\bhash\b/i,
    /\bsign\b/i,
    /\bverify\b/i,
    /\bcipher\b/i,
    /\baes\b/i,
    /\brsa\b/i,
    /\bhmac\b/i,
    /\bsha\b/i,
    /\bmd5\b/i,
  ],
  system: [
    /\bsystem\b/i,
    /\bos\b/i,
    /\benv\b/i,
    /\benvironment\b/i,
    /\bconfig\b/i,
    /\bsetting/i,
    /\bregistry\b/i,
    /\bservice\b/i,
    /\broot\b/i,
    /\badmin\b/i,
    /\bsudo\b/i,
    /\bpermission\b/i,
  ],
  unknown: [], // Never matches - fallback category
};

/**
 * Capabilities that trigger "flag for review" even without violations
 * These represent potentially sensitive operations
 */
export const SENSITIVE_CAPABILITIES: ToolCapability[] = [
  "exec",
  "auth",
  "system",
  "crypto",
];

/**
 * Reasons for flagging based on capabilities
 */
export const CAPABILITY_FLAG_REASONS: Record<ToolCapability, string> = {
  file_system: "File system access capabilities detected",
  network: "Network communication capabilities detected",
  exec: "Command/code execution capabilities - high risk",
  database: "Database access capabilities detected",
  auth: "Authentication/credential handling - review security",
  crypto: "Cryptographic operations - verify proper implementation",
  system: "System-level access capabilities - high risk",
  unknown: "Unable to determine tool capabilities",
};

// ============================================================================
// Capability Inference
// ============================================================================

/**
 * Infer tool capabilities from name and description
 *
 * @param tool - MCP tool object with name and optional description
 * @returns Array of inferred capabilities (may include duplicates if strongly matched)
 */
export function inferToolCapabilities(tool: Tool): ToolCapability[] {
  const capabilities = new Set<ToolCapability>();
  // Replace underscores with spaces so word boundaries work correctly
  // e.g., "execute_shell" becomes "execute shell" for pattern matching
  const textToAnalyze = `${tool.name} ${tool.description || ""}`
    .toLowerCase()
    .replace(/_/g, " ");

  for (const [capability, patterns] of Object.entries(CAPABILITY_KEYWORDS)) {
    if (capability === "unknown") continue;

    for (const pattern of patterns) {
      if (pattern.test(textToAnalyze)) {
        capabilities.add(capability as ToolCapability);
        break; // Found one match for this capability, move to next
      }
    }
  }

  // If no capabilities detected, mark as unknown
  if (capabilities.size === 0) {
    capabilities.add("unknown");
  }

  return Array.from(capabilities);
}

// ============================================================================
// Tool Inventory Building
// ============================================================================

/**
 * Build tool inventory with inferred capabilities
 *
 * @param tools - Array of MCP tools
 * @returns Array of tool inventory items with capabilities
 */
export function buildToolInventory(tools: Tool[]): ToolInventoryItem[] {
  return tools.map((tool) => ({
    name: tool.name,
    description: truncateForTokens(
      tool.description || "",
      MAX_DESCRIPTION_LENGTH,
    ),
    capabilities: inferToolCapabilities(tool),
  }));
}

// ============================================================================
// Flags for Review
// ============================================================================

/**
 * Generate flags for tools that warrant review based on capabilities
 * Even without AUP violations, tools with sensitive capabilities should be flagged
 *
 * @param toolInventory - Tool inventory with capabilities
 * @returns Array of flags for review
 */
export function generateFlagsForReview(
  toolInventory: ToolInventoryItem[],
): FlagForReview[] {
  const flags: FlagForReview[] = [];

  for (const tool of toolInventory) {
    const sensitiveCapabilities = tool.capabilities.filter((cap) =>
      SENSITIVE_CAPABILITIES.includes(cap),
    );

    if (sensitiveCapabilities.length > 0) {
      // Generate reason based on most concerning capability
      const primaryCapability = sensitiveCapabilities[0];
      const reason = CAPABILITY_FLAG_REASONS[primaryCapability];

      flags.push({
        toolName: tool.name,
        reason,
        capabilities: sensitiveCapabilities,
        confidence: "low",
      });
    }
  }

  return flags;
}

// ============================================================================
// Pattern Coverage
// ============================================================================

/**
 * Build pattern coverage info from AUP patterns
 *
 * @returns Pattern coverage metadata
 */
export function buildPatternCoverage(): PatternCoverageInfo {
  // Count total patterns across all categories
  let totalPatterns = 0;
  const categoriesCovered: AUPCategory[] = [];
  const severityBreakdown = {
    critical: 0,
    high: 0,
    medium: 0,
    flag: 0,
  };

  for (const patternDef of AUP_PATTERNS) {
    totalPatterns += patternDef.patterns.length;
    categoriesCovered.push(patternDef.category);

    // Count by severity
    switch (patternDef.severity) {
      case "CRITICAL":
        severityBreakdown.critical += patternDef.patterns.length;
        break;
      case "HIGH":
        severityBreakdown.high += patternDef.patterns.length;
        break;
      case "MEDIUM":
        severityBreakdown.medium += patternDef.patterns.length;
        break;
      case "FLAG":
        severityBreakdown.flag += patternDef.patterns.length;
        break;
    }
  }

  // Sample patterns for transparency (one from each severity level)
  const samplePatterns: string[] = [];
  const seenSeverities = new Set<string>();

  for (const patternDef of AUP_PATTERNS) {
    if (
      !seenSeverities.has(patternDef.severity) &&
      samplePatterns.length < MAX_SAMPLE_PATTERNS
    ) {
      // Take first pattern from this severity level
      const firstPattern = patternDef.patterns[0];
      samplePatterns.push(
        `${patternDef.severity}: ${firstPattern.source} (${patternDef.categoryName})`,
      );
      seenSeverities.add(patternDef.severity);
    }
  }

  return {
    totalPatterns,
    categoriesCovered,
    samplePatterns,
    severityBreakdown,
  };
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Truncate text to fit within token budget
 *
 * @param text - Text to truncate
 * @param maxLength - Maximum character length
 * @returns Truncated text with ellipsis if needed
 */
export function truncateForTokens(text: string, maxLength: number): string {
  if (text.length <= maxLength) {
    return text;
  }
  return text.slice(0, maxLength - 3) + "...";
}
