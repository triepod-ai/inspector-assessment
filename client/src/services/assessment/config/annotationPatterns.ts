/**
 * Tool Annotation Pattern Configuration
 *
 * Configurable pattern system for inferring expected tool behavior from names.
 * Supports JSON configuration files for customization.
 */

import * as fs from "fs";

/**
 * Pattern configuration for tool behavior inference.
 * Each category contains string patterns that are converted to RegExp at runtime.
 * Patterns should end with underscore or hyphen (e.g., "get_", "delete-")
 */
export interface AnnotationPatternConfig {
  /** Patterns indicating read-only operations (e.g., "get_", "list_", "fetch_") */
  readOnly: string[];
  /** Patterns indicating destructive operations (e.g., "delete_", "remove_", "destroy_") */
  destructive: string[];
  /** Patterns indicating write operations that are not destructive (e.g., "create_", "add_") */
  write: string[];
  /** Patterns that are semantically ambiguous - behavior varies by implementation */
  ambiguous: string[];
}

/**
 * Compiled patterns ready for matching.
 * String patterns are converted to RegExp objects.
 */
export interface CompiledPatterns {
  readOnly: RegExp[];
  destructive: RegExp[];
  write: RegExp[];
  ambiguous: RegExp[];
}

/**
 * Result of pattern matching with confidence scoring.
 */
export interface PatternMatchResult {
  category: "readOnly" | "destructive" | "write" | "ambiguous" | "unknown";
  pattern: string | null;
  confidence: "high" | "medium" | "low";
  isAmbiguous: boolean;
}

/**
 * Default annotation patterns.
 * These patterns have been validated against real-world MCP servers.
 */
export const DEFAULT_ANNOTATION_PATTERNS: AnnotationPatternConfig = {
  readOnly: [
    "get_",
    "get-",
    "list_",
    "list-",
    "fetch_",
    "fetch-",
    "read_",
    "read-",
    "query_",
    "query-",
    "search_",
    "search-",
    "find_",
    "find-",
    "show_",
    "show-",
    "view_",
    "view-",
    "describe_",
    "describe-",
    "check_",
    "check-",
    "verify_",
    "verify-",
    "validate_",
    "validate-",
    "count_",
    "count-",
    "status_",
    "status-",
    "info_",
    "info-",
    "lookup_",
    "lookup-",
    "browse_",
    "browse-",
    "preview_",
    "preview-",
    "download_",
    "download-",
  ],
  destructive: [
    "delete_",
    "delete-",
    "remove_",
    "remove-",
    "destroy_",
    "destroy-",
    "drop_",
    "drop-",
    "purge_",
    "purge-",
    "clear_",
    "clear-",
    "wipe_",
    "wipe-",
    "erase_",
    "erase-",
    "reset_",
    "reset-",
    "truncate_",
    "truncate-",
    "revoke_",
    "revoke-",
    "terminate_",
    "terminate-",
    "cancel_",
    "cancel-",
    "kill_",
    "kill-",
    "force_",
    "force-",
  ],
  write: [
    "create_",
    "create-",
    "add_",
    "add-",
    "insert_",
    "insert-",
    "update_",
    "update-",
    "modify_",
    "modify-",
    "edit_",
    "edit-",
    "change_",
    "change-",
    "set_",
    "set-",
    "put_",
    "put-",
    "patch_",
    "patch-",
    "post_",
    "post-",
    "write_",
    "write-",
    "upload_",
    "upload-",
    "send_",
    "send-",
    "submit_",
    "submit-",
    "publish_",
    "publish-",
    "enable_",
    "enable-",
    "disable_",
    "disable-",
    "start_",
    "start-",
    "stop_",
    "stop-",
    "run_",
    "run-",
    "execute_",
    "execute-",
  ],
  ambiguous: [
    "store_",
    "store-",
    "queue_",
    "queue-",
    "cache_",
    "cache-",
    "process_",
    "process-",
    "handle_",
    "handle-",
    "manage_",
    "manage-",
    "sync_",
    "sync-",
    "transfer_",
    "transfer-",
    "push_",
    "push-",
    "pop_",
    "pop-",
    "apply_",
    "apply-",
    "compute_",
    "compute-",
    "calculate_",
    "calculate-",
    "transform_",
    "transform-",
    "convert_",
    "convert-",
    "evaluate_",
    "evaluate-",
    "log_",
    "log-",
    "record_",
    "record-",
    "track_",
    "track-",
    "register_",
    "register-",
    "save_",
    "save-",
  ],
};

/**
 * Convert a string pattern to a RegExp.
 * Handles patterns like "get_" -> /^get[_-]?/i
 */
function patternToRegex(pattern: string): RegExp {
  // Remove trailing underscore/hyphen for the base pattern
  const base = pattern.replace(/[_-]$/, "");
  // Create regex that matches pattern at start of string, with optional underscore/hyphen
  return new RegExp(`^${escapeRegex(base)}[_-]?`, "i");
}

/**
 * Escape special regex characters in a string.
 */
function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Compile string patterns into RegExp objects for efficient matching.
 */
export function compilePatterns(
  config: AnnotationPatternConfig,
): CompiledPatterns {
  return {
    readOnly: config.readOnly.map(patternToRegex),
    destructive: config.destructive.map(patternToRegex),
    write: config.write.map(patternToRegex),
    ambiguous: config.ambiguous.map(patternToRegex),
  };
}

/**
 * Load pattern configuration from a JSON file.
 * Partial configs are merged with defaults.
 *
 * @param configPath - Path to JSON configuration file
 * @returns Merged configuration with defaults
 */
export function loadPatternConfig(
  configPath?: string,
): AnnotationPatternConfig {
  if (!configPath) {
    return DEFAULT_ANNOTATION_PATTERNS;
  }

  try {
    const configContent = fs.readFileSync(configPath, "utf-8");
    const userConfig = JSON.parse(
      configContent,
    ) as Partial<AnnotationPatternConfig>;

    // Merge with defaults - user config overrides defaults for specified categories
    return {
      readOnly: userConfig.readOnly ?? DEFAULT_ANNOTATION_PATTERNS.readOnly,
      destructive:
        userConfig.destructive ?? DEFAULT_ANNOTATION_PATTERNS.destructive,
      write: userConfig.write ?? DEFAULT_ANNOTATION_PATTERNS.write,
      ambiguous: userConfig.ambiguous ?? DEFAULT_ANNOTATION_PATTERNS.ambiguous,
    };
  } catch {
    console.warn(
      `Warning: Could not load pattern config from ${configPath}, using defaults`,
    );
    return DEFAULT_ANNOTATION_PATTERNS;
  }
}

/**
 * Match a tool name against compiled patterns and return the result.
 *
 * @param toolName - The tool name to match
 * @param patterns - Compiled pattern sets
 * @returns Match result with category, confidence, and ambiguity flag
 */
export function matchToolPattern(
  toolName: string,
  patterns: CompiledPatterns,
): PatternMatchResult {
  const lowerName = toolName.toLowerCase();

  // Check ambiguous patterns FIRST (highest priority for this feature)
  for (const pattern of patterns.ambiguous) {
    if (pattern.test(lowerName)) {
      return {
        category: "ambiguous",
        pattern: pattern.source,
        confidence: "low",
        isAmbiguous: true,
      };
    }
  }

  // Check destructive patterns (high confidence)
  for (const pattern of patterns.destructive) {
    if (pattern.test(lowerName)) {
      return {
        category: "destructive",
        pattern: pattern.source,
        confidence: "high",
        isAmbiguous: false,
      };
    }
  }

  // Check read-only patterns (high confidence)
  for (const pattern of patterns.readOnly) {
    if (pattern.test(lowerName)) {
      return {
        category: "readOnly",
        pattern: pattern.source,
        confidence: "high",
        isAmbiguous: false,
      };
    }
  }

  // Check write patterns (medium confidence)
  for (const pattern of patterns.write) {
    if (pattern.test(lowerName)) {
      return {
        category: "write",
        pattern: pattern.source,
        confidence: "medium",
        isAmbiguous: false,
      };
    }
  }

  // No pattern match
  return {
    category: "unknown",
    pattern: null,
    confidence: "low",
    isAmbiguous: true,
  };
}

/**
 * Singleton instance of compiled default patterns for performance.
 */
let defaultCompiledPatterns: CompiledPatterns | null = null;

/**
 * Get compiled default patterns (cached for performance).
 */
export function getDefaultCompiledPatterns(): CompiledPatterns {
  if (!defaultCompiledPatterns) {
    defaultCompiledPatterns = compilePatterns(DEFAULT_ANNOTATION_PATTERNS);
  }
  return defaultCompiledPatterns;
}

// ============================================================================
// Persistence Detection for Write Operations (Three-Tier Classification)
// ============================================================================

/**
 * Persistence model for MCP servers.
 * Determines whether write operations persist immediately or are deferred until explicit save.
 */
export type PersistenceModel = "immediate" | "deferred" | "unknown";

/**
 * Result of persistence model detection for a server.
 */
export interface ServerPersistenceContext {
  model: PersistenceModel;
  hasSaveOperations: boolean;
  hasWriteOperations: boolean;
  indicators: string[];
  confidence: "high" | "medium" | "low";
}

/**
 * Patterns indicating explicit save/persist operations.
 * If a server has these, write operations are likely in-memory until save.
 */
export const SAVE_OPERATION_PATTERNS: RegExp[] = [
  /^save[_-]/i,
  /^persist[_-]/i,
  /^commit[_-]/i,
  /^flush[_-]/i,
  /^write_to[_-]/i,
  /^export[_-]/i,
  /^sync_to[_-]/i,
  /[_-]save$/i,
  /[_-]persist$/i,
  /[_-]commit$/i,
];

/**
 * Patterns indicating write operations (create, add, update, etc.).
 */
export const WRITE_OPERATION_PATTERNS: RegExp[] = [
  /^create[_-]/i,
  /^add[_-]/i,
  /^insert[_-]/i,
  /^update[_-]/i,
  /^modify[_-]/i,
  /^edit[_-]/i,
  /^set[_-]/i,
  /^put[_-]/i,
  /^patch[_-]/i,
];

/**
 * Keywords in tool descriptions that indicate immediate persistence to storage.
 * These suggest the operation writes directly to database/file/API.
 */
export const IMMEDIATE_PERSISTENCE_INDICATORS: RegExp[] = [
  // Database indicators
  /neo4j/i,
  /mongodb/i,
  /postgres/i,
  /mysql/i,
  /sqlite/i,
  /database/i,
  /\bdb\b/i,
  /redis/i,
  /dynamodb/i,
  /firestore/i,
  /supabase/i,
  // File system indicators
  /file\s*(system|storage)/i,
  /\bdisk\b/i,
  /storage\s*backend/i,
  /writes?\s*to\s*(file|disk)/i,
  // Cloud/external storage
  /\bs3\b/i,
  /cloud\s*storage/i,
  /blob\s*storage/i,
  // Persistence language
  /primary.*fallback/i, // "(Neo4j primary, file fallback)"
  /immediately/i,
  /directly\s*(writes?|saves?|stores?)/i,
  /persists?\s*(to|immediately)/i,
  /writes?\s*directly/i,
  /stores?\s*in\s*(database|db|file)/i,
  // API indicators (external state change)
  /external\s*api/i,
  /third[- ]?party\s*(api|service)/i,
];

/**
 * Keywords in tool descriptions that indicate deferred/in-memory operations.
 * These suggest the operation modifies state that isn't persisted until explicit save.
 */
export const DEFERRED_PERSISTENCE_INDICATORS: RegExp[] = [
  /in[- ]?memory/i,
  /until\s*saved/i,
  /before\s*saving/i,
  /temporary/i,
  /\bbuffer\b/i,
  /\bsession\b/i,
  /working\s*copy/i,
  /local\s*state/i,
  /not\s*persisted/i,
  /changes?\s*are\s*not\s*saved/i,
];

/**
 * Detect the persistence model of an MCP server by analyzing its tool set.
 *
 * Logic:
 * - If server has write ops (create_, add_) but NO save ops (save_, persist_) → immediate
 * - If server has write ops AND save ops → deferred (in-memory until save)
 * - Otherwise → unknown
 *
 * @param toolNames - Array of tool names from the server
 * @returns ServerPersistenceContext with model and indicators
 */
export function detectPersistenceModel(
  toolNames: string[],
): ServerPersistenceContext {
  const indicators: string[] = [];

  const hasWriteOps = toolNames.some((name) =>
    WRITE_OPERATION_PATTERNS.some((pattern) => pattern.test(name)),
  );

  const hasSaveOps = toolNames.some((name) =>
    SAVE_OPERATION_PATTERNS.some((pattern) => pattern.test(name)),
  );

  if (hasWriteOps) {
    indicators.push(
      `Write operations detected: ${toolNames
        .filter((n) => WRITE_OPERATION_PATTERNS.some((p) => p.test(n)))
        .join(", ")}`,
    );
  }

  if (hasSaveOps) {
    indicators.push(
      `Save operations detected: ${toolNames
        .filter((n) => SAVE_OPERATION_PATTERNS.some((p) => p.test(n)))
        .join(", ")}`,
    );
  }

  let model: PersistenceModel;
  let confidence: "high" | "medium" | "low";

  if (hasWriteOps && !hasSaveOps) {
    model = "immediate";
    confidence = "medium"; // Medium because we're inferring from absence of save ops
    indicators.push(
      "No save operations found → write operations likely persist immediately",
    );
  } else if (hasWriteOps && hasSaveOps) {
    model = "deferred";
    confidence = "high"; // High because presence of save ops is explicit
    indicators.push(
      "Save operations present → write operations likely in-memory until save",
    );
  } else {
    model = "unknown";
    confidence = "low";
    indicators.push("Cannot determine persistence model from tool names");
  }

  return {
    model,
    hasSaveOperations: hasSaveOps,
    hasWriteOperations: hasWriteOps,
    indicators,
    confidence,
  };
}

/**
 * Check if a tool description indicates immediate persistence.
 *
 * @param description - Tool description to analyze
 * @returns Object with detection result and matched indicators
 */
export function checkDescriptionForImmediatePersistence(description: string): {
  indicatesImmediate: boolean;
  indicatesDeferred: boolean;
  matchedPatterns: string[];
} {
  const matchedPatterns: string[] = [];

  // Check for immediate persistence indicators
  let indicatesImmediate = false;
  for (const pattern of IMMEDIATE_PERSISTENCE_INDICATORS) {
    if (pattern.test(description)) {
      indicatesImmediate = true;
      matchedPatterns.push(`immediate: ${pattern.source}`);
    }
  }

  // Check for deferred persistence indicators
  let indicatesDeferred = false;
  for (const pattern of DEFERRED_PERSISTENCE_INDICATORS) {
    if (pattern.test(description)) {
      indicatesDeferred = true;
      matchedPatterns.push(`deferred: ${pattern.source}`);
    }
  }

  return {
    indicatesImmediate,
    indicatesDeferred,
    matchedPatterns,
  };
}
