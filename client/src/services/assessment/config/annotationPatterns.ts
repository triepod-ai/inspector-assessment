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
