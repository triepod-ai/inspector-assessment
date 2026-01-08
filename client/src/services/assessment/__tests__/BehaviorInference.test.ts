/**
 * BehaviorInference Unit Tests
 *
 * Tests the standalone behavior inference function extracted from ToolAnnotationAssessor.
 * Validates pattern matching, persistence model detection, and edge cases.
 *
 * @group unit
 * @group annotations
 */

import { inferBehavior } from "../modules/annotations/BehaviorInference";
import type { ServerPersistenceContext } from "../config/annotationPatterns";

describe("BehaviorInference", () => {
  describe("inferBehavior", () => {
    describe("read-only tools", () => {
      it("should infer read-only for 'get_*' tools", () => {
        const result = inferBehavior("get_user", "Get user information");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("high");
        expect(result.isAmbiguous).toBe(false);
        expect(result.reason).toContain("read-only pattern");
      });

      it("should infer read-only for 'get-*' tools (kebab-case)", () => {
        const result = inferBehavior("get-weather", "Get current weather");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("high");
      });

      it("should infer read-only for 'fetch_*' tools", () => {
        const result = inferBehavior("fetch_data", "Fetch remote data");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("high");
      });

      it("should infer read-only for 'list_*' tools", () => {
        const result = inferBehavior("list_files", "List files in directory");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("high");
      });

      it("should infer read-only for 'search_*' tools", () => {
        const result = inferBehavior("search_documents", "Search documents");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should infer read-only for 'query_*' tools", () => {
        const result = inferBehavior("query_database", "Query the database");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should infer read-only for 'check_*' tools", () => {
        const result = inferBehavior("check_status", "Check system status");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should infer read-only for runAccessibilityAudit (Issue #18)", () => {
        const result = inferBehavior(
          "runAccessibilityAudit",
          "Run accessibility audit on page",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("medium");
        expect(result.reason).toContain("analysis");
      });

      it("should infer read-only for runSecurityScan (Issue #18)", () => {
        const result = inferBehavior(
          "runSecurityScan",
          "Run security scan on target",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.reason).toContain("analysis");
      });

      it("should infer read-only for runHealthCheck (Issue #18)", () => {
        const result = inferBehavior("runHealthCheck", "Run health check");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });
    });

    describe("write tools (non-destructive)", () => {
      it("should infer non-destructive for 'create_*' tools", () => {
        const result = inferBehavior("create_user", "Create a new user");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("high");
        expect(result.reason).toContain("create");
      });

      it("should infer non-destructive for 'add_*' tools", () => {
        const result = inferBehavior("add_item", "Add item to list");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.reason).toContain("create");
      });

      it("should infer non-destructive for 'insert_*' tools", () => {
        const result = inferBehavior("insert_record", "Insert database record");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should infer non-destructive for 'new_*' tools", () => {
        const result = inferBehavior("new_document", "Create new document");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should infer write for 'update_*' tools without persistence context", () => {
        const result = inferBehavior("update_settings", "Update user settings");

        expect(result.expectedReadOnly).toBe(false);
        // Without persistence context, defaults to non-destructive
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("medium");
      });

      it("should infer write for 'set_*' tools", () => {
        const result = inferBehavior("set_config", "Set configuration value");

        expect(result.expectedReadOnly).toBe(false);
        // Write but not destructive by default
        expect(result.reason).toContain("write pattern");
      });

      it("should infer write for 'modify_*' tools", () => {
        const result = inferBehavior("modify_record", "Modify existing record");

        expect(result.expectedReadOnly).toBe(false);
      });
    });

    describe("destructive tools", () => {
      it("should infer destructive for 'delete_*' tools", () => {
        const result = inferBehavior("delete_file", "Delete a file");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBe("high");
        expect(result.reason).toContain("destructive pattern");
      });

      it("should infer destructive for 'remove_*' tools", () => {
        const result = inferBehavior("remove_user", "Remove user from system");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should infer destructive for 'destroy_*' tools", () => {
        const result = inferBehavior("destroy_session", "Destroy user session");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
      });

      it("should infer destructive for 'drop_*' tools", () => {
        const result = inferBehavior("drop_table", "Drop database table");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
      });

      it("should infer destructive for 'purge_*' tools", () => {
        const result = inferBehavior("purge_cache", "Purge all cache entries");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
      });

      it("should infer destructive for 'clear_*' tools", () => {
        const result = inferBehavior("clear_logs", "Clear all log files");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(true);
      });
    });

    describe("persistence model detection", () => {
      it("should mark update as destructive with immediate persistence context", () => {
        const persistenceContext: ServerPersistenceContext = {
          model: "immediate",
          hasSaveOperations: false,
          hasWriteOperations: true,
          indicators: [],
          confidence: "high",
        };

        const result = inferBehavior(
          "update_user",
          "Update user data",
          undefined,
          persistenceContext,
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.reason).toContain("persist immediately");
      });

      it("should mark update as non-destructive with deferred persistence context", () => {
        const persistenceContext: ServerPersistenceContext = {
          model: "deferred",
          hasSaveOperations: true,
          hasWriteOperations: true,
          indicators: ["save_data"],
          confidence: "high",
        };

        const result = inferBehavior(
          "update_user",
          "Update user data",
          undefined,
          persistenceContext,
        );

        expect(result.expectedDestructive).toBe(false);
        expect(result.reason).toContain("in-memory until explicit save");
      });

      it("should detect immediate persistence from description keywords", () => {
        const result = inferBehavior(
          "update_config",
          "Update configuration and save to disk immediately",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.reason).toContain("immediate persistence");
      });

      it("should detect deferred persistence from description keywords", () => {
        const result = inferBehavior(
          "update_document",
          "Update document in memory buffer (call save to persist)",
        );

        expect(result.expectedDestructive).toBe(false);
        expect(result.reason).toContain("deferred");
      });
    });

    describe("description-based inference", () => {
      // Note: Description-based inference only triggers when NO pattern matches
      // Tool names like "process_*" match the ambiguous pattern and don't fall through

      it("should infer destructive from description mentioning delete", () => {
        // Use a tool name that doesn't match any pattern
        // Note: "deleting" does NOT contain "delete" as substring, so use exact word
        const result = inferBehavior(
          "cleanup_batch",
          "This will delete old entries from the batch",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBe("medium");
        expect(result.reason).toContain("delete");
      });

      it("should infer destructive from description mentioning remove", () => {
        // "cleanup_" doesn't match any pattern, so falls through to description
        // Note: "removing" does NOT contain "remove" as substring, so use exact word
        const result = inferBehavior(
          "cleanup_batch",
          "This will remove old entries from the batch",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.reason).toContain("remove");
      });

      it("should infer read-only from description mentioning read", () => {
        // Use a tool name that doesn't match any pattern
        const result = inferBehavior(
          "access_data",
          "Read data from external source",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBe("medium");
        expect(result.reason).toContain("read-only");
      });

      it("should infer read-only from description mentioning get", () => {
        // "retrieve_" doesn't match any pattern
        const result = inferBehavior(
          "retrieve_info",
          "Get information from the server",
        );

        expect(result.expectedReadOnly).toBe(true);
      });

      it("should infer read-only from description mentioning fetch", () => {
        // "load_" doesn't match any pattern
        const result = inferBehavior("load_data", "Fetch data from remote API");

        expect(result.expectedReadOnly).toBe(true);
      });
    });

    describe("ambiguous patterns", () => {
      // Note: "run_" and "execute_" are classified as WRITE patterns
      // "run_command" specifically is DESTRUCTIVE (explicit command execution)
      // "process_" is an actual AMBIGUOUS pattern

      it("should mark 'process_*' as ambiguous", () => {
        const result = inferBehavior("process_data", "Process the data");

        expect(result.isAmbiguous).toBe(true);
        expect(result.confidence).toBe("low");
        expect(result.reason).toContain("ambiguous");
      });

      it("should mark 'store_*' as ambiguous", () => {
        const result = inferBehavior("store_cache", "Store data in cache");

        expect(result.isAmbiguous).toBe(true);
        expect(result.confidence).toBe("low");
      });

      it("should mark 'handle_*' as ambiguous", () => {
        const result = inferBehavior(
          "handle_request",
          "Handle incoming request",
        );

        expect(result.isAmbiguous).toBe(true);
        expect(result.confidence).toBe("low");
      });

      it("should classify 'run_command' as destructive (explicit command execution)", () => {
        // run_command is explicitly listed in destructive patterns
        const result = inferBehavior("run_command", "Run arbitrary command");

        expect(result.expectedDestructive).toBe(true);
        expect(result.isAmbiguous).toBe(false);
        expect(result.confidence).toBe("high");
      });

      it("should classify 'run_*' (generic) as write pattern", () => {
        // Generic run_ patterns are classified as write
        const result = inferBehavior("run_task", "Run a task");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.isAmbiguous).toBe(false);
        // Write patterns have medium confidence by default
        expect(result.reason).toContain("write pattern");
      });
    });

    describe("confidence levels", () => {
      it("should return high confidence for clear name patterns", () => {
        expect(inferBehavior("get_user").confidence).toBe("high");
        expect(inferBehavior("delete_file").confidence).toBe("high");
        expect(inferBehavior("create_record").confidence).toBe("high");
      });

      it("should return medium confidence for description-based inference", () => {
        const result = inferBehavior(
          "do_something",
          "Read and process the input",
        );
        expect(result.confidence).toBe("medium");
      });

      it("should return medium confidence for run+analysis pattern (Issue #18)", () => {
        expect(inferBehavior("runAccessibilityAudit").confidence).toBe(
          "medium",
        );
        expect(inferBehavior("runSecurityScan").confidence).toBe("medium");
      });

      it("should return low confidence for ambiguous patterns", () => {
        // process_, store_, handle_ are actual ambiguous patterns
        expect(inferBehavior("process_request").confidence).toBe("low");
        expect(inferBehavior("store_value").confidence).toBe("low");
        // unknown patterns also return low confidence
        expect(inferBehavior("unknown_operation").confidence).toBe("low");
      });
    });

    describe("edge cases", () => {
      it("should handle tool without description", () => {
        const result = inferBehavior("get_data");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should handle empty description", () => {
        const result = inferBehavior("get_info", "");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should handle empty tool name gracefully", () => {
        const result = inferBehavior("");

        // Falls through to default case
        expect(result.isAmbiguous).toBe(true);
        expect(result.confidence).toBe("low");
      });

      it("should handle unknown tool name pattern", () => {
        const result = inferBehavior("foobar_xyz");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBe("low");
        expect(result.isAmbiguous).toBe(true);
        expect(result.reason).toContain("Could not infer");
      });

      it("should handle tool name with mixed case", () => {
        const result = inferBehavior("GetUserProfile", "Get user profile data");

        // Pattern matching is case-INSENSITIVE
        // "GetUserProfile" matches /^get[_-]?/i read-only pattern
        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should prioritize run+analysis over generic run pattern", () => {
        // "runAudit" has "run" (ambiguous) but also "audit" (analysis suffix)
        const result = inferBehavior("runAudit");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.isAmbiguous).toBe(false);
        expect(result.reason).toContain("analysis");
      });

      it("should handle camelCase tool names with analysis suffix", () => {
        const result = inferBehavior("runPerformanceAudit");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.isAmbiguous).toBe(false);
      });
    });

    describe("pattern precedence", () => {
      it("should check run+analysis before pattern matching", () => {
        // This is critical for Issue #18 fix - run+analysis takes precedence
        const result = inferBehavior("runAccessibilityAudit");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBe("medium");
        // Should NOT match "run" as ambiguous pattern
        expect(result.isAmbiguous).toBe(false);
      });

      it("should prefer name patterns over description hints", () => {
        // delete_* should win even if description says "read"
        const result = inferBehavior("delete_file", "Read and delete the file");

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should use description when name pattern is unknown", () => {
        // "cleanup_batch" doesn't match any pattern, so falls through to description
        const result = inferBehavior(
          "cleanup_batch",
          "Delete items that are invalid",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBe("medium");
      });

      it("should NOT use description when name matches ambiguous pattern", () => {
        // "process_item" matches ambiguous pattern - returns immediately
        // even though description mentions "delete"
        const result = inferBehavior(
          "process_item",
          "Delete items that are invalid",
        );

        expect(result.isAmbiguous).toBe(true);
        expect(result.confidence).toBe("low");
        // Description inference is NOT applied for ambiguous patterns
      });
    });
  });
});
