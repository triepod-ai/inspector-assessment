/**
 * Architecture & Behavior Inference Integration Tests
 *
 * Critical bug hunting scenarios for Issue #57 modules.
 * Focus: edge cases, signal conflicts, boundary conditions, integration bugs.
 *
 * @group integration
 * @group annotations
 * @group critical
 */

import { inferBehaviorEnhanced } from "../modules/annotations/BehaviorInference";
import { analyzeDescription } from "../modules/annotations/DescriptionAnalyzer";
import {
  analyzeInputSchema,
  analyzeOutputSchema,
  type JSONSchema,
} from "../modules/annotations/SchemaAnalyzer";
import {
  detectArchitecture,
  type ArchitectureContext,
} from "../modules/annotations/ArchitectureDetector";

describe("Architecture & Behavior Integration - Critical Bug Hunting", () => {
  describe("BUG HUNT: Multi-signal conflicts", () => {
    it("CRITICAL: should handle name says read-only but description says destructive", () => {
      const result = inferBehaviorEnhanced(
        "get_and_purge", // 'get' suggests read-only
        "Retrieves old records and permanently deletes them from storage", // destructive!
      );

      // Description should override weak name signal
      expect(result.expectedDestructive).toBe(true);
      expect(result.expectedReadOnly).toBe(false);
      expect(result.reason).toContain("Destructive");
    });

    it("CRITICAL: should handle schema contradicts description", () => {
      const inputSchema: JSONSchema = {
        type: "object",
        properties: {
          id: { type: "string" }, // Read-only signal
          force: { type: "boolean" }, // Destructive signal
          confirm: { type: "boolean" }, // Destructive signal
        },
      };

      const result = inferBehaviorEnhanced(
        "get_item",
        "Retrieves item details", // Read-only description
        inputSchema,
      );

      // Force/confirm flags should override read-only signals
      expect(result.expectedDestructive).toBe(true);
      expect(result.signals.inputSchemaSignal?.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should detect 'get and delete' pattern with conflicting signals", () => {
      const inputSchema: JSONSchema = {
        type: "object",
        properties: {
          query: { type: "string" }, // Read-only signal
        },
      };

      const outputSchema: JSONSchema = {
        type: "object",
        properties: {
          deletedCount: { type: "number" }, // Destructive signal!
        },
      };

      const result = inferBehaviorEnhanced(
        "query_expired_sessions",
        "Queries and removes expired sessions",
        inputSchema,
        outputSchema,
      );

      // Output schema deletedCount should reveal destructive behavior
      expect(result.expectedDestructive).toBe(true);
      expect(result.signals.outputSchemaSignal?.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should handle write keywords that cancel read-only keywords", () => {
      // "retrieves" is high-confidence read-only (90)
      // "creates" is high-confidence write (90)
      const result = analyzeDescription(
        "Retrieves template and creates new document from it",
      );

      // Write should override read-only when both present
      expect(result.expectedReadOnly).toBe(false);
      expect(result.evidence).toEqual(
        expect.arrayContaining([expect.stringContaining("override")]),
      );
    });
  });

  describe("BUG HUNT: Negation edge cases", () => {
    it("CRITICAL: should handle double negation (does not NOT delete)", () => {
      const result = analyzeDescription(
        "This operation does not NOT delete files", // double negative = positive
      );

      // Current implementation: only checks for negation patterns before keyword
      // This is actually ambiguous - should we detect this edge case?
      // Recording current behavior for regression detection
      expect(result.expectedDestructive).toBe(false);
    });

    it("CRITICAL: should handle negation far from keyword", () => {
      const result = analyzeDescription(
        "This operation does not, under any circumstances or conditions, delete any files",
      );

      // Negation window is 30 chars by default
      const distance = "does not, under any circumstances or conditions, "
        .length; // 54 chars
      expect(distance).toBeGreaterThan(30);

      // With default 30 char window, this should NOT be caught
      // This is a potential bug - negation might be missed
      expect(result.expectedDestructive).toBe(true); // Bug: negation not detected!
    });

    it("CRITICAL: should handle negation after keyword (not before)", () => {
      const result = analyzeDescription(
        "Deletes not the original but only temporary files",
      );

      // Current implementation only checks BEFORE keyword
      // This is a limitation - negation after keyword is ignored
      expect(result.expectedDestructive).toBe(true); // Limitation: negation after keyword not detected
    });

    it("CRITICAL: should handle partial word matches with negation", () => {
      const result = analyzeDescription(
        "This does not delete, it undeletes files", // "undelete" contains "delete"
      );

      // Word boundary regex should prevent "undelete" from matching "delete"
      // But negation before first "delete" should work
      expect(result.expectedDestructive).toBe(false);
    });
  });

  describe("BUG HUNT: Schema edge cases", () => {
    it("CRITICAL: should handle schemas with array of union types", () => {
      const schema: JSONSchema = {
        type: ["object", "null"], // Union type
        properties: {
          data: { type: "object" },
        },
      };

      // Union types with "null" might cause issues
      const result = analyzeOutputSchema(schema);
      expect(result).toBeDefined();
      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });

    it("CRITICAL: should handle recursive schema references", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          children: {
            type: "array",
            items: {
              type: "object",
              properties: {
                children: { type: "array" }, // Recursive reference
              },
            },
          },
        },
      };

      const result = analyzeOutputSchema(schema);
      expect(result.expectedReadOnly).toBe(true); // Array return type
    });

    it("CRITICAL: should handle schema with no type specified", () => {
      const schema: JSONSchema = {
        properties: {
          id: { type: "string" },
          name: { type: "string" },
        },
      };

      // Missing top-level "type" field - might cause issues
      const result = analyzeInputSchema(schema);
      expect(result).toBeDefined();
      expect(result.confidence).toBeGreaterThanOrEqual(0);
    });

    it("CRITICAL: should handle empty properties object vs undefined", () => {
      const emptyProps: JSONSchema = {
        type: "object",
        properties: {},
      };

      const noProps: JSONSchema = {
        type: "object",
      };

      const result1 = analyzeInputSchema(emptyProps);
      const result2 = analyzeInputSchema(noProps);

      // Both should be treated as "no schema"
      expect(result1.confidence).toBe(0);
      expect(result2.confidence).toBe(0);
    });

    it("CRITICAL: should handle additionalProperties with schema", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          data: { type: "object" },
        },
        additionalProperties: {
          type: "string", // Additional properties allowed
        },
      };

      const result = analyzeInputSchema(schema);
      expect(result.expectedReadOnly).toBe(false); // Has data payload
    });

    it("CRITICAL: should handle schema with circular JSON.stringify", () => {
      const context: ArchitectureContext = {
        tools: [
          {
            name: "test_tool",
            inputSchema: {
              type: "object",
              properties: {
                callback: {
                  type: "function", // Non-JSON-serializable
                },
              },
            },
          },
        ],
      };

      // Should not throw on JSON.stringify error
      expect(() => detectArchitecture(context)).not.toThrow();
    });
  });

  describe("BUG HUNT: Parameter name case sensitivity", () => {
    it("CRITICAL: should detect force flags regardless of case", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          Force: { type: "boolean" }, // Capital F
          CONFIRM: { type: "boolean" }, // All caps
          CaSCaDe: { type: "boolean" }, // Mixed case
        },
      };

      const result = analyzeInputSchema(schema);

      // Regex should be case-insensitive
      expect(result.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should match pagination params with various casings", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          pageSize: { type: "number" }, // camelCase
          PageSize: { type: "number" }, // PascalCase
          page_size: { type: "number" }, // snake_case
        },
      };

      const result = analyzeInputSchema(schema);

      // All three should be detected as pagination
      expect(result.expectedReadOnly).toBe(true);
      expect(result.confidence).toBeGreaterThan(90);
    });
  });

  describe("BUG HUNT: Architecture detector edge cases", () => {
    it("CRITICAL: should handle very large source code files without OOM", () => {
      const largeContent = "x".repeat(200000); // 200KB of content

      const context: ArchitectureContext = {
        tools: [{ name: "test" }],
        sourceCodeFiles: new Map([
          ["large.js", largeContent],
          ["another.js", largeContent],
        ]),
      };

      // Should limit content to prevent OOM
      expect(() => detectArchitecture(context)).not.toThrow();
    });

    it("CRITICAL: should handle special characters in tool names and descriptions", () => {
      const context: ArchitectureContext = {
        tools: [
          {
            name: "test_<script>alert('xss')</script>",
            description: "Test with <xml> & special 'quotes' and \"escapes\"",
          },
        ],
      };

      const result = detectArchitecture(context);
      expect(result).toBeDefined();
    });

    it("CRITICAL: should detect databases from abbreviated dependency names", () => {
      const context: ArchitectureContext = {
        tools: [{ name: "db_query" }],
        packageJson: {
          dependencies: {
            pg: "^8.0.0", // PostgreSQL (abbreviated)
          },
        },
      };

      const result = detectArchitecture(context);
      expect(result.databaseBackends).toContain("postgresql");
    });

    it("CRITICAL: should handle transport type with extra whitespace", () => {
      const context: ArchitectureContext = {
        tools: [{ name: "test" }],
        transportType: "  HTTP  ", // Extra whitespace
      };

      const result = detectArchitecture(context);
      expect(result.transportModes).toContain("http");
    });

    it("CRITICAL: should classify server with both stdio and external services as hybrid", () => {
      const context: ArchitectureContext = {
        tools: [
          { name: "github_create_issue", description: "Create GitHub issue" },
        ],
        transportType: "stdio",
      };

      const result = detectArchitecture(context);
      expect(result.serverType).toBe("hybrid"); // Stdio + external service = hybrid
    });

    it("CRITICAL: should handle null values in manifest dependencies", () => {
      const context: ArchitectureContext = {
        tools: [{ name: "test" }],
        manifestJson: {
          dependencies: {
            "valid-package": "1.0.0",
            "broken-ref": null as any, // Broken reference
          },
        },
      };

      expect(() => detectArchitecture(context)).not.toThrow();
    });
  });

  describe("BUG HUNT: Behavior inference aggregation edge cases", () => {
    it("CRITICAL: should handle all signals returning zero confidence", () => {
      const result = inferBehaviorEnhanced(
        "foo", // Unknown pattern
        "", // Empty description
        undefined, // No input schema
        undefined, // No output schema
      );

      expect(result.confidence).toBe("low");
      expect(result.isAmbiguous).toBe(true);
    });

    it("CRITICAL: should handle extremely high confidence scores without overflow", () => {
      // Multiple high-confidence signals could theoretically overflow
      const result = inferBehaviorEnhanced(
        "delete_file", // Destructive pattern (90)
        "Permanently deletes and destroys all files irreversibly", // Multiple destructive keywords
        {
          type: "object",
          properties: {
            force: { type: "boolean" }, // 90
            confirm: { type: "boolean" }, // 90
            hard_delete: { type: "boolean" }, // 95
          },
        },
        {
          type: "object",
          properties: {
            deleted: { type: "boolean" }, // 90
            deletedCount: { type: "number" }, // 90
          },
        },
      );

      // Should cap at 100
      expect(result.aggregatedConfidence).toBeLessThanOrEqual(100);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(0);
    });

    it("CRITICAL: should handle negative confidence penalty underflow", () => {
      // Conflicting signals apply -10 to -15 penalties
      const result = inferBehaviorEnhanced(
        "delete_file", // Destructive
        "Retrieves and lists files before deletion", // Read-only + destructive
      );

      // Should not go below 0
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(0);
    });
  });

  describe("BUG HUNT: Keyword boundary conditions", () => {
    it("CRITICAL: should not match keywords inside compound words", () => {
      const result = analyzeDescription(
        "Creates a delegate relationship between nodes", // "delegate" contains "delete"
      );

      // Word boundary regex should prevent false positive
      expect(result.expectedDestructive).toBe(false);
      expect(result.expectedReadOnly).toBe(false); // "Creates" should be detected as write
    });

    it("CRITICAL: should match keywords at start/end of description", () => {
      const startResult = analyzeDescription("Deletes all records");
      const endResult = analyzeDescription(
        "All records will be permanently deletes",
      );

      expect(startResult.expectedDestructive).toBe(true);
      expect(endResult.expectedDestructive).toBe(true); // "deletes" at end
    });

    it("CRITICAL: should handle multi-word keywords with inconsistent spacing", () => {
      const result1 = analyzeDescription("Looks up user information"); // "looks up" (2 spaces)
      const result2 = analyzeDescription("Looks  up user information"); // "looks  up" (3 spaces)

      // Regex uses \\s+ to match one or more spaces
      expect(result1.expectedReadOnly).toBe(true);
      expect(result2.expectedReadOnly).toBe(true);
    });

    it("CRITICAL: should handle keywords followed by punctuation", () => {
      const result = analyzeDescription(
        "Deletes, removes, and destroys all data permanently.",
      );

      // Should match multiple keywords even with punctuation
      expect(result.expectedDestructive).toBe(true);
      expect(result.confidence).toBeGreaterThan(90); // Multiple high-confidence keywords
    });
  });

  describe("BUG HUNT: Signal aggregation with sparse data", () => {
    it("CRITICAL: should handle only name signal available", () => {
      const result = inferBehaviorEnhanced(
        "delete_user",
        undefined,
        undefined,
        undefined,
      );

      expect(result.expectedDestructive).toBe(true);
      expect(result.confidence).toBe("high");
      expect(Object.keys(result.signals)).toHaveLength(1); // Only namePatternSignal
    });

    it("CRITICAL: should handle only description signal available", () => {
      const result = inferBehaviorEnhanced(
        "foo", // Unknown pattern
        "Permanently deletes all user data",
        undefined,
        undefined,
      );

      expect(result.expectedDestructive).toBe(true);
      expect(Object.keys(result.signals).length).toBeGreaterThanOrEqual(2); // name + description
    });

    it("CRITICAL: should handle only schema signals available", () => {
      const result = inferBehaviorEnhanced(
        "foo", // Unknown pattern
        undefined,
        {
          type: "object",
          properties: {
            force: { type: "boolean" },
          },
        },
        {
          type: "object",
          properties: {
            deleted: { type: "boolean" },
          },
        },
      );

      expect(result.expectedDestructive).toBe(true);
      expect(result.signals.inputSchemaSignal).toBeDefined();
      expect(result.signals.outputSchemaSignal).toBeDefined();
    });
  });

  describe("BUG HUNT: Real-world deceptive patterns", () => {
    it("CRITICAL: should detect soft-delete masquerading as read-only", () => {
      const result = inferBehaviorEnhanced(
        "get_and_archive", // Sounds read-only
        "Retrieves records and marks them as archived (soft delete)",
        {
          type: "object",
          properties: {
            id: { type: "string" },
            archive: { type: "boolean" },
          },
        },
        {
          type: "object",
          properties: {
            archived: { type: "boolean" },
            archivedCount: { type: "number" },
          },
        },
      );

      // Description mentions "soft delete" and "marks"
      // But this is still a write operation, not destructive
      expect(result.expectedReadOnly).toBe(false);
    });

    it("CRITICAL: should detect cascade delete hidden in parameters", () => {
      const result = inferBehaviorEnhanced(
        "remove_project",
        "Removes project and related data",
        {
          type: "object",
          properties: {
            id: { type: "string" },
            cascade: { type: "boolean" }, // Hidden danger!
          },
        },
      );

      expect(result.expectedDestructive).toBe(true);
      expect(result.signals.inputSchemaSignal?.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should detect read-modify-write pattern", () => {
      const result = inferBehaviorEnhanced(
        "increment_counter",
        "Reads current value and increments counter",
        {
          type: "object",
          properties: {
            id: { type: "string" },
          },
        },
        {
          type: "object",
          properties: {
            value: { type: "number" },
          },
        },
      );

      // "increments" is not in the write keyword list!
      // This might be a missing keyword
      expect(result.expectedReadOnly).toBe(false); // Should be write
    });

    it("CRITICAL: should detect batch operations that might be destructive", () => {
      const result = inferBehaviorEnhanced(
        "update_users_bulk",
        "Updates multiple users in a single operation",
        {
          type: "object",
          properties: {
            ids: { type: "array", items: { type: "string" } },
            changes: { type: "object" },
          },
        },
      );

      // Bulk operations with "update" should be write
      expect(result.expectedReadOnly).toBe(false);
      expect(result.signals.inputSchemaSignal?.evidence).toEqual(
        expect.arrayContaining([expect.stringContaining("Bulk ID array")]),
      );
    });
  });

  describe("BUG HUNT: Unicode and internationalization", () => {
    it("CRITICAL: should handle Unicode characters in descriptions", () => {
      const result = analyzeDescription("删除所有文件 deletes all files 🗑️");

      // English keyword "deletes" should be detected
      expect(result.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should handle tool names with Unicode", () => {
      const result = inferBehaviorEnhanced("delete_用户", "Deletes user");

      // Pattern matching should work with non-ASCII tool names
      expect(result.expectedDestructive).toBe(true);
    });

    it("CRITICAL: should handle emoji in descriptions", () => {
      const result = analyzeDescription(
        "🔍 Searches and 🗑️ permanently deletes old files",
      );

      expect(result.expectedDestructive).toBe(true);
    });
  });

  describe("BUG HUNT: Precision loss in confidence calculations", () => {
    it("CRITICAL: should handle fractional confidence scores correctly", () => {
      // Average of 3 signals: (90 + 70 + 85) / 3 = 81.666...
      const result = inferBehaviorEnhanced(
        "list_items", // Read-only (90)
        "Retrieves items from storage", // Read-only (~70-90)
      );

      // Should be rounded to integer
      expect(result.aggregatedConfidence).toBe(
        Math.round(result.aggregatedConfidence),
      );
    });

    it("CRITICAL: should handle edge case where confidence is exactly on threshold", () => {
      // numberToConfidence thresholds: >=80 high, >=50 medium, <50 low
      const result = inferBehaviorEnhanced(
        "unknown_op",
        "", // Zero confidence description
        {
          type: "object",
          properties: {
            query: { type: "string" }, // 80 confidence
          },
        },
      );

      // With query param (80) this should be exactly on threshold
      // Should be classified as "high" (>=80)
      expect(result.confidence).toBe("high");
    });
  });
});
