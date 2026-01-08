/**
 * BehaviorInference Integration Tests
 *
 * Tests cross-module signal aggregation for Issue #57:
 * - DescriptionAnalyzer + SchemaAnalyzer + BehaviorInference
 * - Multi-signal confidence aggregation
 * - Conflict resolution between signals
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import { inferBehaviorEnhanced } from "../modules/annotations/BehaviorInference";
import type { JSONSchema } from "../modules/annotations/SchemaAnalyzer";

describe("BehaviorInference - Signal Aggregation Integration", () => {
  describe("High Confidence Scenarios (All Signals Agree)", () => {
    it("should aggregate to high confidence when all signals agree on read-only", () => {
      const result = inferBehaviorEnhanced(
        "list_atlas_projects",
        "Lists all projects in the Neo4j graph database using Cypher queries",
        {
          type: "object",
          properties: {
            limit: { type: "number", description: "Maximum results to return" },
            offset: {
              type: "number",
              description: "Starting offset for pagination",
            },
          },
        } as JSONSchema,
        {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              name: { type: "string" },
            },
          },
        } as JSONSchema,
      );

      expect(result.expectedReadOnly).toBe(true);
      expect(result.expectedDestructive).toBe(false);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(90);
      expect(result.confidence).toBe("high");
      expect(result.isAmbiguous).toBe(false);

      // Verify all signals detected
      expect(result.signals.namePatternSignal).toBeDefined();
      expect(result.signals.descriptionSignal).toBeDefined();
      expect(result.signals.inputSchemaSignal).toBeDefined();
      expect(result.signals.outputSchemaSignal).toBeDefined();

      // Verify signal agreement
      expect(result.signals.namePatternSignal?.expectedReadOnly).toBe(true);
      expect(result.signals.descriptionSignal?.expectedReadOnly).toBe(true);
      expect(result.signals.inputSchemaSignal?.expectedReadOnly).toBe(true);
      expect(result.signals.outputSchemaSignal?.expectedReadOnly).toBe(true);
    });

    it("should aggregate to high confidence when all signals agree on destructive", () => {
      const result = inferBehaviorEnhanced(
        "atlas_database_clean",
        "Permanently removes all data from the database and cannot be undone",
        {
          type: "object",
          properties: {
            confirm: {
              type: "boolean",
              description:
                "Confirmation flag required for destructive operation",
            },
            cascade: {
              type: "boolean",
              description: "Also delete related entities",
            },
          },
          required: ["confirm"],
        } as JSONSchema,
        {
          type: "object",
          properties: {
            deleted: { type: "boolean" },
            deletedCount: { type: "number" },
          },
        } as JSONSchema,
      );

      expect(result.expectedDestructive).toBe(true);
      expect(result.expectedReadOnly).toBe(false);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(90);
      expect(result.confidence).toBe("high");

      // Verify destructive signals
      expect(result.signals.descriptionSignal?.expectedDestructive).toBe(true);
      expect(result.signals.inputSchemaSignal?.expectedDestructive).toBe(true);
      expect(result.signals.outputSchemaSignal?.expectedDestructive).toBe(true);
    });

    it("should aggregate to high confidence for write operations", () => {
      const result = inferBehaviorEnhanced(
        "atlas_project_create",
        "Creates a new project in the Neo4j graph database",
        {
          type: "object",
          properties: {
            data: {
              type: "object",
              properties: {
                name: { type: "string" },
                description: { type: "string" },
              },
              required: ["name"],
            },
          },
        } as JSONSchema,
        {
          type: "object",
          properties: {
            id: { type: "string" },
            createdAt: { type: "string", format: "date-time" },
          },
        } as JSONSchema,
      );

      expect(result.expectedReadOnly).toBe(false);
      expect(result.expectedDestructive).toBe(false); // CREATE is NOT destructive
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(80);
      expect(result.confidence).toBe("high");
    });
  });

  describe("Conflicting Signals (Reduced Confidence)", () => {
    it("should downgrade confidence when name suggests write but description suggests read-only", () => {
      const result = inferBehaviorEnhanced(
        "update_cache",
        "Retrieves and displays the current cache configuration without modifying it",
        {
          type: "object",
          properties: {
            key: { type: "string", description: "Cache key to look up" },
          },
        } as JSONSchema,
        {
          type: "object",
          properties: {
            value: { type: "string" },
            lastModified: { type: "string" },
          },
        } as JSONSchema,
      );

      // Description and schema suggest read-only, but name suggests write
      expect(result.isAmbiguous).toBe(true);
      expect(result.aggregatedConfidence).toBeLessThan(90); // Conflict reduces confidence
      expect(result.reason).toContain("conflicts");
    });

    it("should handle name=destructive + schema=read-only conflict", () => {
      const result = inferBehaviorEnhanced(
        "delete_validator",
        "Validates deletion permissions by checking if user has required role",
        {
          type: "object",
          properties: {
            userId: { type: "string" },
            resourceId: { type: "string" },
          },
        } as JSONSchema,
        {
          type: "object",
          properties: {
            canDelete: { type: "boolean" },
            reason: { type: "string" },
          },
        } as JSONSchema,
      );

      // Name suggests destructive, but description and schema suggest read-only validation
      expect(result.aggregatedConfidence).toBeLessThan(90);
      expect(result.isAmbiguous).toBe(true);
      expect(result.reason).toMatch(/conflicts|conflicting/i);
    });

    it("should prioritize schema force flags over safe description", () => {
      const result = inferBehaviorEnhanced(
        "safe_cleanup_tool",
        "Performs cleanup operations safely with validation",
        {
          type: "object",
          properties: {
            target: { type: "string" },
            force: {
              type: "boolean",
              description: "Skip validation and force cleanup",
            },
          },
        } as JSONSchema,
      );

      // Force flag in schema should override "safe" in name
      expect(result.expectedDestructive).toBe(true);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(70);
    });
  });

  describe("Partial Signals (Varied Confidence)", () => {
    it("should infer from name+description when schema is missing", () => {
      const result = inferBehaviorEnhanced(
        "fetch_user_profile",
        "Retrieves user profile data from the database",
      );

      expect(result.expectedReadOnly).toBe(true);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(70);
      // With improved analysis: "fetch" + "Retrieves" both strong read-only → high confidence
      expect(result.confidence).toBe("high");

      // Only name and description signals should be present
      expect(result.signals.namePatternSignal).toBeDefined();
      expect(result.signals.descriptionSignal).toBeDefined();
      expect(result.signals.inputSchemaSignal).toBeUndefined();
      expect(result.signals.outputSchemaSignal).toBeUndefined();
    });

    it("should handle name-only inference with low confidence", () => {
      const result = inferBehaviorEnhanced("process_data");

      expect(result.isAmbiguous).toBe(true);
      expect(result.aggregatedConfidence).toBeLessThan(50);
      expect(result.confidence).toBe("low");

      // Only name signal should be present (and it's ambiguous)
      expect(result.signals.namePatternSignal).toBeDefined();
      expect(result.signals.descriptionSignal).toBeUndefined();
    });

    it("should boost confidence with input and output schemas", () => {
      const resultWithoutSchemas = inferBehaviorEnhanced(
        "get_reports",
        "Retrieves reports",
      );

      const resultWithSchemas = inferBehaviorEnhanced(
        "get_reports",
        "Retrieves reports",
        {
          type: "object",
          properties: {
            limit: { type: "number" },
          },
        } as JSONSchema,
        {
          type: "array",
          items: { type: "object" },
        } as JSONSchema,
      );

      expect(resultWithSchemas.aggregatedConfidence).toBeGreaterThan(
        resultWithoutSchemas.aggregatedConfidence,
      );
    });
  });

  describe("Signal Priority Rules", () => {
    it("should prioritize destructive signals over read-only", () => {
      const result = inferBehaviorEnhanced(
        "query_and_delete",
        "Queries the database to find expired records and permanently deletes them",
        {
          type: "object",
          properties: {
            maxAge: { type: "number" },
          },
        } as JSONSchema,
      );

      // "query" suggests read-only, but "delete" is destructive and should take priority
      expect(result.expectedDestructive).toBe(true);
      expect(result.expectedReadOnly).toBe(false);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(80);
    });

    it("should boost confidence when multiple signals agree", () => {
      const oneSignal = inferBehaviorEnhanced("list_items");

      const twoSignals = inferBehaviorEnhanced(
        "list_items",
        "Lists all available items",
      );

      const threeSignals = inferBehaviorEnhanced(
        "list_items",
        "Lists all available items",
        {
          type: "object",
          properties: {
            limit: { type: "number" },
          },
        } as JSONSchema,
      );

      expect(twoSignals.aggregatedConfidence).toBeGreaterThan(
        oneSignal.aggregatedConfidence,
      );
      expect(threeSignals.aggregatedConfidence).toBeGreaterThan(
        twoSignals.aggregatedConfidence,
      );
    });

    it("should handle pagination parameters correctly", () => {
      const result = inferBehaviorEnhanced(
        "search_database",
        "Searches the database with pagination support",
        {
          type: "object",
          properties: {
            query: { type: "string" },
            limit: { type: "number" },
            offset: { type: "number" },
          },
        } as JSONSchema,
      );

      expect(result.expectedReadOnly).toBe(true);
      expect(result.signals.inputSchemaSignal?.expectedReadOnly).toBe(true);
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(85);
    });
  });

  describe("Edge Cases and Special Patterns", () => {
    it("should handle tools with no clear signals", () => {
      const result = inferBehaviorEnhanced(
        "tool_xyz_123",
        "A generic utility tool",
        {
          type: "object",
          properties: {
            input: { type: "string" },
          },
        } as JSONSchema,
      );

      expect(result.isAmbiguous).toBe(true);
      expect(result.aggregatedConfidence).toBeLessThan(50);
      expect(result.confidence).toBe("low");
    });

    it("should respect run + analysis suffix exemption", () => {
      const result = inferBehaviorEnhanced(
        "runAccessibilityAudit",
        "Runs accessibility checks on the provided HTML content and returns audit results",
        {
          type: "object",
          properties: {
            html: { type: "string" },
          },
        } as JSONSchema,
      );

      // "run" normally suggests write, but with "audit" suffix it's read-only
      expect(result.expectedReadOnly).toBe(true);
      expect(result.expectedDestructive).toBe(false);
      // Aggregated reason reflects detection source
      expect(result.reason).toContain("Read-only");
    });

    it("should handle bulk operation indicators", () => {
      const result = inferBehaviorEnhanced(
        "bulk_delete_records",
        "Deletes multiple records at once",
        {
          type: "object",
          properties: {
            ids: {
              type: "array",
              items: { type: "string" },
            },
          },
        } as JSONSchema,
      );

      expect(result.expectedDestructive).toBe(true);
      // With gentler boost formula: avg + (count-1)*3, expect ~80-90
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(80);
    });

    it("should detect write operations with update patterns", () => {
      const result = inferBehaviorEnhanced(
        "update_user_profile",
        "Updates the user profile with new information",
        {
          type: "object",
          properties: {
            userId: { type: "string" },
            update: {
              type: "object",
              properties: {
                email: { type: "string" },
              },
            },
          },
        } as JSONSchema,
      );

      expect(result.expectedReadOnly).toBe(false);
      expect(result.expectedDestructive).toBe(false); // UPDATE is write but not destructive
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(80);
    });

    it("should handle empty description gracefully", () => {
      const result = inferBehaviorEnhanced(
        "get_data",
        "", // Empty description
        {
          type: "object",
          properties: {
            id: { type: "string" },
          },
        } as JSONSchema,
      );

      // Should still work with name and schema signals
      expect(result.expectedReadOnly).toBe(true);
      expect(result.signals.descriptionSignal).toBeUndefined();
      expect(result.aggregatedConfidence).toBeGreaterThanOrEqual(70);
    });
  });

  describe("Signal Evidence Tracking", () => {
    it("should track evidence from each signal", () => {
      const result = inferBehaviorEnhanced(
        "delete_project",
        "Permanently removes a project from the system",
        {
          type: "object",
          properties: {
            id: { type: "string" },
            force: { type: "boolean" },
          },
        } as JSONSchema,
        {
          type: "object",
          properties: {
            deleted: { type: "boolean" },
          },
        } as JSONSchema,
      );

      // Verify evidence collection
      expect(result.signals.namePatternSignal?.evidence).toBeDefined();
      expect(result.signals.namePatternSignal?.evidence.length).toBeGreaterThan(
        0,
      );

      expect(result.signals.descriptionSignal?.evidence).toBeDefined();
      expect(result.signals.descriptionSignal?.evidence.length).toBeGreaterThan(
        0,
      );

      expect(result.signals.inputSchemaSignal?.evidence).toBeDefined();
      expect(result.signals.outputSchemaSignal?.evidence).toBeDefined();
    });

    it("should provide clear reasoning for aggregated result", () => {
      const result = inferBehaviorEnhanced(
        "safe_storage_tool",
        "Stores data in memory for later retrieval",
        {
          type: "object",
          properties: {
            key: { type: "string" },
            data: { type: "object" },
          },
        } as JSONSchema,
      );

      expect(result.reason).toBeDefined();
      expect(result.reason.length).toBeGreaterThan(0);
      expect(result.reason).toMatch(/detected from|pattern|signal/i);
    });
  });

  describe("Performance and Stability", () => {
    it("should handle large input schemas without performance degradation", () => {
      const largeSchema: JSONSchema = {
        type: "object",
        properties: {},
      };

      // Generate 100 properties
      for (let i = 0; i < 100; i++) {
        largeSchema.properties![`field${i}`] = {
          type: "string",
          description: `Field ${i}`,
        };
      }

      const start = performance.now();
      const result = inferBehaviorEnhanced(
        "process_large_input",
        "Processes large input data",
        largeSchema,
      );
      const duration = performance.now() - start;

      expect(result).toBeDefined();
      expect(duration).toBeLessThan(50); // Should complete in <50ms
    });

    it("should produce consistent results for identical inputs", () => {
      const inputs = {
        name: "test_tool",
        description: "A test tool for consistency checks",
        inputSchema: {
          type: "object",
          properties: { id: { type: "string" } },
        } as JSONSchema,
      };

      const result1 = inferBehaviorEnhanced(
        inputs.name,
        inputs.description,
        inputs.inputSchema,
      );
      const result2 = inferBehaviorEnhanced(
        inputs.name,
        inputs.description,
        inputs.inputSchema,
      );

      expect(result1.expectedReadOnly).toBe(result2.expectedReadOnly);
      expect(result1.expectedDestructive).toBe(result2.expectedDestructive);
      expect(result1.aggregatedConfidence).toBe(result2.aggregatedConfidence);
      expect(result1.confidence).toBe(result2.confidence);
    });
  });
});
