/**
 * TestDataGenerator - Type Handler Tests
 *
 * Tests for type-specific value generation handlers.
 * Covers Boolean, Array, Object types, Enum handling, and recursive schema generation.
 *
 * Related test files:
 * - TestDataGenerator.test.ts - Core functionality & configuration
 * - TestDataGenerator.stringFields.test.ts - String field detection
 * - TestDataGenerator.numberFields.test.ts - Number field detection
 * - TestDataGenerator.scenarios.test.ts - Scenario generation
 * - TestDataGenerator.dataPool.test.ts - Data pool validation
 * - TestDataGenerator.boundary.test.ts - Boundary scenario optimization
 */

import { TestDataGenerator } from "../TestDataGenerator";

// Helper to access private static methods
const getPrivateStaticMethod = (methodName: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (TestDataGenerator as any)[methodName].bind(TestDataGenerator);
};

describe("TestDataGenerator - Type Handlers", () => {
  // ===========================================================================
  // Type Handlers - Boolean
  // ===========================================================================
  describe("Boolean Type Handler", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    it("should return true for typical variant", () => {
      const result = generateRealisticValue(
        "enabled",
        { type: "boolean" },
        "typical",
      );
      expect(result).toBe(true);
    });

    it("should return false for empty variant", () => {
      const result = generateRealisticValue(
        "enabled",
        { type: "boolean" },
        "empty",
      );
      expect(result).toBe(false);
    });

    it("should return true for maximum variant", () => {
      const result = generateRealisticValue(
        "enabled",
        { type: "boolean" },
        "maximum",
      );
      expect(result).toBe(true);
    });

    it("should return true for special variant", () => {
      const result = generateRealisticValue(
        "enabled",
        { type: "boolean" },
        "special",
      );
      expect(result).toBe(true);
    });
  });

  // ===========================================================================
  // Type Handlers - Array
  // ===========================================================================
  describe("Array Type Handler", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    it("should return empty array for empty variant", () => {
      const result = generateRealisticValue(
        "items",
        { type: "array" },
        "empty",
      );
      expect(result).toEqual([]);
    });

    it("should return single item for empty variant with mutation field entities", () => {
      const result = generateRealisticValue(
        "entities",
        { type: "array", items: { type: "string" } },
        "empty",
      );
      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(1);
    });

    it("should return single item for empty variant with mutation field relations", () => {
      const result = generateRealisticValue(
        "relations",
        { type: "array", items: { type: "object" } },
        "empty",
      );
      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(1);
    });

    it("should return 10 items for maximum variant", () => {
      const result = generateRealisticValue(
        "items",
        { type: "array", items: { type: "string" } },
        "maximum",
      );
      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(10);
    });

    it("should return single item for typical variant with items schema", () => {
      const result = generateRealisticValue(
        "items",
        { type: "array", items: { type: "string" } },
        "typical",
      );
      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(1);
    });

    it("should return tag array for tags field without items schema", () => {
      const result = generateRealisticValue(
        "tags",
        { type: "array" },
        "typical",
      );
      expect(result).toEqual(["tag1", "tag2", "tag3"]);
    });

    it("should return id array for ids field without items schema", () => {
      const result = generateRealisticValue(
        "ids",
        { type: "array" },
        "typical",
      );
      expect(result).toEqual(["id_1", "id_2", "id_3"]);
    });

    it("should return fallback array for unknown field without items schema", () => {
      const result = generateRealisticValue(
        "unknownArray",
        { type: "array" },
        "typical",
      );
      expect(Array.isArray(result)).toBe(true);
    });
  });

  // ===========================================================================
  // Type Handlers - Object
  // ===========================================================================
  describe("Object Type Handler", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    it("should return config object for config field with typical variant", () => {
      const result = generateRealisticValue(
        "config",
        { type: "object" },
        "typical",
      ) as Record<string, unknown>;
      expect(result.enabled).toBe(true);
      expect(result.timeout).toBe(5000);
    });

    it("should return minimal config for config field with empty variant", () => {
      const result = generateRealisticValue(
        "config",
        { type: "object" },
        "empty",
      ) as Record<string, unknown>;
      expect(result.enabled).toBe(false);
    });

    it("should return metadata object for metadata field", () => {
      const result = generateRealisticValue(
        "metadata",
        { type: "object" },
        "typical",
      ) as Record<string, unknown>;
      expect(result.version).toBe("1.0.0");
      expect(result.author).toBe("test");
    });

    it("should return minimal metadata for meta field with empty variant", () => {
      const result = generateRealisticValue(
        "meta",
        { type: "object" },
        "empty",
      ) as Record<string, unknown>;
      expect(result.version).toBe("1.0.0");
    });

    it("should return filter object for filter field", () => {
      const result = generateRealisticValue(
        "filter",
        { type: "object" },
        "typical",
      ) as Record<string, unknown>;
      expect(result.status).toBe("active");
      expect(result.limit).toBe(10);
    });

    it("should return minimal filter for query field with empty variant", () => {
      const result = generateRealisticValue(
        "queryObject",
        { type: "object" },
        "empty",
      ) as Record<string, unknown>;
      // queryObject matches "query" pattern, so returns { limit: 1 }
      expect(result.limit).toBe(1);
    });

    it("should return object from REALISTIC_DATA for maximum variant", () => {
      const result = generateRealisticValue(
        "unknownObject",
        { type: "object" },
        "maximum",
      ) as Record<string, unknown>;
      expect(result.success).toBe(true);
    });

    // TEST-001: Validate FIX-001 - Comment accuracy for REALISTIC_DATA.jsonObjects[4]
    it("should return common success response (not deeply nested) for maximum variant", () => {
      const result = generateRealisticValue(
        "data",
        { type: "object" },
        "maximum",
      ) as Record<string, unknown>;

      // Verify it returns the simple success response (REALISTIC_DATA.jsonObjects[4])
      expect(result).toEqual({ success: true });

      // Verify it's NOT deeply nested (no nested objects or arrays)
      expect(Object.keys(result).length).toBe(1);
      expect(typeof result.success).toBe("boolean");
    });

    it("should return minimal object for unknown field with empty variant", () => {
      const result = generateRealisticValue(
        "unknownObject",
        { type: "object" },
        "empty",
      ) as Record<string, unknown>;
      expect(result.id).toBe(1);
    });
  });

  // ===========================================================================
  // Enum Handling
  // ===========================================================================
  describe("Enum Handling", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    it("should return first enum value for typical variant", () => {
      const result = generateRealisticValue(
        "status",
        { type: "string", enum: ["active", "inactive", "pending"] },
        "typical",
      );
      expect(result).toBe("active");
    });

    it("should return last enum value for non-typical variant", () => {
      const result = generateRealisticValue(
        "status",
        { type: "string", enum: ["active", "inactive", "pending"] },
        "empty",
      );
      expect(result).toBe("pending");
    });

    it("should return last enum value for maximum variant", () => {
      const result = generateRealisticValue(
        "status",
        { type: "string", enum: ["active", "inactive", "pending"] },
        "maximum",
      );
      expect(result).toBe("pending");
    });

    it("should handle single-value enum", () => {
      const result = generateRealisticValue(
        "type",
        { type: "string", enum: ["only"] },
        "typical",
      );
      expect(result).toBe("only");
    });

    it("should handle two-value enum", () => {
      const resultTypical = generateRealisticValue(
        "type",
        { type: "string", enum: ["first", "second"] },
        "typical",
      );
      expect(resultTypical).toBe("first");

      const resultEmpty = generateRealisticValue(
        "type",
        { type: "string", enum: ["first", "second"] },
        "empty",
      );
      expect(resultEmpty).toBe("second");
    });
  });

  // ===========================================================================
  // generateValueFromSchema (Recursive Schema Handling)
  // ===========================================================================
  describe("generateValueFromSchema", () => {
    const generateValueFromSchema = getPrivateStaticMethod(
      "generateValueFromSchema",
    );

    it("should return test for null schema", () => {
      const result = generateValueFromSchema(null, "typical");
      expect(result).toBe("test");
    });

    it("should return test for schema without type", () => {
      const result = generateValueFromSchema({}, "typical");
      expect(result).toBe("test");
    });

    it("should generate object with properties", () => {
      const result = generateValueFromSchema(
        {
          type: "object",
          properties: {
            name: { type: "string" },
            count: { type: "number" },
          },
        },
        "typical",
      ) as Record<string, unknown>;
      expect(typeof result.name).toBe("string");
      expect(typeof result.count).toBe("number");
    });

    it("should generate empty object for object without properties", () => {
      const result = generateValueFromSchema({ type: "object" }, "typical");
      expect(result).toEqual({});
    });

    it("should generate array with single item", () => {
      const result = generateValueFromSchema(
        { type: "array", items: { type: "string" } },
        "typical",
      );
      expect(Array.isArray(result)).toBe(true);
      expect((result as unknown[]).length).toBe(1);
    });

    it("should generate empty array for array without items", () => {
      const result = generateValueFromSchema({ type: "array" }, "typical");
      expect(result).toEqual([]);
    });

    it("should generate string values", () => {
      const resultTypical = generateValueFromSchema(
        { type: "string" },
        "typical",
      );
      expect(resultTypical).toBe("test");

      const resultEmpty = generateValueFromSchema({ type: "string" }, "empty");
      expect(resultEmpty).toBe("");
    });

    it("should generate number values", () => {
      const resultTypical = generateValueFromSchema(
        { type: "number" },
        "typical",
      );
      expect(resultTypical).toBe(1);

      const resultEmpty = generateValueFromSchema({ type: "number" }, "empty");
      expect(resultEmpty).toBe(0);
    });

    it("should generate integer values same as number", () => {
      const result = generateValueFromSchema({ type: "integer" }, "typical");
      expect(result).toBe(1);
    });

    it("should generate boolean values", () => {
      const resultTypical = generateValueFromSchema(
        { type: "boolean" },
        "typical",
      );
      expect(resultTypical).toBe(true);

      const resultEmpty = generateValueFromSchema({ type: "boolean" }, "empty");
      expect(resultEmpty).toBe(false);
    });

    it("should return test for unknown type", () => {
      const result = generateValueFromSchema({ type: "unknown" }, "typical");
      expect(result).toBe("test");
    });
  });
});
