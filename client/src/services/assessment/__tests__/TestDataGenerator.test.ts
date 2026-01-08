/**
 * TestDataGenerator Test Suite
 * Tests smart test data generation for MCP tool testing
 *
 * Note: Boundary scenario tests exist in TestDataGenerator.boundary.test.ts
 * This file focuses on field detection, type handling, variants, and Claude integration.
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { TestDataGenerator, TestScenario } from "../TestDataGenerator";

// Helper to access private methods
const getPrivateMethod = <T>(instance: T, methodName: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (instance as any)[methodName].bind(instance);
};

// Helper to access private static methods
const getPrivateStaticMethod = (methodName: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (TestDataGenerator as any)[methodName].bind(TestDataGenerator);
};

// Tool factory - uses type assertion for flexibility with test schemas
const createTool = (
  name: string,
  properties: Record<string, object> = {},
  required: string[] = [],
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties,
    required,
  },
});

// Mock Claude Bridge factory
const createMockClaudeBridge = (overrides: Record<string, unknown> = {}) => ({
  isFeatureEnabled: jest.fn().mockReturnValue(true),
  generateTestParameters: jest
    .fn()
    .mockResolvedValue([
      { param1: "claude-value-1" },
      { param1: "claude-value-2" },
    ]),
  ...overrides,
});

describe("TestDataGenerator", () => {
  beforeEach(() => {
    // Reset Claude bridge before each test
    TestDataGenerator.setClaudeBridge(null);
    jest.restoreAllMocks();
  });

  // ===========================================================================
  // Claude Bridge Configuration
  // ===========================================================================
  describe("Claude Bridge Configuration", () => {
    it("should return false when no bridge is set", () => {
      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });

    it("should return false when bridge is set but feature disabled", () => {
      const mockBridge = createMockClaudeBridge({
        isFeatureEnabled: jest.fn().mockReturnValue(false),
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });

    it("should return true when bridge is set and feature enabled", () => {
      const mockBridge = createMockClaudeBridge();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      expect(TestDataGenerator.isClaudeEnabled()).toBe(true);
      expect(mockBridge.isFeatureEnabled).toHaveBeenCalledWith(
        "intelligentTestGeneration",
      );
    });

    it("should allow setting bridge to null", () => {
      const mockBridge = createMockClaudeBridge();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);
      expect(TestDataGenerator.isClaudeEnabled()).toBe(true);

      TestDataGenerator.setClaudeBridge(null);
      expect(TestDataGenerator.isClaudeEnabled()).toBe(false);
    });
  });

  // ===========================================================================
  // Logger Configuration (BC Tests for Issue #32)
  // ===========================================================================
  describe("Logger Configuration", () => {
    beforeEach(() => {
      TestDataGenerator.setLogger(null);
    });

    it("should work without logger set (backwards compatible)", () => {
      // All existing generateTestScenarios tests verify this
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });

    it("should accept logger via setLogger", () => {
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        child: jest.fn().mockReturnThis(),
        isLevelEnabled: jest.fn().mockReturnValue(true),
      };

      // Should not throw
      TestDataGenerator.setLogger(mockLogger);

      // Functionality still works
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });

    it("should allow clearing logger with null", () => {
      const mockLogger = {
        debug: jest.fn(),
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn(),
        child: jest.fn().mockReturnThis(),
        isLevelEnabled: jest.fn().mockReturnValue(true),
      };

      TestDataGenerator.setLogger(mockLogger);
      TestDataGenerator.setLogger(null);

      // Functionality still works after clearing
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);
      expect(scenarios.length).toBeGreaterThan(0);
    });
  });

  // ===========================================================================
  // Field Name Detection - String Types
  // ===========================================================================
  describe("Field Name Detection - Strings", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    describe("URL detection", () => {
      it("should detect url field name", () => {
        const result = generateRealisticValue(
          "url",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^https?:\/\//);
      });

      it("should detect apiUrl field name", () => {
        const result = generateRealisticValue(
          "apiUrl",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^https?:\/\//);
      });

      it("should detect endpoint field name", () => {
        const result = generateRealisticValue(
          "endpoint",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^https?:\/\//);
      });

      it("should detect link field name", () => {
        const result = generateRealisticValue(
          "link",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^https?:\/\//);
      });

      it("should return empty string for url with empty variant", () => {
        const result = generateRealisticValue(
          "url",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("");
      });

      it("should return long URL for maximum variant", () => {
        const result = generateRealisticValue(
          "url",
          { type: "string" },
          "maximum",
        );
        expect(result).toContain("very-long-domain-name");
      });

      it("should return URL with special chars for special variant", () => {
        const result = generateRealisticValue(
          "url",
          { type: "string" },
          "special",
        );
        expect(result).toContain("!@#$%");
      });
    });

    describe("Email detection", () => {
      it("should detect email field name", () => {
        const result = generateRealisticValue(
          "email",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/@.*\./);
      });

      it("should detect userEmail field name", () => {
        const result = generateRealisticValue(
          "userEmail",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/@.*\./);
      });

      it("should detect mail field name", () => {
        const result = generateRealisticValue(
          "mail",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/@.*\./);
      });

      it("should return empty string for email with empty variant", () => {
        const result = generateRealisticValue(
          "email",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("");
      });

      it("should return email with plus tag for special variant", () => {
        const result = generateRealisticValue(
          "email",
          { type: "string" },
          "special",
        );
        expect(result).toContain("+");
      });
    });

    describe("Path detection", () => {
      it("should detect path field name", () => {
        const result = generateRealisticValue(
          "path",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^[./]/);
      });

      it("should detect file field name", () => {
        const result = generateRealisticValue(
          "file",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^[./]/);
      });

      it("should detect directory field name", () => {
        const result = generateRealisticValue(
          "directory",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^[./]/);
      });

      it("should detect folder field name", () => {
        const result = generateRealisticValue(
          "folder",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^[./]/);
      });

      it("should return path with spaces for special variant", () => {
        const result = generateRealisticValue(
          "path",
          { type: "string" },
          "special",
        );
        expect(result).toContain(" ");
      });
    });

    describe("Query detection", () => {
      it("should detect query field name", () => {
        const result = generateRealisticValue(
          "query",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
        expect(result).not.toBe("");
      });

      it("should detect search field name", () => {
        const result = generateRealisticValue(
          "search",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should detect filter field name", () => {
        const result = generateRealisticValue(
          "filter",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should return test for query with empty variant (not empty string)", () => {
        const result = generateRealisticValue(
          "query",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("test");
      });

      it("should return query with quotes for special variant", () => {
        const result = generateRealisticValue(
          "query",
          { type: "string" },
          "special",
        );
        expect(result).toContain('"');
      });
    });

    describe("ID detection", () => {
      it("should detect id field name", () => {
        const result = generateRealisticValue(
          "id",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should detect key field name", () => {
        const result = generateRealisticValue(
          "key",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should detect identifier field name", () => {
        const result = generateRealisticValue(
          "identifier",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should return 1 for id with empty variant", () => {
        const result = generateRealisticValue(
          "id",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("1");
      });

      it("should return long id for maximum variant", () => {
        const result = generateRealisticValue(
          "id",
          { type: "string" },
          "maximum",
        );
        expect((result as string).length).toBeGreaterThan(50);
      });
    });

    describe("UUID detection", () => {
      const uuidPattern =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

      it("should return valid UUID for uuid field", () => {
        const result = generateRealisticValue(
          "uuid",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return valid UUID for page_id field", () => {
        const result = generateRealisticValue(
          "page_id",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return valid UUID for database_id field", () => {
        const result = generateRealisticValue(
          "database_id",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return valid UUID for user_id field", () => {
        const result = generateRealisticValue(
          "user_id",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return valid UUID for block_id field", () => {
        const result = generateRealisticValue(
          "block_id",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return nil UUID for uuid with empty variant", () => {
        const result = generateRealisticValue(
          "uuid",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("00000000-0000-0000-0000-000000000000");
      });

      it("should return UUID when schema description mentions uuid", () => {
        const result = generateRealisticValue(
          "itemId",
          { type: "string", description: "The UUID of the item" },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });

      it("should return UUID when schema description mentions universally unique", () => {
        const result = generateRealisticValue(
          "recordId",
          {
            type: "string",
            description: "A universally unique identifier for the record",
          },
          "typical",
        );
        expect(result).toMatch(uuidPattern);
      });
    });

    describe("Name detection", () => {
      it("should detect name field name", () => {
        const result = generateRealisticValue(
          "name",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
        expect(result).not.toBe("");
      });

      it("should detect title field name", () => {
        const result = generateRealisticValue(
          "title",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should detect label field name", () => {
        const result = generateRealisticValue(
          "label",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should return a for name with empty variant (minimal non-empty)", () => {
        const result = generateRealisticValue(
          "name",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("a");
      });

      it("should return name with emoji for special variant", () => {
        const result = generateRealisticValue(
          "name",
          { type: "string" },
          "special",
        );
        expect(result).toContain("🎉");
      });
    });

    describe("Date/Time detection", () => {
      it("should detect date field name", () => {
        const result = generateRealisticValue(
          "date",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should detect time field name", () => {
        const result = generateRealisticValue(
          "time",
          { type: "string" },
          "typical",
        );
        expect(typeof result).toBe("string");
      });

      it("should return empty string for date with empty variant", () => {
        const result = generateRealisticValue(
          "date",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("");
      });
    });

    describe("Default string handling", () => {
      it("should return test for unknown field name", () => {
        const result = generateRealisticValue(
          "unknownField",
          { type: "string" },
          "typical",
        );
        expect(result).toBe("test");
      });

      it("should return empty string for unknown field with empty variant", () => {
        const result = generateRealisticValue(
          "unknownField",
          { type: "string" },
          "empty",
        );
        expect(result).toBe("");
      });

      it("should return repeated x for unknown field with maximum variant", () => {
        const result = generateRealisticValue(
          "unknownField",
          { type: "string" },
          "maximum",
        );
        expect(result).toBe("x".repeat(100));
      });

      it("should return special characters for unknown field with special variant", () => {
        const result = generateRealisticValue(
          "unknownField",
          { type: "string" },
          "special",
        );
        expect(result).toContain("!@#$%");
      });
    });

    describe("Case insensitivity", () => {
      it("should match URL regardless of case", () => {
        const result = generateRealisticValue(
          "URL",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^https?:\/\//);
      });

      it("should match Email regardless of case", () => {
        const result = generateRealisticValue(
          "EMAIL",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/@.*\./);
      });

      it("should match Path regardless of case", () => {
        const result = generateRealisticValue(
          "PATH",
          { type: "string" },
          "typical",
        );
        expect(result).toMatch(/^[./]/);
      });
    });
  });

  // ===========================================================================
  // Field Name Detection - Number Types
  // ===========================================================================
  describe("Field Name Detection - Numbers", () => {
    const generateRealisticValue = getPrivateStaticMethod(
      "generateRealisticValue",
    );

    it("should return 8080 for port field", () => {
      const result = generateRealisticValue(
        "port",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(8080);
    });

    it("should return 5000 for timeout field", () => {
      const result = generateRealisticValue(
        "timeout",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(5000);
    });

    it("should return 5000 for delay field", () => {
      const result = generateRealisticValue(
        "delay",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(5000);
    });

    it("should return 10 for count field", () => {
      const result = generateRealisticValue(
        "count",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(10);
    });

    it("should return 10 for limit field", () => {
      const result = generateRealisticValue(
        "limit",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(10);
    });

    it("should return 0 for page field", () => {
      const result = generateRealisticValue(
        "page",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(0);
    });

    it("should return 0 for offset field", () => {
      const result = generateRealisticValue(
        "offset",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(0);
    });

    it("should return 100 for size field", () => {
      const result = generateRealisticValue(
        "size",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(100);
    });

    it("should return 100 for length field", () => {
      const result = generateRealisticValue(
        "length",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(100);
    });

    it("should return 1 for unknown number field", () => {
      const result = generateRealisticValue(
        "unknownNumber",
        { type: "number" },
        "typical",
      );
      expect(result).toBe(1);
    });

    it("should return schema.minimum for unknown number with minimum", () => {
      const result = generateRealisticValue(
        "unknownNumber",
        { type: "number", minimum: 5 },
        "typical",
      );
      expect(result).toBe(5);
    });

    it("should return 0 for empty variant with no minimum", () => {
      const result = generateRealisticValue(
        "anyNumber",
        { type: "number" },
        "empty",
      );
      expect(result).toBe(0);
    });

    it("should return schema.minimum for empty variant with minimum", () => {
      const result = generateRealisticValue(
        "anyNumber",
        { type: "number", minimum: 10 },
        "empty",
      );
      expect(result).toBe(10);
    });

    it("should return 999999 for maximum variant with no maximum", () => {
      const result = generateRealisticValue(
        "anyNumber",
        { type: "number" },
        "maximum",
      );
      expect(result).toBe(999999);
    });

    it("should return schema.maximum for maximum variant with maximum", () => {
      const result = generateRealisticValue(
        "anyNumber",
        { type: "number", maximum: 100 },
        "maximum",
      );
      expect(result).toBe(100);
    });

    it("should handle integer type same as number", () => {
      const result = generateRealisticValue(
        "port",
        { type: "integer" },
        "typical",
      );
      expect(result).toBe(8080);
    });
  });

  // ===========================================================================
  // Type Handlers - Boolean
  // ===========================================================================
  describe("Type Handlers - Boolean", () => {
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
  describe("Type Handlers - Array", () => {
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
  describe("Type Handlers - Object", () => {
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

  // ===========================================================================
  // generateRealisticParams
  // ===========================================================================
  describe("generateRealisticParams", () => {
    it("should return empty object for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });

    it("should return empty object for non-object schema type", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: { type: "array" } as any,
      };
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });

    it("should generate params for all properties", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");

      expect(typeof result.name).toBe("string");
      expect(typeof result.count).toBe("number");
      expect(typeof result.enabled).toBe("boolean");
    });

    it("should handle empty properties", () => {
      const tool = createTool("test", {});
      const result = TestDataGenerator.generateRealisticParams(tool, "typical");
      expect(result).toEqual({});
    });
  });

  // ===========================================================================
  // generateSingleValue (Backward Compatibility)
  // ===========================================================================
  describe("generateSingleValue", () => {
    it("should call generateRealisticValue with typical variant", () => {
      const result = TestDataGenerator.generateSingleValue("email", {
        type: "string",
      });
      expect(result).toMatch(/@.*\./);
    });

    it("should handle various field types", () => {
      expect(
        TestDataGenerator.generateSingleValue("url", { type: "string" }),
      ).toMatch(/^https?:\/\//);
      expect(
        typeof TestDataGenerator.generateSingleValue("count", {
          type: "number",
        }),
      ).toBe("number");
      expect(
        typeof TestDataGenerator.generateSingleValue("enabled", {
          type: "boolean",
        }),
      ).toBe("boolean");
    });
  });

  // ===========================================================================
  // hasStringInputs
  // ===========================================================================
  describe("hasStringInputs", () => {
    const hasStringInputs = getPrivateStaticMethod("hasStringInputs");

    it("should return false for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return false for non-object schema", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: { type: "array" } as any,
      };
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return false for tool with no string properties", () => {
      const tool = createTool("test", {
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      expect(hasStringInputs(tool)).toBe(false);
    });

    it("should return true for tool with string property", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
      });
      expect(hasStringInputs(tool)).toBe(true);
    });

    it("should return true for tool with only string properties", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        email: { type: "string" },
      });
      expect(hasStringInputs(tool)).toBe(true);
    });

    it("should return false for tool with empty properties", () => {
      const tool = createTool("test", {});
      expect(hasStringInputs(tool)).toBe(false);
    });
  });

  // ===========================================================================
  // Error Scenario Generation
  // ===========================================================================
  describe("generateErrorScenario", () => {
    const generateErrorScenario = getPrivateStaticMethod(
      "generateErrorScenario",
    );

    it("should return empty params for tool without inputSchema", () => {
      // Test edge case where tool has no inputSchema (runtime handles this gracefully)
      const tool = { name: "test", description: "test" } as Tool;
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
      expect(result.category).toBe("error_case");
    });

    it("should return empty params for non-object schema", () => {
      const tool: Tool = {
        name: "test",
        description: "test",
        inputSchema: { type: "array" } as any,
      };
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
    });

    it("should return empty params for tool with no properties", () => {
      const tool = createTool("test", {});
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params).toEqual({});
    });

    it("should provide number for string field", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.name).toBe(123);
    });

    it("should provide string for number field", () => {
      const tool = createTool("test", { count: { type: "number" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.count).toBe("not_a_number");
    });

    it("should provide string for integer field", () => {
      const tool = createTool("test", { count: { type: "integer" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.count).toBe("not_a_number");
    });

    it("should provide string for boolean field", () => {
      const tool = createTool("test", { enabled: { type: "boolean" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.enabled).toBe("not_a_boolean");
    });

    it("should provide string for array field", () => {
      const tool = createTool("test", { items: { type: "array" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.items).toBe("not_an_array");
    });

    it("should provide string for object field", () => {
      const tool = createTool("test", { config: { type: "object" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.config).toBe("not_an_object");
    });

    it("should provide null for unknown type", () => {
      const tool = createTool("test", { custom: { type: "custom" } });
      const result = generateErrorScenario(tool) as TestScenario;
      expect(result.params.custom).toBe(null);
    });

    it("should only set wrong type for first property", () => {
      const tool = createTool("test", {
        first: { type: "string" },
        second: { type: "string" },
        third: { type: "string" },
      });
      const result = generateErrorScenario(tool) as TestScenario;

      // Only one property should be set
      expect(Object.keys(result.params).length).toBe(1);
    });
  });

  // ===========================================================================
  // Edge Case Scenario Generation
  // ===========================================================================
  describe("generateEdgeCaseScenarios", () => {
    const generateEdgeCaseScenarios = getPrivateStaticMethod(
      "generateEdgeCaseScenarios",
    );

    it("should generate 2 scenarios for tool without string inputs", () => {
      const tool = createTool("test", {
        count: { type: "number" },
        enabled: { type: "boolean" },
      });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      // Empty values + Maximum values (no special chars since no strings)
      expect(result.length).toBe(2);
      expect(result[0].name).toBe("Edge Case - Empty Values");
      expect(result[1].name).toBe("Edge Case - Maximum Values");
    });

    it("should generate 3 scenarios for tool with string inputs", () => {
      const tool = createTool("test", {
        name: { type: "string" },
        count: { type: "number" },
      });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      // Empty values + Maximum values + Special characters
      expect(result.length).toBe(3);
      expect(result[2].name).toBe("Edge Case - Special Characters");
    });

    it("should set all scenarios to edge_case category", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateEdgeCaseScenarios(tool) as TestScenario[];

      result.forEach((scenario) => {
        expect(scenario.category).toBe("edge_case");
      });
    });
  });

  // ===========================================================================
  // Happy Path Scenario Generation
  // ===========================================================================
  describe("generateHappyPathScenario", () => {
    const generateHappyPathScenario = getPrivateStaticMethod(
      "generateHappyPathScenario",
    );

    it("should generate happy_path category", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.category).toBe("happy_path");
    });

    it("should use typical variant for params", () => {
      const tool = createTool("test", { email: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.params.email).toMatch(/@.*\./);
    });

    it("should include tool name in description", () => {
      const tool = createTool("my_special_tool", { name: { type: "string" } });
      const result = generateHappyPathScenario(tool) as TestScenario;

      expect(result.description).toContain("my_special_tool");
    });
  });

  // ===========================================================================
  // generateTestScenarios (Integration)
  // ===========================================================================
  describe("generateTestScenarios", () => {
    it("should include happy path scenario", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const happyPath = scenarios.find((s) => s.category === "happy_path");
      expect(happyPath).toBeDefined();
    });

    it("should include edge case scenarios", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const edgeCases = scenarios.filter((s) => s.category === "edge_case");
      expect(edgeCases.length).toBeGreaterThan(0);
    });

    it("should include error case scenario", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const errorCase = scenarios.find((s) => s.category === "error_case");
      expect(errorCase).toBeDefined();
    });

    it("should have at least 4 scenarios for simple tool", () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      // happy path + 3 edge cases + error case = 5
      expect(scenarios.length).toBeGreaterThanOrEqual(4);
    });

    it("should include boundary scenarios when constraints exist", () => {
      const tool = createTool("test", {
        age: { type: "number", minimum: 0, maximum: 100 },
      });
      const scenarios = TestDataGenerator.generateTestScenarios(tool);

      const boundaryScenarios = scenarios.filter(
        (s) => s.category === "boundary",
      );
      expect(boundaryScenarios.length).toBe(2);
    });
  });

  // ===========================================================================
  // generateTestScenariosAsync (Claude Integration)
  // ===========================================================================
  describe("generateTestScenariosAsync", () => {
    it("should use schema-based when Claude disabled", async () => {
      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should use Claude-generated when Claude enabled and returns data", async () => {
      const mockBridge = createMockClaudeBridge();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      // Should have Claude-generated + 1 error case (schema-based)
      const claudeScenarios = scenarios.filter(
        (s) => s.source === "claude-generated",
      );
      const schemaScenarios = scenarios.filter(
        (s) => s.source === "schema-based",
      );

      expect(claudeScenarios.length).toBe(2);
      expect(schemaScenarios.length).toBe(1); // Error case
    });

    it("should fall back to schema-based when Claude returns empty", async () => {
      const mockBridge = createMockClaudeBridge({
        generateTestParameters: jest.fn().mockResolvedValue([]),
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should fall back to schema-based when Claude throws error", async () => {
      const mockBridge = createMockClaudeBridge({
        generateTestParameters: jest
          .fn()
          .mockRejectedValue(new Error("Claude error")),
      });
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      expect(scenarios.every((s) => s.source === "schema-based")).toBe(true);
    });

    it("should add error case to Claude scenarios", async () => {
      const mockBridge = createMockClaudeBridge();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      TestDataGenerator.setClaudeBridge(mockBridge as any);

      const tool = createTool("test", { name: { type: "string" } });
      const scenarios =
        await TestDataGenerator.generateTestScenariosAsync(tool);

      const errorCase = scenarios.find((s) => s.category === "error_case");
      expect(errorCase).toBeDefined();
      expect(errorCase?.source).toBe("schema-based");
    });
  });

  // ===========================================================================
  // Claude Scenario Naming
  // ===========================================================================
  describe("Claude Scenario Naming", () => {
    const getClaudeScenarioName = getPrivateStaticMethod(
      "getClaudeScenarioName",
    );
    const getClaudeScenarioCategory = getPrivateStaticMethod(
      "getClaudeScenarioCategory",
    );

    it("should return Happy Path for index 0", () => {
      expect(getClaudeScenarioName(0)).toBe("Happy Path - Typical Usage");
    });

    it("should return Edge Case for index 1", () => {
      expect(getClaudeScenarioName(1)).toBe("Edge Case - Boundary Values");
    });

    it("should return Minimal Input for index 2", () => {
      expect(getClaudeScenarioName(2)).toBe(
        "Minimal Input - Required Fields Only",
      );
    });

    it("should return Test Case N for index beyond defined names", () => {
      expect(getClaudeScenarioName(10)).toBe("Test Case 11");
    });

    it("should return happy_path category for index 0", () => {
      expect(getClaudeScenarioCategory(0)).toBe("happy_path");
    });

    it("should return edge_case category for index 1", () => {
      expect(getClaudeScenarioCategory(1)).toBe("edge_case");
    });

    it("should return boundary category for index 2", () => {
      expect(getClaudeScenarioCategory(2)).toBe("boundary");
    });

    it("should return happy_path category for index beyond defined", () => {
      expect(getClaudeScenarioCategory(10)).toBe("happy_path");
    });
  });

  // ===========================================================================
  // Category-Aware Generation
  // ===========================================================================
  describe("generateValueForCategory", () => {
    it("should return math expression for calculator category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "expression",
        { type: "string" },
        "calculator",
      );
      expect(result).toBe("2+2");
    });

    it("should return search query for search_retrieval category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "query",
        { type: "string" },
        "search_retrieval",
      );
      expect(result).toBe("hello world");
    });

    it("should return shell command for system_exec category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "command",
        { type: "string" },
        "system_exec",
      );
      expect(result).toBe("echo hello");
    });

    it("should return URL for url_fetcher category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "target",
        { type: "string" },
        "url_fetcher",
      );
      expect(result).toBe("https://api.github.com");
    });

    it("should use field-name detection for URL field even with category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "url",
        { type: "string" },
        "calculator",
      );
      // URL field should override calculator category
      expect(result).toMatch(/^https?:\/\//);
    });

    it("should use field-name detection for email field even with category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "email",
        { type: "string" },
        "system_exec",
      );
      // Email field should override system_exec category
      expect(result).toMatch(/@.*\./);
    });

    it("should fall back to field-name for unknown category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "name",
        { type: "string" },
        "unknown_category",
      );
      expect(typeof result).toBe("string");
    });

    it("should fall back to field-name for GENERIC category", () => {
      const result = TestDataGenerator.generateValueForCategory(
        "name",
        { type: "string" },
        "GENERIC",
      );
      expect(typeof result).toBe("string");
    });
  });

  // ===========================================================================
  // TOOL_CATEGORY_DATA
  // ===========================================================================
  describe("TOOL_CATEGORY_DATA", () => {
    it("should have calculator category with math expressions", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.calculator).toBeDefined();
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.calculator.default).toContain(
        "2+2",
      );
    });

    it("should have search_retrieval category with search queries", () => {
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.search_retrieval,
      ).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.search_retrieval.default,
      ).toContain("hello world");
    });

    it("should have system_exec category with shell commands", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.system_exec).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.system_exec.default,
      ).toContain("echo hello");
    });

    it("should have url_fetcher category with URLs", () => {
      expect(TestDataGenerator.TOOL_CATEGORY_DATA.url_fetcher).toBeDefined();
      expect(
        TestDataGenerator.TOOL_CATEGORY_DATA.url_fetcher.default[0],
      ).toMatch(/^https?:\/\//);
    });
  });

  // ===========================================================================
  // Data Pool Validity
  // ===========================================================================
  describe("REALISTIC_DATA validity", () => {
    // Access private static REALISTIC_DATA
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const REALISTIC_DATA = (TestDataGenerator as any).REALISTIC_DATA;

    it("should have valid URLs", () => {
      REALISTIC_DATA.urls.forEach((url: string) => {
        expect(url).toMatch(/^https?:\/\//);
      });
    });

    it("should have valid emails", () => {
      REALISTIC_DATA.emails.forEach((email: string) => {
        expect(email).toMatch(/@.*\./);
      });
    });

    it("should have valid UUIDs in ids pool", () => {
      const uuidPattern =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const uuids = REALISTIC_DATA.ids.filter((id: string) => id.includes("-"));
      uuids.forEach((uuid: string) => {
        expect(uuid).toMatch(uuidPattern);
      });
    });

    it("should have paths starting with / or .", () => {
      REALISTIC_DATA.paths.forEach((path: string) => {
        expect(path).toMatch(/^[./]/);
      });
    });

    it("should have ISO timestamps", () => {
      REALISTIC_DATA.timestamps.forEach((ts: string) => {
        expect(() => new Date(ts)).not.toThrow();
      });
    });

    it("should have non-empty arrays in arrays pool", () => {
      expect(REALISTIC_DATA.arrays.length).toBeGreaterThan(0);
    });

    it("should have valid JSON objects in jsonObjects pool", () => {
      REALISTIC_DATA.jsonObjects.forEach((obj: unknown) => {
        expect(typeof obj).toBe("object");
        expect(obj).not.toBeNull();
      });
    });
  });
});
