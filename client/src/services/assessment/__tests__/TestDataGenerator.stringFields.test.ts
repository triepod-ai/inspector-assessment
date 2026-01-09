/**
 * TestDataGenerator - String Field Detection Tests
 *
 * Tests for intelligent string field detection based on field names.
 * Covers URL, Email, Path, Query, ID, UUID, Name, Date/Time detection.
 *
 * Related test files:
 * - TestDataGenerator.test.ts - Core functionality & configuration
 * - TestDataGenerator.numberFields.test.ts - Number field detection
 * - TestDataGenerator.typeHandlers.test.ts - Boolean/Array/Object/Enum handling
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

describe("TestDataGenerator - String Field Detection", () => {
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
      const result = generateRealisticValue("url", { type: "string" }, "empty");
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
      const result = generateRealisticValue("id", { type: "string" }, "empty");
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
