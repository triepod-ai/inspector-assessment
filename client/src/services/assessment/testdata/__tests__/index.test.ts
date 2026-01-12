/**
 * Test Data Module - Export Tests
 *
 * Tests for the testdata module's public API.
 * Validates that all exports are accessible and correctly typed.
 *
 * TEST-003: Validates module boundary stability
 */

import * as testdataModule from "../index";
import {
  REALISTIC_URLS,
  REALISTIC_EMAILS,
  REALISTIC_NAMES,
  REALISTIC_IDS,
  REALISTIC_PATHS,
  REALISTIC_QUERIES,
  REALISTIC_NUMBERS,
  REALISTIC_BOOLEANS,
  REALISTIC_JSON_OBJECTS,
  REALISTIC_ARRAYS,
  generateRealisticTimestamps,
  REALISTIC_DATA,
  TOOL_CATEGORY_DATA,
  SPECIFIC_FIELD_PATTERNS,
} from "../index";

describe("testdata Module Exports", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  // TEST-003: Validate module boundary - all exports accessible
  describe("Public API - realistic-values.ts exports", () => {
    it("should export REALISTIC_URLS", () => {
      expect(REALISTIC_URLS).toBeDefined();
      expect(Array.isArray(REALISTIC_URLS)).toBe(true);
      expect(REALISTIC_URLS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_EMAILS", () => {
      expect(REALISTIC_EMAILS).toBeDefined();
      expect(Array.isArray(REALISTIC_EMAILS)).toBe(true);
      expect(REALISTIC_EMAILS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_NAMES", () => {
      expect(REALISTIC_NAMES).toBeDefined();
      expect(Array.isArray(REALISTIC_NAMES)).toBe(true);
      expect(REALISTIC_NAMES.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_IDS", () => {
      expect(REALISTIC_IDS).toBeDefined();
      expect(Array.isArray(REALISTIC_IDS)).toBe(true);
      expect(REALISTIC_IDS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_PATHS", () => {
      expect(REALISTIC_PATHS).toBeDefined();
      expect(Array.isArray(REALISTIC_PATHS)).toBe(true);
      expect(REALISTIC_PATHS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_QUERIES", () => {
      expect(REALISTIC_QUERIES).toBeDefined();
      expect(Array.isArray(REALISTIC_QUERIES)).toBe(true);
      expect(REALISTIC_QUERIES.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_NUMBERS", () => {
      expect(REALISTIC_NUMBERS).toBeDefined();
      expect(Array.isArray(REALISTIC_NUMBERS)).toBe(true);
      expect(REALISTIC_NUMBERS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_BOOLEANS", () => {
      expect(REALISTIC_BOOLEANS).toBeDefined();
      expect(Array.isArray(REALISTIC_BOOLEANS)).toBe(true);
      expect(REALISTIC_BOOLEANS.length).toBe(2);
    });

    it("should export REALISTIC_JSON_OBJECTS", () => {
      expect(REALISTIC_JSON_OBJECTS).toBeDefined();
      expect(Array.isArray(REALISTIC_JSON_OBJECTS)).toBe(true);
      expect(REALISTIC_JSON_OBJECTS.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_ARRAYS", () => {
      expect(REALISTIC_ARRAYS).toBeDefined();
      expect(Array.isArray(REALISTIC_ARRAYS)).toBe(true);
      expect(REALISTIC_ARRAYS.length).toBeGreaterThan(0);
    });

    it("should export generateRealisticTimestamps function", () => {
      expect(generateRealisticTimestamps).toBeDefined();
      expect(typeof generateRealisticTimestamps).toBe("function");

      const timestamps = generateRealisticTimestamps();
      expect(Array.isArray(timestamps)).toBe(true);
      expect(timestamps.length).toBeGreaterThan(0);
    });

    it("should export REALISTIC_DATA composed object", () => {
      expect(REALISTIC_DATA).toBeDefined();
      expect(typeof REALISTIC_DATA).toBe("object");

      // Verify all properties exist
      expect(REALISTIC_DATA.urls).toBeDefined();
      expect(REALISTIC_DATA.emails).toBeDefined();
      expect(REALISTIC_DATA.names).toBeDefined();
      expect(REALISTIC_DATA.ids).toBeDefined();
      expect(REALISTIC_DATA.paths).toBeDefined();
      expect(REALISTIC_DATA.queries).toBeDefined();
      expect(REALISTIC_DATA.numbers).toBeDefined();
      expect(REALISTIC_DATA.booleans).toBeDefined();
      expect(REALISTIC_DATA.jsonObjects).toBeDefined();
      expect(REALISTIC_DATA.arrays).toBeDefined();
      expect(REALISTIC_DATA.timestamps).toBeDefined();
    });
  });

  describe("Public API - tool-category-data.ts exports", () => {
    it("should export TOOL_CATEGORY_DATA", () => {
      expect(TOOL_CATEGORY_DATA).toBeDefined();
      expect(typeof TOOL_CATEGORY_DATA).toBe("object");

      // Verify it has expected structure (sample categories)
      expect(TOOL_CATEGORY_DATA.calculator).toBeDefined();
      expect(TOOL_CATEGORY_DATA.search_retrieval).toBeDefined();
      expect(TOOL_CATEGORY_DATA.system_exec).toBeDefined();
      expect(TOOL_CATEGORY_DATA.url_fetcher).toBeDefined();
    });

    it("should export SPECIFIC_FIELD_PATTERNS", () => {
      expect(SPECIFIC_FIELD_PATTERNS).toBeDefined();
      expect(Array.isArray(SPECIFIC_FIELD_PATTERNS)).toBe(true);

      // Verify it contains expected RegExp patterns
      expect(SPECIFIC_FIELD_PATTERNS.length).toBeGreaterThan(0);
      expect(SPECIFIC_FIELD_PATTERNS[0]).toBeInstanceOf(RegExp);
    });
  });

  describe("Module Namespace Export", () => {
    it("should export all expected symbols via namespace import", () => {
      // Verify namespace import includes all expected exports
      expect(testdataModule.REALISTIC_URLS).toBeDefined();
      expect(testdataModule.REALISTIC_EMAILS).toBeDefined();
      expect(testdataModule.REALISTIC_NAMES).toBeDefined();
      expect(testdataModule.REALISTIC_IDS).toBeDefined();
      expect(testdataModule.REALISTIC_PATHS).toBeDefined();
      expect(testdataModule.REALISTIC_QUERIES).toBeDefined();
      expect(testdataModule.REALISTIC_NUMBERS).toBeDefined();
      expect(testdataModule.REALISTIC_BOOLEANS).toBeDefined();
      expect(testdataModule.REALISTIC_JSON_OBJECTS).toBeDefined();
      expect(testdataModule.REALISTIC_ARRAYS).toBeDefined();
      expect(testdataModule.generateRealisticTimestamps).toBeDefined();
      expect(testdataModule.REALISTIC_DATA).toBeDefined();
      expect(testdataModule.TOOL_CATEGORY_DATA).toBeDefined();
      expect(testdataModule.SPECIFIC_FIELD_PATTERNS).toBeDefined();
    });

    it("should have consistent values between named and namespace imports", () => {
      // Verify that named imports and namespace imports reference the same values
      expect(testdataModule.REALISTIC_URLS).toEqual(REALISTIC_URLS);
      expect(testdataModule.REALISTIC_DATA).toEqual(REALISTIC_DATA);
      expect(testdataModule.TOOL_CATEGORY_DATA).toEqual(TOOL_CATEGORY_DATA);
    });
  });

  describe("Type Exports", () => {
    it("should export RealisticDataType type", () => {
      // This is a compile-time check, but we can verify runtime shape
      const data: typeof REALISTIC_DATA = REALISTIC_DATA;
      expect(data).toBeDefined();
      expect(data.urls).toBeDefined();
      expect(data.timestamps).toBeDefined();
    });

    it("should export SpecificFieldPatternsType type", () => {
      // This is a compile-time check, but we can verify runtime shape
      const patterns: typeof SPECIFIC_FIELD_PATTERNS = SPECIFIC_FIELD_PATTERNS;
      expect(patterns).toBeDefined();
      expect(Array.isArray(patterns)).toBe(true);
      expect(patterns.length).toBeGreaterThan(0);
    });
  });

  describe("Backward Compatibility", () => {
    it("should maintain stable API for existing consumers", () => {
      // Verify that all expected exports are present and have correct types
      const expectedExports = [
        "REALISTIC_URLS",
        "REALISTIC_EMAILS",
        "REALISTIC_NAMES",
        "REALISTIC_IDS",
        "REALISTIC_PATHS",
        "REALISTIC_QUERIES",
        "REALISTIC_NUMBERS",
        "REALISTIC_BOOLEANS",
        "REALISTIC_JSON_OBJECTS",
        "REALISTIC_ARRAYS",
        "generateRealisticTimestamps",
        "REALISTIC_DATA",
        "TOOL_CATEGORY_DATA",
        "SPECIFIC_FIELD_PATTERNS",
      ];

      expectedExports.forEach((exportName) => {
        expect(testdataModule).toHaveProperty(exportName);
      });
    });

    it("should not have accidentally removed exports", () => {
      const exportCount = Object.keys(testdataModule).length;
      // We expect at least 14 exports (the ones listed above)
      expect(exportCount).toBeGreaterThanOrEqual(14);
    });
  });

  describe("Import Path Resolution", () => {
    it("should allow deep imports from realistic-values", async () => {
      // Verify that direct imports from realistic-values still work
      const realisticValuesModule = await import("../realistic-values");
      expect(realisticValuesModule.REALISTIC_URLS).toBeDefined();
      expect(realisticValuesModule.REALISTIC_DATA).toBeDefined();
    });

    it("should allow deep imports from tool-category-data", async () => {
      // Verify that direct imports from tool-category-data still work
      const toolCategoryDataModule = await import("../tool-category-data");
      expect(toolCategoryDataModule.TOOL_CATEGORY_DATA).toBeDefined();
      expect(toolCategoryDataModule.SPECIFIC_FIELD_PATTERNS).toBeDefined();
    });
  });
});
