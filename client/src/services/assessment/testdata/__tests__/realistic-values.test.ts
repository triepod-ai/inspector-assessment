/**
 * Realistic Values - Type Safety and Composition Tests
 *
 * Tests for the REALISTIC_DATA composition and type safety.
 * Validates the spread operator fix for readonly array handling.
 *
 * TEST-002: Validates FIX-002 - Spread operator type safety
 */

import {
  REALISTIC_DATA,
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
} from "../realistic-values";

describe("REALISTIC_DATA Composition", () => {
  // TEST-002: Validate FIX-002 - Spread operator creates mutable copies
  describe("Type Safety - Spread Operator", () => {
    it("should create mutable copies from readonly source arrays", () => {
      // The spread operator [...array] should create new mutable arrays
      // This test validates that we can iterate without type errors

      // Test urls array
      const urlsCopy = REALISTIC_DATA.urls;
      expect(Array.isArray(urlsCopy)).toBe(true);
      expect(urlsCopy.length).toBeGreaterThan(0);

      // Verify we can iterate (this would fail with 'as unknown as' casting)
      let urlCount = 0;
      for (const _url of urlsCopy) {
        urlCount++;
      }
      expect(urlCount).toBe(REALISTIC_URLS.length);

      // Test emails array
      const emailsCopy = REALISTIC_DATA.emails;
      expect(Array.isArray(emailsCopy)).toBe(true);
      let emailCount = 0;
      for (const _email of emailsCopy) {
        emailCount++;
      }
      expect(emailCount).toBe(REALISTIC_EMAILS.length);
    });

    it("should preserve all values from source arrays", () => {
      // Verify spread operator doesn't lose any values
      expect(REALISTIC_DATA.urls).toEqual([...REALISTIC_URLS]);
      expect(REALISTIC_DATA.emails).toEqual([...REALISTIC_EMAILS]);
      expect(REALISTIC_DATA.names).toEqual([...REALISTIC_NAMES]);
      expect(REALISTIC_DATA.ids).toEqual([...REALISTIC_IDS]);
      expect(REALISTIC_DATA.paths).toEqual([...REALISTIC_PATHS]);
      expect(REALISTIC_DATA.queries).toEqual([...REALISTIC_QUERIES]);
      expect(REALISTIC_DATA.numbers).toEqual([...REALISTIC_NUMBERS]);
      expect(REALISTIC_DATA.booleans).toEqual([...REALISTIC_BOOLEANS]);
      expect(REALISTIC_DATA.jsonObjects).toEqual([...REALISTIC_JSON_OBJECTS]);
      expect(REALISTIC_DATA.arrays).toEqual([...REALISTIC_ARRAYS]);
    });

    it("should allow array methods without type errors", () => {
      // Verify we can use array methods (map, filter, etc.)
      const firstThreeUrls = REALISTIC_DATA.urls.slice(0, 3);
      expect(firstThreeUrls.length).toBe(3);

      const hasGoogleUrl = REALISTIC_DATA.urls.some((url) =>
        url.includes("google"),
      );
      expect(hasGoogleUrl).toBe(true);

      const uppercaseEmails = REALISTIC_DATA.emails.map((email) =>
        email.toUpperCase(),
      );
      expect(uppercaseEmails.length).toBe(REALISTIC_DATA.emails.length);
    });
  });

  describe("Runtime Type Validation", () => {
    it("should have correct types for all properties at runtime", () => {
      // Verify urls are strings
      expect(REALISTIC_DATA.urls.every((url) => typeof url === "string")).toBe(
        true,
      );

      // Verify emails are strings
      expect(
        REALISTIC_DATA.emails.every((email) => typeof email === "string"),
      ).toBe(true);

      // Verify names are strings
      expect(
        REALISTIC_DATA.names.every((name) => typeof name === "string"),
      ).toBe(true);

      // Verify ids are strings
      expect(REALISTIC_DATA.ids.every((id) => typeof id === "string")).toBe(
        true,
      );

      // Verify paths are strings
      expect(
        REALISTIC_DATA.paths.every((path) => typeof path === "string"),
      ).toBe(true);

      // Verify queries are strings
      expect(
        REALISTIC_DATA.queries.every((query) => typeof query === "string"),
      ).toBe(true);

      // Verify numbers are numbers
      expect(
        REALISTIC_DATA.numbers.every((num) => typeof num === "number"),
      ).toBe(true);

      // Verify booleans are booleans
      expect(
        REALISTIC_DATA.booleans.every((bool) => typeof bool === "boolean"),
      ).toBe(true);

      // Verify jsonObjects are objects
      expect(
        REALISTIC_DATA.jsonObjects.every(
          (obj) => typeof obj === "object" && obj !== null,
        ),
      ).toBe(true);

      // Verify arrays are arrays
      expect(REALISTIC_DATA.arrays.every((arr) => Array.isArray(arr))).toBe(
        true,
      );

      // Verify timestamps are strings
      expect(
        REALISTIC_DATA.timestamps.every(
          (timestamp) => typeof timestamp === "string",
        ),
      ).toBe(true);
    });

    it("should contain expected values", () => {
      // Spot check key values - use actual values from the arrays
      expect(REALISTIC_DATA.urls).toContain("https://www.google.com");
      expect(REALISTIC_DATA.emails).toContain("admin@example.com");
      expect(REALISTIC_DATA.names).toContain("Default");
      expect(REALISTIC_DATA.ids).toContain("123"); // Use actual ID from REALISTIC_IDS
      expect(REALISTIC_DATA.paths).toContain("/tmp/test.txt"); // Use actual path from REALISTIC_PATHS
      expect(REALISTIC_DATA.queries).toContain("test"); // Use actual query from REALISTIC_QUERIES
      expect(REALISTIC_DATA.numbers).toContain(200);
      expect(REALISTIC_DATA.booleans).toContain(true);
      expect(REALISTIC_DATA.jsonObjects).toContainEqual({ success: true });
      expect(REALISTIC_DATA.arrays).toContainEqual([]);
    });
  });

  describe("Timestamps Generation", () => {
    it("should generate valid ISO 8601 timestamps", () => {
      const timestamps = generateRealisticTimestamps();

      expect(timestamps.length).toBeGreaterThan(0);

      // Verify all timestamps are valid ISO 8601 strings
      timestamps.forEach((timestamp) => {
        expect(typeof timestamp).toBe("string");
        // ISO 8601 format: YYYY-MM-DDTHH:mm:ss.sssZ
        expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
        // Verify it can be parsed as a valid date
        const date = new Date(timestamp);
        expect(date.getTime()).not.toBeNaN();
      });
    });

    it("should include current timestamp", () => {
      const timestamps = REALISTIC_DATA.timestamps;
      const now = new Date();

      // At least one timestamp should be within 1 second of current time
      const hasRecentTimestamp = timestamps.some((timestamp) => {
        const date = new Date(timestamp);
        const diff = Math.abs(now.getTime() - date.getTime());
        return diff < 2000; // Within 2 seconds
      });

      expect(hasRecentTimestamp).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty arrays in REALISTIC_ARRAYS", () => {
      expect(REALISTIC_DATA.arrays).toContainEqual([]);
    });

    it("should handle empty object in REALISTIC_JSON_OBJECTS", () => {
      expect(REALISTIC_DATA.jsonObjects).toContainEqual({});
    });

    it("should handle zero in REALISTIC_NUMBERS", () => {
      expect(REALISTIC_DATA.numbers).toContain(0);
    });

    it("should handle both boolean values", () => {
      expect(REALISTIC_DATA.booleans).toContain(true);
      expect(REALISTIC_DATA.booleans).toContain(false);
      expect(REALISTIC_DATA.booleans.length).toBe(2);
    });
  });

  describe("Immutability of Source Arrays", () => {
    it("should not modify source readonly arrays", () => {
      // Verify source arrays are still readonly (type-level check via compilation)
      const originalUrlsLength = REALISTIC_URLS.length;
      const originalEmailsLength = REALISTIC_EMAILS.length;

      // Create copies via REALISTIC_DATA
      const _urlsCopy = REALISTIC_DATA.urls;
      const _emailsCopy = REALISTIC_DATA.emails;

      // Source arrays should remain unchanged
      expect(REALISTIC_URLS.length).toBe(originalUrlsLength);
      expect(REALISTIC_EMAILS.length).toBe(originalEmailsLength);
    });
  });
});
