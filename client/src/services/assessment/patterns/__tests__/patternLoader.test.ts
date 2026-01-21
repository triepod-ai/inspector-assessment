/**
 * Pattern Loader Tests
 *
 * Verifies JSON pattern loading and RegExp compilation.
 *
 * @since v1.43.0 (Issue #200 - V2 Refactoring)
 */

import {
  loadAnnotationPatterns,
  loadSanitizationPatterns,
  getRawAnnotationPatterns,
  getRawSanitizationPatterns,
  stringToRegExp,
  compilePatterns,
  clearPatternCaches,
  arePatternsLoaded,
} from "../patternLoader";

describe("Pattern Loader", () => {
  beforeEach(() => {
    clearPatternCaches();
  });

  describe("stringToRegExp", () => {
    it("should convert string to case-insensitive RegExp", () => {
      const regex = stringToRegExp("\\btest\\b");
      expect(regex).toBeInstanceOf(RegExp);
      expect(regex.flags).toBe("i");
      expect(regex.test("TEST")).toBe(true);
      expect(regex.test("testing")).toBe(false);
    });
  });

  describe("compilePatterns", () => {
    it("should compile array of strings to RegExp array", () => {
      const patterns = compilePatterns(["\\bfoo\\b", "\\bbar\\b"]);
      expect(patterns).toHaveLength(2);
      expect(patterns[0]).toBeInstanceOf(RegExp);
      expect(patterns[1]).toBeInstanceOf(RegExp);
      expect(patterns[0].test("FOO")).toBe(true);
      expect(patterns[1].test("BAR")).toBe(true);
    });
  });

  describe("loadAnnotationPatterns", () => {
    it("should load and compile annotation patterns from JSON", () => {
      const patterns = loadAnnotationPatterns();

      expect(patterns.readOnly).toBeDefined();
      expect(patterns.destructive).toBeDefined();
      expect(patterns.write).toBeDefined();
      expect(patterns.ambiguous).toBeDefined();

      // Verify patterns are RegExp
      expect(patterns.readOnly[0]).toBeInstanceOf(RegExp);
      expect(patterns.destructive[0]).toBeInstanceOf(RegExp);
    });

    it("should match expected read-only patterns", () => {
      const patterns = loadAnnotationPatterns();

      // Should match read-only patterns
      expect(patterns.readOnly.some((p) => p.test("get_users"))).toBe(true);
      expect(patterns.readOnly.some((p) => p.test("list_items"))).toBe(true);
      expect(patterns.readOnly.some((p) => p.test("fetch_data"))).toBe(true);
    });

    it("should match expected destructive patterns", () => {
      const patterns = loadAnnotationPatterns();

      // Should match destructive patterns
      expect(patterns.destructive.some((p) => p.test("delete_user"))).toBe(
        true,
      );
      expect(patterns.destructive.some((p) => p.test("remove_item"))).toBe(
        true,
      );
      expect(patterns.destructive.some((p) => p.test("run_command"))).toBe(
        true,
      );
    });

    it("should cache patterns on subsequent calls", () => {
      const patterns1 = loadAnnotationPatterns();
      const patterns2 = loadAnnotationPatterns();

      // Should be exact same object (cached)
      expect(patterns1).toBe(patterns2);
    });
  });

  describe("loadSanitizationPatterns", () => {
    it("should load and compile sanitization patterns from JSON", () => {
      const patterns = loadSanitizationPatterns();

      expect(patterns.libraries).toBeDefined();
      expect(patterns.genericKeywords).toBeDefined();
      expect(patterns.responseIndicators).toBeDefined();
      expect(patterns.confidenceBoosts).toBeDefined();
    });

    it("should include expected library patterns", () => {
      const patterns = loadSanitizationPatterns();

      // Should have DOMPurify
      const domPurify = patterns.libraries.find((l) => l.name === "DOMPurify");
      expect(domPurify).toBeDefined();
      expect(domPurify?.category).toBe("xss");
      expect(domPurify?.patterns[0]).toBeInstanceOf(RegExp);
    });

    it("should detect sanitization libraries correctly", () => {
      const patterns = loadSanitizationPatterns();

      // Test DOMPurify detection
      const domPurify = patterns.libraries.find((l) => l.name === "DOMPurify");
      expect(domPurify?.patterns.some((p) => p.test("using DOMPurify"))).toBe(
        true,
      );

      // Test Zod detection
      const zod = patterns.libraries.find((l) => l.name === "Zod");
      expect(zod?.patterns.some((p) => p.test("z.string()"))).toBe(true);
    });

    it("should include confidence boost values", () => {
      const patterns = loadSanitizationPatterns();

      expect(patterns.confidenceBoosts.SPECIFIC_LIBRARY).toBe(25);
      expect(patterns.confidenceBoosts.GENERIC_KEYWORD).toBe(8);
      expect(patterns.confidenceBoosts.RESPONSE_EVIDENCE).toBe(10);
      expect(patterns.confidenceBoosts.MAX_ADJUSTMENT).toBe(50);
    });

    it("should cache patterns on subsequent calls", () => {
      const patterns1 = loadSanitizationPatterns();
      const patterns2 = loadSanitizationPatterns();

      // Should be exact same object (cached)
      expect(patterns1).toBe(patterns2);
    });
  });

  describe("getRawAnnotationPatterns", () => {
    it("should return raw string-based patterns", () => {
      const raw = getRawAnnotationPatterns();

      expect(raw.readOnly).toContain("get_");
      expect(raw.destructive).toContain("delete_");
      expect(raw.write).toContain("create_");
      expect(raw.ambiguous).toContain("store_");
    });
  });

  describe("getRawSanitizationPatterns", () => {
    it("should return raw JSON-loaded patterns", () => {
      const raw = getRawSanitizationPatterns();

      expect(raw.libraries).toBeDefined();
      expect(raw.libraries.length).toBeGreaterThan(0);
      expect(typeof raw.libraries[0].patterns[0]).toBe("string");
    });
  });

  describe("clearPatternCaches", () => {
    it("should clear cached patterns", () => {
      // Load to populate cache
      loadAnnotationPatterns();
      loadSanitizationPatterns();

      expect(arePatternsLoaded().annotation).toBe(true);
      expect(arePatternsLoaded().sanitization).toBe(true);

      // Clear cache
      clearPatternCaches();

      expect(arePatternsLoaded().annotation).toBe(false);
      expect(arePatternsLoaded().sanitization).toBe(false);
    });
  });

  describe("arePatternsLoaded", () => {
    it("should report cache status correctly", () => {
      // Initially empty
      expect(arePatternsLoaded().annotation).toBe(false);
      expect(arePatternsLoaded().sanitization).toBe(false);

      // Load annotation patterns
      loadAnnotationPatterns();
      expect(arePatternsLoaded().annotation).toBe(true);
      expect(arePatternsLoaded().sanitization).toBe(false);

      // Load sanitization patterns
      loadSanitizationPatterns();
      expect(arePatternsLoaded().annotation).toBe(true);
      expect(arePatternsLoaded().sanitization).toBe(true);
    });
  });
});
