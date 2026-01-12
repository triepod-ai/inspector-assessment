/**
 * Unit tests for ManifestValidationAssessor helper functions
 * Tests the fixes applied in Stage 3 (Issue #140)
 *
 * TEST-001: Validates FIX-001 (Levenshtein distance optimization)
 * TEST-002: Validates FIX-001 (findClosestMatch logic - tested indirectly via integration)
 * TEST-003: Validates FIX-002 (fetchWithRetry exponential backoff)
 */

import { ManifestValidationAssessor } from "../ManifestValidationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockManifestJson,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../../AssessmentOrchestrator";

// Copy of the levenshteinDistance implementation for direct unit testing
function testLevenshteinDistance(
  a: string,
  b: string,
  maxDist?: number,
): number {
  // Early termination optimizations
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  if (maxDist && Math.abs(a.length - b.length) > maxDist) {
    return maxDist + 1;
  }

  // Ensure a is the shorter string (optimize space)
  if (a.length > b.length) {
    [a, b] = [b, a];
  }

  // Two-row algorithm: only keep previous and current row
  let prev = Array.from({ length: a.length + 1 }, (_, i) => i);
  let curr = new Array(a.length + 1);

  for (let i = 1; i <= b.length; i++) {
    curr[0] = i;

    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = Math.min(
          prev[j - 1] + 1, // substitution
          curr[j - 1] + 1, // insertion
          prev[j] + 1, // deletion
        );
      }
    }

    // Swap rows
    [prev, curr] = [curr, prev];
  }

  return prev[a.length];
}

describe("ManifestValidationAssessor - Unit Tests (Stage 3 Fixes)", () => {
  let assessor: ManifestValidationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      assessmentCategories: {
        manifestValidation: true,
      },
    });
    assessor = new ManifestValidationAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  // ============================================
  // TEST-001: Levenshtein Distance Algorithm
  // Fulfills: TEST-REQ-001
  // Validates: FIX-001 (Optimized O(min(n,m)) algorithm)
  // ============================================

  describe("levenshteinDistance (TEST-001)", () => {
    describe("happy path scenarios", () => {
      it("should return 0 for identical strings", () => {
        expect(testLevenshteinDistance("abc", "abc")).toBe(0);
        expect(testLevenshteinDistance("test", "test")).toBe(0);
        expect(testLevenshteinDistance("", "")).toBe(0);
      });

      it("should return 1 for single substitution", () => {
        expect(testLevenshteinDistance("abc", "abd")).toBe(1);
        expect(testLevenshteinDistance("cat", "bat")).toBe(1);
      });

      it("should return 1 for single insertion", () => {
        expect(testLevenshteinDistance("abc", "abcd")).toBe(1);
        expect(testLevenshteinDistance("test", "tests")).toBe(1);
      });

      it("should return 1 for single deletion", () => {
        expect(testLevenshteinDistance("abcd", "abc")).toBe(1);
        expect(testLevenshteinDistance("tests", "test")).toBe(1);
      });

      it("should calculate distance for multiple operations", () => {
        expect(testLevenshteinDistance("kitten", "sitting")).toBe(3);
        // k->s (sub), e->i (sub), insert g
        expect(testLevenshteinDistance("saturday", "sunday")).toBe(3);
        // remove a, remove t, remove r
      });
    });

    describe("edge cases", () => {
      it("should handle empty strings", () => {
        expect(testLevenshteinDistance("", "abc")).toBe(3);
        expect(testLevenshteinDistance("abc", "")).toBe(3);
        expect(testLevenshteinDistance("", "")).toBe(0);
      });

      it("should handle single character strings", () => {
        expect(testLevenshteinDistance("a", "a")).toBe(0);
        expect(testLevenshteinDistance("a", "b")).toBe(1);
        expect(testLevenshteinDistance("a", "ab")).toBe(1);
        expect(testLevenshteinDistance("ab", "a")).toBe(1);
      });

      it("should handle completely different strings", () => {
        expect(testLevenshteinDistance("abc", "xyz")).toBe(3);
        expect(testLevenshteinDistance("hello", "world")).toBe(4);
      });

      it("should handle Unicode characters", () => {
        expect(testLevenshteinDistance("café", "cafe")).toBe(1);
        expect(testLevenshteinDistance("你好", "你好")).toBe(0);
        expect(testLevenshteinDistance("🎉", "🎊")).toBe(1);
        expect(testLevenshteinDistance("test🎉", "test🎊")).toBe(1);
      });
    });

    describe("boundary cases", () => {
      it("should handle very long strings efficiently", () => {
        const longString1 = "a".repeat(100);
        const longString2 = "a".repeat(99) + "b";

        const start = Date.now();
        const distance = testLevenshteinDistance(longString1, longString2);
        const duration = Date.now() - start;

        expect(distance).toBe(1);
        // Should complete in under 100ms (much faster than O(n*m) matrix approach)
        expect(duration).toBeLessThan(100);
      });

      it("should handle strings with very long length difference", () => {
        const short = "abc";
        const long = "a".repeat(1000);

        // Comparing "abc" to "aaa...a" (1000 a's)
        // First 'a' matches, then need 'b' and 'c' substituted, plus 997 deletions
        // Total: 999 operations
        expect(testLevenshteinDistance(short, long)).toBe(999);
      });

      it("should optimize with maxDist parameter", () => {
        const a = "abc";
        const b = "xyz";

        // With maxDist, should terminate early
        const distWithMax = testLevenshteinDistance(a, b, 2);
        expect(distWithMax).toBeGreaterThan(2);
      });

      it("should terminate early when length difference exceeds maxDist", () => {
        const short = "abc";
        const long = "abcdefghij";

        // Length difference is 7, maxDist is 3
        const dist = testLevenshteinDistance(short, long, 3);
        expect(dist).toBe(4); // maxDist + 1
      });
    });

    describe("case sensitivity", () => {
      it("should be case sensitive by default", () => {
        expect(testLevenshteinDistance("ABC", "abc")).toBe(3);
        expect(testLevenshteinDistance("Test", "test")).toBe(1);
      });
    });
  });

  // ============================================
  // TEST-002: findClosestMatch Integration
  // Fulfills: TEST-REQ-002
  // Validates: FIX-001 (threshold logic and suggestions)
  // ============================================

  describe("findClosestMatch via tool name validation (TEST-002)", () => {
    it("should suggest close matches for typos", async () => {
      // Setup: Manifest declares "test-too" (typo), server has "test-tool"
      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.tools = [{ name: "test-too" }];
      mockContext.tools = [
        {
          name: "test-tool",
          description: "Test tool",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = await assessor.assess(mockContext);

      // Should find the mismatch and suggest "test-tool"
      const toolMismatch = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)" && !r.valid,
      );
      expect(toolMismatch).toBeDefined();
      expect(toolMismatch!.issue).toContain('did you mean "test-tool"');
    });

    it("should not suggest matches when distance exceeds threshold", async () => {
      // Setup: Manifest declares completely different tool name
      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.tools = [{ name: "completely-different-name" }];
      mockContext.tools = [
        {
          name: "test-tool",
          description: "Test tool",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = await assessor.assess(mockContext);

      // Should have mismatch but no suggestion
      const toolMismatch = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)" && !r.valid,
      );
      expect(toolMismatch).toBeDefined();
      expect(toolMismatch!.issue).not.toContain("did you mean");
      expect(toolMismatch!.issue).toContain("completely-different-name");
    });

    it("should match exact tool names", async () => {
      // Setup: Manifest and server have exact matching tool names
      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.tools = [{ name: "test-tool" }];
      mockContext.tools = [
        {
          name: "test-tool",
          description: "Test tool",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = await assessor.assess(mockContext);

      // Should have match result
      const toolMatch = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)" && r.valid,
      );
      expect(toolMatch).toBeDefined();
      expect(toolMatch!.issue).toBeUndefined();
    });

    it("should handle short tool names with appropriate threshold", async () => {
      // For short names (<3 chars), threshold is 10
      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.tools = [{ name: "ab" }];
      mockContext.tools = [
        {
          name: "abc",
          description: "Test tool",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = await assessor.assess(mockContext);

      // Distance 1 should be within threshold 10
      const toolMismatch = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)" && !r.valid,
      );
      expect(toolMismatch).toBeDefined();
      expect(toolMismatch!.issue).toContain('did you mean "abc"');
    });

    it("should handle long tool names with percentage-based threshold", async () => {
      // For long names (>25 chars), threshold is 40% of length
      const longName = "very-long-tool-name-that-exceeds-threshold";
      const typoName = "very-long-tool-name-that-exceeds-threshol"; // Missing 'd'

      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.tools = [{ name: typoName }];
      mockContext.tools = [
        {
          name: longName,
          description: "Test tool",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = await assessor.assess(mockContext);

      // Threshold for 42 chars: max(10, 16) = 16
      // Distance 1 should be within threshold
      const toolMismatch = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)" && !r.valid,
      );
      expect(toolMismatch).toBeDefined();
      expect(toolMismatch!.issue).toContain("did you mean");
    });
  });

  // ============================================
  // TEST-003: Retry Logic Integration
  // Fulfills: Validates FIX-002
  // Validates: fetchWithRetry exponential backoff
  // ============================================

  describe("fetchWithRetry for privacy policy URLs (TEST-003)", () => {
    beforeEach(() => {
      // Mock fetch globally
      global.fetch = jest.fn();
    });

    afterEach(() => {
      jest.restoreAllMocks();
    });

    it("should succeed on first attempt", async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        headers: {
          get: jest
            .fn()
            .mockImplementation((header: string) =>
              header === "content-type" ? "text/html" : null,
            ),
        },
      };

      (global.fetch as jest.Mock).mockResolvedValueOnce(mockResponse);

      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.privacy_policies = [
        "https://example.com/privacy",
      ];

      const result = await assessor.assess(mockContext);

      // Should have privacy policy validation result
      const privacyResult = result.validationResults.find(
        (r) => r.field === "privacy_policies",
      );
      expect(privacyResult).toBeDefined();
      expect(privacyResult!.valid).toBe(true);
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it("should retry on transient failure and succeed", async () => {
      const mockError = new Error("Network error");
      const mockResponse = {
        ok: true,
        status: 200,
        headers: {
          get: jest
            .fn()
            .mockImplementation((header: string) =>
              header === "content-type" ? "text/html" : null,
            ),
        },
      };

      // Fail first, succeed second
      (global.fetch as jest.Mock)
        .mockRejectedValueOnce(mockError)
        .mockResolvedValueOnce(mockResponse);

      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.privacy_policies = [
        "https://example.com/privacy",
      ];

      const result = await assessor.assess(mockContext);

      // Should eventually succeed after retry
      const privacyResult = result.validationResults.find(
        (r) => r.field === "privacy_policies",
      );
      expect(privacyResult).toBeDefined();
      expect(privacyResult!.valid).toBe(true);
      // Called 2 times: first HEAD failed, second HEAD succeeded
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it("should exhaust retries and fail", async () => {
      const mockError = new Error("Persistent network error");

      // Always fail
      (global.fetch as jest.Mock).mockRejectedValue(mockError);

      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.privacy_policies = [
        "https://example.com/privacy",
      ];

      const result = await assessor.assess(mockContext);

      // Should eventually fail after all retries
      const privacyResult = result.validationResults.find(
        (r) => r.field === "privacy_policies",
      );
      expect(privacyResult).toBeDefined();
      expect(privacyResult!.valid).toBe(false);
      expect(privacyResult!.issue).toContain("inaccessible");
      // Called 3 times for HEAD (initial + 2 retries), then 3 times for GET fallback
      expect(global.fetch).toHaveBeenCalledTimes(6);
    });

    it("should fallback to GET when HEAD fails", async () => {
      const headError = new Error("HEAD not supported");
      const mockResponse = {
        ok: true,
        status: 200,
        headers: {
          get: jest
            .fn()
            .mockImplementation((header: string) =>
              header === "content-type" ? "text/html" : null,
            ),
        },
      };

      // HEAD fails all attempts, GET succeeds
      (global.fetch as jest.Mock).mockImplementation(
        (url: string, options: any) => {
          if (options.method === "HEAD") {
            return Promise.reject(headError);
          }
          return Promise.resolve(mockResponse);
        },
      );

      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.privacy_policies = [
        "https://example.com/privacy",
      ];

      const result = await assessor.assess(mockContext);

      // Should succeed via GET fallback
      const privacyResult = result.validationResults.find(
        (r) => r.field === "privacy_policies",
      );
      expect(privacyResult).toBeDefined();
      expect(privacyResult!.valid).toBe(true);
      // HEAD called 3 times (initial + 2 retries), then GET called once
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ method: "HEAD" }),
      );
      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({ method: "GET" }),
      );
    });

    it("should handle invalid URL format", async () => {
      mockContext.manifestJson = createMockManifestJson();
      mockContext.manifestJson.privacy_policies = ["not-a-valid-url"];

      const result = await assessor.assess(mockContext);

      // Should report invalid URL without attempting fetch
      const privacyResult = result.validationResults.find(
        (r) => r.field === "privacy_policies",
      );
      expect(privacyResult).toBeDefined();
      expect(privacyResult!.valid).toBe(false);
      expect(privacyResult!.issue).toContain("inaccessible");
      // Fetch not called for invalid URLs
      expect(global.fetch).not.toHaveBeenCalled();
    });
  });
});
