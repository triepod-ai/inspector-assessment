/**
 * ConfidenceScorer - Context Keyword Tests (Issue #146)
 *
 * Tests for the context classification system added in Issue #146:
 * - CONFIRMED: Operation succeeded, payload was executed (high confidence)
 * - LIKELY_FALSE_POSITIVE: Payload reflected in error message (low confidence + manual review)
 * - SUSPECTED: Ambiguous case, continues to downstream logic (medium confidence)
 *
 * These tests verify that ConfidenceScorer correctly extracts context from
 * evidence strings and applies appropriate confidence adjustments.
 */

import { ConfidenceScorer } from "../modules/securityTests/ConfidenceScorer";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SecurityPayload } from "@/lib/securityPatterns";

describe("ConfidenceScorer - Context Keywords (Issue #146)", () => {
  let scorer: ConfidenceScorer;

  beforeEach(() => {
    scorer = new ConfidenceScorer();
  });

  const mockTool: Tool = {
    name: "test_tool",
    description: "Test tool",
    inputSchema: { type: "object", properties: {} },
  };

  const mockPayload: SecurityPayload = {
    payload: "../../../etc/passwd",
    evidence: /etc\/passwd/i,
    category: "path_traversal",
  };

  describe("CONFIRMED context - High confidence vulnerability", () => {
    it("should return high confidence when evidence contains [Context: CONFIRMED]", () => {
      const evidence =
        "Pattern matched [Context: CONFIRMED] - operation succeeded";
      const result = scorer.calculateConfidence(
        mockTool,
        true, // isVulnerable
        evidence,
        "File contents: root:x:0:0",
        mockPayload,
      );

      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });

    it("should extract CONFIRMED context from middle of evidence string", () => {
      const evidence =
        "Pattern detected. [Context: CONFIRMED] Additional evidence found.";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "success response",
        mockPayload,
      );

      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });

    it("should prioritize CONFIRMED context over other confidence factors", () => {
      // Tool is a "search" tool which would normally trigger low confidence for data tools
      const searchTool: Tool = {
        name: "search_files",
        description: "searches for files",
        inputSchema: { type: "object", properties: {} },
      };

      const evidence = "admin found [Context: CONFIRMED]";
      const result = scorer.calculateConfidence(
        searchTool,
        true,
        evidence,
        '{"results": ["admin-file.txt"]}',
        mockPayload,
      );

      // Should be high confidence despite being a search tool
      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });
  });

  describe("LIKELY_FALSE_POSITIVE context - Low confidence with manual review", () => {
    it("should return low confidence when evidence contains [Context: LIKELY_FALSE_POSITIVE]", () => {
      const evidence =
        "Payload reflected [Context: LIKELY_FALSE_POSITIVE] in error message";
      const result = scorer.calculateConfidence(
        mockTool,
        true, // Still marked as vulnerable by pattern match
        evidence,
        "Error: Failed to get ../../../etc/passwd - 404 not found",
        mockPayload,
      );

      expect(result.confidence).toBe("low");
      expect(result.requiresManualReview).toBe(true);
      expect(result.manualReviewReason).toContain(
        "Payload reflected in error message",
      );
      expect(result.reviewGuidance).toContain(
        "rejected the operation but echoed the payload",
      );
    });

    it("should provide clear manual review guidance for LIKELY_FALSE_POSITIVE", () => {
      const evidence = "[Context: LIKELY_FALSE_POSITIVE]";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "404 error response",
        mockPayload,
      );

      expect(result.reviewGuidance).toBeDefined();
      expect(result.reviewGuidance).toContain(
        "Verify if the tool actually processed the payload",
      );
      expect(result.reviewGuidance).toContain("HTTP status code");
    });

    it("should extract LIKELY_FALSE_POSITIVE from complex evidence string", () => {
      const evidence =
        "Multiple patterns detected. [Context: LIKELY_FALSE_POSITIVE] See error response for details.";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "error response",
        mockPayload,
      );

      expect(result.confidence).toBe("low");
      expect(result.requiresManualReview).toBe(true);
    });
  });

  describe("SUSPECTED context - Continues to downstream logic", () => {
    it("should NOT short-circuit on SUSPECTED context", () => {
      const evidence = "Pattern matched [Context: SUSPECTED] - ambiguous case";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "ambiguous response",
        mockPayload,
      );

      // Should continue to downstream logic (no specific handling for SUSPECTED)
      // Result depends on downstream confidence calculation
      expect(result.confidence).toBeDefined();
      expect(["high", "medium", "low"]).toContain(result.confidence);
    });

    it("should allow downstream logic to determine confidence for SUSPECTED cases", () => {
      // Search tool with SUSPECTED context should trigger structured data checks
      const searchTool: Tool = {
        name: "search_data",
        description: "searches database",
        inputSchema: { type: "object", properties: {} },
      };

      const evidence = "[Context: SUSPECTED] admin keyword found";
      const result = scorer.calculateConfidence(
        searchTool,
        true,
        evidence,
        '{"name": "admin-user", "role": "admin"}',
        { payload: "admin", evidence: /admin/i, category: "test" },
      );

      // Should be low confidence due to structured data tool detection
      expect(result.confidence).toBe("low");
      expect(result.requiresManualReview).toBe(true);
    });
  });

  describe("Edge cases - Context keyword extraction", () => {
    it("should handle malformed context string (no match)", () => {
      const evidence = "[Context: INVALID_CONTEXT] unknown context type";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "response",
        mockPayload,
      );

      // Should continue to downstream logic (context not matched)
      expect(result).toBeDefined();
      expect(result.confidence).toBeDefined();
    });

    it("should handle empty evidence string", () => {
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        "", // Empty evidence
        "response",
        mockPayload,
      );

      expect(result).toBeDefined();
      expect(result.confidence).toBeDefined();
    });

    it("should handle evidence without context keyword", () => {
      const evidence = "Pattern matched - no context specified";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "response",
        mockPayload,
      );

      expect(result).toBeDefined();
      expect(result.confidence).toBeDefined();
    });

    it("should extract first context keyword if multiple present (edge case)", () => {
      // This should never happen in practice, but test defensive behavior
      const evidence =
        "[Context: CONFIRMED] and [Context: LIKELY_FALSE_POSITIVE]";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "response",
        mockPayload,
      );

      // Should extract CONFIRMED (first match)
      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });

    it("should handle context keyword with extra whitespace", () => {
      const evidence = "[Context:   CONFIRMED  ] extra spaces";
      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "response",
        mockPayload,
      );

      // Regex should not match due to extra spaces (strict format)
      // Should continue to downstream logic
      expect(result).toBeDefined();
    });
  });

  describe("Context priority - Context overrides other factors", () => {
    it("should prioritize LIKELY_FALSE_POSITIVE over sanitization detection", () => {
      const evidence = "[Context: LIKELY_FALSE_POSITIVE]";
      const sanitization = {
        detected: true,
        totalConfidenceAdjustment: 30, // Strong sanitization
        libraries: ["DOMPurify"],
        genericPatterns: [],
        evidence: ["DOMPurify.sanitize detected"],
        sanitizationTypes: [],
      };

      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "error response",
        mockPayload,
        sanitization,
      );

      // Context should take priority
      expect(result.confidence).toBe("low");
      expect(result.manualReviewReason).toContain("error message");
      // Should not mention sanitization
    });

    it("should prioritize CONFIRMED over sanitization detection", () => {
      const evidence = "[Context: CONFIRMED]";
      const sanitization = {
        detected: true,
        totalConfidenceAdjustment: 50, // Very strong sanitization
        libraries: ["DOMPurify", "validator"],
        genericPatterns: [],
        evidence: ["Multiple sanitization libraries"],
        sanitizationTypes: [],
      };

      const result = scorer.calculateConfidence(
        mockTool,
        true,
        evidence,
        "success response",
        mockPayload,
        sanitization,
      );

      // Context should take priority
      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });
  });
});
