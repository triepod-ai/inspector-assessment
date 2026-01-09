/**
 * ConfidenceScorer Tests
 * Tests for confidence level calculation in vulnerability detection
 */

import { ConfidenceScorer } from "../modules/securityTests/ConfidenceScorer";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SecurityPayload } from "@/lib/securityPatterns";
import type { SanitizationDetectionResult } from "../modules/securityTests/SanitizationDetector";

describe("ConfidenceScorer", () => {
  let scorer: ConfidenceScorer;

  beforeEach(() => {
    scorer = new ConfidenceScorer();
  });

  // Helper to create mock tool
  const createTool = (name: string, description: string = ""): Tool => ({
    name,
    description,
    inputSchema: { type: "object", properties: {} },
  });

  // Helper to create mock payload
  const createPayload = (
    payload: string,
    evidence?: RegExp,
  ): SecurityPayload => ({
    payload,
    evidence,
    category: "test",
  });

  describe("calculateConfidence", () => {
    describe("sanitization adjustments (Issue #56)", () => {
      const createSanitizationResult = (
        adjustment: number,
        libraries: string[] = [],
        genericPatterns: string[] = [],
        evidence: string[] = [],
      ): SanitizationDetectionResult => ({
        detected: true,
        totalConfidenceAdjustment: adjustment,
        libraries,
        genericPatterns,
        evidence,
        sanitizationTypes: [],
      });

      it("should downgrade to low confidence with strong sanitization (>=30)", () => {
        const tool = createTool("execute", "runs commands");
        const sanitization = createSanitizationResult(
          30,
          ["DOMPurify"],
          [],
          ["DOMPurify.sanitize detected"],
        );

        const result = scorer.calculateConfidence(
          tool,
          true,
          "executed",
          "output",
          createPayload("<script>"),
          sanitization,
        );

        expect(result.confidence).toBe("low");
        expect(result.requiresManualReview).toBe(true);
        expect(result.manualReviewReason).toContain("DOMPurify");
      });

      it("should downgrade to medium confidence with moderate sanitization (>=15)", () => {
        const tool = createTool("execute", "runs commands");
        const sanitization = createSanitizationResult(
          15,
          [],
          ["sanitize"],
          ["sanitize pattern found"],
        );

        const result = scorer.calculateConfidence(
          tool,
          true,
          "executed",
          "output",
          createPayload("<script>"),
          sanitization,
        );

        expect(result.confidence).toBe("medium");
        expect(result.requiresManualReview).toBe(true);
      });

      it("should NOT adjust confidence when not vulnerable", () => {
        const tool = createTool("execute", "runs commands");
        const sanitization = createSanitizationResult(50, ["DOMPurify"]);

        const result = scorer.calculateConfidence(
          tool,
          false, // Not vulnerable
          "safely reflected",
          "output",
          createPayload("<script>"),
          sanitization,
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });
    });

    describe("high confidence cases", () => {
      it("should return high confidence for safely reflected", () => {
        const tool = createTool("search");
        const result = scorer.calculateConfidence(
          tool,
          false,
          "safely reflected",
          "response",
          createPayload("test"),
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });

      it("should return high confidence for API wrapper", () => {
        const tool = createTool("api_call");
        const result = scorer.calculateConfidence(
          tool,
          false,
          "API wrapper",
          "response",
          createPayload("test"),
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });

      it("should return high confidence for safe: true evidence", () => {
        const tool = createTool("safe_tool");
        const result = scorer.calculateConfidence(
          tool,
          false,
          "safe: true response",
          "response",
          createPayload("test"),
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });

      it("should return high confidence for vulnerable execution in non-data tool", () => {
        const tool = createTool("execute_command", "runs shell commands");
        const result = scorer.calculateConfidence(
          tool,
          true,
          "command executed",
          "uid=0(root)",
          createPayload("id"),
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });
    });

    describe("low confidence cases - structured data tools", () => {
      it("should return low confidence for data tool with structured response", () => {
        const tool = createTool("search_docs", "searches documentation");
        const result = scorer.calculateConfidence(
          tool,
          true,
          "pattern found",
          '{"title": "admin guide", "description": "how to admin"}',
          createPayload("admin", /admin/i),
        );

        expect(result.confidence).toBe("low");
        expect(result.requiresManualReview).toBe(true);
        expect(result.manualReviewReason).toContain("structured data");
      });

      it("should return low confidence for data tool echoing input", () => {
        const tool = createTool("find_library", "finds npm libraries");
        const result = scorer.calculateConfidence(
          tool,
          true,
          "pattern found",
          "Results for: admin-toolkit",
          createPayload("admin-toolkit", /admin/i),
        );

        expect(result.confidence).toBe("low");
        expect(result.requiresManualReview).toBe(true);
      });

      it("should return low confidence for numeric pattern in metadata", () => {
        const tool = createTool("execute_calc", "performs calculations");
        const result = scorer.calculateConfidence(
          tool,
          true,
          "4 found",
          '{"trust score": 4, "rating": 4.5}',
          createPayload("2 + 2", /4/), // Simple pattern that contains digit "4" in toString()
        );

        expect(result.confidence).toBe("low");
        expect(result.requiresManualReview).toBe(true);
        expect(result.manualReviewReason).toContain("numeric");
      });

      it("should return low confidence for admin keywords in search tool", () => {
        const tool = createTool(
          "search_api",
          "search documentation and library API",
        );
        const result = scorer.calculateConfidence(
          tool,
          true,
          "admin found",
          "Results: admin-api-library",
          createPayload("assume admin role"),
        );

        expect(result.confidence).toBe("low");
        expect(result.requiresManualReview).toBe(true);
        expect(result.manualReviewReason).toContain("Admin-related");
      });
    });

    describe("medium confidence cases", () => {
      it("should return medium confidence for execution with ambiguity in data tool", () => {
        const tool = createTool("search_and_run", "searches and executes");
        const result = scorer.calculateConfidence(
          tool,
          true,
          "command executed",
          "executed search query",
          createPayload("ls -la"),
        );

        expect(result.confidence).toBe("medium");
        expect(result.requiresManualReview).toBe(true);
      });
    });

    describe("default high confidence", () => {
      it("should return high confidence for clear non-vulnerable case", () => {
        const tool = createTool("random_tool");
        const result = scorer.calculateConfidence(
          tool,
          false,
          "no issues found",
          "normal response",
          createPayload("test"),
        );

        expect(result.confidence).toBe("high");
        expect(result.requiresManualReview).toBe(false);
      });
    });
  });

  describe("isStructuredDataTool", () => {
    it("should detect search tools", () => {
      expect(scorer.isStructuredDataTool("search", "")).toBe(true);
      expect(scorer.isStructuredDataTool("search_docs", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "search for items")).toBe(true);
    });

    it("should detect find tools", () => {
      expect(scorer.isStructuredDataTool("find_user", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "finds matching items")).toBe(
        true,
      );
    });

    it("should detect lookup tools", () => {
      expect(scorer.isStructuredDataTool("lookup", "")).toBe(true);
      expect(scorer.isStructuredDataTool("dns_lookup", "")).toBe(true);
    });

    it("should detect query tools", () => {
      expect(scorer.isStructuredDataTool("query_db", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "query the database")).toBe(true);
    });

    it("should detect retrieve tools", () => {
      expect(scorer.isStructuredDataTool("retrieve_data", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "retrieves records")).toBe(true);
    });

    it("should detect fetch tools", () => {
      expect(scorer.isStructuredDataTool("fetch_items", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "fetches from API")).toBe(true);
    });

    it("should detect get tools", () => {
      expect(scorer.isStructuredDataTool("get_user", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "gets the value")).toBe(true);
    });

    it("should detect list tools", () => {
      expect(scorer.isStructuredDataTool("list_files", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "lists all items")).toBe(true);
    });

    it("should detect resolve tools", () => {
      expect(scorer.isStructuredDataTool("resolve_dns", "")).toBe(true);
      expect(scorer.isStructuredDataTool("", "resolves the reference")).toBe(
        true,
      );
    });

    it("should detect discover tools", () => {
      expect(scorer.isStructuredDataTool("discover_services", "")).toBe(true);
    });

    it("should detect browse tools", () => {
      expect(scorer.isStructuredDataTool("browse_catalog", "")).toBe(true);
    });

    it("should NOT detect non-data tools", () => {
      expect(scorer.isStructuredDataTool("execute", "runs commands")).toBe(
        false,
      );
      expect(scorer.isStructuredDataTool("create_user", "creates a user")).toBe(
        false,
      );
      expect(scorer.isStructuredDataTool("delete_item", "deletes items")).toBe(
        false,
      );
    });
  });

  describe("isValidationPattern", () => {
    it("should detect type error patterns", () => {
      expect(scorer.isValidationPattern(/type.*error/i)).toBe(true);
      expect(scorer.isValidationPattern(/TypeError/i)).toBe(true);
    });

    it("should detect invalid type patterns", () => {
      expect(scorer.isValidationPattern(/invalid.*type/i)).toBe(true);
    });

    it("should detect error patterns", () => {
      expect(scorer.isValidationPattern(/error/i)).toBe(true);
    });

    it("should detect invalid patterns", () => {
      expect(scorer.isValidationPattern(/invalid/i)).toBe(true);
    });

    it("should detect failed patterns", () => {
      expect(scorer.isValidationPattern(/failed/i)).toBe(true);
    });

    it("should detect negative value patterns", () => {
      expect(scorer.isValidationPattern(/negative.*not.*allowed/i)).toBe(true);
    });

    it("should detect positive requirement patterns", () => {
      expect(scorer.isValidationPattern(/must.*be.*positive/i)).toBe(true);
    });

    it("should detect invalid value patterns", () => {
      expect(scorer.isValidationPattern(/invalid.*value/i)).toBe(true);
    });

    it("should detect overflow patterns", () => {
      expect(scorer.isValidationPattern(/overflow/i)).toBe(true);
    });

    it("should detect out of range patterns", () => {
      expect(scorer.isValidationPattern(/out.*of.*range/i)).toBe(true);
    });

    it("should NOT detect non-validation patterns", () => {
      expect(scorer.isValidationPattern(/root:x:0:0/)).toBe(false);
      expect(scorer.isValidationPattern(/uid=\d+/)).toBe(false);
      expect(scorer.isValidationPattern(/success/)).toBe(false);
    });
  });
});
