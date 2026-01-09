/**
 * MathAnalyzer Tests
 * Tests for math computation detection (Calculator Injection)
 */

import { MathAnalyzer } from "../modules/securityTests/MathAnalyzer";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("MathAnalyzer", () => {
  let analyzer: MathAnalyzer;

  beforeEach(() => {
    analyzer = new MathAnalyzer();
  });

  // Helper to create mock tool
  const createTool = (name: string, description: string = ""): Tool => ({
    name,
    description,
    inputSchema: { type: "object", properties: {} },
  });

  describe("analyzeComputedMathResult", () => {
    describe("HTTP error handling", () => {
      it("should return not computed for HTTP errors", () => {
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "404 not found",
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("high");
        expect(result.reason).toBe("HTTP error response");
      });

      it("should return not computed for 500 errors", () => {
        const result = analyzer.analyzeComputedMathResult(
          "3 * 3",
          "500 internal server error",
        );
        expect(result.isComputed).toBe(false);
      });
    });

    describe("non-math expressions", () => {
      it("should return not computed for non-math payloads", () => {
        const result = analyzer.analyzeComputedMathResult(
          "hello world",
          "some response",
        );
        expect(result.isComputed).toBe(false);
        expect(result.reason).toBe("Not a math expression");
      });

      it("should return not computed for SQL injection payloads", () => {
        const result = analyzer.analyzeComputedMathResult(
          "SELECT * FROM users",
          "some response",
        );
        expect(result.isComputed).toBe(false);
        expect(result.reason).toBe("Not a math expression");
      });
    });

    describe("high confidence detection", () => {
      it("should detect simple addition with high confidence", () => {
        const result = analyzer.analyzeComputedMathResult("2 + 2", "4");
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
        expect(result.reason).toBe("Response is exactly the computed result");
      });

      it("should detect multiplication with high confidence", () => {
        const result = analyzer.analyzeComputedMathResult("7 * 8", "56");
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should detect subtraction with high confidence", () => {
        const result = analyzer.analyzeComputedMathResult("10 - 3", "7");
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should detect division with high confidence", () => {
        const result = analyzer.analyzeComputedMathResult("8 / 2", "4");
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should detect three-operand expressions", () => {
        const result = analyzer.analyzeComputedMathResult("1 + 2 + 3", "6");
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
      });

      it("should detect with computational language", () => {
        const result = analyzer.analyzeComputedMathResult(
          "5 + 5",
          "the answer is 10",
        );
        expect(result.isComputed).toBe(true);
        expect(result.confidence).toBe("high");
        expect(result.reason).toBe("Response contains computational language");
      });
    });

    describe("low confidence - coincidental data", () => {
      it("should return low confidence for structured data fields", () => {
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          '{"count": 4, "status": "ok"}',
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
        expect(result.reason).toContain("structured data field");
      });

      it("should return low confidence for records field", () => {
        const result = analyzer.analyzeComputedMathResult(
          "1 + 1",
          '{"records": 2, "page": 1}',
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
      });

      it("should return low confidence for total field", () => {
        const result = analyzer.analyzeComputedMathResult(
          "3 + 3",
          '{"total": 6, "items": []}',
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
      });
    });

    describe("low confidence - tool classification", () => {
      it("should return low confidence for data fetcher tools", () => {
        const tool = createTool("fetch_data", "Fetches data from API");
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "Found 4 results",
          tool,
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
      });

      it("should return low confidence for get_ prefixed tools", () => {
        const tool = createTool("get_users", "Gets user list");
        // Use response that doesn't match structured data patterns
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "Response value: 4",
          tool,
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
        // Could match either tool category or name pattern check
        expect(result.reason).toMatch(/Tool (name|classified)/);
      });

      it("should return low confidence for list_ prefixed tools", () => {
        const tool = createTool("list_items", "Lists all items");
        // Use response that doesn't match structured data patterns
        const result = analyzer.analyzeComputedMathResult(
          "1 + 1",
          "Data: 2",
          tool,
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
      });

      it("should return low confidence for search tools", () => {
        const tool = createTool("search", "Search the database");
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "Found 4 matches",
          tool,
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("low");
      });
    });

    describe("medium confidence - ambiguous", () => {
      it("should return medium confidence for longer responses without computational language", () => {
        // Use response that doesn't match structured data patterns but is long
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "The request was processed successfully. Your input has been validated and stored. Value: 4",
        );
        expect(result.isComputed).toBe(false);
        expect(result.confidence).toBe("medium");
      });
    });

    describe("not computed - original expression present", () => {
      it("should not flag when original expression is echoed", () => {
        const result = analyzer.analyzeComputedMathResult(
          "2 + 2",
          "Stored: 2 + 2, result: 4",
        );
        expect(result.isComputed).toBe(false);
        expect(result.reason).toBe("No computed result found");
      });

      it("should not flag when only original expression present", () => {
        const result = analyzer.analyzeComputedMathResult(
          "5 * 5",
          "Query: 5 * 5",
        );
        expect(result.isComputed).toBe(false);
      });
    });
  });

  describe("isComputedMathResult (legacy)", () => {
    it("should return true for high confidence computed results", () => {
      expect(analyzer.isComputedMathResult("2 + 2", "4")).toBe(true);
      expect(analyzer.isComputedMathResult("3 * 4", "12")).toBe(true);
    });

    it("should return false for low/medium confidence results", () => {
      expect(analyzer.isComputedMathResult("2 + 2", '{"count": 4}')).toBe(
        false,
      );
    });

    it("should return false for non-math payloads", () => {
      expect(analyzer.isComputedMathResult("hello", "world")).toBe(false);
    });
  });

  describe("isCoincidentalNumericInStructuredData", () => {
    describe("JSON responses", () => {
      it("should detect numeric in count field", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(5, '{"count": 5}'),
        ).toBe(true);
      });

      it("should detect numeric in total field", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(
            10,
            '{"total": 10, "items": []}',
          ),
        ).toBe(true);
      });

      it("should detect numeric in nested objects", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(
            3,
            '{"data": {"records": 3}}',
          ),
        ).toBe(true);
      });

      it("should detect numeric in arrays", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(
            7,
            '{"items": [{"count": 7}]}',
          ),
        ).toBe(true);
      });

      it("should NOT detect numeric in non-data fields", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(42, '{"answer": 42}'),
        ).toBe(false);
      });
    });

    describe("text responses", () => {
      it("should detect 'records: N' pattern", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(5, "records: 5"),
        ).toBe(true);
      });

      it("should detect 'N records' pattern", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(3, "3 records found"),
        ).toBe(true);
      });

      it("should detect 'page X of N' pattern", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(10, "page 1 of 10"),
        ).toBe(true);
      });

      it("should detect 'total: N' pattern", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(25, "total: 25"),
        ).toBe(true);
      });

      it("should detect 'found N items' pattern", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(8, "found 8 results"),
        ).toBe(true);
      });

      it("should NOT detect numeric in plain text", () => {
        expect(
          analyzer.isCoincidentalNumericInStructuredData(4, "The answer is 4"),
        ).toBe(false);
      });
    });
  });

  describe("edge cases", () => {
    it("should handle division with floor", () => {
      const result = analyzer.analyzeComputedMathResult("7 / 2", "3");
      expect(result.isComputed).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should handle zero results", () => {
      const result = analyzer.analyzeComputedMathResult("5 - 5", "0");
      expect(result.isComputed).toBe(true);
    });

    it("should handle negative results", () => {
      const result = analyzer.analyzeComputedMathResult("3 - 8", "-5");
      expect(result.isComputed).toBe(true);
    });

    it("should handle whitespace variations in payload", () => {
      const result1 = analyzer.analyzeComputedMathResult("2+2", "4");
      const result2 = analyzer.analyzeComputedMathResult("2  +  2", "4");
      expect(result1.isComputed).toBe(true);
      expect(result2.isComputed).toBe(true);
    });

    it("should handle large numbers", () => {
      const result = analyzer.analyzeComputedMathResult("999 + 1", "1000");
      expect(result.isComputed).toBe(true);
    });
  });
});
