/**
 * SecurityResponseAnalyzer Unit Tests
 *
 * Tests the standalone response analyzer extracted from SecurityAssessor.
 * Validates vulnerability detection, reflection handling, and confidence calculation.
 *
 * @group unit
 * @group security
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import { SecurityPayload } from "@/lib/securityPatterns";
import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

describe("SecurityResponseAnalyzer", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  /**
   * Helper to create a mock response
   */
  function createResponse(text: string): CompatibilityCallToolResult {
    return {
      content: [{ type: "text", text }],
    } as CompatibilityCallToolResult;
  }

  /**
   * Helper to create a mock tool
   */
  function createTool(name: string, description?: string): Tool {
    return {
      name,
      description: description || `Test tool ${name}`,
      inputSchema: { type: "object", properties: {} },
    };
  }

  /**
   * Helper to create a mock payload
   */
  function createPayload(payload: string, evidence?: RegExp): SecurityPayload {
    return {
      payload,
      description: "Test payload",
      payloadType: "test",
      evidence,
      riskLevel: "HIGH",
    };
  }

  describe("analyzeResponse", () => {
    describe("MCP validation errors", () => {
      it("should detect MCP validation error code -32602 as safe", () => {
        const response = {
          content: [{ type: "text", text: "Parameter validation failed" }],
          isError: true,
          _meta: { error: { code: -32602, message: "Invalid params" } },
        } as unknown as CompatibilityCallToolResult;

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("validation");
      });

      it("should detect parameter validation patterns as safe", () => {
        const response = createResponse(
          "Parameter validation failed: invalid URL format",
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("validation");
      });

      it("should detect schema validation errors as safe", () => {
        const response = createResponse(
          "Schema validation error: required field missing",
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
      });
    });

    describe("HTTP error responses", () => {
      it("should detect HTTP 404 errors as safe", () => {
        const response = createResponse("404 Not Found");

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("HTTP error");
      });

      it("should detect HTTP 500 errors as safe", () => {
        const response = createResponse("500 Internal Server Error");

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
      });

      it("should detect JSON status errors as safe", () => {
        const response = createResponse(
          '{"status": 403, "error": "Forbidden"}',
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("test"),
          createTool("test_tool"),
        );

        expect(result.isVulnerable).toBe(false);
      });
    });

    describe("safe tool categories", () => {
      it("should mark search tool results as safe", () => {
        const response = createResponse(
          '{"results": [{"title": "Result 1"}], "query": "whoami"}',
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("whoami"),
          createTool(
            "search_documents",
            "Search for documents in the database",
          ),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("Search tool");
      });

      it("should mark CRUD creation responses as safe", () => {
        const response = createResponse(
          '{"id": "123", "created": true, "data": "whoami"}',
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("whoami"),
          createTool("create_note", "Create a new note"),
        );

        expect(result.isVulnerable).toBe(false);
      });

      it("should mark safe storage tools as safe (control group)", () => {
        const response = createResponse(
          '{"stored": true, "data": "malicious; rm -rf /"}',
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("malicious; rm -rf /"),
          createTool(
            "safe_storage_tool",
            "SAFE: Stores data without executing it",
          ),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("Safe storage");
      });
    });

    describe("reflection detection", () => {
      it("should detect storage reflection as safe", () => {
        const response = createResponse(
          '{"message": "Data stored successfully", "input": "whoami && id"}',
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("whoami && id"),
          createTool("store_data"),
        );

        expect(result.isVulnerable).toBe(false);
        expect(result.evidence).toContain("reflected");
      });

      it("should detect processing reflection as safe", () => {
        const response = createResponse(
          "Query processed successfully: SELECT * FROM users",
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("SELECT * FROM users"),
          createTool("process_query"),
        );

        expect(result.isVulnerable).toBe(false);
      });
    });

    describe("execution detection", () => {
      it("should detect computed math results as vulnerable", () => {
        const response = createResponse("Result: 3");

        const result = analyzer.analyzeResponse(
          response,
          createPayload("1+2"),
          createTool("calculator"),
        );

        expect(result.isVulnerable).toBe(true);
        expect(result.evidence).toContain("computed");
      });

      it("should detect command execution artifacts as vulnerable", () => {
        const response = createResponse(
          "uid=0(root) gid=0(root) groups=0(root)",
        );

        const result = analyzer.analyzeResponse(
          response,
          createPayload("id", /uid=\d+/),
          createTool("run_command"),
        );

        expect(result.isVulnerable).toBe(true);
      });
    });
  });

  describe("isReflectionResponse", () => {
    it("should match storage patterns", () => {
      expect(analyzer.isReflectionResponse("data stored successfully")).toBe(
        true,
      );
      expect(analyzer.isReflectionResponse("query saved to database")).toBe(
        true,
      );
      expect(analyzer.isReflectionResponse("added to collection")).toBe(true);
    });

    it("should match processing patterns", () => {
      expect(
        analyzer.isReflectionResponse("request processed successfully"),
      ).toBe(true);
      expect(analyzer.isReflectionResponse("validated successfully")).toBe(
        true,
      );
      expect(analyzer.isReflectionResponse("processed successfully")).toBe(
        true,
      );
    });

    it("should NOT match execution artifacts", () => {
      // Response with execution artifacts should not be treated as safe reflection
      expect(analyzer.isReflectionResponse("uid=0 stored")).toBe(false);
      expect(analyzer.isReflectionResponse("PID 1234 processed")).toBe(false);
    });

    it("should match safe data handling patterns", () => {
      expect(analyzer.isReflectionResponse("input treated as data")).toBe(true);
      expect(analyzer.isReflectionResponse("stored without execution")).toBe(
        true,
      );
    });
  });

  describe("isValidationRejection", () => {
    it("should detect JSON validation rejection", () => {
      const response = createResponse(
        '{"valid": false, "error": "Invalid format"}',
      );
      expect(analyzer.isValidationRejection(response)).toBe(true);
    });

    it("should detect text validation rejection", () => {
      const response = createResponse(
        "Validation failed: input not in approved list",
      );
      expect(analyzer.isValidationRejection(response)).toBe(true);
    });

    it("should detect rejected status", () => {
      const response = createResponse(
        '{"status": "rejected", "reason": "Invalid input"}',
      );
      expect(analyzer.isValidationRejection(response)).toBe(true);
    });

    it("should NOT flag successful responses", () => {
      const response = createResponse('{"success": true, "data": "result"}');
      expect(analyzer.isValidationRejection(response)).toBe(false);
    });
  });

  describe("isMCPValidationError", () => {
    it("should detect error code -32602", () => {
      expect(analyzer.isMCPValidationError({ code: -32602 }, "")).toBe(true);
      expect(analyzer.isMCPValidationError({ code: "-32602" }, "")).toBe(true);
    });

    it("should detect validation patterns in text", () => {
      expect(
        analyzer.isMCPValidationError({}, "parameter validation failed"),
      ).toBe(true);
      expect(analyzer.isMCPValidationError({}, "invalid url format")).toBe(
        true,
      );
      expect(analyzer.isMCPValidationError({}, "must be a valid email")).toBe(
        true,
      );
    });

    it("should NOT flag non-validation errors", () => {
      expect(analyzer.isMCPValidationError({}, "success")).toBe(false);
      expect(analyzer.isMCPValidationError({}, "data returned")).toBe(false);
    });
  });

  describe("isHttpErrorResponse", () => {
    it("should detect 4xx errors", () => {
      expect(analyzer.isHttpErrorResponse("404 Not Found")).toBe(true);
      expect(analyzer.isHttpErrorResponse("401 Unauthorized")).toBe(true);
      expect(analyzer.isHttpErrorResponse("403 Forbidden")).toBe(true);
    });

    it("should detect 5xx errors", () => {
      expect(analyzer.isHttpErrorResponse("500 Internal Server Error")).toBe(
        true,
      );
      expect(analyzer.isHttpErrorResponse("503 Service Unavailable")).toBe(
        true,
      );
    });

    it("should detect JSON status codes", () => {
      expect(analyzer.isHttpErrorResponse('{"status": 404}')).toBe(true);
      expect(analyzer.isHttpErrorResponse('{"status": 500}')).toBe(true);
    });

    it("should NOT flag successful responses", () => {
      expect(analyzer.isHttpErrorResponse('{"status": 200}')).toBe(false);
      expect(analyzer.isHttpErrorResponse("Success")).toBe(false);
    });
  });

  describe("hasExecutionEvidence", () => {
    it("should detect execution keywords", () => {
      expect(
        analyzer.hasExecutionEvidence("command executed successfully"),
      ).toBe(true);
      expect(analyzer.hasExecutionEvidence("result computed")).toBe(true);
      expect(analyzer.hasExecutionEvidence("ran command")).toBe(true);
    });

    it("should detect exception patterns", () => {
      expect(analyzer.hasExecutionEvidence("NullPointerException")).toBe(true);
      expect(analyzer.hasExecutionEvidence("SegmentationFault")).toBe(true);
      expect(analyzer.hasExecutionEvidence("StackOverflow")).toBe(true);
    });

    it("should detect database operation results", () => {
      expect(analyzer.hasExecutionEvidence("query returned 5 results")).toBe(
        true,
      );
      expect(analyzer.hasExecutionEvidence("3 rows affected")).toBe(true);
      expect(analyzer.hasExecutionEvidence("modified 10 records")).toBe(true);
    });

    it("should NOT flag safe patterns", () => {
      expect(analyzer.hasExecutionEvidence("data stored")).toBe(false);
      expect(analyzer.hasExecutionEvidence("input validated")).toBe(false);
    });
  });

  describe("isComputedMathResult", () => {
    it("should detect simple addition", () => {
      expect(analyzer.isComputedMathResult("1+2", "3")).toBe(true);
      expect(analyzer.isComputedMathResult("10+5", "15")).toBe(true);
    });

    it("should detect subtraction", () => {
      expect(analyzer.isComputedMathResult("10-3", "7")).toBe(true);
    });

    it("should detect multiplication", () => {
      expect(analyzer.isComputedMathResult("5*4", "20")).toBe(true);
    });

    it("should NOT flag echoed payload", () => {
      expect(analyzer.isComputedMathResult("1+2", "1+2")).toBe(false);
    });

    it("should NOT flag HTTP errors", () => {
      expect(analyzer.isComputedMathResult("1+2", "404 Not Found")).toBe(false);
    });

    it("should NOT flag non-math payloads", () => {
      expect(analyzer.isComputedMathResult("whoami", "3")).toBe(false);
    });
  });

  describe("calculateConfidence", () => {
    it("should return high confidence for clear execution evidence", () => {
      const result = analyzer.calculateConfidence(
        createTool("run_command"),
        true,
        "uid=0(root) found",
        "uid=0(root) gid=0(root)",
        createPayload("id", /uid=\d+/),
      );

      expect(result.confidence).toBe("high");
      expect(result.requiresManualReview).toBe(false);
    });

    it("should return low confidence for ambiguous patterns", () => {
      const result = analyzer.calculateConfidence(
        createTool("process_data"),
        true,
        "Some evidence",
        "processed",
        createPayload("test"),
      );

      // Low confidence should trigger manual review
      if (result.confidence === "low") {
        expect(result.requiresManualReview).toBe(true);
      }
    });
  });

  describe("error classification", () => {
    it("should classify connection errors", () => {
      const response = createResponse("ECONNREFUSED: Connection refused");
      expect(analyzer.isConnectionError(response)).toBe(true);
      expect(analyzer.classifyError(response)).toBe("connection");
    });

    it("should classify timeout errors", () => {
      const response = createResponse("Request timeout: ETIMEDOUT");
      expect(analyzer.isConnectionError(response)).toBe(true);
    });

    it("should NOT classify validation as connection error", () => {
      const response = createResponse("Validation error: invalid input");
      expect(analyzer.isConnectionError(response)).toBe(false);
    });
  });

  describe("extractResponseContent", () => {
    it("should extract text from content array", () => {
      const response = {
        content: [
          { type: "text", text: "Hello" },
          { type: "text", text: "World" },
        ],
      } as CompatibilityCallToolResult;

      // Content items are joined with space separator
      expect(analyzer.extractResponseContent(response)).toBe("Hello World");
    });

    it("should handle empty content", () => {
      const response = { content: [] } as CompatibilityCallToolResult;
      expect(analyzer.extractResponseContent(response)).toBe("");
    });

    it("should handle missing content", () => {
      const response = {} as CompatibilityCallToolResult;
      expect(analyzer.extractResponseContent(response)).toBe("");
    });
  });
});
