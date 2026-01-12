/**
 * SecurityPatternLibrary Tests
 * Validates pattern compilation and helper functions
 */

import {
  HTTP_ERROR_PATTERNS,
  VALIDATION_ERROR_PATTERNS,
  EXECUTION_INDICATORS,
  EXECUTION_ARTIFACT_PATTERNS,
  CONNECTION_ERROR_PATTERNS,
  STATUS_PATTERNS,
  REFLECTION_PATTERNS,
  AUTH_FAIL_OPEN_PATTERNS,
  AUTH_FAIL_CLOSED_PATTERNS,
  SEARCH_RESULT_PATTERNS,
  CREATION_PATTERNS,
  ECHOED_PAYLOAD_PATTERNS,
  DATA_TOOL_PATTERNS,
  SIMPLE_MATH_PATTERN,
  COMPUTATIONAL_INDICATORS,
  STRUCTURED_DATA_FIELD_NAMES,
  matchesAny,
  isHttpError,
  hasMcpErrorPrefix,
} from "../modules/securityTests/SecurityPatternLibrary";

describe("SecurityPatternLibrary", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Pattern Compilation", () => {
    it("should compile all HTTP_ERROR_PATTERNS", () => {
      expect(HTTP_ERROR_PATTERNS.statusWithContext).toBeInstanceOf(RegExp);
      expect(HTTP_ERROR_PATTERNS.statusAtStart).toBeInstanceOf(RegExp);
      expect(HTTP_ERROR_PATTERNS.notFound).toBeInstanceOf(RegExp);
      expect(HTTP_ERROR_PATTERNS.jsonStatus).toBeInstanceOf(RegExp);
    });

    it("should compile all VALIDATION_ERROR_PATTERNS", () => {
      expect(VALIDATION_ERROR_PATTERNS.length).toBeGreaterThan(0);
      VALIDATION_ERROR_PATTERNS.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
      });
    });

    it("should compile all EXECUTION_INDICATORS", () => {
      expect(EXECUTION_INDICATORS.length).toBe(22);
      EXECUTION_INDICATORS.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
      });
    });

    it("should compile all EXECUTION_ARTIFACT_PATTERNS", () => {
      expect(EXECUTION_ARTIFACT_PATTERNS.alwaysExecution.length).toBe(11);
      expect(EXECUTION_ARTIFACT_PATTERNS.contextSensitive.length).toBe(3);
      [
        ...EXECUTION_ARTIFACT_PATTERNS.alwaysExecution,
        ...EXECUTION_ARTIFACT_PATTERNS.contextSensitive,
      ].forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
      });
    });

    it("should compile all CONNECTION_ERROR_PATTERNS", () => {
      expect(CONNECTION_ERROR_PATTERNS.unambiguous.length).toBe(17);
      expect(CONNECTION_ERROR_PATTERNS.contextual.length).toBe(7);
      expect(CONNECTION_ERROR_PATTERNS.mcpPrefix).toBeInstanceOf(RegExp);
    });

    it("should compile all STATUS_PATTERNS", () => {
      expect(STATUS_PATTERNS.length).toBe(17);
      STATUS_PATTERNS.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
      });
    });

    it("should compile all REFLECTION_PATTERNS", () => {
      expect(REFLECTION_PATTERNS.length).toBeGreaterThan(80);
      REFLECTION_PATTERNS.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
      });
    });

    it("should compile all AUTH_FAIL_OPEN_PATTERNS", () => {
      expect(AUTH_FAIL_OPEN_PATTERNS.length).toBe(11);
      AUTH_FAIL_OPEN_PATTERNS.forEach(({ pattern, evidence }) => {
        expect(pattern).toBeInstanceOf(RegExp);
        expect(typeof evidence).toBe("string");
      });
    });

    it("should compile all AUTH_FAIL_CLOSED_PATTERNS", () => {
      expect(AUTH_FAIL_CLOSED_PATTERNS.length).toBe(10);
      AUTH_FAIL_CLOSED_PATTERNS.forEach(({ pattern, evidence }) => {
        expect(pattern).toBeInstanceOf(RegExp);
        expect(typeof evidence).toBe("string");
      });
    });

    it("should compile SIMPLE_MATH_PATTERN", () => {
      expect(SIMPLE_MATH_PATTERN).toBeInstanceOf(RegExp);
    });
  });

  describe("HTTP_ERROR_PATTERNS", () => {
    it("should match 404 not found", () => {
      expect(HTTP_ERROR_PATTERNS.statusWithContext.test("404 not found")).toBe(
        true,
      );
      expect(
        HTTP_ERROR_PATTERNS.statusWithContext.test("Error 404: Page not found"),
      ).toBe(true);
    });

    it("should match 500 errors", () => {
      expect(
        HTTP_ERROR_PATTERNS.statusWithContext.test("500 internal server error"),
      ).toBe(true);
      expect(
        HTTP_ERROR_PATTERNS.statusWithContext.test("503 service unavailable"),
      ).toBe(true);
    });

    it("should match status at start", () => {
      expect(HTTP_ERROR_PATTERNS.statusAtStart.test("404: Not Found")).toBe(
        true,
      );
      expect(HTTP_ERROR_PATTERNS.statusAtStart.test("500 Error")).toBe(true);
    });

    it("should match JSON status", () => {
      expect(HTTP_ERROR_PATTERNS.jsonStatus.test('{"status": 404}')).toBe(true);
      expect(HTTP_ERROR_PATTERNS.jsonStatus.test('{"status":500}')).toBe(true);
    });

    it("should NOT match successful responses", () => {
      expect(HTTP_ERROR_PATTERNS.statusWithContext.test("200 OK")).toBe(false);
      expect(HTTP_ERROR_PATTERNS.statusAtStart.test("Success")).toBe(false);
    });
  });

  describe("VALIDATION_ERROR_PATTERNS", () => {
    it("should match MCP validation errors", () => {
      const testCases = [
        "parameter validation failed",
        "schema validation error",
        "invalid url format",
        "must be a valid email",
        "validation error: field required",
        "type mismatch: expected string",
        "field 'name' is required",
      ];

      testCases.forEach((text) => {
        expect(matchesAny(VALIDATION_ERROR_PATTERNS, text)).toBe(true);
      });
    });

    it("should NOT match successful responses", () => {
      expect(matchesAny(VALIDATION_ERROR_PATTERNS, "Success")).toBe(false);
      expect(matchesAny(VALIDATION_ERROR_PATTERNS, '{"result": "ok"}')).toBe(
        false,
      );
    });
  });

  describe("EXECUTION_INDICATORS", () => {
    it("should match execution keywords", () => {
      expect(
        matchesAny(EXECUTION_INDICATORS, "command executed successfully"),
      ).toBe(true);
      expect(matchesAny(EXECUTION_INDICATORS, "computed the result")).toBe(
        true,
      );
      expect(
        matchesAny(EXECUTION_INDICATORS, "NullPointerException at line 5"),
      ).toBe(true);
    });

    it("should match database operation results", () => {
      expect(matchesAny(EXECUTION_INDICATORS, "query returned 5 results")).toBe(
        true,
      );
      expect(matchesAny(EXECUTION_INDICATORS, "modified 3 records")).toBe(true);
      expect(matchesAny(EXECUTION_INDICATORS, "10 rows affected")).toBe(true);
    });

    it("should NOT match safe storage patterns", () => {
      expect(matchesAny(EXECUTION_INDICATORS, "data stored safely")).toBe(
        false,
      );
      expect(matchesAny(EXECUTION_INDICATORS, "query saved for later")).toBe(
        false,
      );
    });
  });

  describe("CONNECTION_ERROR_PATTERNS", () => {
    it("should match unambiguous connection errors", () => {
      expect(
        matchesAny(CONNECTION_ERROR_PATTERNS.unambiguous, "ECONNREFUSED"),
      ).toBe(true);
      expect(
        matchesAny(CONNECTION_ERROR_PATTERNS.unambiguous, "socket hang up"),
      ).toBe(true);
      expect(
        matchesAny(
          CONNECTION_ERROR_PATTERNS.unambiguous,
          "MCP error -32603: Internal error",
        ),
      ).toBe(true);
    });

    it("should match contextual patterns with MCP prefix", () => {
      const mcpError = "MCP error -32000: bad request";
      expect(hasMcpErrorPrefix(mcpError)).toBe(true);
      expect(matchesAny(CONNECTION_ERROR_PATTERNS.contextual, mcpError)).toBe(
        true,
      );
    });
  });

  describe("REFLECTION_PATTERNS", () => {
    it("should match storage patterns", () => {
      expect(matchesAny(REFLECTION_PATTERNS, "stored query successfully")).toBe(
        true,
      );
      expect(matchesAny(REFLECTION_PATTERNS, "data stored safely")).toBe(true);
      expect(matchesAny(REFLECTION_PATTERNS, "added to collection")).toBe(true);
    });

    it("should match safe handling patterns", () => {
      expect(matchesAny(REFLECTION_PATTERNS, "treated as data")).toBe(true);
      expect(matchesAny(REFLECTION_PATTERNS, "without execution")).toBe(true);
      expect(matchesAny(REFLECTION_PATTERNS, "[sanitized]")).toBe(true);
    });

    it("should match rate limiting patterns", () => {
      expect(matchesAny(REFLECTION_PATTERNS, "rate limit exceeded")).toBe(true);
      expect(matchesAny(REFLECTION_PATTERNS, "input too large")).toBe(true);
    });
  });

  describe("AUTH_FAIL_OPEN_PATTERNS", () => {
    it("should match fail-open vulnerability patterns", () => {
      const failOpenResponses = [
        '{"auth_type": "fail-open"}',
        '{"auth_status": "bypassed"}',
        "access granted despite token error",
        "authentication skipped",
      ];

      failOpenResponses.forEach((response) => {
        const matched = AUTH_FAIL_OPEN_PATTERNS.some(({ pattern }) =>
          pattern.test(response),
        );
        expect(matched).toBe(true);
      });
    });
  });

  describe("AUTH_FAIL_CLOSED_PATTERNS", () => {
    it("should match fail-closed safe patterns", () => {
      const failClosedResponses = [
        '{"auth_type": "fail-closed"}',
        '{"auth_status": "denied"}',
        "access denied",
        "authentication failed",
        "unauthorized",
      ];

      failClosedResponses.forEach((response) => {
        const matched = AUTH_FAIL_CLOSED_PATTERNS.some(({ pattern }) =>
          pattern.test(response),
        );
        expect(matched).toBe(true);
      });
    });
  });

  describe("SIMPLE_MATH_PATTERN", () => {
    it("should match simple math expressions", () => {
      expect(SIMPLE_MATH_PATTERN.test("2 + 2")).toBe(true);
      expect(SIMPLE_MATH_PATTERN.test("10 - 5")).toBe(true);
      expect(SIMPLE_MATH_PATTERN.test("3 * 4")).toBe(true);
      expect(SIMPLE_MATH_PATTERN.test("8 / 2")).toBe(true);
    });

    it("should match three-operand expressions", () => {
      expect(SIMPLE_MATH_PATTERN.test("1 + 2 + 3")).toBe(true);
      expect(SIMPLE_MATH_PATTERN.test("10 - 2 * 3")).toBe(true);
    });

    it("should capture operands and operators", () => {
      const match = "7 + 3".match(SIMPLE_MATH_PATTERN);
      expect(match).not.toBeNull();
      expect(match![1]).toBe("7");
      expect(match![2]).toBe("+");
      expect(match![3]).toBe("3");
    });

    it("should NOT match non-math expressions", () => {
      expect(SIMPLE_MATH_PATTERN.test("hello world")).toBe(false);
      expect(SIMPLE_MATH_PATTERN.test("2+")).toBe(false);
      expect(SIMPLE_MATH_PATTERN.test("SELECT * FROM")).toBe(false);
    });
  });

  describe("COMPUTATIONAL_INDICATORS", () => {
    it("should match computational language", () => {
      expect(matchesAny(COMPUTATIONAL_INDICATORS, "the answer is 42")).toBe(
        true,
      );
      expect(matchesAny(COMPUTATIONAL_INDICATORS, "result = 10")).toBe(true);
      expect(matchesAny(COMPUTATIONAL_INDICATORS, "evaluates to 5")).toBe(true);
      expect(matchesAny(COMPUTATIONAL_INDICATORS, "sum is 15")).toBe(true);
    });

    it("should NOT match data responses", () => {
      expect(matchesAny(COMPUTATIONAL_INDICATORS, '{"count": 5}')).toBe(false);
      expect(matchesAny(COMPUTATIONAL_INDICATORS, "Found 3 records")).toBe(
        false,
      );
    });
  });

  describe("Helper Functions", () => {
    describe("matchesAny", () => {
      it("should return true when any pattern matches", () => {
        const patterns = [/foo/i, /bar/i, /baz/i];
        expect(matchesAny(patterns, "FOO")).toBe(true);
        expect(matchesAny(patterns, "contains bar here")).toBe(true);
      });

      it("should return false when no pattern matches", () => {
        const patterns = [/foo/i, /bar/i];
        expect(matchesAny(patterns, "qux")).toBe(false);
      });
    });

    describe("isHttpError", () => {
      it("should detect HTTP errors", () => {
        expect(isHttpError("404 not found")).toBe(true);
        expect(isHttpError("500 internal server error")).toBe(true);
        expect(isHttpError('{"status": 403}')).toBe(true);
      });

      it("should detect short not found responses", () => {
        expect(isHttpError("not found")).toBe(true);
      });

      it("should NOT detect success responses", () => {
        expect(isHttpError("200 OK")).toBe(false);
        expect(isHttpError('{"success": true}')).toBe(false);
      });
    });

    describe("hasMcpErrorPrefix", () => {
      it("should detect MCP error prefix", () => {
        expect(hasMcpErrorPrefix("MCP error -32000: Bad request")).toBe(true);
        expect(hasMcpErrorPrefix("mcp error -32603: Internal error")).toBe(
          true,
        );
      });

      it("should NOT match non-MCP errors", () => {
        expect(hasMcpErrorPrefix("Error: Something went wrong")).toBe(false);
        expect(hasMcpErrorPrefix("404 Not Found")).toBe(false);
      });
    });
  });

  describe("Pattern Consolidation", () => {
    it("should have no duplicate HTTP error patterns", () => {
      // Previously had 3 copies - now consolidated into HTTP_ERROR_PATTERNS object
      expect(Object.keys(HTTP_ERROR_PATTERNS).length).toBe(4);
    });

    it("should have no duplicate connection error patterns", () => {
      // Previously had 2 copies - now consolidated into CONNECTION_ERROR_PATTERNS object
      expect(CONNECTION_ERROR_PATTERNS.unambiguous.length).toBe(17);
      expect(CONNECTION_ERROR_PATTERNS.contextual.length).toBe(7);
    });
  });

  describe("Pattern Counts", () => {
    it("should have expected pattern counts", () => {
      expect(VALIDATION_ERROR_PATTERNS.length).toBe(18);
      expect(EXECUTION_INDICATORS.length).toBe(22);
      expect(SEARCH_RESULT_PATTERNS.length).toBe(10);
      expect(CREATION_PATTERNS.length).toBe(13);
      expect(ECHOED_PAYLOAD_PATTERNS.length).toBe(9);
      expect(DATA_TOOL_PATTERNS.length).toBe(11);
      expect(STRUCTURED_DATA_FIELD_NAMES.length).toBe(27);
    });
  });
});
