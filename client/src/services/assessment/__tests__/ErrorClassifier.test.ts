/**
 * ErrorClassifier Tests
 * Tests for error classification and connection error detection
 */

import { ErrorClassifier } from "../modules/securityTests/ErrorClassifier";
import type { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

describe("ErrorClassifier", () => {
  let classifier: ErrorClassifier;

  beforeEach(() => {
    classifier = new ErrorClassifier();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Helper to create mock response
  const createResponse = (text: string): CompatibilityCallToolResult => ({
    content: [{ type: "text", text }],
  });

  describe("isConnectionError", () => {
    it("should detect ECONNREFUSED", () => {
      const response = createResponse("Error: ECONNREFUSED 127.0.0.1:8080");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should detect socket hang up", () => {
      const response = createResponse("socket hang up");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should detect ETIMEDOUT", () => {
      const response = createResponse("ETIMEDOUT: connection timed out");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should detect fetch failed", () => {
      const response = createResponse("fetch failed: network error");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should detect MCP error codes", () => {
      const response1 = createResponse("MCP error -32603: Internal error");
      const response2 = createResponse("MCP error -32001: Method not found");
      const response3 = createResponse("MCP error -32000: Server error");

      expect(classifier.isConnectionError(response1)).toBe(true);
      expect(classifier.isConnectionError(response2)).toBe(true);
      expect(classifier.isConnectionError(response3)).toBe(true);
    });

    it("should detect unknown tool errors", () => {
      const response = createResponse("unknown tool: some_tool");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should detect contextual patterns with MCP prefix", () => {
      const response = createResponse("MCP error -32600: bad request");
      expect(classifier.isConnectionError(response)).toBe(true);
    });

    it("should NOT flag successful responses", () => {
      const response = createResponse('{"result": "success"}');
      expect(classifier.isConnectionError(response)).toBe(false);
    });

    it("should NOT flag validation errors as connection errors", () => {
      const response = createResponse("parameter validation failed");
      expect(classifier.isConnectionError(response)).toBe(false);
    });
  });

  describe("isConnectionErrorFromException", () => {
    it("should detect connection errors from Error objects", () => {
      const error = new Error("ECONNREFUSED");
      expect(classifier.isConnectionErrorFromException(error)).toBe(true);
    });

    it("should detect socket hang up from exceptions", () => {
      const error = new Error("socket hang up");
      expect(classifier.isConnectionErrorFromException(error)).toBe(true);
    });

    it("should detect MCP errors from exceptions", () => {
      const error = new Error("MCP error -32603: Internal error");
      expect(classifier.isConnectionErrorFromException(error)).toBe(true);
    });

    it("should return false for non-Error values", () => {
      expect(classifier.isConnectionErrorFromException("string error")).toBe(
        false,
      );
      expect(classifier.isConnectionErrorFromException(null)).toBe(false);
      expect(classifier.isConnectionErrorFromException(undefined)).toBe(false);
    });

    it("should NOT flag validation errors from exceptions", () => {
      const error = new Error("validation failed");
      expect(classifier.isConnectionErrorFromException(error)).toBe(false);
    });
  });

  describe("classifyError", () => {
    it('should classify connection errors as "connection"', () => {
      const responses = [
        createResponse("socket hang up"),
        createResponse("ECONNREFUSED"),
        createResponse("ETIMEDOUT"),
        createResponse("fetch failed"),
        createResponse("connection reset"),
      ];

      responses.forEach((response) => {
        expect(classifier.classifyError(response)).toBe("connection");
      });
    });

    it('should classify server errors as "server"', () => {
      const responses = [
        createResponse("MCP error -32603: Internal error"),
        createResponse("internal server error"),
        createResponse("service unavailable"),
        createResponse("gateway timeout"),
        createResponse("HTTP 500"),
        createResponse("error POSTing to endpoint"),
        createResponse("bad request"),
        createResponse("unauthorized"),
      ];

      responses.forEach((response) => {
        expect(classifier.classifyError(response)).toBe("server");
      });
    });

    it('should classify protocol errors as "protocol"', () => {
      const response = createResponse("MCP error -32001: Method not found");
      expect(classifier.classifyError(response)).toBe("protocol");
    });

    it('should default to "protocol" for unknown errors', () => {
      const response = createResponse("some random error text");
      expect(classifier.classifyError(response)).toBe("protocol");
    });
  });

  describe("classifyErrorFromException", () => {
    it('should classify connection errors as "connection"', () => {
      const errors = [
        new Error("socket hang up"),
        new Error("ECONNREFUSED"),
        new Error("ETIMEDOUT"),
        new Error("network error"),
      ];

      errors.forEach((error) => {
        expect(classifier.classifyErrorFromException(error)).toBe("connection");
      });
    });

    it('should classify server errors as "server"', () => {
      const errors = [
        new Error("MCP error -32603: Internal error"),
        new Error("internal server error"),
        new Error("HTTP 500"),
      ];

      errors.forEach((error) => {
        expect(classifier.classifyErrorFromException(error)).toBe("server");
      });
    });

    it('should return "protocol" for non-Error values', () => {
      expect(classifier.classifyErrorFromException("string")).toBe("protocol");
      expect(classifier.classifyErrorFromException(null)).toBe("protocol");
    });
  });

  describe("extractErrorInfo", () => {
    it("should extract error info from JSON error response", () => {
      const response = createResponse(
        JSON.stringify({
          error: {
            code: -32602,
            message: "Invalid params",
          },
        }),
      );

      const info = classifier.extractErrorInfo(response);
      expect(info.code).toBe(-32602);
      expect(info.message).toBe("Invalid params");
    });

    it("should extract error info from flat JSON", () => {
      const response = createResponse(
        JSON.stringify({
          code: 404,
          message: "Not found",
        }),
      );

      const info = classifier.extractErrorInfo(response);
      expect(info.code).toBe(404);
      expect(info.message).toBe("Not found");
    });

    it("should extract error info from MCP error text format", () => {
      const response = createResponse("MCP error -32602: Invalid params");

      const info = classifier.extractErrorInfo(response);
      expect(info.code).toBe(-32602);
      expect(info.message).toBe("Invalid params");
    });

    it("should return empty object for non-error responses", () => {
      const response = createResponse("Success");
      const info = classifier.extractErrorInfo(response);
      expect(info).toEqual({});
    });
  });

  describe("extractResponseContent", () => {
    it("should extract text from content array", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          { type: "text", text: "Hello" },
          { type: "text", text: "World" },
        ],
      };

      expect(classifier.extractResponseContent(response)).toBe("Hello World");
    });

    it("should handle non-text content types", () => {
      const response: CompatibilityCallToolResult = {
        content: [
          { type: "text", text: "Text" },
          { type: "image", text: undefined } as unknown as {
            type: string;
            text?: string;
          },
        ],
      };

      expect(classifier.extractResponseContent(response)).toBe("Text ");
    });

    it("should handle string content", () => {
      const response = {
        content: "Plain string content",
      } as unknown as CompatibilityCallToolResult;

      expect(classifier.extractResponseContent(response)).toBe(
        "Plain string content",
      );
    });

    it("should handle undefined content", () => {
      const response = {} as CompatibilityCallToolResult;
      expect(classifier.extractResponseContent(response)).toBe("");
    });
  });
});
