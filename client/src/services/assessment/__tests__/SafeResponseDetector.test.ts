/**
 * SafeResponseDetector Tests
 * Tests for safe response pattern detection
 */

import { SafeResponseDetector } from "../modules/securityTests/SafeResponseDetector";
import type { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

describe("SafeResponseDetector", () => {
  let detector: SafeResponseDetector;

  beforeEach(() => {
    detector = new SafeResponseDetector();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Helper to create mock response
  const createResponse = (text: string): CompatibilityCallToolResult => ({
    content: [{ type: "text", text }],
  });

  describe("isMCPValidationError", () => {
    it("should detect -32602 error code", () => {
      expect(detector.isMCPValidationError({ code: -32602 }, "")).toBe(true);
      expect(detector.isMCPValidationError({ code: "-32602" }, "")).toBe(true);
    });

    it("should detect validation error patterns", () => {
      expect(
        detector.isMCPValidationError({}, "parameter validation failed"),
      ).toBe(true);
      expect(detector.isMCPValidationError({}, "schema validation error")).toBe(
        true,
      );
      expect(detector.isMCPValidationError({}, "invalid url format")).toBe(
        true,
      );
      expect(detector.isMCPValidationError({}, "must be a valid email")).toBe(
        true,
      );
    });

    it("should detect required field patterns", () => {
      expect(detector.isMCPValidationError({}, "field is required")).toBe(true);
      expect(
        detector.isMCPValidationError({}, "missing required parameter"),
      ).toBe(true);
      expect(detector.isMCPValidationError({}, "cannot be empty")).toBe(true);
    });

    it("should NOT detect successful responses", () => {
      expect(detector.isMCPValidationError({}, '{"result": "success"}')).toBe(
        false,
      );
      expect(detector.isMCPValidationError({}, "Operation completed")).toBe(
        false,
      );
    });
  });

  describe("isHttpErrorResponse", () => {
    it("should detect 4xx errors", () => {
      expect(detector.isHttpErrorResponse("404 not found")).toBe(true);
      expect(detector.isHttpErrorResponse("401 unauthorized")).toBe(true);
      expect(detector.isHttpErrorResponse("403 forbidden")).toBe(true);
    });

    it("should detect 5xx errors", () => {
      expect(detector.isHttpErrorResponse("500 internal server error")).toBe(
        true,
      );
      expect(detector.isHttpErrorResponse("503 service unavailable")).toBe(
        true,
      );
    });

    it("should detect status code at start", () => {
      expect(detector.isHttpErrorResponse("404: Not Found")).toBe(true);
      expect(detector.isHttpErrorResponse("500 Server Error")).toBe(true);
    });

    it("should detect JSON status codes", () => {
      expect(detector.isHttpErrorResponse('{"status": 404}')).toBe(true);
      expect(detector.isHttpErrorResponse('{"status": 500}')).toBe(true);
    });

    it("should detect short not found responses", () => {
      expect(detector.isHttpErrorResponse("Not found")).toBe(true);
    });

    it("should NOT detect successful responses", () => {
      expect(detector.isHttpErrorResponse('{"result": "ok"}')).toBe(false);
      expect(detector.isHttpErrorResponse("200 OK")).toBe(false);
    });
  });

  describe("isReflectionResponse", () => {
    describe("storage patterns", () => {
      it("should detect stored query patterns", () => {
        expect(detector.isReflectionResponse("stored query successfully")).toBe(
          true,
        );
        expect(detector.isReflectionResponse("query stored in database")).toBe(
          true,
        );
      });

      it("should detect saved input patterns", () => {
        expect(
          detector.isReflectionResponse("saved input for processing"),
        ).toBe(true);
        expect(detector.isReflectionResponse("input saved to file")).toBe(true);
      });

      it("should detect data stored patterns", () => {
        expect(detector.isReflectionResponse("data stored safely")).toBe(true);
        expect(detector.isReflectionResponse("stored data successfully")).toBe(
          true,
        );
      });
    });

    describe("safe handling patterns", () => {
      it("should detect treated as data patterns", () => {
        expect(detector.isReflectionResponse("treated as data")).toBe(true);
        expect(detector.isReflectionResponse("stored as data")).toBe(true);
      });

      it("should detect without execution patterns", () => {
        expect(detector.isReflectionResponse("without execution")).toBe(true);
        expect(detector.isReflectionResponse("not executed")).toBe(true);
      });

      it("should detect sanitization markers", () => {
        expect(detector.isReflectionResponse("input [sanitized]")).toBe(true);
        expect(detector.isReflectionResponse("[redacted] content")).toBe(true);
        expect(detector.isReflectionResponse("value [filtered]")).toBe(true);
      });
    });

    describe("status patterns", () => {
      it("should detect action executed successfully", () => {
        expect(
          detector.isReflectionResponse("action executed successfully: test"),
        ).toBe(true);
      });

      it("should detect safe: true JSON patterns", () => {
        expect(
          detector.isReflectionResponse('{"safe": true, "message": "ok"}'),
        ).toBe(true);
      });

      it("should detect vulnerable: false patterns", () => {
        expect(
          detector.isReflectionResponse(
            '{"vulnerable": false, "stored": true}',
          ),
        ).toBe(true);
      });
    });

    describe("execution artifact exclusion", () => {
      it("should NOT detect reflection when execution artifacts present", () => {
        // passwd format indicates real execution
        expect(
          detector.isReflectionResponse(
            "stored root:x:0:0:root:/root:/bin/bash",
          ),
        ).toBe(false);
      });

      it("should NOT detect reflection with uid= output", () => {
        expect(
          detector.isReflectionResponse("stored uid=0(root) gid=0(root)"),
        ).toBe(false);
      });
    });

    describe("JSON status detection", () => {
      it("should detect test action patterns", () => {
        expect(
          detector.isReflectionResponse('{"action": "test", "result": "ok"}'),
        ).toBe(true);
      });

      it("should detect completed status", () => {
        expect(
          detector.isReflectionResponse('{"status": "completed", "data": {}}'),
        ).toBe(true);
      });
    });
  });

  describe("isSearchResultResponse", () => {
    it("should detect results array pattern", () => {
      expect(detector.isSearchResultResponse('{"results": [1, 2, 3]}')).toBe(
        true,
      );
    });

    it("should detect search type pattern", () => {
      expect(
        detector.isSearchResultResponse('{"type": "search", "data": []}'),
      ).toBe(true);
    });

    it("should detect found N results pattern", () => {
      expect(detector.isSearchResultResponse("found 5 results")).toBe(true);
      expect(detector.isSearchResultResponse("Found 10 items")).toBe(true);
    });

    it("should detect pagination patterns", () => {
      expect(detector.isSearchResultResponse('{"has_more": true}')).toBe(true);
      expect(detector.isSearchResultResponse("next_cursor: abc123")).toBe(true);
    });

    it("should NOT detect non-search responses", () => {
      expect(detector.isSearchResultResponse('{"data": "value"}')).toBe(false);
    });
  });

  describe("isCreationResponse", () => {
    it("should detect successfully created pattern", () => {
      expect(detector.isCreationResponse("successfully created")).toBe(true);
      expect(detector.isCreationResponse("database created")).toBe(true);
      expect(detector.isCreationResponse("page created")).toBe(true);
    });

    it("should detect SQL creation patterns", () => {
      expect(detector.isCreationResponse("CREATE TABLE users")).toBe(true);
      expect(detector.isCreationResponse("INSERT INTO products")).toBe(true);
    });

    it("should detect UUID patterns", () => {
      expect(
        detector.isCreationResponse(
          '{"id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}',
        ),
      ).toBe(true);
    });

    it("should detect timestamp patterns", () => {
      expect(
        detector.isCreationResponse('{"created_time": "2024-01-01"}'),
      ).toBe(true);
      expect(
        detector.isCreationResponse('{"last_edited_time": "2024-01-01"}'),
      ).toBe(true);
    });

    it("should NOT detect read-only responses", () => {
      expect(detector.isCreationResponse('{"data": "value"}')).toBe(false);
    });
  });

  describe("isValidationRejection", () => {
    describe("JSON responses", () => {
      it("should detect valid: false", () => {
        const response = createResponse('{"valid": false}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect error: true", () => {
        const response = createResponse('{"error": true}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect status: rejected", () => {
        const response = createResponse('{"status": "rejected"}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect status: invalid", () => {
        const response = createResponse('{"status": "invalid"}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect status: failed", () => {
        const response = createResponse('{"status": "failed"}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect errors array", () => {
        const response = createResponse(
          '{"errors": ["Field required", "Invalid format"]}',
        );
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect string error field", () => {
        const response = createResponse('{"error": "Invalid input"}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect result with rejection pattern", () => {
        const response = createResponse('{"result": "validation failed"}');
        expect(detector.isValidationRejection(response)).toBe(true);
      });
    });

    describe("text responses", () => {
      it("should detect validation failed", () => {
        const response = createResponse("validation failed");
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect rejected", () => {
        const response = createResponse("Request rejected");
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect not approved", () => {
        const response = createResponse("Input not approved");
        expect(detector.isValidationRejection(response)).toBe(true);
      });

      it("should detect invalid input", () => {
        const response = createResponse("invalid input provided");
        expect(detector.isValidationRejection(response)).toBe(true);
      });
    });

    describe("non-rejection responses", () => {
      it("should NOT detect successful responses", () => {
        const response = createResponse('{"result": "success"}');
        expect(detector.isValidationRejection(response)).toBe(false);
      });

      it("should NOT detect valid: true", () => {
        const response = createResponse('{"valid": true}');
        expect(detector.isValidationRejection(response)).toBe(false);
      });

      it("should NOT detect empty errors array", () => {
        const response = createResponse('{"errors": []}');
        expect(detector.isValidationRejection(response)).toBe(false);
      });
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
      expect(detector.extractResponseContent(response)).toBe("Hello World");
    });

    it("should handle string content", () => {
      const response = {
        content: "Plain text",
      } as unknown as CompatibilityCallToolResult;
      expect(detector.extractResponseContent(response)).toBe("Plain text");
    });

    it("should handle undefined content", () => {
      const response = {} as CompatibilityCallToolResult;
      expect(detector.extractResponseContent(response)).toBe("");
    });
  });
});
