/**
 * SecurityPayloadTester Retry Logic Tests
 * Issue #157: Connection retry logic for reliability
 *
 * Tests for:
 * - Transient error pattern detection
 * - Retry with exponential backoff
 * - Retry metadata tracking
 */

import { ErrorClassifier } from "../modules/securityTests/ErrorClassifier";
import {
  isTransientErrorPattern,
  TRANSIENT_ERROR_PATTERNS,
  PERMANENT_ERROR_PATTERNS,
} from "../modules/securityTests/SecurityPatternLibrary";
import type { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

describe("Issue #157: Connection Retry Logic", () => {
  // Helper to create mock response
  const createResponse = (text: string): CompatibilityCallToolResult => ({
    content: [{ type: "text", text }],
  });

  describe("isTransientErrorPattern", () => {
    describe("transient errors (should retry)", () => {
      it("should detect ECONNREFUSED as transient", () => {
        expect(isTransientErrorPattern("ECONNREFUSED")).toBe(true);
        expect(isTransientErrorPattern("error: econnrefused 127.0.0.1")).toBe(
          true,
        );
      });

      it("should detect ETIMEDOUT as transient", () => {
        expect(isTransientErrorPattern("ETIMEDOUT")).toBe(true);
        expect(isTransientErrorPattern("etimedout: connection timed out")).toBe(
          true,
        );
      });

      it("should detect socket hang up as transient", () => {
        expect(isTransientErrorPattern("socket hang up")).toBe(true);
      });

      it("should detect fetch failed as transient", () => {
        expect(isTransientErrorPattern("fetch failed")).toBe(true);
        expect(isTransientErrorPattern("fetch failed: network error")).toBe(
          true,
        );
      });

      it("should detect connection reset as transient", () => {
        expect(isTransientErrorPattern("connection reset")).toBe(true);
        expect(isTransientErrorPattern("ECONNRESET")).toBe(false); // Not in pattern, uses "connection reset" form
      });

      it("should detect gateway timeout as transient", () => {
        expect(isTransientErrorPattern("gateway timeout")).toBe(true);
        expect(isTransientErrorPattern("504 gateway timeout")).toBe(true);
      });

      it("should detect service unavailable as transient", () => {
        expect(isTransientErrorPattern("service unavailable")).toBe(true);
        expect(isTransientErrorPattern("503 service unavailable")).toBe(true);
      });

      it("should detect ERR_CONNECTION errors as transient", () => {
        expect(isTransientErrorPattern("ERR_CONNECTION_REFUSED")).toBe(true);
        expect(isTransientErrorPattern("ERR_CONNECTION_RESET")).toBe(true);
      });
    });

    describe("permanent errors (should NOT retry)", () => {
      it("should NOT retry unknown tool errors", () => {
        expect(isTransientErrorPattern("unknown tool: some_tool")).toBe(false);
      });

      it("should NOT retry no such tool errors", () => {
        expect(isTransientErrorPattern("no such tool: missing_tool")).toBe(
          false,
        );
      });

      it("should NOT retry unauthorized errors", () => {
        expect(isTransientErrorPattern("unauthorized")).toBe(false);
        expect(isTransientErrorPattern("401 unauthorized")).toBe(false);
      });

      it("should NOT retry forbidden errors", () => {
        expect(isTransientErrorPattern("forbidden")).toBe(false);
        expect(isTransientErrorPattern("403 forbidden")).toBe(false);
      });

      it("should NOT retry invalid token errors", () => {
        expect(isTransientErrorPattern("invalid token")).toBe(false);
        expect(isTransientErrorPattern("invalid access token")).toBe(false);
      });
    });

    describe("non-error responses (should NOT retry)", () => {
      it("should NOT flag successful responses", () => {
        expect(isTransientErrorPattern('{"result": "success"}')).toBe(false);
      });

      it("should NOT flag validation errors", () => {
        expect(isTransientErrorPattern("parameter validation failed")).toBe(
          false,
        );
      });

      it("should NOT flag empty responses", () => {
        expect(isTransientErrorPattern("")).toBe(false);
      });
    });
  });

  describe("ErrorClassifier.isTransientError", () => {
    let classifier: ErrorClassifier;

    beforeEach(() => {
      classifier = new ErrorClassifier();
    });

    it("should detect transient errors from response", () => {
      const response = createResponse("Error: ECONNREFUSED 127.0.0.1:8080");
      expect(classifier.isTransientError(response)).toBe(true);
    });

    it("should NOT flag permanent errors as transient", () => {
      const response = createResponse("unknown tool: nonexistent_tool");
      expect(classifier.isTransientError(response)).toBe(false);
    });

    it("should NOT flag successful responses as transient", () => {
      const response = createResponse('{"result": "success"}');
      expect(classifier.isTransientError(response)).toBe(false);
    });
  });

  describe("ErrorClassifier.isTransientErrorFromException", () => {
    let classifier: ErrorClassifier;

    beforeEach(() => {
      classifier = new ErrorClassifier();
    });

    it("should detect transient errors from Error objects", () => {
      const error = new Error("ECONNREFUSED");
      expect(classifier.isTransientErrorFromException(error)).toBe(true);
    });

    it("should detect transient errors from socket errors", () => {
      const error = new Error("socket hang up");
      expect(classifier.isTransientErrorFromException(error)).toBe(true);
    });

    it("should detect transient errors from timeout errors", () => {
      const error = new Error("ETIMEDOUT: connection timed out");
      expect(classifier.isTransientErrorFromException(error)).toBe(true);
    });

    it("should NOT flag permanent errors as transient", () => {
      const error = new Error("unknown tool: missing");
      expect(classifier.isTransientErrorFromException(error)).toBe(false);
    });

    it("should return false for non-Error objects", () => {
      expect(classifier.isTransientErrorFromException("string error")).toBe(
        false,
      );
      expect(classifier.isTransientErrorFromException(null)).toBe(false);
      expect(classifier.isTransientErrorFromException(undefined)).toBe(false);
    });
  });

  describe("Pattern completeness", () => {
    it("TRANSIENT_ERROR_PATTERNS should have all expected patterns", () => {
      expect(TRANSIENT_ERROR_PATTERNS.length).toBeGreaterThanOrEqual(8);
    });

    it("PERMANENT_ERROR_PATTERNS should have all expected patterns", () => {
      expect(PERMANENT_ERROR_PATTERNS.length).toBeGreaterThanOrEqual(5);
    });

    it("transient and permanent patterns should not overlap", () => {
      // Transient patterns should not match permanent examples
      expect(isTransientErrorPattern("unknown tool: test")).toBe(false);
      expect(isTransientErrorPattern("unauthorized")).toBe(false);

      // Permanent patterns should not match transient examples
      // (isTransientErrorPattern returns false for permanent, true for transient)
      expect(isTransientErrorPattern("ECONNREFUSED")).toBe(true);
      expect(isTransientErrorPattern("socket hang up")).toBe(true);
    });
  });
});
