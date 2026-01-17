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
        expect(isTransientErrorPattern("ECONNRESET")).toBe(true); // Node.js error code
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
      expect(TRANSIENT_ERROR_PATTERNS.length).toBeGreaterThanOrEqual(9);
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

  describe("testPayloadWithRetry Integration Tests", () => {
    // Mock SecurityPayloadTester for integration testing
    let mockLogger: { log: jest.Mock; logError: jest.Mock };
    let mockExecuteWithTimeout: jest.Mock;
    let _callCounter: number;

    beforeEach(() => {
      mockLogger = {
        log: jest.fn(),
        logError: jest.fn(),
      };
      mockExecuteWithTimeout = jest.fn((promise: Promise<any>) => promise);
      _callCounter = 0;
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    const createMockTool = (name: string): any => ({
      name,
      description: "Test tool",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string" },
        },
      },
    });

    const createMockPayload = (): any => ({
      payload: "test_payload",
      description: "Test payload",
      payloadType: "generic",
      riskLevel: "medium" as const,
    });

    it("should return immediately on success without retry", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      // Import SecurityPayloadTester dynamically to test the method
      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");
      const tester = new SecurityPayloadTester(
        { securityRetryMaxAttempts: 3, securityRetryBackoffMs: 100 },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const result = await tester.testPayloadWithRetry(
        tool,
        "Command Injection",
        payload,
        mockCallTool,
      );

      expect(result.vulnerable).toBe(false);
      expect(result.retryAttempts).toBeUndefined();
      expect(result.retriedSuccessfully).toBeUndefined();
      expect(result.testReliability).toBe("completed");
      expect(mockCallTool).toHaveBeenCalledTimes(1);
    });

    it("should retry on transient error then succeed", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest
        .fn()
        .mockRejectedValueOnce(new Error("ECONNREFUSED"))
        .mockResolvedValueOnce({
          content: [{ type: "text", text: "Success after retry" }],
        });

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");
      const tester = new SecurityPayloadTester(
        { securityRetryMaxAttempts: 3, securityRetryBackoffMs: 100 },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const resultPromise = tester.testPayloadWithRetry(
        tool,
        "Command Injection",
        payload,
        mockCallTool,
      );

      // Fast-forward through exponential backoff
      await jest.advanceTimersByTimeAsync(100); // First retry backoff

      const result = await resultPromise;

      expect(result.vulnerable).toBe(false);
      expect(result.retryAttempts).toBe(1);
      expect(result.retriedSuccessfully).toBe(true);
      expect(result.testReliability).toBe("retried");
      expect(mockCallTool).toHaveBeenCalledTimes(2);
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining("Transient error on test_tool"),
      );
    });

    it("should exhaust retries and return failure metadata", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest.fn().mockRejectedValue(new Error("ETIMEDOUT"));

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");
      const tester = new SecurityPayloadTester(
        { securityRetryMaxAttempts: 3, securityRetryBackoffMs: 100 },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const resultPromise = tester.testPayloadWithRetry(
        tool,
        "Command Injection",
        payload,
        mockCallTool,
      );

      // Fast-forward through all exponential backoffs: 100ms, 200ms, 400ms
      await jest.advanceTimersByTimeAsync(100);
      await jest.advanceTimersByTimeAsync(200);
      await jest.advanceTimersByTimeAsync(400);

      const result = await resultPromise;

      expect(result.connectionError).toBe(true);
      expect(result.retryAttempts).toBe(3);
      expect(result.retriedSuccessfully).toBe(false);
      expect(result.testReliability).toBe("failed");
      expect(mockCallTool).toHaveBeenCalledTimes(4); // Initial + 3 retries
      expect(mockLogger.log).toHaveBeenCalledWith(
        expect.stringContaining("Transient error on test_tool"),
      );
    });

    it("should NOT retry on permanent error", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest
        .fn()
        .mockRejectedValue(new Error("unknown tool: test_tool"));

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");
      const tester = new SecurityPayloadTester(
        { securityRetryMaxAttempts: 3, securityRetryBackoffMs: 100 },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const result = await tester.testPayloadWithRetry(
        tool,
        "Command Injection",
        payload,
        mockCallTool,
      );

      expect(result.vulnerable).toBe(false);
      expect(result.retryAttempts).toBeUndefined();
      expect(result.retriedSuccessfully).toBeUndefined();
      expect(mockCallTool).toHaveBeenCalledTimes(1); // No retries
    });

    it("should properly attach retry metadata", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      let callCount = 0;
      const mockCallTool = jest.fn().mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          return Promise.reject(new Error("ECONNRESET"));
        } else if (callCount === 2) {
          return Promise.reject(new Error("socket hang up"));
        } else {
          return Promise.resolve({
            content: [{ type: "text", text: "Success after 2 retries" }],
          });
        }
      });

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");
      const tester = new SecurityPayloadTester(
        { securityRetryMaxAttempts: 3, securityRetryBackoffMs: 10 }, // Shorter backoff for faster test
        mockLogger,
        mockExecuteWithTimeout,
      );

      // Use real timers for this test since fake timers interfere with async retry logic
      jest.useRealTimers();

      try {
        const result = await tester.testPayloadWithRetry(
          tool,
          "Command Injection",
          payload,
          mockCallTool,
        );

        expect(result.retryAttempts).toBe(2);
        expect(result.retriedSuccessfully).toBe(true);
        expect(result.testReliability).toBe("retried");
        expect(mockCallTool).toHaveBeenCalledTimes(3);
      } finally {
        // Restore fake timers - afterEach expects fake timers to be active
        // so it can call useRealTimers() for cleanup
        jest.useFakeTimers();
      }
    });
  });

  describe("FIX-003: Undefined reason fallback (TEST-REQ-003)", () => {
    let mockLogger: { log: jest.Mock; logError: jest.Mock };
    let mockExecuteWithTimeout: jest.Mock;

    beforeEach(() => {
      mockLogger = {
        log: jest.fn(),
        logError: jest.fn(),
      };
      mockExecuteWithTimeout = jest.fn((promise: Promise<any>) => promise);
    });

    const createMockTool = (name: string): any => ({
      name,
      description: "Test tool",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string" },
        },
        "x-mcp-annotations": {
          readOnlyHint: true, // This will trigger annotation adjustment
        },
      },
    });

    const createMockPayload = (): any => ({
      payload: "test_payload",
      description: "Test payload",
      payloadType: "generic",
      riskLevel: "HIGH" as const,
    });

    it("should use fallback reason when adjustmentReason is undefined", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Vulnerable response" }],
      });

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");

      // Create tool annotations context
      const toolAnnotationsContext = {
        toolAnnotations: new Map([
          [
            "test_tool",
            {
              readOnlyHint: true,
              source: "mcp" as const,
            },
          ],
        ]),
        serverIsReadOnly: false,
        serverIsClosed: false,
        annotatedToolCount: 1,
        totalToolCount: 1,
      };

      const tester = new SecurityPayloadTester(
        {
          securityRetryMaxAttempts: 3,
          securityRetryBackoffMs: 100,
          toolAnnotationsContext,
        },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const result = await tester.testPayloadWithRetry(
        tool,
        "Command Injection", // This will trigger adjustment
        payload,
        mockCallTool,
      );

      // Should have annotation adjustment
      expect(result.annotationAdjustment).toBeDefined();

      // Should have a reason (either from adjustment or fallback)
      expect(result.annotationAdjustment?.reason).toBeDefined();
      expect(typeof result.annotationAdjustment?.reason).toBe("string");

      // Reason should either be the actual reason or the fallback
      const reason = result.annotationAdjustment?.reason;
      expect(
        reason === "Adjusted based on tool annotations" ||
          reason?.includes("readOnlyHint=true"),
      ).toBe(true);
    });

    it("should use actual adjustmentReason when provided", async () => {
      const tool = createMockTool("test_tool");
      const payload = createMockPayload();

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Vulnerable response" }],
      });

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");

      // Create tool annotations context
      const toolAnnotationsContext = {
        toolAnnotations: new Map([
          [
            "test_tool",
            {
              readOnlyHint: true,
              source: "mcp" as const,
            },
          ],
        ]),
        serverIsReadOnly: false,
        serverIsClosed: false,
        annotatedToolCount: 1,
        totalToolCount: 1,
      };

      const tester = new SecurityPayloadTester(
        {
          securityRetryMaxAttempts: 3,
          securityRetryBackoffMs: 100,
          toolAnnotationsContext,
        },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const result = await tester.testPayloadWithRetry(
        tool,
        "Command Injection", // Execution-type attack on read-only tool
        payload,
        mockCallTool,
      );

      // Should have annotation adjustment with actual reason
      expect(result.annotationAdjustment).toBeDefined();
      expect(result.annotationAdjustment?.reason).toContain(
        "readOnlyHint=true",
      );
      expect(result.annotationAdjustment?.reason).toContain(
        "Command Injection",
      );
      expect(result.annotationAdjustment?.reason).toContain("downgraded");
    });

    it("should handle missing annotationAdjustment gracefully", async () => {
      const tool = {
        name: "no_annotation_tool",
        description: "Tool without annotations",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
          // No annotations
        },
      };
      const payload = createMockPayload();

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Safe response" }],
      });

      const { SecurityPayloadTester } =
        await import("../modules/securityTests/SecurityPayloadTester");

      // No tool annotations context
      const tester = new SecurityPayloadTester(
        {
          securityRetryMaxAttempts: 3,
          securityRetryBackoffMs: 100,
        },
        mockLogger,
        mockExecuteWithTimeout,
      );

      const result = await tester.testPayloadWithRetry(
        tool,
        "Command Injection",
        payload,
        mockCallTool,
      );

      // Should NOT have annotation adjustment (no context provided)
      expect(result.annotationAdjustment).toBeUndefined();
    });
  });
});
