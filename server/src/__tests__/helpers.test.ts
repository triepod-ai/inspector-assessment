/**
 * Server Helper Functions Unit Tests
 *
 * Tests for pure functions: is401Error, getHttpHeaders, updateHeadersInPlace
 */

import { jest, describe, it, expect } from "@jest/globals";
import {
  is401Error,
  getHttpHeaders,
  updateHeadersInPlace,
} from "../helpers.js";
import { SseError } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Request } from "express";

/**
 * Create a mock ErrorEvent for SseError constructor
 * ErrorEvent is a browser API not available in Node.js, so we create a minimal mock
 */
const createMockErrorEvent = (message = "error"): ErrorEvent => {
  // Create a minimal mock that satisfies the ErrorEvent interface
  return {
    type: "error",
    message,
    bubbles: false,
    cancelable: false,
    composed: false,
    defaultPrevented: false,
    eventPhase: 0,
    isTrusted: false,
    returnValue: true,
    srcElement: null,
    target: null,
    currentTarget: null,
    timeStamp: Date.now(),
    cancelBubble: false,
    NONE: 0,
    CAPTURING_PHASE: 1,
    AT_TARGET: 2,
    BUBBLING_PHASE: 3,
    colno: 0,
    lineno: 0,
    filename: "",
    error: null,
    composedPath: () => [],
    initEvent: () => {},
    preventDefault: () => {},
    stopImmediatePropagation: () => {},
    stopPropagation: () => {},
  } as unknown as ErrorEvent;
};

/**
 * Helper to create a mock Express request with headers
 */
const createMockRequest = (
  headers: Record<string, string | string[] | undefined>,
): Partial<Request> => ({
  headers: headers as Request["headers"],
});

describe("is401Error", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("SseError detection", () => {
    it("should return true for SseError with code 401", () => {
      const error = new SseError(401, "Unauthorized", createMockErrorEvent());
      expect(is401Error(error)).toBe(true);
    });

    it("should return false for SseError with non-401 code", () => {
      const error = new SseError(404, "Not Found", createMockErrorEvent());
      expect(is401Error(error)).toBe(false);
    });
  });

  describe("StreamableHTTPError detection", () => {
    it("should return true for StreamableHTTPError with code 401", () => {
      const error = new StreamableHTTPError(401, "Unauthorized");
      expect(is401Error(error)).toBe(true);
    });

    it("should return false for StreamableHTTPError with non-401 code", () => {
      const error = new StreamableHTTPError(500, "Internal Server Error");
      expect(is401Error(error)).toBe(false);
    });
  });

  describe("Generic Error detection", () => {
    it("should return true for Error containing 'HTTP 401'", () => {
      const error = new Error("HTTP 401 Unauthorized");
      expect(is401Error(error)).toBe(true);
    });

    it("should return true for Error containing '(401)'", () => {
      const error = new Error("Server returned (401) unauthorized");
      expect(is401Error(error)).toBe(true);
    });

    it("should return false for Error with other codes", () => {
      const error = new Error("HTTP 500 Internal Server Error");
      expect(is401Error(error)).toBe(false);
    });

    it("should return false for generic error without 401", () => {
      const error = new Error("Something went wrong");
      expect(is401Error(error)).toBe(false);
    });
  });

  describe("Non-Error values", () => {
    it("should return false for null", () => {
      expect(is401Error(null)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(is401Error(undefined)).toBe(false);
    });

    it("should return false for string", () => {
      expect(is401Error("HTTP 401")).toBe(false);
    });

    it("should return false for number", () => {
      expect(is401Error(401)).toBe(false);
    });

    it("should return false for plain object", () => {
      expect(is401Error({ code: 401 })).toBe(false);
    });
  });
});

describe("getHttpHeaders", () => {
  describe("MCP header forwarding", () => {
    it("should forward mcp-* headers", () => {
      const req = createMockRequest({
        "mcp-custom-header": "custom-value",
        "mcp-another": "another-value",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["mcp-custom-header"]).toBe("custom-value");
      expect(headers["mcp-another"]).toBe("another-value");
    });

    it("should forward authorization header", () => {
      const req = createMockRequest({
        authorization: "Bearer token123",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["authorization"]).toBe("Bearer token123");
    });

    it("should forward last-event-id header", () => {
      const req = createMockRequest({
        "last-event-id": "event-42",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["last-event-id"]).toBe("event-42");
    });
  });

  describe("Header exclusions", () => {
    it("should exclude x-mcp-proxy-auth header", () => {
      const req = createMockRequest({
        "x-mcp-proxy-auth": "Bearer secret",
        "mcp-other": "value",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["x-mcp-proxy-auth"]).toBeUndefined();
      expect(headers["mcp-other"]).toBe("value");
    });

    it("should exclude mcp-session-id header", () => {
      const req = createMockRequest({
        "mcp-session-id": "session-123",
        "mcp-other": "value",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["mcp-session-id"]).toBeUndefined();
      expect(headers["mcp-other"]).toBe("value");
    });

    it("should not forward non-mcp headers", () => {
      const req = createMockRequest({
        "content-type": "application/json",
        "x-custom-header": "value",
        host: "localhost:3000",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["content-type"]).toBeUndefined();
      expect(headers["x-custom-header"]).toBeUndefined();
      expect(headers["host"]).toBeUndefined();
    });
  });

  describe("Array header values", () => {
    it("should use last element for array header values", () => {
      const req = createMockRequest({
        "mcp-multi": ["first", "second", "last"],
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["mcp-multi"]).toBe("last");
    });

    it("should handle empty array gracefully", () => {
      const req = createMockRequest({
        "mcp-empty": [],
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["mcp-empty"]).toBeUndefined();
    });
  });

  describe("Custom auth header (x-custom-auth-header)", () => {
    it("should forward custom auth header when specified", () => {
      const req = createMockRequest({
        "x-custom-auth-header": "X-API-Key",
        "x-api-key": "secret-key-123",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["X-API-Key"]).toBe("secret-key-123");
    });

    it("should handle array values for custom auth header", () => {
      const req = createMockRequest({
        "x-custom-auth-header": "X-Token",
        "x-token": ["old-token", "new-token"],
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["X-Token"]).toBe("new-token");
    });

    it("should ignore if custom auth header value not present", () => {
      const req = createMockRequest({
        "x-custom-auth-header": "X-Missing",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["X-Missing"]).toBeUndefined();
    });
  });

  describe("Multiple custom headers (x-custom-auth-headers)", () => {
    it("should forward multiple custom headers from JSON array", () => {
      const req = createMockRequest({
        "x-custom-auth-headers": JSON.stringify(["X-API-Key", "X-Client-ID"]),
        "x-api-key": "api-key-value",
        "x-client-id": "client-123",
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["X-API-Key"]).toBe("api-key-value");
      expect(headers["X-Client-ID"]).toBe("client-123");
    });

    it("should handle array values in custom headers", () => {
      const req = createMockRequest({
        "x-custom-auth-headers": JSON.stringify(["X-Token"]),
        "x-token": ["first", "second"],
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["X-Token"]).toBe("second");
    });

    it("should handle malformed JSON gracefully", () => {
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});
      const req = createMockRequest({
        "x-custom-auth-headers": "not-valid-json",
      });
      const headers = getHttpHeaders(req as Request);
      expect(consoleSpy).toHaveBeenCalled();
      expect(Object.keys(headers)).toHaveLength(0);
      consoleSpy.mockRestore();
    });

    it("should ignore non-array JSON values", () => {
      const req = createMockRequest({
        "x-custom-auth-headers": JSON.stringify({ key: "value" }),
      });
      // Should not throw, just not add any headers
      const headers = getHttpHeaders(req as Request);
      expect(headers).toEqual({});
    });
  });

  describe("Empty and undefined values", () => {
    it("should handle empty request headers", () => {
      const req = createMockRequest({});
      const headers = getHttpHeaders(req as Request);
      expect(headers).toEqual({});
    });

    it("should skip undefined header values", () => {
      const req = createMockRequest({
        "mcp-defined": "value",
        "mcp-undefined": undefined,
      });
      const headers = getHttpHeaders(req as Request);
      expect(headers["mcp-defined"]).toBe("value");
      expect(headers["mcp-undefined"]).toBeUndefined();
    });
  });
});

describe("updateHeadersInPlace", () => {
  it("should replace all headers with new ones", () => {
    const current: Record<string, string> = {
      "Old-Header": "old-value",
      Another: "another",
    };
    const updated: Record<string, string> = { "New-Header": "new-value" };
    updateHeadersInPlace(current, updated);
    expect(current).toEqual({ "New-Header": "new-value" });
    expect(current["Old-Header"]).toBeUndefined();
  });

  it("should preserve Accept header when present", () => {
    const current: Record<string, string> = {
      Accept: "text/event-stream",
      "Old-Header": "old",
    };
    const updated: Record<string, string> = { "New-Header": "new" };
    updateHeadersInPlace(current, updated);
    expect(current).toEqual({
      Accept: "text/event-stream",
      "New-Header": "new",
    });
  });

  it("should not add Accept header if not originally present", () => {
    const current: Record<string, string> = { "Old-Header": "old" };
    const updated: Record<string, string> = { "New-Header": "new" };
    updateHeadersInPlace(current, updated);
    expect(current).toEqual({ "New-Header": "new" });
    expect(current["Accept"]).toBeUndefined();
  });

  it("should handle empty current headers", () => {
    const current: Record<string, string> = {};
    const updated: Record<string, string> = { "New-Header": "new" };
    updateHeadersInPlace(current, updated);
    expect(current).toEqual({ "New-Header": "new" });
  });

  it("should handle empty new headers", () => {
    const current: Record<string, string> = { "Old-Header": "old" };
    const updated: Record<string, string> = {};
    updateHeadersInPlace(current, updated);
    expect(current).toEqual({});
  });

  it("should preserve Accept even when updating with new Accept", () => {
    const current: Record<string, string> = {
      Accept: "original-accept",
      Other: "value",
    };
    const updated: Record<string, string> = {
      Accept: "new-accept",
      "New-Header": "new",
    };
    updateHeadersInPlace(current, updated);
    // New Accept from updated is applied, then original Accept is restored
    expect(current["Accept"]).toBe("original-accept");
    expect(current["New-Header"]).toBe("new");
  });

  it("should mutate the original object reference", () => {
    const current: Record<string, string> = { Header: "value" };
    const originalRef = current;
    updateHeadersInPlace(current, { New: "value" });
    expect(current).toBe(originalRef);
    expect(originalRef["New"]).toBe("value");
  });
});
