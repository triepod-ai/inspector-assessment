/**
 * Transport Module Unit Tests
 *
 * Tests for transport creation and configuration validation.
 * Tests focus on input validation and error handling rather than
 * mocked transport implementations due to ESM limitations.
 */

import { jest, describe, it, expect, afterEach } from "@jest/globals";
import { createTransport, type TransportOptions } from "../transport.js";

describe("Transport Creation", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Input Validation", () => {
    it("should throw error when URL is missing for HTTP transport", () => {
      const options: TransportOptions = {
        transportType: "http",
      };

      expect(() => createTransport(options)).toThrow(
        /URL must be provided for SSE or HTTP transport types/,
      );
    });

    it("should throw error when URL is missing for SSE transport", () => {
      const options: TransportOptions = {
        transportType: "sse",
      };

      expect(() => createTransport(options)).toThrow(
        /URL must be provided for SSE or HTTP transport types/,
      );
    });

    it("should throw error for invalid URL format", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: ":::invalid-url",
      };

      expect(() => createTransport(options)).toThrow(
        /Failed to create transport/,
      );
    });

    it("should throw error for unsupported transport type", () => {
      const options = {
        transportType: "websocket" as "stdio" | "http" | "sse",
        url: "ws://localhost:3000",
      };

      expect(() => createTransport(options)).toThrow(
        /Unsupported transport type/,
      );
    });
  });

  describe("STDIO Transport", () => {
    it("should create transport for valid stdio options", () => {
      const options: TransportOptions = {
        transportType: "stdio",
        command: "python",
        args: ["server.py"],
      };

      // Should not throw
      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should handle missing args", () => {
      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should handle empty command", () => {
      const options: TransportOptions = {
        transportType: "stdio",
        command: "",
      };

      // Should not throw - empty command is handled by findActualExecutable
      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });
  });

  describe("HTTP Transport", () => {
    it("should create transport for valid HTTP options", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "http://localhost:3000/mcp",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should create transport with headers", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "http://localhost:3000/mcp",
        headers: {
          Authorization: "Bearer token",
        },
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should handle HTTPS URLs", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "https://api.example.com/mcp",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });
  });

  describe("SSE Transport", () => {
    it("should create transport for valid SSE options", () => {
      const options: TransportOptions = {
        transportType: "sse",
        url: "http://localhost:3000/sse",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should create transport with headers", () => {
      const options: TransportOptions = {
        transportType: "sse",
        url: "http://localhost:3000/sse",
        headers: {
          "X-API-Key": "secret",
        },
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });
  });
});

describe("TransportOptions Type", () => {
  it("should accept all valid transport types", () => {
    const stdioOptions: TransportOptions = {
      transportType: "stdio",
      command: "node",
      args: ["server.js"],
    };

    const httpOptions: TransportOptions = {
      transportType: "http",
      url: "http://localhost:3000/mcp",
    };

    const sseOptions: TransportOptions = {
      transportType: "sse",
      url: "http://localhost:3000/sse",
    };

    // Type checking - these should compile without errors
    expect(stdioOptions.transportType).toBe("stdio");
    expect(httpOptions.transportType).toBe("http");
    expect(sseOptions.transportType).toBe("sse");
  });

  it("should allow optional headers for HTTP/SSE", () => {
    const withHeaders: TransportOptions = {
      transportType: "http",
      url: "http://localhost:3000/mcp",
      headers: { "Content-Type": "application/json" },
    };

    const withoutHeaders: TransportOptions = {
      transportType: "http",
      url: "http://localhost:3000/mcp",
    };

    expect(withHeaders.headers).toBeDefined();
    expect(withoutHeaders.headers).toBeUndefined();
  });

  it("should allow optional command args", () => {
    const withArgs: TransportOptions = {
      transportType: "stdio",
      command: "python",
      args: ["-m", "server"],
    };

    const withoutArgs: TransportOptions = {
      transportType: "stdio",
      command: "python",
    };

    expect(withArgs.args).toEqual(["-m", "server"]);
    expect(withoutArgs.args).toBeUndefined();
  });
});
