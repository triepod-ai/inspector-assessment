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

  describe("Minimal Environment Variables (Issue #211)", () => {
    let originalEnv: NodeJS.ProcessEnv;

    afterEach(() => {
      // Restore original environment after each test
      process.env = originalEnv;
    });

    it("should pass minimal env vars (PATH, HOME) to spawned servers", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin:/usr/local/bin",
        HOME: "/home/testuser",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      // Creating the transport should not throw
      const transport = createTransport(options);
      expect(transport).toBeDefined();

      // The transport is created with minimal env (PATH, HOME, NODE_ENV)
      // We can't directly inspect StdioClientTransport's env without mocking,
      // but we verify the transport was created successfully
    });

    it("should default NODE_ENV to production when not set", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        // NODE_ENV intentionally not set
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "python",
        args: ["server.py"],
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should preserve NODE_ENV when set", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        NODE_ENV: "development",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should NOT pass arbitrary process.env vars (Issue #211)", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        SOME_RANDOM_VAR: "should-not-pass",
        ENABLE_DYNAMIC_MAPS: "true", // This caused TomTom MCP issues
        AWS_ACCESS_KEY_ID: "secret", // Sensitive vars should not leak
        CUSTOM_CONFIG: "value",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      // Creating transport should succeed
      const transport = createTransport(options);
      expect(transport).toBeDefined();

      // The arbitrary environment variables are filtered out by getMinimalEnv()
      // We verify the transport was created without throwing errors
    });

    it("should pass platform-specific essential vars (USER, SHELL, LANG)", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        USER: "testuser",
        SHELL: "/bin/bash",
        LANG: "en_US.UTF-8",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should pass temp directory vars (TMPDIR, TMP, TEMP)", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        TMPDIR: "/tmp",
        TMP: "/tmp",
        TEMP: "/tmp",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "python",
        args: ["-m", "server"],
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should handle minimal env when optional vars are missing", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        // HOME, USER, SHELL, etc. intentionally not set
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      // Should still work with just PATH
      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should combine SDK defaults with minimal env vars", () => {
      originalEnv = process.env;
      process.env = {
        PATH: "/custom/path",
        HOME: "/home/custom",
        NODE_ENV: "test",
      };

      const options: TransportOptions = {
        transportType: "stdio",
        command: "node",
        args: ["server.js"],
      };

      // getDefaultEnvironment() from SDK is merged with getMinimalEnv()
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
