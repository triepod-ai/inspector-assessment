/**
 * Server Connection Unit Tests
 *
 * Tests for connectToServer() that establishes MCP server connections.
 */

import { jest, describe, it, expect, beforeEach } from "@jest/globals";

// Create mock transport classes
const mockStdioTransport = {
  stderr: {
    on: jest.fn(),
  },
};
const mockSSETransport = {};
const mockHTTPTransport = {};

const mockConnect = jest.fn<() => Promise<void>>();
const mockClient = {
  connect: mockConnect,
};

// Mock MCP SDK
jest.unstable_mockModule("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: jest.fn().mockImplementation(() => mockClient),
}));

jest.unstable_mockModule("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: jest.fn().mockImplementation(() => mockStdioTransport),
}));

jest.unstable_mockModule("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: jest.fn().mockImplementation(() => mockSSETransport),
}));

jest.unstable_mockModule(
  "@modelcontextprotocol/sdk/client/streamableHttp.js",
  () => ({
    StreamableHTTPClientTransport: jest
      .fn()
      .mockImplementation(() => mockHTTPTransport),
  }),
);

// Import after mocking
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { StdioClientTransport } =
  await import("@modelcontextprotocol/sdk/client/stdio.js");
const { SSEClientTransport } =
  await import("@modelcontextprotocol/sdk/client/sse.js");
const { StreamableHTTPClientTransport } =
  await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
const { connectToServer } =
  await import("../../lib/assessment-runner/server-connection.js");

describe("connectToServer", () => {
  beforeEach(() => {
    mockConnect.mockResolvedValue(undefined);
    mockStdioTransport.stderr.on.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    jest.unmock("@modelcontextprotocol/sdk/client/index.js");
    jest.unmock("@modelcontextprotocol/sdk/client/stdio.js");
    jest.unmock("@modelcontextprotocol/sdk/client/sse.js");
    jest.unmock("@modelcontextprotocol/sdk/client/streamableHttp.js");
  });

  describe("HTTP transport", () => {
    it("should create StreamableHTTPClientTransport for transport:http", async () => {
      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      await connectToServer(config);

      expect(StreamableHTTPClientTransport).toHaveBeenCalledWith(
        expect.any(URL),
      );
      const urlArg = (StreamableHTTPClientTransport as jest.Mock).mock
        .calls[0][0];
      expect(urlArg.toString()).toBe("http://localhost:8080/");
    });

    it('should throw "URL required for HTTP transport" when url missing', async () => {
      const config = {
        transport: "http" as const,
        url: undefined,
      };

      await expect(
        connectToServer(
          config as unknown as { transport: "http"; url: string },
        ),
      ).rejects.toThrow("URL required for HTTP transport");
    });
  });

  describe("SSE transport", () => {
    it("should create SSEClientTransport for transport:sse", async () => {
      const config = {
        transport: "sse" as const,
        url: "http://localhost:3000/events",
      };

      await connectToServer(config);

      expect(SSEClientTransport).toHaveBeenCalledWith(expect.any(URL));
      const urlArg = (SSEClientTransport as jest.Mock).mock.calls[0][0];
      expect(urlArg.toString()).toBe("http://localhost:3000/events");
    });

    it('should throw "URL required for SSE transport" when url missing', async () => {
      const config = {
        transport: "sse" as const,
        url: undefined,
      };

      await expect(
        connectToServer(config as unknown as { transport: "sse"; url: string }),
      ).rejects.toThrow("URL required for SSE transport");
    });
  });

  describe("stdio transport", () => {
    it("should create StdioClientTransport for transport:stdio", async () => {
      const config = {
        transport: "stdio" as const,
        command: "node",
        args: ["server.js"],
        env: { NODE_ENV: "test" },
        cwd: "/app",
      };

      await connectToServer(config);

      expect(StdioClientTransport).toHaveBeenCalledWith(
        expect.objectContaining({
          command: "node",
          args: ["server.js"],
          cwd: "/app",
          stderr: "pipe",
        }),
      );
    });

    it("should create StdioClientTransport when transport is undefined (default)", async () => {
      const config = {
        transport: "stdio" as const,
        command: "python",
        args: ["-m", "server"],
      };

      await connectToServer(config);

      expect(StdioClientTransport).toHaveBeenCalled();
    });

    it('should throw "Command required for stdio transport" when command missing', async () => {
      const config = {
        transport: "stdio" as const,
        command: undefined,
      };

      await expect(
        connectToServer(
          config as unknown as { transport: "stdio"; command: string },
        ),
      ).rejects.toThrow("Command required for stdio transport");
    });

    it("should pass minimal env vars plus config.env overrides", async () => {
      const originalEnv = process.env;
      process.env = { PATH: "/usr/bin", HOME: "/home/user" };

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
        env: { CUSTOM_VAR: "value" },
      };

      await connectToServer(config);

      const callArg = (StdioClientTransport as jest.Mock).mock.calls[0][0] as {
        env: Record<string, string>;
      };
      // Minimal env vars (PATH, HOME) should be present
      expect(callArg.env).toEqual(
        expect.objectContaining({
          PATH: "/usr/bin",
          HOME: "/home/user",
          CUSTOM_VAR: "value",
        }),
      );
      // NODE_ENV should default to "production" when not set
      expect(callArg.env.NODE_ENV).toBe("production");

      process.env = originalEnv;
    });

    it("should NOT pass arbitrary process.env vars (Issue #211)", async () => {
      const originalEnv = process.env;
      process.env = {
        PATH: "/usr/bin",
        HOME: "/home/user",
        SOME_RANDOM_VAR: "should-not-pass",
        ENABLE_DYNAMIC_MAPS: "true", // This caused TomTom MCP issues
        AWS_ACCESS_KEY_ID: "secret", // Sensitive vars should not leak
      };

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
        env: {},
      };

      await connectToServer(config);

      const callArg = (StdioClientTransport as jest.Mock).mock.calls[0][0] as {
        env: Record<string, string>;
      };
      // These arbitrary vars should NOT be in the env
      expect(callArg.env.SOME_RANDOM_VAR).toBeUndefined();
      expect(callArg.env.ENABLE_DYNAMIC_MAPS).toBeUndefined();
      expect(callArg.env.AWS_ACCESS_KEY_ID).toBeUndefined();
      // But essential vars should still be present
      expect(callArg.env.PATH).toBe("/usr/bin");
      expect(callArg.env.HOME).toBe("/home/user");

      process.env = originalEnv;
    });

    it("should setup stderr listener before connecting", async () => {
      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await connectToServer(config);

      // stderr.on should be called to capture error output
      expect(mockStdioTransport.stderr.on).toHaveBeenCalledWith(
        "data",
        expect.any(Function),
      );
    });
  });

  describe("Client creation", () => {
    it("should create Client with correct info", async () => {
      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      await connectToServer(config);

      expect(Client).toHaveBeenCalledWith(
        { name: "mcp-assess-full", version: "1.0.0" },
        { capabilities: {} },
      );
    });

    it("should call client.connect with transport", async () => {
      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      await connectToServer(config);

      expect(mockConnect).toHaveBeenCalledWith(mockHTTPTransport);
    });

    it("should return connected client", async () => {
      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      const result = await connectToServer(config);

      expect(result).toBe(mockClient);
    });
  });

  describe("connection error handling", () => {
    it("should include stderr in error message on connection failure", async () => {
      // Setup stderr capture
      let stderrCallback: (data: Buffer) => void = () => {};
      mockStdioTransport.stderr.on.mockImplementation(
        (event: string, cb: (data: Buffer) => void) => {
          if (event === "data") {
            stderrCallback = cb;
          }
        },
      );

      mockConnect.mockImplementation(async () => {
        // Simulate stderr output before connection failure
        stderrCallback(Buffer.from("Error: Module not found\n"));
        throw new Error("Connection refused");
      });

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: ["server.js"],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Failed to connect.*Module not found/s,
      );
    });

    it("should provide helpful context in error message", async () => {
      let stderrCallback: (data: Buffer) => void = () => {};
      mockStdioTransport.stderr.on.mockImplementation(
        (event: string, cb: (data: Buffer) => void) => {
          if (event === "data") {
            stderrCallback = cb;
          }
        },
      );

      mockConnect.mockImplementation(async () => {
        stderrCallback(Buffer.from("Missing API key"));
        throw new Error("Process exited");
      });

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(/Common causes/);
    });

    it("should throw simple error when no stderr captured", async () => {
      mockConnect.mockRejectedValue(new Error("Connection timeout"));

      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      await expect(connectToServer(config)).rejects.toThrow(
        "Failed to connect to MCP server: Connection timeout",
      );
    });
  });

  // ============================================================================
  // GAP-002: SIGKILL Detection Tests (Issue #212)
  // ============================================================================

  describe("SIGKILL detection (Issue #212)", () => {
    it('should detect SIGKILL from "exit code 137" error message', async () => {
      let stderrCallback: (data: Buffer) => void = () => {};
      mockStdioTransport.stderr.on.mockImplementation(
        (event: string, cb: (data: Buffer) => void) => {
          if (event === "data") {
            stderrCallback = cb;
          }
        },
      );

      mockConnect.mockImplementation(async () => {
        throw new Error("Process exited with exit code 137");
      });

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: ["server.js"],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Exit code 137 \(SIGKILL\) detected/,
      );
    });

    it('should detect SIGKILL from "SIGKILL" in error message', async () => {
      mockConnect.mockRejectedValue(new Error("Process killed with SIGKILL"));

      const config = {
        transport: "stdio" as const,
        command: "python",
        args: ["server.py"],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Exit code 137 \(SIGKILL\) detected/,
      );
    });

    it('should detect SIGKILL from "killed" (lowercase) in error message', async () => {
      mockConnect.mockRejectedValue(
        new Error("Server process was killed unexpectedly"),
      );

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Exit code 137 \(SIGKILL\) detected/,
      );
    });

    it("should NOT trigger SIGKILL help for regular errors", async () => {
      mockConnect.mockRejectedValue(new Error("Connection refused"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      const error = await connectToServer(config).catch((e) => e);
      expect(error.message).not.toMatch(/Exit code 137 \(SIGKILL\) detected/);
      expect(error.message).toMatch(/Failed to connect to MCP server/);
      expect(error.message).toMatch(/Common causes/);
    });

    it("should include xattr suggestion in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("exit code 137"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /xattr -d com\.apple\.quarantine/,
      );
    });

    it("should include Security & Privacy suggestion in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("Process killed with SIGKILL"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /System Preferences > Security & Privacy/,
      );
    });

    it("should mention Gatekeeper in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("exit code 137"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /macOS Gatekeeper blocked unsigned native binaries/,
      );
    });

    it("should mention native module examples in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("killed"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /canvas, sharp, better-sqlite3/,
      );
    });

    it("should mention pre-flight warnings in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("SIGKILL"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Check pre-flight warnings above for detected native modules/,
      );
    });

    it("should suggest pure JavaScript alternatives in SIGKILL error message", async () => {
      mockConnect.mockRejectedValue(new Error("exit code 137"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /jimp instead of sharp/,
      );
    });

    it("should include both stderr and SIGKILL help when process is killed", async () => {
      let stderrCallback: (data: Buffer) => void = () => {};
      mockStdioTransport.stderr.on.mockImplementation(
        (event: string, cb: (data: Buffer) => void) => {
          if (event === "data") {
            stderrCallback = cb;
          }
        },
      );

      mockConnect.mockImplementation(async () => {
        stderrCallback(Buffer.from("Loading canvas module..."));
        throw new Error("Process killed (exit code 137)");
      });

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: ["server.js"],
      };

      const error = await connectToServer(config).catch((e) => e);
      expect(error.message).toMatch(/Loading canvas module/);
      expect(error.message).toMatch(/Exit code 137 \(SIGKILL\) detected/);
      expect(error.message).toMatch(/macOS Gatekeeper/);
      expect(error.message).toMatch(/xattr/);
    });

    it("should handle SIGKILL detection for HTTP transport", async () => {
      // SIGKILL can occur during startup even for HTTP servers
      mockConnect.mockRejectedValue(
        new Error("Server startup failed: exit code 137"),
      );

      const config = {
        transport: "http" as const,
        url: "http://localhost:8080",
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Exit code 137 \(SIGKILL\) detected/,
      );
    });

    it("should handle SIGKILL detection for SSE transport", async () => {
      mockConnect.mockRejectedValue(new Error("Connection killed"));

      const config = {
        transport: "sse" as const,
        url: "http://localhost:3000/events",
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Exit code 137 \(SIGKILL\) detected/,
      );
    });

    it("should mention OOM as possible cause in SIGKILL error", async () => {
      mockConnect.mockRejectedValue(new Error("SIGKILL"));

      const config = {
        transport: "stdio" as const,
        command: "node",
        args: [],
      };

      await expect(connectToServer(config)).rejects.toThrow(
        /Out of memory during native module initialization/,
      );
    });
  });
});
