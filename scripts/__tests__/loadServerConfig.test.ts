/**
 * loadServerConfig Unit Tests
 *
 * Tests for the server configuration loading function in run-security-assessment.ts.
 * Validates flat configs, nested mcpServers format, and error handling.
 *
 * Uses jest.unstable_mockModule for proper ESM mocking.
 */

import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import * as os from "os";
import * as path from "path";

// Create mock functions BEFORE setting up the mock module
const mockExistsSync = jest.fn<(path: string) => boolean>();
const mockReadFileSync = jest.fn<(path: string, encoding: string) => string>();

// Use unstable_mockModule for ESM - must be before dynamic import
jest.unstable_mockModule("fs", () => ({
  existsSync: mockExistsSync,
  readFileSync: mockReadFileSync,
}));

// Dynamic import AFTER mock setup - this is required for ESM mocking
const { loadServerConfig } = await import("../run-security-assessment.js");

describe("loadServerConfig", () => {
  beforeEach(() => {
    // Default: config file exists
    mockExistsSync.mockReturnValue(true);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  afterAll(() => {
    jest.unmock("fs");
  });

  // ============================================================================
  // Flat Config Format Tests
  // ============================================================================

  describe("flat config format", () => {
    it("should load stdio config with command and args", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          command: "python",
          args: ["server.py", "--port", "8080"],
          env: { DEBUG: "true" },
        }),
      );

      const config = loadServerConfig("test-server", "/tmp/config.json");

      expect(config.transport).toBe("stdio");
      expect(config.command).toBe("python");
      expect(config.args).toEqual(["server.py", "--port", "8080"]);
      expect(config.env).toEqual({ DEBUG: "true" });
    });

    it("should load HTTP config", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "http",
          url: "http://localhost:3000/mcp",
        }),
      );

      const config = loadServerConfig("test-server", "/tmp/config.json");

      expect(config.transport).toBe("http");
      expect(config.url).toBe("http://localhost:3000/mcp");
    });

    it("should load SSE config", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "sse",
          url: "http://localhost:3000/sse",
        }),
      );

      const config = loadServerConfig("test-server", "/tmp/config.json");

      expect(config.transport).toBe("sse");
      expect(config.url).toBe("http://localhost:3000/sse");
    });

    it("should default transport to http when url is present but transport not specified", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          url: "http://localhost:3000/mcp",
        }),
      );

      const config = loadServerConfig("test-server", "/tmp/config.json");

      expect(config.transport).toBe("http");
      expect(config.url).toBe("http://localhost:3000/mcp");
    });

    it("should default args and env to empty when not provided", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          command: "node",
        }),
      );

      const config = loadServerConfig("test-server", "/tmp/config.json");

      expect(config.transport).toBe("stdio");
      expect(config.command).toBe("node");
      expect(config.args).toEqual([]);
      expect(config.env).toEqual({});
    });
  });

  // ============================================================================
  // Nested mcpServers Format Tests (Claude Desktop config)
  // ============================================================================

  describe("nested mcpServers format", () => {
    it("should extract server config from mcpServers", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            "my-server": {
              command: "python",
              args: ["mcp-server.py"],
            },
          },
        }),
      );

      const config = loadServerConfig("my-server", "/tmp/config.json");

      expect(config.transport).toBe("stdio");
      expect(config.command).toBe("python");
      expect(config.args).toEqual(["mcp-server.py"]);
    });

    it("should handle HTTP transport in mcpServers", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            "http-server": {
              transport: "http",
              url: "http://localhost:10900/mcp",
            },
          },
        }),
      );

      const config = loadServerConfig("http-server", "/tmp/config.json");

      expect(config.transport).toBe("http");
      expect(config.url).toBe("http://localhost:10900/mcp");
    });

    it("should throw helpful error when server not found in mcpServers", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            "server-a": { command: "python" },
            "server-b": { command: "node" },
          },
        }),
      );

      expect(() =>
        loadServerConfig("missing-server", "/tmp/config.json"),
      ).toThrow(
        "Server 'missing-server' not found in mcpServers. Available: server-a, server-b",
      );
    });

    it("should throw error listing all available servers when server not found", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            alpha: { command: "cmd1" },
            beta: { command: "cmd2" },
            gamma: { command: "cmd3" },
          },
        }),
      );

      expect(() => loadServerConfig("delta", "/tmp/config.json")).toThrow(
        /Available: alpha, beta, gamma/,
      );
    });
  });

  // ============================================================================
  // Error Handling Tests
  // ============================================================================

  describe("error handling", () => {
    it("should throw when config file not found", () => {
      mockExistsSync.mockReturnValue(false);

      expect(() =>
        loadServerConfig("test-server", "/tmp/missing-config.json"),
      ).toThrow("Server config not found: /tmp/missing-config.json");
    });

    it("should throw when JSON is invalid", () => {
      mockReadFileSync.mockReturnValue("{ invalid json }");

      expect(() =>
        loadServerConfig("test-server", "/tmp/config.json"),
      ).toThrow(); // JSON.parse will throw
    });

    it("should throw when HTTP transport missing url", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "http",
          // url is missing
        }),
      );

      expect(() => loadServerConfig("test-server", "/tmp/config.json")).toThrow(
        "Invalid server config: transport is 'http' but 'url' is missing",
      );
    });

    it("should throw when SSE transport missing url", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "sse",
          // url is missing
        }),
      );

      expect(() => loadServerConfig("test-server", "/tmp/config.json")).toThrow(
        "Invalid server config: transport is 'sse' but 'url' is missing",
      );
    });

    it("should throw when missing both command and url", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          args: ["some-arg"], // Only args, no command or url
        }),
      );

      expect(() => loadServerConfig("test-server", "/tmp/config.json")).toThrow(
        "Invalid server config: missing 'command' or 'url' field",
      );
    });
  });

  // ============================================================================
  // Default Config Path Tests
  // ============================================================================

  describe("default config path", () => {
    it("should use default path when configPath not provided", () => {
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          command: "python",
          args: ["server.py"],
        }),
      );

      loadServerConfig("my-mcp-server");

      // Should check for ~/.config/mcp/servers/my-mcp-server.json
      const expectedPath = path.join(
        os.homedir(),
        ".config",
        "mcp",
        "servers",
        "my-mcp-server.json",
      );
      expect(mockExistsSync).toHaveBeenCalledWith(expectedPath);
    });
  });
});
