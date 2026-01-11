/**
 * Server Config Unit Tests
 *
 * Tests for loadServerConfig() that loads MCP server configuration.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import * as os from "os";
import * as path from "path";

// Mock fs module
jest.unstable_mockModule("fs", () => ({
  existsSync: jest.fn(),
  readFileSync: jest.fn(),
}));

// Import after mocking
const fs = await import("fs");
const { loadServerConfig } =
  await import("../../lib/assessment-runner/server-config.js");

describe("loadServerConfig", () => {
  const mockExistsSync = fs.existsSync as jest.Mock;
  const mockReadFileSync = fs.readFileSync as jest.Mock;
  const homedir = os.homedir();

  beforeEach(() => {
    jest.clearAllMocks();
    mockExistsSync.mockReturnValue(false);
  });

  describe("config path resolution", () => {
    it("should search explicit configPath first when provided", () => {
      const configPath = "/custom/path/config.json";
      mockExistsSync.mockImplementation((p: string) => p === configPath);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            myserver: { command: "node", args: ["server.js"] },
          },
        }),
      );

      const result = loadServerConfig("myserver", configPath);

      expect(mockExistsSync).toHaveBeenCalledWith(configPath);
      expect(result.transport).toBe("stdio");
      expect(result.command).toBe("node");
    });

    it("should search ~/.config/mcp/servers/{serverName}.json", () => {
      const expectedPath = path.join(
        homedir,
        ".config",
        "mcp",
        "servers",
        "testserver.json",
      );
      mockExistsSync.mockImplementation((p: string) => p === expectedPath);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          command: "python",
          args: ["-m", "server"],
        }),
      );

      const result = loadServerConfig("testserver");

      expect(mockExistsSync).toHaveBeenCalledWith(expectedPath);
      expect(result.command).toBe("python");
    });

    it("should search ~/.config/claude/claude_desktop_config.json", () => {
      const claudePath = path.join(
        homedir,
        ".config",
        "claude",
        "claude_desktop_config.json",
      );
      mockExistsSync.mockImplementation((p: string) => p === claudePath);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            myserver: { command: "npx", args: ["-y", "@example/server"] },
          },
        }),
      );

      const result = loadServerConfig("myserver");

      expect(mockExistsSync).toHaveBeenCalledWith(claudePath);
      expect(result.command).toBe("npx");
    });
  });

  describe("stdio transport configuration", () => {
    it("should return stdio config from mcpServers.{name}.command", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            testserver: {
              command: "node",
              args: ["index.js", "--port", "3000"],
              env: { NODE_ENV: "production" },
              cwd: "/app",
            },
          },
        }),
      );

      const result = loadServerConfig("testserver", "/config.json");

      expect(result).toEqual({
        transport: "stdio",
        command: "node",
        args: ["index.js", "--port", "3000"],
        env: { NODE_ENV: "production" },
        cwd: "/app",
      });
    });

    it("should return stdio config from root-level command", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          command: "python",
          args: ["server.py"],
        }),
      );

      const result = loadServerConfig("anyserver", "/server-config.json");

      expect(result).toEqual({
        transport: "stdio",
        command: "python",
        args: ["server.py"],
        env: {},
      });
    });

    it("should default args and env to empty when not provided", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            simple: { command: "simple-server" },
          },
        }),
      );

      const result = loadServerConfig("simple", "/config.json");

      expect(result.args).toEqual([]);
      expect(result.env).toEqual({});
    });
  });

  describe("http transport configuration", () => {
    it("should return http config from mcpServers with transport:http", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            httpserver: {
              transport: "http",
              url: "http://localhost:8080",
            },
          },
        }),
      );

      const result = loadServerConfig("httpserver", "/config.json");

      expect(result).toEqual({
        transport: "http",
        url: "http://localhost:8080",
      });
    });

    it("should return http config when only url is specified (infer http)", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            urlserver: {
              url: "http://api.example.com/mcp",
            },
          },
        }),
      );

      const result = loadServerConfig("urlserver", "/config.json");

      expect(result.transport).toBe("http");
      expect(result.url).toBe("http://api.example.com/mcp");
    });

    it("should return http config from root-level url", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          url: "http://root-server.com/api",
        }),
      );

      const result = loadServerConfig("anyserver", "/root-config.json");

      expect(result.transport).toBe("http");
      expect(result.url).toBe("http://root-server.com/api");
    });
  });

  describe("sse transport configuration", () => {
    it("should return sse config from mcpServers with transport:sse", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            sseserver: {
              transport: "sse",
              url: "http://localhost:3000/events",
            },
          },
        }),
      );

      const result = loadServerConfig("sseserver", "/config.json");

      expect(result).toEqual({
        transport: "sse",
        url: "http://localhost:3000/events",
      });
    });

    it("should return sse config from root-level transport:sse", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "sse",
          url: "http://sse-server.com/stream",
        }),
      );

      const result = loadServerConfig("anyserver", "/sse-config.json");

      expect(result.transport).toBe("sse");
      expect(result.url).toBe("http://sse-server.com/stream");
    });
  });

  describe("error handling", () => {
    it('should throw "Invalid JSON" on malformed config file', () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue("{ invalid json }");

      expect(() => loadServerConfig("server", "/bad.json")).toThrow(
        /Invalid JSON in config file/,
      );
    });

    it('should throw "url is missing" when transport=http but no url', () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            nourl: {
              transport: "http",
            },
          },
        }),
      );

      // Zod union validation returns "Invalid input" when neither HTTP/SSE nor stdio schema matches
      expect(() => loadServerConfig("nourl", "/config.json")).toThrow(
        /Invalid/,
      );
    });

    it("should throw validation error when transport=sse but no url", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          mcpServers: {
            nourl: {
              transport: "sse",
            },
          },
        }),
      );

      // Zod union validation returns "Invalid input" when neither HTTP/SSE nor stdio schema matches
      expect(() => loadServerConfig("nourl", "/config.json")).toThrow(
        /Invalid/,
      );
    });

    it("should throw validation error for root-level transport:http without url", () => {
      mockExistsSync.mockReturnValue(true);
      mockReadFileSync.mockReturnValue(
        JSON.stringify({
          transport: "http",
        }),
      );

      // Zod union validation returns "Invalid input" when neither HTTP/SSE nor stdio schema matches
      expect(() => loadServerConfig("server", "/config.json")).toThrow(
        /Invalid/,
      );
    });

    it('should throw "Server config not found" when server not in any path', () => {
      mockExistsSync.mockReturnValue(false);

      expect(() => loadServerConfig("nonexistent")).toThrow(
        /Server config not found for: nonexistent/,
      );
    });

    it("should list all tried paths in error message", () => {
      mockExistsSync.mockReturnValue(false);

      try {
        loadServerConfig("missing", "/custom/path.json");
        fail("Should have thrown");
      } catch (e) {
        const error = e as Error;
        expect(error.message).toContain("/custom/path.json");
        expect(error.message).toContain(".config/mcp/servers/missing.json");
        expect(error.message).toContain("claude_desktop_config.json");
      }
    });
  });

  describe("server not found in config file", () => {
    it("should continue searching if server name not in mcpServers", () => {
      const firstPath = "/first.json";
      const secondPath = path.join(
        homedir,
        ".config",
        "mcp",
        "servers",
        "target.json",
      );

      mockExistsSync.mockImplementation(
        (p: string) => p === firstPath || p === secondPath,
      );
      mockReadFileSync.mockImplementation((p: string) => {
        if (p === firstPath) {
          return JSON.stringify({
            mcpServers: { other: { command: "other" } },
          });
        }
        return JSON.stringify({ command: "found" });
      });

      const result = loadServerConfig("target", firstPath);

      expect(result.command).toBe("found");
    });
  });
});
