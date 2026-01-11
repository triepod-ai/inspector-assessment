/**
 * Tests for server-config.ts Zod validation integration (Issue #84)
 *
 * Verifies that loadServerConfig() correctly validates config files
 * using Zod schemas and provides helpful error messages.
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { loadServerConfig } from "../server-config.js";

describe("loadServerConfig with Zod validation", () => {
  const tmpDir = os.tmpdir();
  let testConfigPath: string;

  beforeEach(() => {
    testConfigPath = path.join(tmpDir, `test-config-${Date.now()}.json`);
  });

  afterEach(() => {
    // Clean up test config files
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }
  });

  describe("valid configurations", () => {
    it("should load valid HTTP config", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          transport: "http",
          url: "http://localhost:8080/mcp",
        }),
      );

      const config = loadServerConfig("test-server", testConfigPath);

      expect(config.transport).toBe("http");
      expect(config.url).toBe("http://localhost:8080/mcp");
    });

    it("should load valid SSE config", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          transport: "sse",
          url: "http://localhost:8080/sse",
        }),
      );

      const config = loadServerConfig("test-server", testConfigPath);

      expect(config.transport).toBe("sse");
      expect(config.url).toBe("http://localhost:8080/sse");
    });

    it("should load valid stdio config", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          command: "/usr/bin/node",
          args: ["server.js"],
          env: { NODE_ENV: "production" },
        }),
      );

      const config = loadServerConfig("test-server", testConfigPath);

      expect(config.transport).toBe("stdio");
      expect(config.command).toBe("/usr/bin/node");
      expect(config.args).toEqual(["server.js"]);
      expect(config.env).toEqual({ NODE_ENV: "production" });
    });

    it("should load config from Claude Desktop format", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          mcpServers: {
            "my-server": {
              command: "/usr/bin/python",
              args: ["-m", "mcp_server"],
            },
          },
        }),
      );

      const config = loadServerConfig("my-server", testConfigPath);

      expect(config.transport).toBe("stdio");
      expect(config.command).toBe("/usr/bin/python");
      expect(config.args).toEqual(["-m", "mcp_server"]);
    });

    it("should default HTTP transport when url present without transport field", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          url: "http://localhost:8080/mcp",
        }),
      );

      const config = loadServerConfig("test-server", testConfigPath);

      expect(config.transport).toBe("http");
      expect(config.url).toBe("http://localhost:8080/mcp");
    });
  });

  describe("invalid configurations with Zod validation errors", () => {
    it("should throw Zod error for invalid URL", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          transport: "http",
          url: "not-a-valid-url",
        }),
      );

      expect(() => loadServerConfig("test-server", testConfigPath)).toThrow(
        /url must be a valid URL/,
      );
    });

    it("should throw Zod error for empty command in stdio config", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          command: "",
        }),
      );

      expect(() => loadServerConfig("test-server", testConfigPath)).toThrow(
        /command is required/,
      );
    });

    it("should include config source in error message", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          transport: "http",
          url: "invalid",
        }),
      );

      expect(() => loadServerConfig("test-server", testConfigPath)).toThrow(
        new RegExp(testConfigPath),
      );
    });
  });

  describe("error handling", () => {
    it("should throw for invalid JSON", () => {
      fs.writeFileSync(testConfigPath, "not valid json {");

      expect(() => loadServerConfig("test-server", testConfigPath)).toThrow(
        /Invalid JSON/,
      );
    });

    it("should throw for missing config file", () => {
      expect(() =>
        loadServerConfig("nonexistent-server", "/nonexistent/path.json"),
      ).toThrow(/Server config not found/);
    });

    it("should throw for server not in Claude Desktop config", () => {
      fs.writeFileSync(
        testConfigPath,
        JSON.stringify({
          mcpServers: {
            "other-server": { command: "node" },
          },
        }),
      );

      expect(() => loadServerConfig("missing-server", testConfigPath)).toThrow(
        /Server config not found/,
      );
    });
  });
});
