/**
 * Tests for Server Configuration Zod Schemas
 *
 * Validates the schema definitions used for server config file parsing.
 *
 * @module cli/lib/assessment-runner/__tests__/server-configSchemas
 */

import { jest, describe, test, expect, afterEach } from "@jest/globals";
import { ZodError } from "zod";
import {
  HttpSseServerConfigSchema,
  StdioServerConfigSchema,
  ServerEntrySchema,
  ClaudeDesktopConfigSchema,
  StandaloneConfigSchema,
  ConfigFileSchema,
  parseConfigFile,
  safeParseConfigFile,
  validateServerEntry,
  isHttpSseConfig,
  isStdioConfig,
  TransportTypeSchema,
} from "../server-configSchemas.js";
import type {
  HttpSseServerConfig,
  StdioServerConfig,
  ServerEntry,
} from "../server-configSchemas.js";

describe("server-configSchemas", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Re-exported schemas", () => {
    test("exports TransportTypeSchema", () => {
      expect(TransportTypeSchema.safeParse("stdio").success).toBe(true);
      expect(TransportTypeSchema.safeParse("http").success).toBe(true);
      expect(TransportTypeSchema.safeParse("sse").success).toBe(true);
    });
  });

  describe("HttpSseServerConfigSchema", () => {
    describe("valid configs", () => {
      test("accepts url only", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          url: "http://localhost:3000/mcp",
        });
        expect(result.success).toBe(true);
      });

      test("accepts url with transport http", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          transport: "http",
          url: "http://localhost:3000/mcp",
        });
        expect(result.success).toBe(true);
      });

      test("accepts url with transport sse", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          transport: "sse",
          url: "http://localhost:3000/sse",
        });
        expect(result.success).toBe(true);
      });

      test("accepts https url", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          url: "https://api.example.com/mcp",
        });
        expect(result.success).toBe(true);
      });
    });

    describe("invalid configs", () => {
      test("rejects missing url", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          transport: "http",
        });
        expect(result.success).toBe(false);
      });

      test("rejects invalid URL format", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          url: "not-a-valid-url",
        });
        expect(result.success).toBe(false);
      });

      test("rejects empty url", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          url: "",
        });
        expect(result.success).toBe(false);
      });

      test("rejects invalid transport value", () => {
        const result = HttpSseServerConfigSchema.safeParse({
          transport: "stdio", // stdio not allowed in this schema
          url: "http://localhost:3000",
        });
        expect(result.success).toBe(false);
      });
    });
  });

  describe("StdioServerConfigSchema", () => {
    describe("valid configs", () => {
      test("accepts command only (minimum valid)", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
        });
        expect(result.success).toBe(true);
      });

      test("accepts command with args", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
          args: ["server.py", "--port", "8080"],
        });
        expect(result.success).toBe(true);
      });

      test("accepts command with env record", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
          env: { DEBUG: "true", PATH: "/usr/bin" },
        });
        expect(result.success).toBe(true);
      });

      test("accepts command with cwd", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
          cwd: "/home/user/project",
        });
        expect(result.success).toBe(true);
      });

      test("accepts full config with all fields", () => {
        const result = StdioServerConfigSchema.safeParse({
          transport: "stdio",
          command: "python3",
          args: ["server.py"],
          env: { DEBUG: "1" },
          cwd: "/home/user/project",
        });
        expect(result.success).toBe(true);
      });
    });

    describe("invalid configs", () => {
      test("rejects missing command", () => {
        const result = StdioServerConfigSchema.safeParse({
          transport: "stdio",
        });
        expect(result.success).toBe(false);
      });

      test("rejects empty command", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "",
        });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain(
            "command is required",
          );
        }
      });

      test("rejects non-string array for args", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
          args: [1, 2, 3],
        });
        expect(result.success).toBe(false);
      });

      test("rejects non-string values in env", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
          env: { DEBUG: 123 },
        });
        expect(result.success).toBe(false);
      });
    });

    describe("default values", () => {
      test("args defaults to empty array", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
        });
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.args).toEqual([]);
        }
      });

      test("env defaults to empty object", () => {
        const result = StdioServerConfigSchema.safeParse({
          command: "python3",
        });
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.env).toEqual({});
        }
      });
    });
  });

  describe("ServerEntrySchema", () => {
    test("accepts HTTP config", () => {
      const result = ServerEntrySchema.safeParse({
        url: "http://localhost:3000/mcp",
      });
      expect(result.success).toBe(true);
    });

    test("accepts SSE config", () => {
      const result = ServerEntrySchema.safeParse({
        transport: "sse",
        url: "http://localhost:3000/sse",
      });
      expect(result.success).toBe(true);
    });

    test("accepts stdio config", () => {
      const result = ServerEntrySchema.safeParse({
        command: "python3",
        args: ["server.py"],
      });
      expect(result.success).toBe(true);
    });

    test("rejects config matching neither schema", () => {
      const result = ServerEntrySchema.safeParse({
        transport: "unknown",
      });
      expect(result.success).toBe(false);
    });

    test("rejects empty object", () => {
      const result = ServerEntrySchema.safeParse({});
      expect(result.success).toBe(false);
    });
  });

  describe("ClaudeDesktopConfigSchema", () => {
    test("accepts {mcpServers: {...}} format", () => {
      const result = ClaudeDesktopConfigSchema.safeParse({
        mcpServers: {
          "my-server": { url: "http://localhost:3000/mcp" },
          "another-server": { command: "python3", args: ["server.py"] },
        },
      });
      expect(result.success).toBe(true);
    });

    test("accepts empty mcpServers object", () => {
      const result = ClaudeDesktopConfigSchema.safeParse({
        mcpServers: {},
      });
      expect(result.success).toBe(true);
    });

    test("accepts config without mcpServers (undefined)", () => {
      const result = ClaudeDesktopConfigSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    test("rejects invalid server entry within mcpServers", () => {
      const result = ClaudeDesktopConfigSchema.safeParse({
        mcpServers: {
          "invalid-server": { transport: "invalid" },
        },
      });
      expect(result.success).toBe(false);
    });
  });

  describe("StandaloneConfigSchema", () => {
    test("accepts HTTP config directly", () => {
      const result = StandaloneConfigSchema.safeParse({
        url: "http://localhost:3000/mcp",
      });
      expect(result.success).toBe(true);
    });

    test("accepts stdio config directly", () => {
      const result = StandaloneConfigSchema.safeParse({
        command: "python3",
      });
      expect(result.success).toBe(true);
    });

    test("is equivalent to ServerEntrySchema", () => {
      expect(StandaloneConfigSchema).toBe(ServerEntrySchema);
    });
  });

  describe("ConfigFileSchema", () => {
    test("accepts Claude Desktop format", () => {
      const result = ConfigFileSchema.safeParse({
        mcpServers: {
          "test-server": { url: "http://localhost:3000/mcp" },
        },
      });
      expect(result.success).toBe(true);
    });

    test("accepts standalone HTTP config", () => {
      const result = ConfigFileSchema.safeParse({
        url: "http://localhost:3000/mcp",
      });
      expect(result.success).toBe(true);
    });

    test("accepts standalone stdio config", () => {
      const result = ConfigFileSchema.safeParse({
        command: "python3",
        args: ["server.py"],
      });
      expect(result.success).toBe(true);
    });

    test("accepts unknown keys (Zod passthrough by default)", () => {
      // ClaudeDesktopConfigSchema has mcpServers as optional
      // Extra keys are allowed by default in Zod (non-strict mode)
      const result = ConfigFileSchema.safeParse({
        invalid: "config",
      });
      // This passes because it matches ClaudeDesktopConfigSchema with mcpServers undefined
      expect(result.success).toBe(true);
    });

    test("rejects truly invalid values", () => {
      // null is not a valid object
      const result = ConfigFileSchema.safeParse(null);
      expect(result.success).toBe(false);
    });
  });

  describe("parseConfigFile", () => {
    test("parses valid Claude Desktop config", () => {
      const config = parseConfigFile({
        mcpServers: {
          "test-server": { url: "http://localhost:3000/mcp" },
        },
      });
      expect(config).toBeDefined();
    });

    test("parses valid standalone config", () => {
      const config = parseConfigFile({
        url: "http://localhost:3000/mcp",
      });
      expect(config).toBeDefined();
    });

    test("throws ZodError for null input", () => {
      expect(() => parseConfigFile(null)).toThrow(ZodError);
    });

    test("throws ZodError for non-object input", () => {
      expect(() => parseConfigFile("string")).toThrow(ZodError);
    });
  });

  describe("safeParseConfigFile", () => {
    test("returns success for valid config", () => {
      const result = safeParseConfigFile({
        url: "http://localhost:3000/mcp",
      });
      expect(result.success).toBe(true);
    });

    test("returns error for null input", () => {
      const result = safeParseConfigFile(null);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(ZodError);
      }
    });

    test("returns error for non-object input", () => {
      const result = safeParseConfigFile("string");
      expect(result.success).toBe(false);
    });
  });

  describe("validateServerEntry", () => {
    test("returns empty array for valid HTTP entry", () => {
      const errors = validateServerEntry({
        url: "http://localhost:3000/mcp",
      });
      expect(errors).toEqual([]);
    });

    test("returns empty array for valid stdio entry", () => {
      const errors = validateServerEntry({
        command: "python3",
      });
      expect(errors).toEqual([]);
    });

    test("returns errors for invalid entry", () => {
      const errors = validateServerEntry({});
      expect(errors.length).toBeGreaterThan(0);
    });

    test("includes path in error messages", () => {
      const errors = validateServerEntry({
        url: "not-a-url",
      });
      expect(errors.length).toBeGreaterThan(0);
      // Should contain error about invalid URL
      expect(errors.some((e) => e.includes("url"))).toBe(true);
    });
  });

  describe("isHttpSseConfig", () => {
    test("returns true for config with url", () => {
      const config: ServerEntry = { url: "http://localhost:3000" };
      expect(isHttpSseConfig(config)).toBe(true);
    });

    test("returns true for config with transport http", () => {
      const config: ServerEntry = {
        transport: "http",
        url: "http://localhost:3000",
      };
      expect(isHttpSseConfig(config)).toBe(true);
    });

    test("returns true for config with transport sse", () => {
      const config: ServerEntry = {
        transport: "sse",
        url: "http://localhost:3000",
      };
      expect(isHttpSseConfig(config)).toBe(true);
    });

    test("returns false for stdio config without url", () => {
      const config: ServerEntry = { command: "python3", args: [], env: {} };
      expect(isHttpSseConfig(config)).toBe(false);
    });
  });

  describe("isStdioConfig", () => {
    test("returns true for config with command (no url)", () => {
      const config: ServerEntry = { command: "python3", args: [], env: {} };
      expect(isStdioConfig(config)).toBe(true);
    });

    test("returns false for HTTP config", () => {
      const config: ServerEntry = { url: "http://localhost:3000" };
      expect(isStdioConfig(config)).toBe(false);
    });

    test("returns false for config with both url and command", () => {
      // If both are present, isStdioConfig returns false because url takes precedence
      const config = {
        url: "http://localhost:3000",
        command: "python3",
        args: [],
        env: {},
      } as ServerEntry;
      expect(isStdioConfig(config)).toBe(false);
    });
  });
});
