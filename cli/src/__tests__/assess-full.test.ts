/**
 * Assess-Full CLI Unit Tests
 *
 * Tests for CLI argument parsing concepts, config building, and validation logic.
 * These tests focus on pure logic that can be tested without mocking complex
 * external dependencies. For integration testing of the full CLI, use the
 * actual CLI binary.
 */

import { describe, it, expect } from "@jest/globals";
import * as fs from "fs";
import * as path from "path";

/**
 * Pure function tests - these test logic concepts used in the CLI
 * without needing to import the actual module (which has side effects)
 */

describe("CLI Argument Parsing Concepts", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Profile Flag Parsing", () => {
    const VALID_PROFILES = ["quick", "security", "compliance", "full"];

    function parseProfile(args: string[]): {
      profile?: string;
      error?: string;
    } {
      const profileIndex = args.indexOf("--profile");
      if (profileIndex === -1) {
        return {}; // No profile specified
      }
      const profileValue = args[profileIndex + 1];
      if (!profileValue || profileValue.startsWith("--")) {
        return { error: "Missing profile value" };
      }
      if (!VALID_PROFILES.includes(profileValue)) {
        return { error: `Invalid profile: ${profileValue}` };
      }
      return { profile: profileValue };
    }

    it("should parse valid profile flags", () => {
      expect(parseProfile(["--profile", "quick"])).toEqual({
        profile: "quick",
      });
      expect(parseProfile(["--profile", "security"])).toEqual({
        profile: "security",
      });
      expect(parseProfile(["--profile", "compliance"])).toEqual({
        profile: "compliance",
      });
      expect(parseProfile(["--profile", "full"])).toEqual({ profile: "full" });
    });

    it("should handle missing profile value", () => {
      expect(parseProfile(["--profile"])).toEqual({
        error: "Missing profile value",
      });
      expect(parseProfile(["--profile", "--other"])).toEqual({
        error: "Missing profile value",
      });
    });

    it("should reject invalid profile names", () => {
      expect(parseProfile(["--profile", "invalid"])).toEqual({
        error: "Invalid profile: invalid",
      });
      expect(parseProfile(["--profile", "QUICK"])).toEqual({
        error: "Invalid profile: QUICK",
      });
    });

    it("should return empty when no profile specified", () => {
      expect(parseProfile([])).toEqual({});
      expect(parseProfile(["--server", "test"])).toEqual({});
    });
  });

  describe("Module List Parsing", () => {
    function parseModules(input: string): string[] {
      return input
        .split(",")
        .map((n) => n.trim())
        .filter(Boolean);
    }

    it("should parse comma-separated modules", () => {
      expect(parseModules("security,functionality")).toEqual([
        "security",
        "functionality",
      ]);
    });

    it("should trim whitespace", () => {
      expect(parseModules("security , functionality , temporal")).toEqual([
        "security",
        "functionality",
        "temporal",
      ]);
    });

    it("should filter empty values", () => {
      expect(parseModules("security,,functionality")).toEqual([
        "security",
        "functionality",
      ]);
    });

    it("should handle single module", () => {
      expect(parseModules("security")).toEqual(["security"]);
    });

    it("should handle empty input", () => {
      expect(parseModules("")).toEqual([]);
    });
  });

  describe("Output Format Validation", () => {
    const VALID_FORMATS = ["json", "markdown", "html"] as const;
    type Format = (typeof VALID_FORMATS)[number];

    function validateFormat(format: string): format is Format {
      return (VALID_FORMATS as readonly string[]).includes(format);
    }

    it("should accept valid formats", () => {
      expect(validateFormat("json")).toBe(true);
      expect(validateFormat("markdown")).toBe(true);
      expect(validateFormat("html")).toBe(true);
    });

    it("should reject invalid formats", () => {
      expect(validateFormat("xml")).toBe(false);
      expect(validateFormat("JSON")).toBe(false);
      expect(validateFormat("pdf")).toBe(false);
    });
  });
});

describe("Config File Handling", () => {
  describe("Config Parsing", () => {
    interface TransportConfig {
      transport?: "stdio" | "http" | "sse";
      command?: string;
      args?: string[];
      url?: string;
      headers?: Record<string, string>;
    }

    function validateConfig(config: TransportConfig): {
      valid: boolean;
      error?: string;
    } {
      const transport = config.transport || "stdio";

      if (transport === "stdio") {
        if (!config.command) {
          return { valid: false, error: "STDIO transport requires command" };
        }
        return { valid: true };
      }

      if (transport === "http" || transport === "sse") {
        if (!config.url) {
          return {
            valid: false,
            error: `${transport.toUpperCase()} transport requires url`,
          };
        }
        return { valid: true };
      }

      return { valid: false, error: `Unknown transport: ${transport}` };
    }

    it("should validate STDIO config", () => {
      expect(
        validateConfig({
          transport: "stdio",
          command: "python",
          args: ["-m", "server"],
        }),
      ).toEqual({ valid: true });
    });

    it("should require command for STDIO", () => {
      expect(validateConfig({ transport: "stdio" })).toEqual({
        valid: false,
        error: "STDIO transport requires command",
      });
    });

    it("should validate HTTP config", () => {
      expect(
        validateConfig({ transport: "http", url: "http://localhost:3000/mcp" }),
      ).toEqual({ valid: true });
    });

    it("should require url for HTTP", () => {
      expect(validateConfig({ transport: "http" })).toEqual({
        valid: false,
        error: "HTTP transport requires url",
      });
    });

    it("should validate SSE config", () => {
      expect(
        validateConfig({ transport: "sse", url: "http://localhost:3000/sse" }),
      ).toEqual({ valid: true });
    });

    it("should require url for SSE", () => {
      expect(validateConfig({ transport: "sse" })).toEqual({
        valid: false,
        error: "SSE transport requires url",
      });
    });

    it("should default to STDIO when transport not specified", () => {
      expect(validateConfig({ command: "node" })).toEqual({ valid: true });
    });
  });

  describe("Config File Reading", () => {
    it("should detect JSON file by extension", () => {
      const filePath = "/tmp/config.json";
      expect(path.extname(filePath)).toBe(".json");
    });

    it("should handle paths with multiple dots", () => {
      const filePath = "/tmp/my.server.config.json";
      expect(path.extname(filePath)).toBe(".json");
    });
  });
});

describe("Exit Code Logic", () => {
  interface AssessmentResult {
    overallStatus: "PASS" | "FAIL";
    security?: {
      vulnerabilities?: unknown[];
    };
  }

  function determineExitCode(result: AssessmentResult): number {
    if (result.overallStatus === "FAIL") return 1;
    if (
      result.security?.vulnerabilities &&
      result.security.vulnerabilities.length > 0
    ) {
      return 1;
    }
    return 0;
  }

  it("should return 0 for PASS with no vulnerabilities", () => {
    expect(determineExitCode({ overallStatus: "PASS" })).toBe(0);
  });

  it("should return 1 for FAIL status", () => {
    expect(determineExitCode({ overallStatus: "FAIL" })).toBe(1);
  });

  it("should return 1 when vulnerabilities exist", () => {
    expect(
      determineExitCode({
        overallStatus: "PASS",
        security: { vulnerabilities: [{ type: "injection" }] },
      }),
    ).toBe(1);
  });

  it("should return 0 for PASS with empty vulnerabilities", () => {
    expect(
      determineExitCode({
        overallStatus: "PASS",
        security: { vulnerabilities: [] },
      }),
    ).toBe(0);
  });
});

describe("State Management Concepts", () => {
  describe("Resume Flag Parsing", () => {
    function getResumeMode(args: string[]): "resume" | "no-resume" | "default" {
      if (args.includes("--no-resume")) return "no-resume";
      if (args.includes("--resume")) return "resume";
      return "default";
    }

    it("should detect --resume flag", () => {
      expect(getResumeMode(["--resume"])).toBe("resume");
      expect(getResumeMode(["--server", "test", "--resume"])).toBe("resume");
    });

    it("should detect --no-resume flag", () => {
      expect(getResumeMode(["--no-resume"])).toBe("no-resume");
    });

    it("should return default when neither specified", () => {
      expect(getResumeMode([])).toBe("default");
      expect(getResumeMode(["--server", "test"])).toBe("default");
    });

    it("should handle --no-resume even when --resume also present", () => {
      // --no-resume takes precedence
      expect(getResumeMode(["--resume", "--no-resume"])).toBe("no-resume");
    });
  });

  describe("State File Path Generation", () => {
    function getStateFilePath(serverName: string, outputDir?: string): string {
      const dir = outputDir || "/tmp";
      return path.join(dir, `.${serverName}-assessment-state.json`);
    }

    it("should generate state file path with server name", () => {
      expect(getStateFilePath("test-server")).toBe(
        "/tmp/.test-server-assessment-state.json",
      );
    });

    it("should use custom output directory", () => {
      expect(getStateFilePath("test-server", "/home/user/results")).toBe(
        "/home/user/results/.test-server-assessment-state.json",
      );
    });

    it("should handle server names with special characters", () => {
      expect(getStateFilePath("my-mcp-server")).toBe(
        "/tmp/.my-mcp-server-assessment-state.json",
      );
    });
  });
});

describe("Output Path Generation", () => {
  describe("Default Output Paths", () => {
    function getDefaultOutputPath(serverName: string, format: string): string {
      const ext = format === "markdown" ? ".md" : `.${format}`;
      return `/tmp/inspector-assessment-${serverName}${ext}`;
    }

    it("should generate JSON output path", () => {
      expect(getDefaultOutputPath("my-server", "json")).toBe(
        "/tmp/inspector-assessment-my-server.json",
      );
    });

    it("should generate Markdown output path", () => {
      expect(getDefaultOutputPath("my-server", "markdown")).toBe(
        "/tmp/inspector-assessment-my-server.md",
      );
    });

    it("should generate HTML output path", () => {
      expect(getDefaultOutputPath("my-server", "html")).toBe(
        "/tmp/inspector-assessment-my-server.html",
      );
    });
  });

  describe("Custom Output Paths", () => {
    function resolveOutputPath(
      specified: string | undefined,
      serverName: string,
      format: string,
    ): string {
      if (specified) {
        // If directory, append filename
        if (!path.extname(specified)) {
          const ext = format === "markdown" ? ".md" : `.${format}`;
          return path.join(
            specified,
            `inspector-assessment-${serverName}${ext}`,
          );
        }
        return specified;
      }
      const ext = format === "markdown" ? ".md" : `.${format}`;
      return `/tmp/inspector-assessment-${serverName}${ext}`;
    }

    it("should use specified path directly if it has extension", () => {
      expect(
        resolveOutputPath("/home/user/results.json", "server", "json"),
      ).toBe("/home/user/results.json");
    });

    it("should append filename if path is a directory", () => {
      expect(resolveOutputPath("/home/user/results", "server", "json")).toBe(
        "/home/user/results/inspector-assessment-server.json",
      );
    });

    it("should use default when not specified", () => {
      expect(resolveOutputPath(undefined, "server", "json")).toBe(
        "/tmp/inspector-assessment-server.json",
      );
    });
  });
});

describe("Boolean Flag Parsing", () => {
  function parseBooleanFlags(args: string[]): Record<string, boolean> {
    const flags: Record<string, boolean> = {
      verbose: false,
      silent: false,
      claudeEnabled: false,
      includePolicy: false,
      preflight: false,
    };

    if (args.includes("--verbose") || args.includes("-v")) flags.verbose = true;
    if (args.includes("--silent") || args.includes("-s")) flags.silent = true;
    if (args.includes("--claude-enabled")) flags.claudeEnabled = true;
    if (args.includes("--include-policy")) flags.includePolicy = true;
    if (args.includes("--preflight")) flags.preflight = true;

    return flags;
  }

  it("should parse verbose flag", () => {
    expect(parseBooleanFlags(["--verbose"]).verbose).toBe(true);
    expect(parseBooleanFlags(["-v"]).verbose).toBe(true);
  });

  it("should parse silent flag", () => {
    expect(parseBooleanFlags(["--silent"]).silent).toBe(true);
    expect(parseBooleanFlags(["-s"]).silent).toBe(true);
  });

  it("should parse claude-enabled flag", () => {
    expect(parseBooleanFlags(["--claude-enabled"]).claudeEnabled).toBe(true);
  });

  it("should parse include-policy flag", () => {
    expect(parseBooleanFlags(["--include-policy"]).includePolicy).toBe(true);
  });

  it("should parse preflight flag", () => {
    expect(parseBooleanFlags(["--preflight"]).preflight).toBe(true);
  });

  it("should handle multiple flags", () => {
    const flags = parseBooleanFlags([
      "--verbose",
      "--include-policy",
      "--preflight",
    ]);
    expect(flags.verbose).toBe(true);
    expect(flags.includePolicy).toBe(true);
    expect(flags.preflight).toBe(true);
    expect(flags.silent).toBe(false);
  });

  it("should return all false when no flags", () => {
    const flags = parseBooleanFlags([]);
    expect(Object.values(flags).every((v) => v === false)).toBe(true);
  });
});
