/**
 * Tests for CLI Parser Zod Schemas
 *
 * Validates the schema definitions used for CLI argument parsing.
 *
 * @module cli/lib/__tests__/cli-parserSchemas
 */

import { jest, describe, test, expect, afterEach } from "@jest/globals";
import { ZodError } from "zod";
import {
  AssessmentProfileNameSchema,
  AssessmentModuleNameSchema,
  ServerConfigSchema,
  AssessmentOptionsSchema,
  ValidationResultSchema,
  validateAssessmentOptions,
  validateServerConfig,
  parseAssessmentOptions,
  safeParseAssessmentOptions,
  parseModuleNames,
  safeParseModuleNames,
  LogLevelSchema,
  ReportFormatSchema,
  TransportTypeSchema,
  ZOD_SCHEMA_VERSION,
} from "../cli-parserSchemas.js";

describe("cli-parserSchemas", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Re-exported schemas", () => {
    test("exports ZOD_SCHEMA_VERSION", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });

    test("exports LogLevelSchema", () => {
      const validLevels = ["silent", "error", "warn", "info", "debug"];
      for (const level of validLevels) {
        expect(LogLevelSchema.safeParse(level).success).toBe(true);
      }
    });

    test("exports ReportFormatSchema", () => {
      expect(ReportFormatSchema.safeParse("json").success).toBe(true);
      expect(ReportFormatSchema.safeParse("markdown").success).toBe(true);
    });

    test("exports TransportTypeSchema", () => {
      const validTypes = ["stdio", "http", "sse"];
      for (const type of validTypes) {
        expect(TransportTypeSchema.safeParse(type).success).toBe(true);
      }
    });
  });

  describe("AssessmentProfileNameSchema", () => {
    describe("valid profiles", () => {
      test('accepts "quick"', () => {
        const result = AssessmentProfileNameSchema.safeParse("quick");
        expect(result.success).toBe(true);
      });

      test('accepts "security"', () => {
        const result = AssessmentProfileNameSchema.safeParse("security");
        expect(result.success).toBe(true);
      });

      test('accepts "compliance"', () => {
        const result = AssessmentProfileNameSchema.safeParse("compliance");
        expect(result.success).toBe(true);
      });

      test('accepts "full"', () => {
        const result = AssessmentProfileNameSchema.safeParse("full");
        expect(result.success).toBe(true);
      });
    });

    describe("invalid profiles", () => {
      test('rejects uppercase "QUICK"', () => {
        const result = AssessmentProfileNameSchema.safeParse("QUICK");
        expect(result.success).toBe(false);
      });

      test("rejects unknown profile", () => {
        const result = AssessmentProfileNameSchema.safeParse("unknown");
        expect(result.success).toBe(false);
      });

      test("rejects empty string", () => {
        const result = AssessmentProfileNameSchema.safeParse("");
        expect(result.success).toBe(false);
      });

      test("rejects null", () => {
        const result = AssessmentProfileNameSchema.safeParse(null);
        expect(result.success).toBe(false);
      });
    });
  });

  describe("AssessmentModuleNameSchema", () => {
    const validModules = [
      "functionality",
      "security",
      "documentation",
      "errorHandling",
      "usability",
      "mcpSpecCompliance",
      "aupCompliance",
      "toolAnnotations",
      "prohibitedLibraries",
      "manifestValidation",
      "portability",
      "externalAPIScanner",
      "authentication",
      "temporal",
      "resources",
      "prompts",
      "crossCapability",
      "protocolConformance",
      // New unified modules (v1.25.0+)
      "protocolCompliance",
      "developerExperience",
      // Quality tier modules (v1.40.0+)
      "fileModularization",
      "conformance",
    ];

    describe("valid modules", () => {
      test("accepts all 22 valid module names", () => {
        for (const module of validModules) {
          const result = AssessmentModuleNameSchema.safeParse(module);
          expect(result.success).toBe(true);
        }
      });

      test("count of valid modules is 22", () => {
        expect(validModules.length).toBe(22);
      });
    });

    describe("invalid modules", () => {
      test("rejects unknown module name", () => {
        const result = AssessmentModuleNameSchema.safeParse("unknownModule");
        expect(result.success).toBe(false);
      });

      test("rejects case-sensitive mismatch", () => {
        const result = AssessmentModuleNameSchema.safeParse("Security");
        expect(result.success).toBe(false);
      });

      test("rejects empty string", () => {
        const result = AssessmentModuleNameSchema.safeParse("");
        expect(result.success).toBe(false);
      });

      test("rejects typo", () => {
        const result = AssessmentModuleNameSchema.safeParse("functinoality");
        expect(result.success).toBe(false);
      });
    });
  });

  describe("ServerConfigSchema", () => {
    describe("http/sse transport", () => {
      test("accepts http transport with url", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "http",
          url: "http://localhost:3000/mcp",
        });
        expect(result.success).toBe(true);
      });

      test("accepts sse transport with url", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "sse",
          url: "http://localhost:3000/sse",
        });
        expect(result.success).toBe(true);
      });

      test("rejects http transport without url", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "http",
        });
        expect(result.success).toBe(false);
      });

      test("rejects sse transport without url", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "sse",
        });
        expect(result.success).toBe(false);
      });

      test("rejects http transport with empty url", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "http",
          url: "",
        });
        expect(result.success).toBe(false);
      });
    });

    describe("stdio transport", () => {
      test("accepts stdio transport with command", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "stdio",
          command: "python3",
        });
        expect(result.success).toBe(true);
      });

      test("accepts stdio transport with command, args, and env", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "stdio",
          command: "python3",
          args: ["server.py", "--port", "8080"],
          env: { DEBUG: "true" },
          cwd: "/home/user/server",
        });
        expect(result.success).toBe(true);
      });

      test("rejects stdio transport without command", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "stdio",
        });
        expect(result.success).toBe(false);
      });

      test("rejects stdio transport with empty command", () => {
        const result = ServerConfigSchema.safeParse({
          transport: "stdio",
          command: "",
        });
        expect(result.success).toBe(false);
      });
    });

    describe("no transport specified", () => {
      test("accepts config with url only (infers http/sse)", () => {
        const result = ServerConfigSchema.safeParse({
          url: "http://localhost:3000/mcp",
        });
        expect(result.success).toBe(true);
      });

      test("accepts config with command only (infers stdio)", () => {
        const result = ServerConfigSchema.safeParse({
          command: "python3",
        });
        expect(result.success).toBe(true);
      });

      test("rejects config with neither url nor command", () => {
        const result = ServerConfigSchema.safeParse({});
        expect(result.success).toBe(false);
      });

      test("accepts config with both url and command", () => {
        // When both are present and no transport specified, validation passes
        // because either url or command satisfies the refinement
        const result = ServerConfigSchema.safeParse({
          url: "http://localhost:3000/mcp",
          command: "python3",
        });
        expect(result.success).toBe(true);
      });
    });

    describe("optional fields", () => {
      test("accepts args as string array", () => {
        const result = ServerConfigSchema.safeParse({
          command: "python3",
          args: ["--verbose", "-m", "module"],
        });
        expect(result.success).toBe(true);
      });

      test("accepts env as record", () => {
        const result = ServerConfigSchema.safeParse({
          command: "python3",
          env: { PATH: "/usr/bin", DEBUG: "1" },
        });
        expect(result.success).toBe(true);
      });

      test("accepts cwd", () => {
        const result = ServerConfigSchema.safeParse({
          command: "python3",
          cwd: "/home/user/project",
        });
        expect(result.success).toBe(true);
      });

      test("rejects non-string array for args", () => {
        const result = ServerConfigSchema.safeParse({
          command: "python3",
          args: [1, 2, 3],
        });
        expect(result.success).toBe(false);
      });
    });
  });

  describe("AssessmentOptionsSchema", () => {
    describe("required fields", () => {
      test("requires serverName", () => {
        const result = AssessmentOptionsSchema.safeParse({});
        expect(result.success).toBe(false);
      });

      test("rejects empty serverName", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "",
        });
        expect(result.success).toBe(false);
      });

      test("accepts minimal valid options", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
        });
        expect(result.success).toBe(true);
      });
    });

    describe("optional fields", () => {
      test("accepts all optional fields", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          serverConfigPath: "/path/to/config.json",
          outputPath: "/path/to/output.json",
          sourceCodePath: "/path/to/source",
          verbose: true,
          jsonOnly: false,
          format: "json",
          includePolicy: true,
          preflightOnly: false,
          logLevel: "debug",
        });
        expect(result.success).toBe(true);
      });

      test("validates mcpAuditorUrl as URL", () => {
        const validResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          mcpAuditorUrl: "http://localhost:8085",
        });
        expect(validResult.success).toBe(true);

        const invalidResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          mcpAuditorUrl: "not-a-url",
        });
        expect(invalidResult.success).toBe(false);
      });

      test("validates temporalInvocations as positive integer", () => {
        const validResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          temporalInvocations: 5,
        });
        expect(validResult.success).toBe(true);

        const zeroResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          temporalInvocations: 0,
        });
        expect(zeroResult.success).toBe(false);

        const negativeResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          temporalInvocations: -1,
        });
        expect(negativeResult.success).toBe(false);

        const floatResult = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          temporalInvocations: 3.5,
        });
        expect(floatResult.success).toBe(false);
      });
    });

    describe("refinement: profile + modules", () => {
      test("accepts profile alone", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          profile: "quick",
        });
        expect(result.success).toBe(true);
      });

      test("accepts skipModules alone", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          skipModules: ["security", "temporal"],
        });
        expect(result.success).toBe(true);
      });

      test("accepts onlyModules alone", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          onlyModules: ["functionality", "documentation"],
        });
        expect(result.success).toBe(true);
      });

      test("rejects profile + skipModules", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          profile: "quick",
          skipModules: ["security"],
        });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain(
            "--profile cannot be used with --skip-modules or --only-modules",
          );
        }
      });

      test("rejects profile + onlyModules", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          profile: "security",
          onlyModules: ["functionality"],
        });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain(
            "--profile cannot be used with --skip-modules or --only-modules",
          );
        }
      });

      test("accepts profile with empty module arrays", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          profile: "quick",
          skipModules: [],
          onlyModules: [],
        });
        expect(result.success).toBe(true);
      });
    });

    describe("refinement: skip + only modules", () => {
      test("rejects skipModules + onlyModules together", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          skipModules: ["security"],
          onlyModules: ["functionality"],
        });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain(
            "--skip-modules and --only-modules are mutually exclusive",
          );
        }
      });

      test("accepts both as empty arrays", () => {
        const result = AssessmentOptionsSchema.safeParse({
          serverName: "test-server",
          skipModules: [],
          onlyModules: [],
        });
        expect(result.success).toBe(true);
      });
    });
  });

  describe("ValidationResultSchema", () => {
    test("accepts valid result with no errors", () => {
      const result = ValidationResultSchema.safeParse({
        valid: true,
        errors: [],
      });
      expect(result.success).toBe(true);
    });

    test("accepts valid result with errors", () => {
      const result = ValidationResultSchema.safeParse({
        valid: false,
        errors: ["Error 1", "Error 2"],
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing valid field", () => {
      const result = ValidationResultSchema.safeParse({
        errors: [],
      });
      expect(result.success).toBe(false);
    });

    test("rejects missing errors field", () => {
      const result = ValidationResultSchema.safeParse({
        valid: true,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("validateAssessmentOptions", () => {
    test("returns empty array for valid options", () => {
      const errors = validateAssessmentOptions({
        serverName: "test-server",
      });
      expect(errors).toEqual([]);
    });

    test("returns error array for invalid options", () => {
      const errors = validateAssessmentOptions({});
      expect(errors.length).toBeGreaterThan(0);
    });

    test("includes path in error messages", () => {
      const errors = validateAssessmentOptions({
        serverName: "",
      });
      expect(errors[0]).toContain("serverName");
    });

    test("returns multiple errors for multiple issues", () => {
      const errors = validateAssessmentOptions({
        serverName: "test",
        profile: "quick",
        skipModules: ["security"],
      });
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("validateServerConfig", () => {
    test("returns empty array for valid config", () => {
      const errors = validateServerConfig({
        url: "http://localhost:3000/mcp",
      });
      expect(errors).toEqual([]);
    });

    test("returns error array for invalid config", () => {
      const errors = validateServerConfig({});
      expect(errors.length).toBeGreaterThan(0);
    });

    test("returns error for http without url", () => {
      const errors = validateServerConfig({
        transport: "http",
      });
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("parseAssessmentOptions", () => {
    test("returns parsed options for valid input", () => {
      const options = parseAssessmentOptions({
        serverName: "test-server",
        verbose: true,
      });
      expect(options.serverName).toBe("test-server");
      expect(options.verbose).toBe(true);
    });

    test("throws ZodError for invalid input", () => {
      expect(() => parseAssessmentOptions({})).toThrow(ZodError);
    });

    test("throws ZodError for empty serverName", () => {
      expect(() => parseAssessmentOptions({ serverName: "" })).toThrow(
        ZodError,
      );
    });
  });

  describe("safeParseAssessmentOptions", () => {
    test("returns success: true with data for valid input", () => {
      const result = safeParseAssessmentOptions({
        serverName: "test-server",
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.serverName).toBe("test-server");
      }
    });

    test("returns success: false with error for invalid input", () => {
      const result = safeParseAssessmentOptions({});
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(ZodError);
      }
    });
  });

  describe("parseModuleNames", () => {
    test("parses single module name", () => {
      const modules = parseModuleNames("functionality");
      expect(modules).toEqual(["functionality"]);
    });

    test("parses comma-separated modules", () => {
      const modules = parseModuleNames("functionality,security,documentation");
      expect(modules).toEqual(["functionality", "security", "documentation"]);
    });

    test("trims whitespace", () => {
      const modules = parseModuleNames(
        "  functionality , security , temporal  ",
      );
      expect(modules).toEqual(["functionality", "security", "temporal"]);
    });

    test("filters empty strings", () => {
      const modules = parseModuleNames("functionality,,security");
      expect(modules).toEqual(["functionality", "security"]);
    });

    test("throws for invalid module name", () => {
      expect(() => parseModuleNames("functionality,invalid,security")).toThrow(
        ZodError,
      );
    });

    test("returns empty array for empty string", () => {
      // Empty string splits to [""], trim to [""], filter(Boolean) removes falsy values
      // Result is empty array [] which is valid
      const modules = parseModuleNames("");
      expect(modules).toEqual([]);
    });
  });

  describe("safeParseModuleNames", () => {
    test("returns valid array for all valid names", () => {
      const result = safeParseModuleNames("functionality,security");
      expect(result.valid).toEqual(["functionality", "security"]);
      expect(result.invalid).toEqual([]);
    });

    test("returns invalid array for unknown names", () => {
      const result = safeParseModuleNames("invalid1,invalid2");
      expect(result.valid).toEqual([]);
      expect(result.invalid).toEqual(["invalid1", "invalid2"]);
    });

    test("handles mixed valid/invalid input", () => {
      const result = safeParseModuleNames("functionality,invalid,security");
      expect(result.valid).toEqual(["functionality", "security"]);
      expect(result.invalid).toEqual(["invalid"]);
    });

    test("trims whitespace in names", () => {
      const result = safeParseModuleNames("  functionality , security  ");
      expect(result.valid).toEqual(["functionality", "security"]);
    });

    test("handles empty string", () => {
      const result = safeParseModuleNames("");
      expect(result.valid).toEqual([]);
      expect(result.invalid).toEqual([]);
    });
  });
});
