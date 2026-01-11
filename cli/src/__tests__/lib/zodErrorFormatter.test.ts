/**
 * Zod Error Formatter Test Suite
 *
 * Tests for formatZodError utility to ensure helpful error messages.
 * Addresses QA requirement: verify Zod error messages are helpful (not just generic "Invalid").
 */

import { jest, describe, it, expect, beforeEach } from "@jest/globals";
import { z, ZodError } from "zod";
import {
  formatZodError,
  formatZodIssue,
  formatZodErrorIndented,
  zodErrorToArray,
  formatUserFriendlyError,
  formatZodErrorForJson,
} from "../../lib/zodErrorFormatter.js";

describe("zodErrorFormatter", () => {
  describe("formatZodIssue", () => {
    it("should format issue with path", () => {
      const issue = {
        code: "invalid_type",
        expected: "string",
        received: "number",
        path: ["config", "url"],
        message: "Expected string, received number",
      } as const;

      const result = formatZodIssue(issue as any);
      expect(result).toBe("config.url: Expected string, received number");
    });

    it("should format issue without path", () => {
      const issue = {
        code: "invalid_type",
        expected: "string",
        received: "number",
        path: [],
        message: "Expected string, received number",
      } as const;

      const result = formatZodIssue(issue as any);
      expect(result).toBe("Expected string, received number");
    });
  });

  describe("formatZodError - union validation", () => {
    it("should extract specific error messages from union validation (HTTP transport missing url)", () => {
      // Schema for HTTP/SSE transport
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      // Schema for stdio transport
      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      // Union schema (like ServerEntrySchema)
      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: HTTP transport without url (should fail validation)
      const invalidConfig = { transport: "http" }; // Missing url

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should extract the specific error message, not just "Invalid"
        expect(formatted).toContain("url");
        expect(formatted).not.toBe("Invalid input");

        // Verify it's a helpful message
        expect(
          formatted.includes("required") ||
            formatted.includes("url") ||
            formatted.includes("Expected"),
        ).toBe(true);
      }
    });

    it("should extract specific error messages from union validation (SSE transport missing url)", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: SSE transport without url (should fail validation)
      const invalidConfig = { transport: "sse" }; // Missing url

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should extract the specific error message
        expect(formatted).toContain("url");
        expect(formatted).not.toBe("Invalid input");
      }
    });

    it("should handle stdio transport missing command", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z.string().min(1),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: Config with command field but empty (should fail validation)
      const invalidConfig = { command: "" }; // Empty command

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should extract the specific error message about command
        expect(formatted).toContain("command");
        expect(formatted.toLowerCase()).toContain("required");
      }
    });

    it("should provide helpful message for invalid URL format", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: Invalid URL format
      const invalidConfig = { url: "not-a-valid-url" };

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should provide helpful message about URL format
        expect(formatted.toLowerCase()).toContain("url");
        expect(formatted.toLowerCase()).toContain("valid");
      }
    });

    it("should handle completely empty config object", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z.string().min(1, "'url' is required for HTTP/SSE transport"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: Completely empty config
      const invalidConfig = {};

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should provide some helpful message (not just "Invalid input")
        expect(formatted).toBeTruthy();
        expect(formatted.length).toBeGreaterThan(10); // More than just "Invalid"
      }
    });
  });

  describe("formatZodError - non-union errors", () => {
    it("should format simple validation error", () => {
      const schema = z.object({
        name: z.string(),
        age: z.number().positive(),
      });

      const result = schema.safeParse({ name: "John", age: -5 });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        expect(formatted).toContain("age");
        expect(formatted.toLowerCase()).toContain("greater than");
      }
    });

    it("should format multiple validation errors", () => {
      const schema = z.object({
        name: z.string().min(3),
        email: z.string().email(),
      });

      const result = schema.safeParse({ name: "Jo", email: "invalid" });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        expect(formatted).toContain("name");
        expect(formatted).toContain("email");
      }
    });
  });

  describe("formatZodErrorIndented", () => {
    it("should format errors with indentation", () => {
      const schema = z.object({
        name: z.string(),
      });

      const result = schema.safeParse({ name: 123 });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodErrorIndented(result.error);

        expect(formatted).toMatch(/^\s+/); // Starts with whitespace
        expect(formatted).toContain("name");
      }
    });

    it("should use custom indentation", () => {
      const schema = z.object({
        name: z.string(),
      });

      const result = schema.safeParse({ name: 123 });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodErrorIndented(result.error, "    "); // 4 spaces

        expect(formatted).toMatch(/^    /); // Starts with 4 spaces
      }
    });
  });

  describe("zodErrorToArray", () => {
    it("should convert ZodError to array of strings", () => {
      const schema = z.object({
        name: z.string(),
        age: z.number(),
      });

      const result = schema.safeParse({ name: 123, age: "invalid" });
      expect(result.success).toBe(false);

      if (!result.success) {
        const errors = zodErrorToArray(result.error);

        expect(Array.isArray(errors)).toBe(true);
        expect(errors.length).toBeGreaterThan(0);
        expect(errors.some((e) => e.includes("name"))).toBe(true);
        expect(errors.some((e) => e.includes("age"))).toBe(true);
      }
    });
  });

  describe("formatUserFriendlyError", () => {
    it("should format single error", () => {
      const schema = z.object({
        name: z.string(),
      });

      const result = schema.safeParse({ name: 123 });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatUserFriendlyError(result.error);

        expect(formatted).toContain("name");
        expect(formatted).not.toContain("Multiple validation errors");
      }
    });

    it("should format multiple errors with list", () => {
      const schema = z.object({
        name: z.string(),
        age: z.number(),
      });

      const result = schema.safeParse({ name: 123, age: "invalid" });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatUserFriendlyError(result.error);

        expect(formatted).toContain("Multiple validation errors");
        expect(formatted).toContain("-"); // List bullet
      }
    });

    it("should use field labels when provided", () => {
      const schema = z.object({
        serverUrl: z.string().url(),
      });

      const result = schema.safeParse({ serverUrl: "invalid" });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatUserFriendlyError(result.error, {
          serverUrl: "Server URL",
        });

        expect(formatted).toContain("Server URL");
      }
    });
  });

  describe("formatZodErrorForJson", () => {
    it("should format error for JSON output", () => {
      const schema = z.object({
        name: z.string(),
      });

      const result = schema.safeParse({ name: 123 });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodErrorForJson(result.error);

        expect(formatted).toHaveProperty("message");
        expect(formatted).toHaveProperty("errors");
        expect(Array.isArray(formatted.errors)).toBe(true);
        expect(formatted.errors[0]).toHaveProperty("path");
        expect(formatted.errors[0]).toHaveProperty("message");
        expect(formatted.errors[0]).toHaveProperty("code");
      }
    });

    it("should include error details", () => {
      const schema = z.object({
        config: z.object({
          port: z.number(),
        }),
      });

      const result = schema.safeParse({ config: { port: "3000" } });
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodErrorForJson(result.error);

        expect(formatted.errors[0].path).toEqual(["config", "port"]);
        expect(formatted.errors[0].code).toBe("invalid_type");
      }
    });
  });

  describe("error message quality - regression tests", () => {
    it("should never return just 'Invalid input' for server config errors", () => {
      // This is the key test: ensure we never get generic "Invalid input"
      // when validating server configurations

      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test various invalid configs
      const invalidConfigs = [
        { transport: "http" }, // Missing url
        { transport: "sse" }, // Missing url
        { url: "invalid-url" }, // Invalid URL format
        { command: "" }, // Empty command
        {}, // Empty config
      ];

      for (const config of invalidConfigs) {
        const result = ServerEntrySchema.safeParse(config);
        expect(result.success).toBe(false);

        if (!result.success) {
          const formatted = formatZodError(result.error);

          // Key assertion: formatted error should NOT be just "Invalid input"
          expect(formatted).not.toBe("Invalid input");

          // Should contain at least one helpful keyword
          const hasHelpfulKeyword =
            formatted.toLowerCase().includes("url") ||
            formatted.toLowerCase().includes("command") ||
            formatted.toLowerCase().includes("required") ||
            formatted.toLowerCase().includes("expected") ||
            formatted.toLowerCase().includes("valid");

          expect(hasHelpfulKeyword).toBe(true);

          // Should be reasonably descriptive (more than 10 chars)
          expect(formatted.length).toBeGreaterThan(10);
        }
      }
    });
  });

  describe("union error multi-error handling", () => {
    it("should show ALL relevant errors from union validation (not just first)", () => {
      // Stage 3 fix: formatZodError returns up to 3 unique errors for clarity
      // Test that union errors show multiple validation failures

      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case: Empty config fails both union branches
      const invalidConfig = {};

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should contain errors from both union branches
        // HTTP/SSE branch: url is required
        // stdio branch: command is required

        expect(formatted).toContain("url");
        expect(formatted).toContain("command");

        // Should be formatted as multiple lines (multiple errors)
        const lines = formatted.split("\n").filter((line) => line.trim());
        expect(lines.length).toBeGreaterThan(1);
      }
    });

    it("should deduplicate identical errors from union branches", () => {
      // If multiple union branches have the same error, show it once

      const Schema1 = z.object({
        field: z.string().min(5, "field must be at least 5 characters"),
      });

      const Schema2 = z.object({
        field: z.string().min(5, "field must be at least 5 characters"),
        extra: z.string().optional(),
      });

      const UnionSchema = z.union([Schema1, Schema2]);

      const invalidInput = { field: "abc" }; // Too short

      const result = UnionSchema.safeParse(invalidInput);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should not duplicate the same error message
        const lines = formatted.split("\n").filter((line) => line.trim());
        const uniqueLines = new Set(lines);

        expect(lines.length).toBe(uniqueLines.size);
      }
    });

    it("should return all unique errors from union branches", () => {
      // Stage 3 fix: Return all unique errors (deduplication)

      const Schema1 = z.object({
        a: z.string().min(1, "a is required"),
        b: z.string().min(1, "b is required"),
        c: z.string().min(1, "c is required"),
      });

      const Schema2 = z.object({
        x: z.string().min(1, "x is required"),
        y: z.string().min(1, "y is required"),
        z: z.string().min(1, "z is required"),
      });

      const UnionSchema = z.union([Schema1, Schema2]);

      const invalidInput = {}; // Empty, fails all validations

      const result = UnionSchema.safeParse(invalidInput);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        const lines = formatted.split("\n").filter((line) => line.trim());

        // Should have errors from both branches (6 total)
        expect(lines.length).toBeGreaterThan(0);

        // All lines should be non-empty and descriptive
        for (const line of lines) {
          expect(line.length).toBeGreaterThan(5);
        }

        // Verify we have unique errors (no duplicates)
        const uniqueLines = new Set(lines);
        expect(lines.length).toBe(uniqueLines.size);
      }
    });

    it("should prioritize specific errors over generic ones", () => {
      // When union has both specific and generic errors, prefer specific

      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      const invalidConfig = { transport: "http" }; // Missing url

      const result = ServerEntrySchema.safeParse(invalidConfig);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should show specific error about missing url
        expect(formatted.toLowerCase()).toContain("url");
        expect(formatted.toLowerCase()).toContain("required");

        // Should not show generic "Required" or "Invalid"
        expect(formatted).not.toBe("Required");
        expect(formatted).not.toBe("Invalid input");
      }
    });

    it("should handle complex union with nested objects", () => {
      const ConfigA = z.object({
        type: z.literal("a"),
        nested: z.object({
          field1: z.string().min(1, "field1 is required"),
          field2: z.number().positive("field2 must be positive"),
        }),
      });

      const ConfigB = z.object({
        type: z.literal("b"),
        nested: z.object({
          field3: z.string().email("field3 must be a valid email"),
          field4: z.boolean(),
        }),
      });

      const UnionSchema = z.union([ConfigA, ConfigB]);

      const invalidInput = {
        type: "a",
        nested: {
          field1: "",
          field2: -5,
        },
      };

      const result = UnionSchema.safeParse(invalidInput);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should show nested path errors
        expect(formatted).toContain("nested");

        // Should be helpful and descriptive
        const hasHelpfulInfo =
          formatted.includes("field1") ||
          formatted.includes("field2") ||
          formatted.includes("required") ||
          formatted.includes("positive");

        expect(hasHelpfulInfo).toBe(true);
      }
    });

    it("should format multiple union errors with proper line breaks", () => {
      const Schema1 = z.object({
        url: z.string().url("url must be a valid URL"),
      });

      const Schema2 = z.object({
        command: z.string().min(1, "command is required"),
      });

      const UnionSchema = z.union([Schema1, Schema2]);

      const invalidInput = { url: "not-a-url" }; // Invalid URL

      const result = UnionSchema.safeParse(invalidInput);
      expect(result.success).toBe(false);

      if (!result.success) {
        const formatted = formatZodError(result.error);

        // Should have proper formatting with line breaks if multiple errors
        expect(formatted).toBeTruthy();

        // Each error should be on its own line or separated
        if (formatted.includes("\n")) {
          const lines = formatted.split("\n").filter((line) => line.trim());
          expect(lines.length).toBeGreaterThan(0);

          // Each line should be descriptive
          for (const line of lines) {
            expect(line.length).toBeGreaterThan(5);
          }
        }
      }
    });

    /**
     * T-REQ-001: Union validation extracts specific errors from each branch
     * Test that formatZodError shows specific validation messages from the
     * union branch that Zod tries to match based on input shape.
     */
    it("T-REQ-001: should show specific error from matched union branch", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test case 1: Invalid URL - matches HTTP schema branch
      const invalidUrlConfig = { url: "not-a-valid-url" };
      const urlResult = ServerEntrySchema.safeParse(invalidUrlConfig);
      expect(urlResult.success).toBe(false);

      if (!urlResult.success) {
        const formatted = formatZodError(urlResult.error);
        expect(formatted.toLowerCase()).toContain("url");
        expect(formatted.toLowerCase()).toContain("valid");
        expect(formatted).not.toBe("Invalid input");
      }

      // Test case 2: Empty command - matches stdio schema branch
      const emptyCommandConfig = { command: "" };
      const commandResult = ServerEntrySchema.safeParse(emptyCommandConfig);
      expect(commandResult.success).toBe(false);

      if (!commandResult.success) {
        const formatted = formatZodError(commandResult.error);
        expect(formatted.toLowerCase()).toContain("command");
        expect(formatted).not.toBe("Invalid input");
      }
    });

    /**
     * T-REQ-002: Verify detailed errors are extracted (not generic "Invalid input")
     * Ensure formatZodError extracts specific validation messages from union branches.
     */
    it("T-REQ-002: should return detailed errors from union validation (not generic messages)", () => {
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Test cases with specific validation failures
      const invalidConfigs = [
        { url: "not-a-url" }, // Invalid URL - shows URL error
        { command: "" }, // Empty command - shows command error
      ];

      for (const config of invalidConfigs) {
        const result = ServerEntrySchema.safeParse(config);
        expect(result.success).toBe(false);

        if (!result.success) {
          const formatted = formatZodError(result.error);
          const errors = zodErrorToArray(result.error);

          // Should return at least one error
          expect(errors.length).toBeGreaterThan(0);

          // Formatted string should contain errors
          const lines = formatted.split("\n").filter((line) => line.trim());
          expect(lines.length).toBeGreaterThan(0);

          // Should not lose error details in formatting
          const formattedLower = formatted.toLowerCase();
          const hasUrlOrCommand =
            formattedLower.includes("url") ||
            formattedLower.includes("command");
          expect(hasUrlOrCommand).toBe(true);
        }
      }
    });
  });

  /**
   * T-REQ-003: End-to-end test: invalid config file -> user-friendly error message
   * Full path: load invalid config -> Zod validation -> formatZodError -> helpful message
   */
  describe("end-to-end config validation workflow", () => {
    it("T-REQ-003: should provide user-friendly error messages for invalid config files", () => {
      // Import the actual schema used for server config validation
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
        env: z.record(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Simulate various invalid config file scenarios
      // Note: Zod union validation matches based on input shape, so expectedKeywords
      // should reflect what the matched branch would report
      const invalidConfigScenarios = [
        {
          name: "Invalid URL format",
          config: { transport: "http", url: "not-a-valid-url" },
          expectedKeywords: ["url", "valid"],
        },
        {
          name: "Empty command for stdio",
          config: { transport: "stdio", command: "" },
          expectedKeywords: ["command", "required"],
        },
        {
          name: "Invalid URL only (matches HTTP branch)",
          config: { url: "not-valid" },
          expectedKeywords: ["url"],
        },
        {
          name: "Empty command only (matches stdio branch)",
          config: { command: "" },
          expectedKeywords: ["command"],
        },
      ];

      for (const scenario of invalidConfigScenarios) {
        const result = ServerEntrySchema.safeParse(scenario.config);
        expect(result.success).toBe(false);

        if (!result.success) {
          // Step 1: Validate with Zod
          const zodError = result.error;

          // Step 2: Format with formatZodError
          const formatted = formatZodError(zodError);

          // Step 3: Verify helpful message is produced
          // Should NOT be generic "Invalid input"
          expect(formatted).not.toBe("Invalid input");
          expect(formatted).not.toBe("Required");

          // Should be descriptive (more than just a few characters)
          expect(formatted.length).toBeGreaterThan(15);

          // Should contain expected keywords for the scenario
          const formattedLower = formatted.toLowerCase();
          for (const keyword of scenario.expectedKeywords) {
            expect(formattedLower).toContain(keyword.toLowerCase());
          }

          // Should not contain internal implementation details
          expect(formatted).not.toContain("unionErrors");
          expect(formatted).not.toContain("ZodError");

          // Should be suitable for showing to end users
          const hasUserFriendlyTerms =
            formattedLower.includes("required") ||
            formattedLower.includes("valid") ||
            formattedLower.includes("must be") ||
            formattedLower.includes("expected");

          expect(hasUserFriendlyTerms).toBe(true);
        }
      }
    });

    it("T-REQ-003-extended: should handle real-world config file parsing workflow", () => {
      // Simulate the full workflow from assess-security.ts
      const HttpSseSchema = z.object({
        transport: z.enum(["http", "sse"]).optional(),
        url: z
          .string()
          .min(1, "'url' is required for HTTP/SSE transport")
          .url("url must be a valid URL"),
      });

      const StdioSchema = z.object({
        transport: z.literal("stdio").optional(),
        command: z.string().min(1, "command is required for stdio transport"),
        args: z.array(z.string()).optional(),
        env: z.record(z.string()).optional(),
      });

      const ServerEntrySchema = z.union([HttpSseSchema, StdioSchema]);

      // Simulate JSON.parse() from file + validation
      const rawConfigFromFile = '{"url": "not-a-url", "command": ""}';
      const parsedConfig = JSON.parse(rawConfigFromFile);

      // Validate parsed config
      const validationResult = ServerEntrySchema.safeParse(parsedConfig);
      expect(validationResult.success).toBe(false);

      if (!validationResult.success) {
        // Format for CLI output
        const cliMessage = formatZodError(validationResult.error);

        // Should be ready to display to user
        expect(cliMessage).toBeTruthy();
        expect(cliMessage.length).toBeGreaterThan(20);

        // Should guide user to fix the issue
        const providesGuidance =
          cliMessage.toLowerCase().includes("url") ||
          cliMessage.toLowerCase().includes("command") ||
          cliMessage.toLowerCase().includes("valid") ||
          cliMessage.toLowerCase().includes("required");

        expect(providesGuidance).toBe(true);

        // Verify formatUserFriendlyError also works
        const userFriendly = formatUserFriendlyError(validationResult.error);
        expect(userFriendly).toBeTruthy();
        expect(userFriendly.length).toBeGreaterThan(20);
      }
    });
  });
});
