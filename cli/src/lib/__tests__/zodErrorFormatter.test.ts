/**
 * Tests for Zod Error Formatting Utilities
 *
 * Validates the error formatting functions for CLI-friendly output.
 *
 * @module cli/lib/__tests__/zodErrorFormatter
 */

// Uses Jest globals (describe, test, expect)
import { jest } from "@jest/globals";
import { z, ZodError } from "zod";
import {
  formatZodIssue,
  formatZodError,
  formatZodErrorIndented,
  printZodErrorForCli,
  zodErrorToArray,
  formatZodErrorForJson,
  formatUserFriendlyError,
} from "../zodErrorFormatter.js";

// Helper to create a ZodError with specific issues
function createZodError(
  issues: Array<{
    path: (string | number)[];
    message: string;
    code?: string;
  }>,
): ZodError {
  // Create a schema that will fail and then manipulate the error
  const schema = z.object({ dummy: z.string() });
  const result = schema.safeParse({ dummy: 123 });
  if (!result.success) {
    // Replace the errors with our custom issues
    (result.error as any).issues = issues.map((issue) => ({
      code: issue.code || "custom",
      path: issue.path,
      message: issue.message,
    }));
    return result.error;
  }
  throw new Error("Failed to create ZodError");
}

describe("zodErrorFormatter", () => {
  describe("formatZodIssue", () => {
    test("formats issue with empty path (message only)", () => {
      const issue = { code: "custom" as const, path: [], message: "Required" };
      const result = formatZodIssue(issue as any);
      expect(result).toBe("Required");
    });

    test("formats issue with single-level path", () => {
      const issue = {
        code: "custom" as const,
        path: ["field"],
        message: "Invalid value",
      };
      const result = formatZodIssue(issue as any);
      expect(result).toBe("field: Invalid value");
    });

    test("formats issue with nested path", () => {
      const issue = {
        code: "custom" as const,
        path: ["config", "nested", "field"],
        message: "Must be a string",
      };
      const result = formatZodIssue(issue as any);
      expect(result).toBe("config.nested.field: Must be a string");
    });

    test("formats issue with array index in path", () => {
      const issue = {
        code: "custom" as const,
        path: ["items", 0, "name"],
        message: "Required",
      };
      const result = formatZodIssue(issue as any);
      expect(result).toBe("items.0.name: Required");
    });
  });

  describe("formatZodError", () => {
    test("formats single error", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodError(error);
      expect(result).toBe("field: Invalid value");
    });

    test("formats multiple errors with newlines", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1" },
        { path: ["field2"], message: "Error 2" },
        { path: ["field3"], message: "Error 3" },
      ]);
      const result = formatZodError(error);
      expect(result).toBe("field1: Error 1\nfield2: Error 2\nfield3: Error 3");
    });

    test("handles error with empty path", () => {
      const error = createZodError([{ path: [], message: "Global error" }]);
      const result = formatZodError(error);
      expect(result).toBe("Global error");
    });
  });

  describe("formatZodErrorIndented", () => {
    test("uses default indentation (two spaces)", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodErrorIndented(error);
      expect(result).toBe("  field: Invalid value");
    });

    test("uses custom indentation", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodErrorIndented(error, "\t");
      expect(result).toBe("\tfield: Invalid value");
    });

    test("uses four spaces indentation", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodErrorIndented(error, "    ");
      expect(result).toBe("    field: Invalid value");
    });

    test("applies indent to each line for multiple errors", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1" },
        { path: ["field2"], message: "Error 2" },
      ]);
      const result = formatZodErrorIndented(error, ">> ");
      expect(result).toBe(">> field1: Error 1\n>> field2: Error 2");
    });

    test("uses empty indentation", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodErrorIndented(error, "");
      expect(result).toBe("field: Invalid value");
    });
  });

  describe("printZodErrorForCli", () => {
    let consoleSpy: ReturnType<typeof jest.spyOn>;

    beforeEach(() => {
      consoleSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    });

    afterEach(() => {
      consoleSpy.mockRestore();
    });

    test("prints with context prefix", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      printZodErrorForCli(error, "config file");
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error in config file:\n  field: Invalid value",
      );
    });

    test("prints without context (default prefix)", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      printZodErrorForCli(error);
      expect(consoleSpy).toHaveBeenCalledWith(
        "Validation error:\n  field: Invalid value",
      );
    });

    test("outputs multiple errors with indentation", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1" },
        { path: ["field2"], message: "Error 2" },
      ]);
      printZodErrorForCli(error, "CLI arguments");
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error in CLI arguments:\n  field1: Error 1\n  field2: Error 2",
      );
    });
  });

  describe("zodErrorToArray", () => {
    test("converts single error to array", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = zodErrorToArray(error);
      expect(result).toEqual(["field: Invalid value"]);
    });

    test("converts multiple errors to array", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1" },
        { path: ["field2"], message: "Error 2" },
        { path: ["field3"], message: "Error 3" },
      ]);
      const result = zodErrorToArray(error);
      expect(result).toEqual([
        "field1: Error 1",
        "field2: Error 2",
        "field3: Error 3",
      ]);
    });

    test("returns array preserving order", () => {
      const error = createZodError([
        { path: ["z"], message: "Z error" },
        { path: ["a"], message: "A error" },
        { path: ["m"], message: "M error" },
      ]);
      const result = zodErrorToArray(error);
      expect(result).toEqual(["z: Z error", "a: A error", "m: M error"]);
    });
  });

  describe("formatZodErrorForJson", () => {
    test("includes message field", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value" },
      ]);
      const result = formatZodErrorForJson(error);
      expect(result.message).toBe("Validation failed");
    });

    test("includes errors array with path, message, code", () => {
      const error = createZodError([
        { path: ["field"], message: "Invalid value", code: "invalid_type" },
      ]);
      const result = formatZodErrorForJson(error);
      expect(result.errors).toHaveLength(1);
      expect(result.errors[0]).toEqual({
        path: ["field"],
        message: "Invalid value",
        code: "invalid_type",
      });
    });

    test("preserves path as array with numbers and strings", () => {
      const error = createZodError([
        { path: ["items", 0, "nested", 1, "field"], message: "Error" },
      ]);
      const result = formatZodErrorForJson(error);
      expect(result.errors[0].path).toEqual(["items", 0, "nested", 1, "field"]);
    });

    test("handles multiple errors", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1", code: "too_small" },
        { path: ["field2"], message: "Error 2", code: "invalid_type" },
      ]);
      const result = formatZodErrorForJson(error);
      expect(result.errors).toHaveLength(2);
      expect(result.errors[0].code).toBe("too_small");
      expect(result.errors[1].code).toBe("invalid_type");
    });
  });

  describe("formatUserFriendlyError", () => {
    test("single error returns plain message", () => {
      const error = createZodError([
        { path: ["username"], message: "Required" },
      ]);
      const result = formatUserFriendlyError(error);
      expect(result).toBe("username: Required");
    });

    test("single error with empty path returns message only", () => {
      const error = createZodError([{ path: [], message: "Invalid input" }]);
      const result = formatUserFriendlyError(error);
      expect(result).toBe("Invalid input");
    });

    test("multiple errors returns bulleted list", () => {
      const error = createZodError([
        { path: ["field1"], message: "Error 1" },
        { path: ["field2"], message: "Error 2" },
      ]);
      const result = formatUserFriendlyError(error);
      expect(result).toBe(
        "Multiple validation errors:\n  - field1: Error 1\n  - field2: Error 2",
      );
    });

    test("applies field label mapping", () => {
      const error = createZodError([
        { path: ["serverName"], message: "Required" },
      ]);
      const labels = { serverName: "Server Name" };
      const result = formatUserFriendlyError(error, labels);
      expect(result).toBe("Server Name: Required");
    });

    test("applies labels for multiple errors", () => {
      const error = createZodError([
        { path: ["serverName"], message: "Required" },
        { path: ["configPath"], message: "Invalid path" },
      ]);
      const labels = {
        serverName: "Server Name",
        configPath: "Configuration Path",
      };
      const result = formatUserFriendlyError(error, labels);
      expect(result).toBe(
        "Multiple validation errors:\n  - Server Name: Required\n  - Configuration Path: Invalid path",
      );
    });

    test("falls back to path when no matching label", () => {
      const error = createZodError([
        { path: ["unknownField"], message: "Error" },
      ]);
      const labels = { otherField: "Other Field" };
      const result = formatUserFriendlyError(error, labels);
      expect(result).toBe("unknownField: Error");
    });

    test("handles nested path with labels", () => {
      const error = createZodError([
        { path: ["config", "nested"], message: "Invalid" },
      ]);
      const labels = { "config.nested": "Nested Config" };
      const result = formatUserFriendlyError(error, labels);
      expect(result).toBe("Nested Config: Invalid");
    });
  });
});
