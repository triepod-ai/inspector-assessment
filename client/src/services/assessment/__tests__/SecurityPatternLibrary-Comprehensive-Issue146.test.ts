/**
 * Security Pattern Library - Comprehensive Pattern Tests (Issue #146)
 *
 * Comprehensive test coverage for all ERROR_CONTEXT_PATTERNS and SUCCESS_CONTEXT_PATTERNS.
 * Ensures every pattern correctly detects its intended error/success indicators.
 *
 * Pattern coverage:
 * - ERROR_CONTEXT_PATTERNS: 12 patterns
 * - SUCCESS_CONTEXT_PATTERNS: 9 patterns
 * - Edge cases: empty strings, multiple patterns, case sensitivity
 */

import {
  ERROR_CONTEXT_PATTERNS,
  SUCCESS_CONTEXT_PATTERNS,
  hasErrorContext,
  hasSuccessContext,
  isPayloadInErrorContext,
} from "../modules/securityTests/SecurityPatternLibrary";

describe("SecurityPatternLibrary - Comprehensive Pattern Coverage (Issue #146)", () => {
  // ==========================================================================
  // ERROR_CONTEXT_PATTERNS - All 12 patterns
  // ==========================================================================

  describe("ERROR_CONTEXT_PATTERNS - All 12 patterns", () => {
    it("Pattern 1: failed to get/read/load/access/process/fetch/retrieve/find", () => {
      const testCases = [
        "Failed to get resource",
        "Failed to read file",
        "Failed to load data",
        "Failed to access path",
        "Failed to process request",
        "Failed to fetch resource",
        "Failed to retrieve data",
        "Failed to find item",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 2: error: response status: XXX", () => {
      expect(hasErrorContext("Error: Response status: 404")).toBe(true);
      expect(hasErrorContext("Error: Response status: 500")).toBe(true);
      expect(hasErrorContext("Error: Response status: 403")).toBe(true);
    });

    it("Pattern 3: could not/cannot/unable to find/locate/access/read/get/load", () => {
      const testCases = [
        "Could not find resource",
        "Cannot locate file",
        "Unable to access path",
        "Could not read data",
        "Cannot get resource",
        "Unable to load file",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 4: not found/doesn't exist/no such/does not exist", () => {
      const testCases = [
        "Resource not found",
        "File doesn't exist",
        "No such file or directory",
        "Item does not exist",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 5: error loading/reading/processing/fetching/accessing", () => {
      const testCases = [
        "Error loading resource",
        "Error reading file",
        "Error processing data",
        "Error fetching content",
        "Error accessing path",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 6: operation/request failed", () => {
      expect(hasErrorContext("Operation failed")).toBe(true);
      expect(hasErrorContext("Request failed")).toBe(true);
      expect(hasErrorContext("The operation failed due to error")).toBe(true);
    });

    it("Pattern 7: invalid path/file/resource/input/parameter", () => {
      const testCases = [
        "Invalid path provided",
        "Invalid file format",
        "Invalid resource identifier",
        "Invalid input",
        "Invalid parameter value",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 8: rejected/refused/denied", () => {
      const testCases = [
        "Request rejected",
        "Access refused",
        "Operation denied",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 9: resource/file/path is invalid/not allowed", () => {
      const testCases = [
        "Resource is invalid",
        "File is not allowed",
        "Path invalid",
        "Resource not allowed",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("Pattern 10: access denied/forbidden", () => {
      expect(hasErrorContext("Access denied")).toBe(true);
      expect(hasErrorContext("Access forbidden")).toBe(true);
    });

    it("Pattern 11: permission denied", () => {
      expect(hasErrorContext("Permission denied")).toBe(true);
      expect(hasErrorContext("Permission denied for path /etc/passwd")).toBe(
        true,
      );
    });

    it("Pattern 12: HTTP status codes (4XX/5XX) with error indicators", () => {
      const testCases = [
        "404 error",
        "404 not found",
        "400 bad request",
        "401 unauthorized",
        "403 forbidden",
        "500 error",
        "503 error",
      ];

      testCases.forEach((text) => {
        expect(hasErrorContext(text)).toBe(true);
      });
    });

    it("should NOT detect error context in success responses", () => {
      const successResponses = [
        "File contents: root:x:0:0",
        "Successfully retrieved data",
        "Operation completed",
        "Data returned successfully",
      ];

      successResponses.forEach((text) => {
        expect(hasErrorContext(text)).toBe(false);
      });
    });
  });

  // ==========================================================================
  // SUCCESS_CONTEXT_PATTERNS - All 9 patterns
  // ==========================================================================

  describe("SUCCESS_CONTEXT_PATTERNS - All 9 patterns", () => {
    it("Pattern 1: successfully/completed + read/loaded/accessed/executed/retrieved", () => {
      const testCases = [
        "Successfully read file",
        "Successfully loaded data",
        "Successfully accessed resource",
        "Successfully executed command",
        "Successfully retrieved records",
        "Completed read operation",
        "Completed loaded process",
      ];

      testCases.forEach((text) => {
        expect(hasSuccessContext(text)).toBe(true);
      });
    });

    it("Pattern 2: file contents:", () => {
      expect(hasSuccessContext("File contents: root:x:0:0")).toBe(true);
      expect(hasSuccessContext("File content: data here")).toBe(true);
    });

    it("Pattern 3: data retrieved", () => {
      expect(hasSuccessContext("Data retrieved successfully")).toBe(true);
      expect(hasSuccessContext("Data retrieved from database")).toBe(true);
    });

    it("Pattern 4: execution result:", () => {
      expect(hasSuccessContext("Execution result: uid=0(root)")).toBe(true);
      expect(hasSuccessContext("Execution result: command output")).toBe(true);
    });

    it("Pattern 5: output:", () => {
      expect(hasSuccessContext("Output: command executed")).toBe(true);
      expect(hasSuccessContext("Output: process completed")).toBe(true);
    });

    it("Pattern 6: results:/result:", () => {
      expect(hasSuccessContext("Results: 42 records found")).toBe(true);
      expect(hasSuccessContext("Result: operation completed")).toBe(true);
    });

    it("Pattern 7: returned data/content/results", () => {
      const testCases = [
        "Returned data from API",
        "Returned content successfully",
        "Returned results to client",
      ];

      testCases.forEach((text) => {
        expect(hasSuccessContext(text)).toBe(true);
      });
    });

    it("Pattern 8: read X bytes", () => {
      expect(hasSuccessContext("Read 1024 bytes from file")).toBe(true);
      expect(hasSuccessContext("Read 42 bytes")).toBe(true);
    });

    it("Pattern 9: fetched from/data", () => {
      expect(hasSuccessContext("Fetched from database")).toBe(true);
      expect(hasSuccessContext("Fetched data successfully")).toBe(true);
    });

    it("should NOT detect success context in error responses", () => {
      const errorResponses = [
        "Failed to get resource - 404 not found",
        "Error: could not access file",
        "Permission denied",
        "Invalid input parameter",
      ];

      errorResponses.forEach((text) => {
        expect(hasSuccessContext(text)).toBe(false);
      });
    });
  });

  // ==========================================================================
  // Edge Cases - Multiple patterns, empty strings, case sensitivity
  // ==========================================================================

  describe("Edge cases - hasErrorContext", () => {
    it("should detect multiple error patterns in single response", () => {
      const response =
        "Failed to get resource ../../../etc/passwd. Error: Response status: 404. File not found.";

      expect(hasErrorContext(response)).toBe(true);
      // Contains: "Failed to get", "Error: Response status: 404", "not found"
    });

    it("should return false for empty string", () => {
      expect(hasErrorContext("")).toBe(false);
    });

    it("should be case-insensitive", () => {
      expect(hasErrorContext("FAILED TO GET RESOURCE")).toBe(true);
      expect(hasErrorContext("permission DENIED")).toBe(true);
      expect(hasErrorContext("Not Found")).toBe(true);
    });

    it("should NOT match partial words", () => {
      // "error" should match as word boundary, not substring
      expect(hasErrorContext("terror movie")).toBe(false);
      expect(hasErrorContext("errorboundary component")).toBe(false);
    });
  });

  describe("Edge cases - hasSuccessContext", () => {
    it("should detect multiple success patterns in single response", () => {
      const response =
        "Successfully read file. File contents: root:x:0:0. Output: command executed. Read 1024 bytes.";

      expect(hasSuccessContext(response)).toBe(true);
      // Contains: "Successfully read", "File contents:", "Output:", "Read X bytes"
    });

    it("should return false for empty string", () => {
      expect(hasSuccessContext("")).toBe(false);
    });

    it("should be case-insensitive", () => {
      expect(hasSuccessContext("SUCCESSFULLY READ FILE")).toBe(true);
      expect(hasSuccessContext("File Contents: DATA")).toBe(true);
      expect(hasSuccessContext("EXECUTION RESULT: OUTPUT")).toBe(true);
    });
  });

  // ==========================================================================
  // isPayloadInErrorContext - Comprehensive edge cases
  // ==========================================================================

  describe("isPayloadInErrorContext - Edge cases", () => {
    it("should detect payload in error context", () => {
      const response =
        "Failed to get dataflow ../../../etc/passwd schema file. Error: Response status: 404";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should return false if no error context (payload reflected in success)", () => {
      const response = "File contents: ../../../etc/passwd";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });

    it("should return false if payload not reflected (error context but no payload)", () => {
      const response = "Failed to get resource. Error: Response status: 404";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });

    it("should handle empty payload string", () => {
      const response = "Failed to get resource. Error: Response status: 404";
      const payload = "";

      // Empty payload is always "contained" in any string
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should handle empty response string", () => {
      const response = "";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });

    it("should be case-insensitive for payload matching", () => {
      const response = "Failed to get RESOURCE: ../../../ETC/PASSWD";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should be case-insensitive for error pattern matching", () => {
      const response =
        "FAILED TO GET RESOURCE: ../../../etc/passwd - NOT FOUND";
      const payload = "../../../etc/passwd";

      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should handle special regex characters in payload", () => {
      const response = "Failed to get: test.file.txt - not found";
      const payload = "test.file.txt"; // Contains regex metacharacters

      // Should treat payload as literal string, not regex
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should handle payload that is substring of longer string", () => {
      const response =
        "Failed to get resource: /path/to/../../../etc/passwd/subdir";
      const payload = "../../../etc/passwd";

      // Payload is contained as substring
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });
  });

  // ==========================================================================
  // Real-world scenarios - Both success and error patterns
  // ==========================================================================

  describe("Real-world scenarios", () => {
    it("should handle ambiguous response with both success and error indicators", () => {
      const response =
        "Operation completed but error occurred: Failed to get secondary resource. Results: partial data returned.";

      // Both patterns present
      expect(hasSuccessContext(response)).toBe(true); // "Results:", "completed"
      expect(hasErrorContext(response)).toBe(true); // "error", "Failed to get"
    });

    it("should handle JSON error response", () => {
      const response = JSON.stringify({
        error: "Failed to get resource",
        status: 404,
        message: "File not found: ../../../etc/passwd",
      });

      expect(hasErrorContext(response)).toBe(true);
      expect(isPayloadInErrorContext(response, "../../../etc/passwd")).toBe(
        true,
      );
    });

    it("should handle JSON success response", () => {
      const response = JSON.stringify({
        status: "success",
        data: "File contents: root:x:0:0:root:/root:/bin/bash",
        bytesRead: 45,
      });

      expect(hasSuccessContext(response)).toBe(true);
    });

    it("should handle multiline error response", () => {
      const response = `
        Failed to get resource.
        Error: Response status: 404
        Resource not found: ../../../etc/passwd
        Operation failed.
      `;

      expect(hasErrorContext(response)).toBe(true);
      expect(isPayloadInErrorContext(response, "../../../etc/passwd")).toBe(
        true,
      );
    });

    it("should handle multiline success response", () => {
      const response = `
        Operation successfully completed.
        File contents:
        root:x:0:0:root:/root:/bin/bash
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        Read 142 bytes.
      `;

      expect(hasSuccessContext(response)).toBe(true);
    });
  });
});
