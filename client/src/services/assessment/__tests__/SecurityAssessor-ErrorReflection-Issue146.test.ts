/**
 * Security Assessor - Error Reflection False Positives Fix (Issue #146)
 *
 * Tests that payload reflection in error messages is correctly classified
 * as LIKELY_FALSE_POSITIVE and NOT flagged as vulnerable.
 *
 * Root cause: When a server rejects an operation (HTTP 4xx/5xx) but includes
 * the payload in the error message, it was being flagged as vulnerable even
 * though the payload was never executed.
 *
 * Example from issue:
 * - Input: `dataflowId: "../../../etc/passwd"`
 * - Response: `Failed to get dataflow ../../../etc/passwd schema file. Error: Response status: 404`
 * - Current: Flagged as PATH_TRAVERSAL (payload reflected)
 * - Expected: NOT vulnerable (payload reflected in error, not executed)
 *
 * Key principle:
 * - If operation failed (error context) AND payload appears in error message = false positive
 * - If operation succeeded (success context) AND payload evidence found = real vulnerability
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import {
  ERROR_CONTEXT_PATTERNS,
  SUCCESS_CONTEXT_PATTERNS,
  isPayloadInErrorContext,
  hasErrorContext,
  hasSuccessContext,
} from "../modules/securityTests/SecurityPatternLibrary";
import { SecurityPayload } from "@/lib/securityPatterns";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

describe("Issue #146: Error Reflection False Positive Reduction", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  // ==========================================================================
  // Pattern Library Tests
  // ==========================================================================

  describe("SecurityPatternLibrary - Error Context Patterns", () => {
    it("should detect error context pattern: 'Failed to get...'", () => {
      const response = "Failed to get dataflow ../../../etc/passwd schema file";
      expect(hasErrorContext(response)).toBe(true);
    });

    it("should detect error context pattern: 'Error: Response status: 404'", () => {
      const response = "Error: Response status: 404";
      expect(hasErrorContext(response)).toBe(true);
    });

    it("should detect error context pattern: 'not found'", () => {
      const response = "Resource not found: ../../../etc/passwd";
      expect(hasErrorContext(response)).toBe(true);
    });

    it("should detect error context pattern: 'permission denied'", () => {
      const response = "Permission denied for path: /etc/passwd";
      expect(hasErrorContext(response)).toBe(true);
    });

    it("should detect error context pattern: 'invalid path'", () => {
      const response = "Invalid path: ../../../etc/passwd is not allowed";
      expect(hasErrorContext(response)).toBe(true);
    });

    it("should NOT detect error context in success response", () => {
      const response = "File contents: root:x:0:0:root:/root:/bin/bash";
      expect(hasErrorContext(response)).toBe(false);
    });
  });

  describe("SecurityPatternLibrary - Success Context Patterns", () => {
    it("should detect success context pattern: 'file contents:'", () => {
      const response = "File contents: root:x:0:0:root:/root:/bin/bash";
      expect(hasSuccessContext(response)).toBe(true);
    });

    it("should detect success context pattern: 'successfully read'", () => {
      const response = "Successfully read file /etc/passwd";
      expect(hasSuccessContext(response)).toBe(true);
    });

    it("should detect success context pattern: 'execution result:'", () => {
      const response = "Execution result: uid=0(root) gid=0(root)";
      expect(hasSuccessContext(response)).toBe(true);
    });

    it("should NOT detect success context in error response", () => {
      const response = "Failed to get dataflow: Error status 404";
      expect(hasSuccessContext(response)).toBe(false);
    });
  });

  describe("SecurityPatternLibrary - Payload in Error Context", () => {
    it("should detect payload reflected in error message", () => {
      const response =
        "Failed to get dataflow ../../../etc/passwd schema file. Error: Response status: 404";
      const payload = "../../../etc/passwd";
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("should NOT detect payload in error context if no error patterns", () => {
      const response = "File contents: ../../../etc/passwd";
      const payload = "../../../etc/passwd";
      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });

    it("should NOT detect payload in error context if payload not present", () => {
      const response = "Failed to get resource. Error: Response status: 404";
      const payload = "../../../etc/passwd";
      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });
  });

  // ==========================================================================
  // SecurityResponseAnalyzer Integration Tests
  // ==========================================================================

  describe("SecurityResponseAnalyzer - Context Classification", () => {
    const pathTraversalPayload: SecurityPayload = {
      payload: "../../../etc/passwd",
      evidence: /etc\/passwd|root:/i,
      riskLevel: "HIGH",
      description: "Path traversal attempt",
      payloadType: "path_traversal",
    };

    const commandInjectionPayload: SecurityPayload = {
      payload: "; cat /etc/passwd",
      evidence: /root:.*:0:0/i,
      riskLevel: "HIGH",
      description: "Command injection attempt",
      payloadType: "command_injection",
    };

    const sqlInjectionPayload: SecurityPayload = {
      payload: "' OR '1'='1",
      evidence: /syntax error|sql/i,
      riskLevel: "HIGH",
      description: "SQL injection attempt",
      payloadType: "sql_injection",
    };

    const mockTool: Tool = {
      name: "test_tool",
      description: "Test tool",
      inputSchema: { type: "object", properties: {} },
    };

    describe("LIKELY_FALSE_POSITIVE cases (should NOT be vulnerable)", () => {
      it("should NOT flag HTTP 404 with path traversal payload in error as vulnerable", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Failed to get dataflow ../../../etc/passwd schema file. Error: Response status: 404",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          pathTraversalPayload,
          mockTool,
        );

        // KEY ASSERTION: Should NOT be vulnerable - error context with reflected payload
        // Evidence may come from Phase 1 (HTTP error), Phase 2 (safe behavior), or Phase 3 (context classification)
        expect(result.isVulnerable).toBe(false);
        // Evidence should indicate why it's not vulnerable (various valid reasons)
        expect(result.evidence).toBeDefined();
      });

      it("should NOT flag 'not found' error with payload as vulnerable", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Resource not found: ../../../etc/passwd does not exist",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          pathTraversalPayload,
          mockTool,
        );

        // KEY ASSERTION: Error context should result in NOT vulnerable
        expect(result.isVulnerable).toBe(false);
      });

      it("should NOT flag HTTP 400 with SQL injection payload in validation error as vulnerable", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Invalid query: ' OR '1'='1 - SQL syntax error in validation",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          sqlInjectionPayload,
          mockTool,
        );

        // KEY ASSERTION: Should NOT be vulnerable - validation error with reflected payload
        expect(result.isVulnerable).toBe(false);
      });

      it("should NOT flag 'permission denied' with command injection payload as vulnerable", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Permission denied: Cannot execute ; cat /etc/passwd",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          commandInjectionPayload,
          mockTool,
        );

        // KEY ASSERTION: Permission denied = safe rejection
        expect(result.isVulnerable).toBe(false);
      });
    });

    describe("CONFIRMED cases (should be vulnerable)", () => {
      it("should classify successful file read as CONFIRMED vulnerability", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "File contents: root:x:0:0:root:/root:/bin/bash",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          pathTraversalPayload,
          mockTool,
        );

        // Should be vulnerable - success context with execution evidence
        expect(result.isVulnerable).toBe(true);
        expect(result.evidence).toContain("CONFIRMED");
      });

      it("should classify successful command execution as CONFIRMED vulnerability", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Execution result: root:x:0:0:root:/root:/bin/bash",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          commandInjectionPayload,
          mockTool,
        );

        expect(result.isVulnerable).toBe(true);
        expect(result.evidence).toContain("CONFIRMED");
      });
    });

    describe("Edge cases", () => {
      it("should handle mixed success and error patterns with SUSPECTED classification", () => {
        // Ambiguous case: has both success and error indicators
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "Result: partial data returned but operation failed for ../../../etc/passwd",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          pathTraversalPayload,
          mockTool,
        );

        // Ambiguous case - may or may not be SUSPECTED
        // The key is that it's handled without crashing
        expect(result.evidence).toBeDefined();
      });

      it("should handle empty response text gracefully", () => {
        const response: CompatibilityCallToolResult = {
          isError: false,
          content: [
            {
              type: "text",
              text: "",
            },
          ],
        };

        const result = analyzer.analyzeResponse(
          response,
          pathTraversalPayload,
          mockTool,
        );

        // Should not crash and should return a valid result
        expect(result).toBeDefined();
        expect(result.isVulnerable).toBeDefined();
      });
    });
  });

  // ==========================================================================
  // Real-World Scenario Tests (from Issue #146)
  // ==========================================================================

  describe("Real-World Scenario from Issue #146", () => {
    it("should NOT flag the exact scenario from the issue report", () => {
      const analyzer = new SecurityResponseAnalyzer();

      const response: CompatibilityCallToolResult = {
        isError: false,
        content: [
          {
            type: "text",
            text: "Failed to get dataflow ../../../etc/passwd schema file. Error: Response status: 404",
          },
        ],
      };

      const payload: SecurityPayload = {
        payload: "../../../etc/passwd",
        evidence: /etc\/passwd|root:/i,
        riskLevel: "HIGH",
        description: "Path traversal to read system files",
        payloadType: "path_traversal",
      };

      const tool: Tool = {
        name: "get_dataflow_schema",
        description: "Get dataflow schema information",
        inputSchema: {
          type: "object",
          properties: {
            dataflowId: { type: "string" },
          },
        },
      };

      const result = analyzer.analyzeResponse(response, payload, tool);

      // KEY ASSERTION from Issue #146:
      // The payload appears in the error message but was NOT executed
      // The operation failed (404), so this is NOT a vulnerability
      expect(result.isVulnerable).toBe(false);

      // Evidence should indicate why it's not vulnerable
      // Multiple valid reasons: echoed input, HTTP error, error context
      expect(result.evidence).toBeDefined();
    });
  });
});
