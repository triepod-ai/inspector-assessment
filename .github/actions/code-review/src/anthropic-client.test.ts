import { describe, it, expect, vi, beforeEach } from "vitest";
import { CodeReviewClient } from "./anthropic-client.js";
import type { PRDiff } from "./types.js";
import Anthropic from "@anthropic-ai/sdk";

describe("CodeReviewClient - Pattern Matching (TEST-REQ-001)", () => {
  let client: CodeReviewClient;

  beforeEach(() => {
    client = new CodeReviewClient("test-api-key");
  });

  describe("matchPattern - Happy Path", () => {
    it("should match exact filename", () => {
      const diff: PRDiff = {
        files: [
          {
            filename: "file.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      // This should filter out file.js since *.js matches
      const result = client["reviewDiff"](diff);

      // We're testing that matchPattern uses minimatch internally
      // file.js should match the pattern "*.js" (if we add it to excludePatterns)
      expect(client["matchPattern"]("file.js", "file.js")).toBe(true);
    });

    it("should match single glob pattern", () => {
      expect(client["matchPattern"]("src/index.ts", "src/*.ts")).toBe(true);
      expect(client["matchPattern"]("src/other.ts", "src/*.ts")).toBe(true);
      expect(client["matchPattern"]("lib/index.ts", "src/*.ts")).toBe(false);
    });

    it("should match double glob pattern", () => {
      expect(client["matchPattern"]("dist/foo/bar.js", "dist/**")).toBe(true);
      expect(client["matchPattern"]("dist/a/b/c/d.js", "dist/**")).toBe(true);
      expect(client["matchPattern"]("src/foo/bar.js", "dist/**")).toBe(false);
    });

    it("should match double glob with extension", () => {
      expect(client["matchPattern"]("dist/foo/bar.js", "dist/**/*.js")).toBe(
        true,
      );
      expect(client["matchPattern"]("dist/a/b/c/d.js", "dist/**/*.js")).toBe(
        true,
      );
      expect(client["matchPattern"]("dist/foo/bar.ts", "dist/**/*.js")).toBe(
        false,
      );
    });
  });

  describe("matchPattern - Edge Cases", () => {
    it("should handle multiple consecutive asterisks", () => {
      // minimatch normalizes multiple ** to single **
      expect(client["matchPattern"]("a/b/c/file.js", "**/**/*.js")).toBe(true);
      expect(client["matchPattern"]("file.js", "**/**/*.js")).toBe(true);
    });

    it("should handle question mark pattern", () => {
      expect(client["matchPattern"]("file1.ts", "file?.ts")).toBe(true);
      expect(client["matchPattern"]("fileA.ts", "file?.ts")).toBe(true);
      expect(client["matchPattern"]("file12.ts", "file?.ts")).toBe(false);
      expect(client["matchPattern"]("file.ts", "file?.ts")).toBe(false);
    });

    it("should handle empty filename", () => {
      expect(client["matchPattern"]("", "*.js")).toBe(false);
      // minimatch("", "**") returns true (matches everything)
      expect(client["matchPattern"]("", "**")).toBe(true);
    });

    it("should handle empty pattern", () => {
      expect(client["matchPattern"]("file.js", "")).toBe(false);
    });

    it("should handle pattern with brackets", () => {
      expect(client["matchPattern"]("file.js", "*.{js,ts}")).toBe(true);
      expect(client["matchPattern"]("file.ts", "*.{js,ts}")).toBe(true);
      expect(client["matchPattern"]("file.css", "*.{js,ts}")).toBe(false);
    });
  });

  describe("matchPattern - Security (ReDoS Prevention)", () => {
    it("should handle complex patterns efficiently", () => {
      const start = performance.now();

      // These patterns previously could cause ReDoS with naive regex
      const testCases = [
        { file: "a".repeat(100) + ".js", pattern: "**/*.js" },
        { file: "a/b/c/d/e/f/g.js", pattern: "**/**/**/**/*.js" },
        {
          file: "x".repeat(50) + "/" + "y".repeat(50) + ".js",
          pattern: "**/*.js",
        },
      ];

      testCases.forEach(({ file, pattern }) => {
        client["matchPattern"](file, pattern);
      });

      const duration = performance.now() - start;

      // Should complete in < 100ms (minimatch is fast)
      expect(duration).toBeLessThan(100);
    });

    it("should handle pathological ReDoS payload safely", () => {
      const start = performance.now();

      // Classic ReDoS payload that would hang with naive regex
      const evilFilename = "a".repeat(50) + "X";
      const evilPattern = "(a+)+$";

      // minimatch handles this safely
      expect(() => {
        client["matchPattern"](evilFilename, evilPattern);
      }).not.toThrow();

      const duration = performance.now() - start;
      expect(duration).toBeLessThan(100);
    });
  });
});

describe("CodeReviewClient - JSON Extraction and Validation (TEST-REQ-002, TEST-REQ-003)", () => {
  let client: CodeReviewClient;

  beforeEach(() => {
    client = new CodeReviewClient("test-api-key");
  });

  describe("reviewDiff - JSON Extraction (TEST-REQ-002)", () => {
    it("should parse valid JSON response", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "Test review",
              findings: [
                {
                  severity: "P0",
                  title: "Critical issue",
                  file: "test.js",
                  line: 10,
                  problem: "Security vulnerability",
                  rationale: "This is dangerous",
                },
              ],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 5,
            deletions: 2,
            patch: "test patch",
          },
        ],
        totalAdditions: 5,
        totalDeletions: 2,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Test review");
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe("P0");
      expect(result.criticalCount).toBe(1);
    });

    it("should handle JSON wrapped in ```json code block", async () => {
      const jsonContent = {
        summary: "Test review",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json\n" + JSON.stringify(jsonContent) + "\n```",
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Test review");
      expect(result.findings).toHaveLength(0);
    });

    it("should handle JSON wrapped in ``` code block", async () => {
      const jsonContent = {
        summary: "Test review",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```\n" + JSON.stringify(jsonContent) + "\n```",
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Test review");
    });

    // Issue #130: Additional tests for robust regex extraction
    it("should handle JSON with extra whitespace in code block", async () => {
      const jsonContent = {
        summary: "Test review with whitespace",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json  \n\n" + JSON.stringify(jsonContent) + "\n\n```",
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Test review with whitespace");
    });

    it("should handle code block with no newlines (compact format)", async () => {
      const jsonContent = {
        summary: "Compact format test",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json" + JSON.stringify(jsonContent) + "```",
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Compact format test");
    });

    it("should handle plain JSON without code block fences", async () => {
      const jsonContent = {
        summary: "Plain JSON test",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(jsonContent),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Plain JSON test");
    });

    // Issue #130 (FIX-001): Tests for whitespace before closing fence
    // Validates fix in anthropic-client.ts line 119-121 (regex update)
    it("should handle single space before closing fence (TEST-REQ-001)", async () => {
      const jsonContent = {
        summary: "Single space before fence",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json\n" + JSON.stringify(jsonContent) + "\n ```", // Single space before closing
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Single space before fence");
    });

    it("should handle multiple spaces before closing fence (TEST-REQ-001)", async () => {
      const jsonContent = {
        summary: "Multiple spaces before fence",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json\n" + JSON.stringify(jsonContent) + "\n    ```", // Four spaces before closing
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Multiple spaces before fence");
    });

    it("should handle tab before closing fence (TEST-REQ-001)", async () => {
      const jsonContent = {
        summary: "Tab before fence",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json\n" + JSON.stringify(jsonContent) + "\n\t```", // Tab before closing
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Tab before fence");
    });

    it("should handle excessive whitespace before closing fence (TEST-REQ-002)", async () => {
      const jsonContent = {
        summary: "Excessive whitespace before fence",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text:
              "```json\n" +
              JSON.stringify(jsonContent) +
              "\n" +
              " ".repeat(50) +
              "```", // 50 spaces before closing
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("Excessive whitespace before fence");
    });

    it("should handle no whitespace before closing fence (TEST-REQ-002 backward compatibility)", async () => {
      const jsonContent = {
        summary: "No whitespace before fence",
        findings: [],
      };

      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "```json\n" + JSON.stringify(jsonContent) + "\n```", // No whitespace before closing (standard format)
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.summary).toBe("No whitespace before fence");
    });

    it("should handle empty findings array", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "No issues found",
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.findings).toHaveLength(0);
      expect(result.criticalCount).toBe(0);
      expect(result.warningCount).toBe(0);
      expect(result.suggestionCount).toBe(0);
    });

    it("should throw on invalid JSON structure", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: "{ invalid json",
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      await expect(client.reviewDiff(diff)).rejects.toThrow(
        "Invalid JSON response from code review",
      );
    });

    it("should throw on missing required fields", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              // missing summary
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      await expect(client.reviewDiff(diff)).rejects.toThrow(
        "Invalid response format from code review",
      );
    });

    it("should throw on invalid severity value", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "Test",
              findings: [
                {
                  severity: "INVALID",
                  title: "Test",
                  file: "test.js",
                  problem: "Test",
                  rationale: "Test",
                },
              ],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      await expect(client.reviewDiff(diff)).rejects.toThrow(
        "Invalid response format from code review",
      );
    });
  });

  describe("reviewDiff - Response Validation (TEST-REQ-003)", () => {
    it("should count all severity levels correctly", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "Multiple findings",
              findings: [
                {
                  severity: "P0",
                  title: "Critical",
                  file: "test.js",
                  problem: "Critical issue",
                  rationale: "Very bad",
                },
                {
                  severity: "P0",
                  title: "Another Critical",
                  file: "test.js",
                  problem: "Another critical issue",
                  rationale: "Also very bad",
                },
                {
                  severity: "P1",
                  title: "Warning",
                  file: "test.js",
                  problem: "Warning issue",
                  rationale: "Should fix",
                },
                {
                  severity: "P2",
                  title: "Suggestion",
                  file: "test.js",
                  problem: "Minor issue",
                  rationale: "Nice to have",
                },
                {
                  severity: "P3",
                  title: "Low priority",
                  file: "test.js",
                  problem: "Very minor",
                  rationale: "Optional",
                },
              ],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.criticalCount).toBe(2); // P0
      expect(result.warningCount).toBe(1); // P1
      expect(result.suggestionCount).toBe(2); // P2 + P3
      expect(result.findings).toHaveLength(5);
    });

    it("should handle finding with all optional fields present", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "Test",
              findings: [
                {
                  severity: "P0",
                  title: "Complete finding",
                  file: "test.js",
                  line: 42,
                  problem: "Issue description",
                  currentCode: "const x = 1;",
                  suggestedFix: "const x = 2;",
                  rationale: "Because reasons",
                },
              ],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.findings[0]).toMatchObject({
        severity: "P0",
        title: "Complete finding",
        file: "test.js",
        line: 42,
        problem: "Issue description",
        currentCode: "const x = 1;",
        suggestedFix: "const x = 2;",
        rationale: "Because reasons",
      });
    });

    it("should handle finding with no optional fields", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message" as const,
        role: "assistant" as const,
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              summary: "Test",
              findings: [
                {
                  severity: "P1",
                  title: "Minimal finding",
                  file: "test.js",
                  problem: "Issue",
                  rationale: "Reason",
                  // no line, currentCode, suggestedFix
                },
              ],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn" as const,
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };

      vi.spyOn(client["client"].messages, "create").mockResolvedValue(
        mockResponse,
      );

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      const result = await client.reviewDiff(diff);

      expect(result.findings[0]).toMatchObject({
        severity: "P1",
        title: "Minimal finding",
        file: "test.js",
        problem: "Issue",
        rationale: "Reason",
      });
      expect(result.findings[0].line).toBeUndefined();
      expect(result.findings[0].currentCode).toBeUndefined();
      expect(result.findings[0].suggestedFix).toBeUndefined();
    });
  });

  describe("reviewDiff - Error Handling", () => {
    it("should handle rate limit errors", async () => {
      const error = new Anthropic.RateLimitError(
        "Rate limited",
        null as never,
        undefined,
      );
      vi.spyOn(client["client"].messages, "create").mockRejectedValue(error);

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      await expect(client.reviewDiff(diff)).rejects.toThrow(
        "Rate limited by Anthropic API",
      );
    });

    it("should handle authentication errors", async () => {
      const error = new Anthropic.AuthenticationError(
        "Invalid API key",
        null as never,
        undefined,
      );
      vi.spyOn(client["client"].messages, "create").mockRejectedValue(error);

      const diff: PRDiff = {
        files: [
          {
            filename: "test.js",
            status: "modified",
            additions: 1,
            deletions: 0,
            patch: "test",
          },
        ],
        totalAdditions: 1,
        totalDeletions: 0,
      };

      await expect(client.reviewDiff(diff)).rejects.toThrow(
        "Invalid Anthropic API key",
      );
    });
  });
});
