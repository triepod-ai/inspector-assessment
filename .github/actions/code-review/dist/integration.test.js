import { describe, it, expect, vi, beforeEach } from "vitest";
import { CodeReviewClient } from "./anthropic-client.js";
describe("CodeReviewClient - Integration Tests", () => {
  let client;
  beforeEach(() => {
    client = new CodeReviewClient("test-api-key");
  });
  describe("reviewDiff - File Filtering with Exclude Patterns", () => {
    it("should filter out files matching default exclude patterns", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message",
        role: "assistant",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              summary: "Test review",
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };
      const createSpy = vi
        .spyOn(client["client"].messages, "create")
        .mockResolvedValue(mockResponse);
      const diff = {
        files: [
          {
            filename: "package-lock.json",
            status: "modified",
            additions: 1000,
            deletions: 500,
            patch: "lock file changes",
          },
          {
            filename: "src/index.ts",
            status: "modified",
            additions: 10,
            deletions: 5,
            patch: "actual code changes",
          },
          {
            filename: "dist/bundle.min.js",
            status: "modified",
            additions: 5000,
            deletions: 0,
            patch: "minified code",
          },
        ],
        totalAdditions: 6010,
        totalDeletions: 505,
      };
      const result = await client.reviewDiff(diff);
      // Verify the API was called (meaning some files passed filter)
      expect(createSpy).toHaveBeenCalled();
      // Check that the prompt only included the non-excluded file
      const callArgs = createSpy.mock.calls[0][0];
      const userMessage = callArgs.messages[0].content;
      // Should include src/index.ts
      expect(userMessage).toContain("src/index.ts");
      // Should NOT include excluded files
      expect(userMessage).not.toContain("package-lock.json");
      expect(userMessage).not.toContain("bundle.min.js");
    });
    it("should return empty result when all files are excluded", async () => {
      const diff = {
        files: [
          {
            filename: "package-lock.json",
            status: "modified",
            additions: 1000,
            deletions: 500,
            patch: "lock file changes",
          },
          {
            filename: "yarn.lock",
            status: "modified",
            additions: 800,
            deletions: 400,
            patch: "lock file changes",
          },
        ],
        totalAdditions: 1800,
        totalDeletions: 900,
      };
      const result = await client.reviewDiff(diff);
      expect(result.summary).toContain("No reviewable files");
      expect(result.findings).toHaveLength(0);
      expect(result.tokensUsed.total).toBe(0);
    });
    it("should filter files using custom exclude patterns", async () => {
      const customClient = new CodeReviewClient("test-api-key", {
        excludePatterns: ["**/*.test.ts", "**/__tests__/**"],
      });
      const mockResponse = {
        id: "msg_123",
        type: "message",
        role: "assistant",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              summary: "Test review",
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };
      const createSpy = vi
        .spyOn(customClient["client"].messages, "create")
        .mockResolvedValue(mockResponse);
      const diff = {
        files: [
          {
            filename: "src/index.test.ts",
            status: "modified",
            additions: 50,
            deletions: 10,
            patch: "test changes",
          },
          {
            filename: "src/__tests__/helper.ts",
            status: "modified",
            additions: 20,
            deletions: 5,
            patch: "test helper changes",
          },
          {
            filename: "src/index.ts",
            status: "modified",
            additions: 10,
            deletions: 5,
            patch: "actual code changes",
          },
        ],
        totalAdditions: 80,
        totalDeletions: 20,
      };
      const result = await customClient.reviewDiff(diff);
      expect(createSpy).toHaveBeenCalled();
      const callArgs = createSpy.mock.calls[0][0];
      const userMessage = callArgs.messages[0].content;
      // Should include src/index.ts
      expect(userMessage).toContain("src/index.ts");
      // Should NOT include test files
      expect(userMessage).not.toContain("index.test.ts");
      expect(userMessage).not.toContain("__tests__");
    });
    it("should handle complex glob patterns correctly", async () => {
      const mockResponse = {
        id: "msg_123",
        type: "message",
        role: "assistant",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              summary: "Test review",
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };
      const createSpy = vi
        .spyOn(client["client"].messages, "create")
        .mockResolvedValue(mockResponse);
      const diff = {
        files: [
          {
            filename: "dist/nested/deep/file.js",
            status: "modified",
            additions: 100,
            deletions: 50,
            patch: "dist file",
          },
          {
            filename: "src/components/Button.tsx",
            status: "modified",
            additions: 10,
            deletions: 5,
            patch: "component changes",
          },
        ],
        totalAdditions: 110,
        totalDeletions: 55,
      };
      await client.reviewDiff(diff);
      expect(createSpy).toHaveBeenCalled();
      const callArgs = createSpy.mock.calls[0][0];
      const userMessage = callArgs.messages[0].content;
      // dist/** pattern should match dist/nested/deep/file.js
      expect(userMessage).not.toContain("dist/nested/deep/file.js");
      // Should include the component
      expect(userMessage).toContain("Button.tsx");
    });
  });
  describe("reviewDiff - Diff Size Limits", () => {
    it("should truncate large diffs", async () => {
      const customClient = new CodeReviewClient("test-api-key", {
        maxDiffSize: 100, // Very small limit for testing
      });
      const mockResponse = {
        id: "msg_123",
        type: "message",
        role: "assistant",
        content: [
          {
            type: "text",
            text: JSON.stringify({
              summary: "Test review",
              findings: [],
            }),
          },
        ],
        model: "claude-sonnet-4-20250514",
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: {
          input_tokens: 100,
          output_tokens: 50,
        },
      };
      const createSpy = vi
        .spyOn(customClient["client"].messages, "create")
        .mockResolvedValue(mockResponse);
      const largePatch = "a".repeat(200);
      const diff = {
        files: [
          {
            filename: "large.ts",
            status: "modified",
            additions: 100,
            deletions: 50,
            patch: largePatch,
          },
        ],
        totalAdditions: 100,
        totalDeletions: 50,
      };
      await customClient.reviewDiff(diff);
      expect(createSpy).toHaveBeenCalled();
      const callArgs = createSpy.mock.calls[0][0];
      const userMessage = callArgs.messages[0].content;
      // Should contain truncation message
      expect(userMessage).toContain("diff truncated due to size");
    });
  });
});
