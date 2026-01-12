/**
 * Tool Wrapper Unit Tests
 *
 * Tests for createCallToolWrapper() that wraps MCP client.callTool().
 */

import { jest, describe, it, expect, beforeEach } from "@jest/globals";

// Import the actual function (no mocking needed for this module)
import { createCallToolWrapper } from "../../lib/assessment-runner/tool-wrapper.js";

describe("createCallToolWrapper", () => {
  let mockClient: {
    callTool: jest.Mock<() => Promise<unknown>>;
  };
  let mockCallTool: jest.Mock<() => Promise<unknown>>;

  beforeEach(() => {
    mockCallTool = jest.fn<() => Promise<unknown>>();
    mockClient = {
      callTool: mockCallTool,
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("successful tool calls", () => {
    it("should wrap successful tool response with content array", async () => {
      mockCallTool.mockResolvedValue({
        content: [{ type: "text", text: "Hello, World!" }],
      });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("greet", { name: "World" });

      expect(mockCallTool).toHaveBeenCalledWith({
        name: "greet",
        arguments: { name: "World" },
      });
      expect(result.content).toEqual([{ type: "text", text: "Hello, World!" }]);
    });

    it("should include structuredContent from response when present", async () => {
      mockCallTool.mockResolvedValue({
        content: [{ type: "text", text: "result" }],
        structuredContent: { data: [1, 2, 3] },
      });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("getData", {});

      expect(result.structuredContent).toEqual({ data: [1, 2, 3] });
    });

    it("should set isError false by default", async () => {
      mockCallTool.mockResolvedValue({
        content: [{ type: "text", text: "success" }],
      });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("tool", {});

      expect(result.isError).toBe(false);
    });

    it("should preserve isError true when response has error flag", async () => {
      mockCallTool.mockResolvedValue({
        content: [{ type: "text", text: "Tool error occurred" }],
        isError: true,
      });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("failingTool", {});

      expect(result.isError).toBe(true);
      expect(result.content).toEqual([
        { type: "text", text: "Tool error occurred" },
      ]);
    });
  });

  describe("exception handling", () => {
    it("should catch exceptions and return error text content", async () => {
      mockCallTool.mockRejectedValue(new Error("Network timeout"));

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("networkTool", {});

      expect(result.content).toEqual([
        { type: "text", text: "Error: Network timeout" },
      ]);
    });

    it("should set isError true on caught exceptions", async () => {
      mockCallTool.mockRejectedValue(new Error("Something went wrong"));

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("brokenTool", {});

      expect(result.isError).toBe(true);
    });

    it("should handle non-Error exceptions", async () => {
      mockCallTool.mockRejectedValue("String error");

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      const result = await callTool("stringErrorTool", {});

      expect(result.content).toEqual([
        { type: "text", text: "Error: String error" },
      ]);
      expect(result.isError).toBe(true);
    });
  });

  describe("argument passing", () => {
    it("should pass parameters as arguments to callTool", async () => {
      mockCallTool.mockResolvedValue({ content: [] });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      await callTool("complexTool", {
        query: "search term",
        limit: 10,
        options: { deep: true },
      });

      expect(mockCallTool).toHaveBeenCalledWith({
        name: "complexTool",
        arguments: {
          query: "search term",
          limit: 10,
          options: { deep: true },
        },
      });
    });

    it("should handle empty parameters", async () => {
      mockCallTool.mockResolvedValue({ content: [] });

      const callTool = createCallToolWrapper(
        mockClient as unknown as Parameters<typeof createCallToolWrapper>[0],
      );
      await callTool("noArgsTool", {});

      expect(mockCallTool).toHaveBeenCalledWith({
        name: "noArgsTool",
        arguments: {},
      });
    });
  });
});
