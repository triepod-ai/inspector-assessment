import { renderHook, act, waitFor } from "@testing-library/react";
import { useToolExecution } from "../useToolExecution";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Mock the paramUtils module
jest.mock("@/utils/paramUtils", () => ({
  cleanParams: jest.fn((params) => params),
}));

describe("useToolExecution", () => {
  const createMockOptions = () => {
    const makeRequest = jest.fn();
    const clearError = jest.fn();
    const setError = jest.fn();
    const lastToolCallOriginTabRef = { current: "tools" };
    const currentTabRef = { current: "tools" };

    return {
      makeRequest,
      tools: [] as Tool[],
      metadata: {},
      lastToolCallOriginTabRef,
      currentTabRef,
      clearError,
      setError,
    };
  };

  const createMockTool = (overrides?: Partial<Tool>): Tool => ({
    name: "test_tool",
    description: "A test tool",
    inputSchema: {
      type: "object",
      properties: {
        param1: { type: "string" },
      },
    },
    ...overrides,
  });

  const createMockResult = (): CompatibilityCallToolResult => ({
    content: [{ type: "text", text: "Success" }],
    isError: false,
  });

  describe("initial state", () => {
    it("should return null tool result initially", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useToolExecution(options));

      expect(result.current.toolResult).toBeNull();
      expect(result.current.isExecuting).toBe(false);
    });
  });

  describe("callTool", () => {
    it("should call makeRequest with correct parameters", async () => {
      const options = createMockOptions();
      const mockResult = createMockResult();
      options.makeRequest.mockResolvedValue(mockResult);

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", { param1: "value" });
      });

      expect(options.makeRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          method: "tools/call",
          params: expect.objectContaining({
            name: "test_tool",
            arguments: { param1: "value" },
          }),
        }),
        expect.anything(),
      );
    });

    it("should set tool result on success", async () => {
      const options = createMockOptions();
      const mockResult = createMockResult();
      options.makeRequest.mockResolvedValue(mockResult);

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", {});
      });

      expect(result.current.toolResult).toEqual(mockResult);
    });

    it("should handle errors gracefully", async () => {
      const options = createMockOptions();
      options.makeRequest.mockRejectedValue(new Error("Tool execution failed"));

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", {});
      });

      expect(result.current.toolResult).toEqual({
        content: [{ type: "text", text: "Tool execution failed" }],
        isError: true,
      });
    });

    it("should clear error on success", async () => {
      const options = createMockOptions();
      options.makeRequest.mockResolvedValue(createMockResult());

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", {});
      });

      expect(options.clearError).toHaveBeenCalledWith("tools");
    });

    it("should track originating tab", async () => {
      const options = createMockOptions();
      options.currentTabRef.current = "resources";
      options.makeRequest.mockResolvedValue(createMockResult());

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", {});
      });

      expect(options.lastToolCallOriginTabRef.current).toBe("resources");
    });

    it("should merge metadata", async () => {
      const options = createMockOptions();
      options.metadata = { generalKey: "generalValue" };
      options.makeRequest.mockResolvedValue(createMockResult());

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool(
          "test_tool",
          {},
          { toolKey: "toolValue" },
        );
      });

      expect(options.makeRequest).toHaveBeenCalledWith(
        expect.objectContaining({
          params: expect.objectContaining({
            _meta: expect.objectContaining({
              generalKey: "generalValue",
              toolKey: "toolValue",
              progressToken: expect.any(Number),
            }),
          }),
        }),
        expect.anything(),
      );
    });

    it("should set isExecuting during execution", async () => {
      const options = createMockOptions();
      let resolveRequest: (value: CompatibilityCallToolResult) => void;
      options.makeRequest.mockReturnValue(
        new Promise((resolve) => {
          resolveRequest = resolve;
        }),
      );

      const { result } = renderHook(() => useToolExecution(options));

      let callPromise: Promise<CompatibilityCallToolResult>;
      act(() => {
        callPromise = result.current.callTool("test_tool", {});
      });

      // Should be executing
      expect(result.current.isExecuting).toBe(true);

      // Resolve the request
      await act(async () => {
        resolveRequest!(createMockResult());
        await callPromise;
      });

      // Should no longer be executing
      expect(result.current.isExecuting).toBe(false);
    });
  });

  describe("clearToolResult", () => {
    it("should clear the tool result", async () => {
      const options = createMockOptions();
      options.makeRequest.mockResolvedValue(createMockResult());

      const { result } = renderHook(() => useToolExecution(options));

      await act(async () => {
        await result.current.callTool("test_tool", {});
      });

      expect(result.current.toolResult).not.toBeNull();

      act(() => {
        result.current.clearToolResult();
      });

      expect(result.current.toolResult).toBeNull();
    });
  });
});
