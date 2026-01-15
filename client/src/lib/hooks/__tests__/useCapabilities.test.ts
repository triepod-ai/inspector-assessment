import { renderHook, act } from "@testing-library/react";
import { useCapabilities } from "../useCapabilities";
import { Resource, Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock the schemaUtils module
jest.mock("@/utils/schemaUtils", () => ({
  cacheToolOutputSchemas: jest.fn(),
}));

describe("useCapabilities", () => {
  const createMockOptions = () => {
    const sendMCPRequest = jest.fn();
    const lastToolCallOriginTabRef = { current: "tools" };
    const currentTabRef = { current: "tools" };

    return {
      sendMCPRequest,
      lastToolCallOriginTabRef,
      currentTabRef,
    };
  };

  const createMockResource = (overrides?: Partial<Resource>): Resource => ({
    uri: "file:///test",
    name: "Test Resource",
    ...overrides,
  });

  const createMockTool = (overrides?: Partial<Tool>): Tool => ({
    name: "test_tool",
    description: "A test tool",
    inputSchema: { type: "object", properties: {} },
    ...overrides,
  });

  describe("initial state", () => {
    it("should return empty arrays initially", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));

      expect(result.current.resources).toEqual([]);
      expect(result.current.resourceTemplates).toEqual([]);
      expect(result.current.prompts).toEqual([]);
      expect(result.current.tools).toEqual([]);
      expect(result.current.roots).toEqual([]);
      expect(result.current.isLoading).toBe(false);
    });

    it("should return null for selected items initially", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));

      expect(result.current.selectedResource).toBeNull();
      expect(result.current.selectedPrompt).toBeNull();
      expect(result.current.selectedTool).toBeNull();
    });
  });

  describe("resources", () => {
    it("should list resources", async () => {
      const options = createMockOptions();
      const mockResources = [createMockResource()];
      options.sendMCPRequest.mockResolvedValue({
        resources: mockResources,
        nextCursor: undefined,
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listResources();
      });

      expect(result.current.resources).toEqual(mockResources);
    });

    it("should clear resources", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({
        resources: [createMockResource()],
        nextCursor: "cursor123",
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listResources();
      });

      expect(result.current.resources).toHaveLength(1);

      act(() => {
        result.current.clearResources();
      });

      expect(result.current.resources).toHaveLength(0);
      expect(result.current.nextResourceCursor).toBeUndefined();
    });

    it("should read resource and update content map", async () => {
      const options = createMockOptions();
      const mockResponse = { contents: [{ text: "content" }] };
      options.sendMCPRequest.mockResolvedValue(mockResponse);

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.readResource("file:///test");
      });

      expect(result.current.resourceContent).toBe(
        JSON.stringify(mockResponse, null, 2),
      );
      expect(result.current.resourceContentMap["file:///test"]).toBe(
        JSON.stringify(mockResponse, null, 2),
      );
    });

    it("should set selected resource", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));
      const resource = createMockResource();

      act(() => {
        result.current.setSelectedResource(resource);
      });

      expect(result.current.selectedResource).toEqual(resource);
    });
  });

  describe("prompts", () => {
    it("should list prompts", async () => {
      const options = createMockOptions();
      const mockPrompts = [{ name: "test_prompt", description: "Test" }];
      options.sendMCPRequest.mockResolvedValue({
        prompts: mockPrompts,
        nextCursor: undefined,
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listPrompts();
      });

      expect(result.current.prompts).toEqual(mockPrompts);
    });

    it("should get prompt and update content", async () => {
      const options = createMockOptions();
      const mockResponse = { messages: [{ content: "test" }] };
      options.sendMCPRequest.mockResolvedValue(mockResponse);

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.getPrompt("test_prompt", { arg1: "value1" });
      });

      expect(result.current.promptContent).toBe(
        JSON.stringify(mockResponse, null, 2),
      );
    });

    it("should clear prompts", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({
        prompts: [{ name: "test" }],
        nextCursor: "cursor",
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listPrompts();
      });

      act(() => {
        result.current.clearPrompts();
      });

      expect(result.current.prompts).toHaveLength(0);
      expect(result.current.nextPromptCursor).toBeUndefined();
    });
  });

  describe("tools", () => {
    it("should list tools", async () => {
      const options = createMockOptions();
      const mockTools = [createMockTool()];
      options.sendMCPRequest.mockResolvedValue({
        tools: mockTools,
        nextCursor: undefined,
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listTools();
      });

      expect(result.current.tools).toEqual(mockTools);
    });

    it("should clear tools", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({
        tools: [createMockTool()],
        nextCursor: "cursor",
      });

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.listTools();
      });

      act(() => {
        result.current.clearTools();
      });

      expect(result.current.tools).toHaveLength(0);
      expect(result.current.nextToolCursor).toBeUndefined();
    });

    it("should set selected tool", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));
      const tool = createMockTool();

      act(() => {
        result.current.setSelectedTool(tool);
      });

      expect(result.current.selectedTool).toEqual(tool);
    });
  });

  describe("roots", () => {
    it("should set roots and keep ref in sync", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));
      const newRoots = [{ uri: "file:///root", name: "Root" }];

      act(() => {
        result.current.setRoots(newRoots);
      });

      expect(result.current.roots).toEqual(newRoots);
      expect(result.current.rootsRef.current).toEqual(newRoots);
    });

    it("should support functional updates for roots", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useCapabilities(options));

      act(() => {
        result.current.setRoots([{ uri: "file:///1", name: "First" }]);
      });

      act(() => {
        result.current.setRoots((prev) => [
          ...prev,
          { uri: "file:///2", name: "Second" },
        ]);
      });

      expect(result.current.roots).toHaveLength(2);
      expect(result.current.rootsRef.current).toHaveLength(2);
    });
  });

  describe("loading state", () => {
    it("should track loading state during list operations", async () => {
      const options = createMockOptions();
      let resolveRequest: (value: unknown) => void;
      options.sendMCPRequest.mockReturnValue(
        new Promise((resolve) => {
          resolveRequest = resolve;
        }),
      );

      const { result } = renderHook(() => useCapabilities(options));

      let listPromise: Promise<void>;
      act(() => {
        listPromise = result.current.listResources();
      });

      expect(result.current.isLoading).toBe(true);

      await act(async () => {
        resolveRequest!({ resources: [], nextCursor: undefined });
        await listPromise;
      });

      expect(result.current.isLoading).toBe(false);
    });
  });

  describe("subscriptions", () => {
    it("should subscribe to resource", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({});

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.subscribeToResource("file:///test");
      });

      expect(result.current.resourceSubscriptions.has("file:///test")).toBe(
        true,
      );
    });

    it("should not duplicate subscriptions", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({});

      const { result } = renderHook(() => useCapabilities(options));

      // First subscription
      await act(async () => {
        await result.current.subscribeToResource("file:///test");
      });

      // Second subscription to same URI (should be no-op)
      await act(async () => {
        await result.current.subscribeToResource("file:///test");
      });

      // Should only call once since second is duplicate
      expect(options.sendMCPRequest).toHaveBeenCalledTimes(1);
    });

    it("should unsubscribe from resource", async () => {
      const options = createMockOptions();
      options.sendMCPRequest.mockResolvedValue({});

      const { result } = renderHook(() => useCapabilities(options));

      await act(async () => {
        await result.current.subscribeToResource("file:///test");
      });

      await act(async () => {
        await result.current.unsubscribeFromResource("file:///test");
      });

      expect(result.current.resourceSubscriptions.has("file:///test")).toBe(
        false,
      );
    });
  });
});
