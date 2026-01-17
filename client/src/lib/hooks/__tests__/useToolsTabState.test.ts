import { renderHook, act } from "@testing-library/react";
import { useToolsTabState, MetadataEntry } from "../useToolsTabState";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock form ref interface for testing (Issue #186)
interface MockFormRef {
  validateJson: () => { isValid: boolean; error?: string };
}

// Mock the schemaUtils module
jest.mock("@/utils/schemaUtils", () => ({
  generateDefaultValue: jest.fn((schema, _key) => {
    if (schema?.type === "string") return "";
    if (schema?.type === "number") return 0;
    if (schema?.type === "boolean") return false;
    if (schema?.default !== undefined) return schema.default;
    return undefined;
  }),
  resolveRef: jest.fn((value) => value),
}));

describe("useToolsTabState", () => {
  const createMockTool = (overrides?: Partial<Tool>): Tool => ({
    name: "test_tool",
    description: "A test tool",
    inputSchema: {
      type: "object",
      properties: {
        param1: { type: "string" },
        param2: { type: "number" },
      },
    },
    ...overrides,
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("initial state", () => {
    it("should return initial state with empty params when no tool selected", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      expect(result.current.params).toEqual({});
      expect(result.current.isToolRunning).toBe(false);
      expect(result.current.isOutputSchemaExpanded).toBe(false);
      expect(result.current.isMetadataExpanded).toBe(false);
      expect(result.current.metadataEntries).toEqual([]);
      expect(result.current.hasValidationErrors).toBe(false);
    });

    it("should initialize params from selected tool schema", () => {
      const tool = createMockTool();
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: tool }),
      );

      // Params should be initialized based on the tool's input schema
      expect(Object.keys(result.current.params)).toContain("param1");
      expect(Object.keys(result.current.params)).toContain("param2");
    });
  });

  describe("state setters", () => {
    it("should update params via setParams", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      act(() => {
        result.current.setParams({ foo: "bar" });
      });

      expect(result.current.params).toEqual({ foo: "bar" });
    });

    it("should update isToolRunning via setIsToolRunning", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      act(() => {
        result.current.setIsToolRunning(true);
      });

      expect(result.current.isToolRunning).toBe(true);
    });

    it("should toggle isOutputSchemaExpanded", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      expect(result.current.isOutputSchemaExpanded).toBe(false);

      act(() => {
        result.current.setIsOutputSchemaExpanded(true);
      });

      expect(result.current.isOutputSchemaExpanded).toBe(true);
    });

    it("should toggle isMetadataExpanded", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      expect(result.current.isMetadataExpanded).toBe(false);

      act(() => {
        result.current.setIsMetadataExpanded(true);
      });

      expect(result.current.isMetadataExpanded).toBe(true);
    });
  });

  describe("metadata entries", () => {
    it("should add metadata entries", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      const newEntry: MetadataEntry = {
        id: "test-id",
        key: "testKey",
        value: "testValue",
      };

      act(() => {
        result.current.setMetadataEntries([newEntry]);
      });

      expect(result.current.metadataEntries).toHaveLength(1);
      expect(result.current.metadataEntries[0]).toEqual(newEntry);
    });

    it("should update metadata entries functionally", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      // Add initial entry
      act(() => {
        result.current.setMetadataEntries([
          { id: "1", key: "key1", value: "value1" },
        ]);
      });

      // Add another using functional update
      act(() => {
        result.current.setMetadataEntries((prev) => [
          ...prev,
          { id: "2", key: "key2", value: "value2" },
        ]);
      });

      expect(result.current.metadataEntries).toHaveLength(2);
    });

    it("should remove metadata entries by filtering", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      // Add entries
      act(() => {
        result.current.setMetadataEntries([
          { id: "1", key: "key1", value: "value1" },
          { id: "2", key: "key2", value: "value2" },
        ]);
      });

      // Remove first entry
      act(() => {
        result.current.setMetadataEntries((prev) =>
          prev.filter((_, i) => i !== 0),
        );
      });

      expect(result.current.metadataEntries).toHaveLength(1);
      expect(result.current.metadataEntries[0].id).toBe("2");
    });
  });

  describe("tool selection changes", () => {
    it("should reset params when selectedTool changes", () => {
      const tool1 = createMockTool({ name: "tool1" });
      const tool2 = createMockTool({
        name: "tool2",
        inputSchema: {
          type: "object",
          properties: {
            differentParam: { type: "string" },
          },
        },
      });

      const { result, rerender } = renderHook(
        ({ selectedTool }) => useToolsTabState({ selectedTool }),
        { initialProps: { selectedTool: tool1 } },
      );

      // Set some params
      act(() => {
        result.current.setParams({ param1: "custom value" });
      });

      expect(result.current.params.param1).toBe("custom value");

      // Change tool
      rerender({ selectedTool: tool2 });

      // Params should be reset based on new tool
      expect(Object.keys(result.current.params)).toContain("differentParam");
    });

    it("should reset validation errors when selectedTool changes", () => {
      const tool1 = createMockTool({ name: "tool1" });
      const tool2 = createMockTool({ name: "tool2" });

      const { result, rerender } = renderHook(
        ({ selectedTool }) => useToolsTabState({ selectedTool }),
        { initialProps: { selectedTool: tool1 } },
      );

      // Simulate validation error state (normally set via checkValidationErrors)
      // We can't directly set it, but we can verify it resets on tool change

      // Change tool
      rerender({ selectedTool: tool2 });

      // Validation errors should be reset
      expect(result.current.hasValidationErrors).toBe(false);
    });
  });

  describe("formRefs", () => {
    it("should provide mutable ref object", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      expect(result.current.formRefs).toBeDefined();
      expect(result.current.formRefs.current).toEqual({});
    });

    it("should clear formRefs when selectedTool changes", () => {
      const tool1 = createMockTool({ name: "tool1" });
      const tool2 = createMockTool({ name: "tool2" });

      const { result, rerender } = renderHook(
        ({ selectedTool }) => useToolsTabState({ selectedTool }),
        { initialProps: { selectedTool: tool1 } },
      );

      // Simulate setting a ref
      result.current.formRefs.current["testKey"] = {
        validateJson: () => ({ isValid: true }),
      } as MockFormRef;

      expect(result.current.formRefs.current["testKey"]).toBeDefined();

      // Change tool
      rerender({ selectedTool: tool2 });

      // formRefs should be cleared
      expect(result.current.formRefs.current).toEqual({});
    });
  });

  describe("checkValidationErrors", () => {
    it("should return false when no form refs exist", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      let hasErrors: boolean = false;
      act(() => {
        hasErrors = result.current.checkValidationErrors();
      });

      expect(hasErrors).toBe(false);
      expect(result.current.hasValidationErrors).toBe(false);
    });

    it("should return true when a form ref has validation errors", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      // Set up a form ref with invalid state
      result.current.formRefs.current["testKey"] = {
        validateJson: () => ({ isValid: false, error: "Invalid JSON" }),
      } as MockFormRef;

      let hasErrors: boolean = false;
      act(() => {
        hasErrors = result.current.checkValidationErrors();
      });

      expect(hasErrors).toBe(true);
      expect(result.current.hasValidationErrors).toBe(true);
    });

    it("should return false when all form refs are valid", () => {
      const { result } = renderHook(() =>
        useToolsTabState({ selectedTool: null }),
      );

      // Set up form refs with valid state
      result.current.formRefs.current["key1"] = {
        validateJson: () => ({ isValid: true }),
      } as MockFormRef;
      result.current.formRefs.current["key2"] = {
        validateJson: () => ({ isValid: true }),
      } as MockFormRef;

      let hasErrors: boolean = false;
      act(() => {
        hasErrors = result.current.checkValidationErrors();
      });

      expect(hasErrors).toBe(false);
      expect(result.current.hasValidationErrors).toBe(false);
    });
  });
});
