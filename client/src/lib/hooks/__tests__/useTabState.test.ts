import { renderHook, act } from "@testing-library/react";
import { useTabState } from "../useTabState";
import { ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";

describe("useTabState", () => {
  // Save original window.location
  const originalLocation = window.location;

  beforeEach(() => {
    // Reset hash before each test
    window.location.hash = "";
  });

  afterEach(() => {
    window.location.hash = "";
  });

  const createMockCapabilities = (
    overrides?: Partial<ServerCapabilities>,
  ): ServerCapabilities => ({
    ...overrides,
  });

  describe("initial state", () => {
    it("should return default tab when no hash present", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      expect(result.current.activeTab).toBe("resources");
    });

    it("should read initial tab from URL hash", () => {
      window.location.hash = "tools";

      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      expect(result.current.activeTab).toBe("tools");
    });
  });

  describe("setActiveTab", () => {
    it("should update active tab and URL hash", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      act(() => {
        result.current.setActiveTab("prompts");
      });

      expect(result.current.activeTab).toBe("prompts");
      expect(window.location.hash).toBe("#prompts");
    });

    it("should keep currentTabRef in sync", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      act(() => {
        result.current.setActiveTab("tools");
      });

      expect(result.current.currentTabRef.current).toBe("tools");
    });
  });

  describe("tab validation", () => {
    it("should validate tab against server capabilities", () => {
      window.location.hash = "resources";

      const { result, rerender } = renderHook(
        ({ serverCapabilities, isConnected }) =>
          useTabState({ serverCapabilities, isConnected }),
        {
          initialProps: {
            serverCapabilities: null as ServerCapabilities | null,
            isConnected: false,
          },
        },
      );

      // Update with capabilities that don't include resources
      rerender({
        serverCapabilities: createMockCapabilities({
          prompts: {},
          tools: {},
        }),
        isConnected: true,
      });

      // Should switch to first available tab (prompts)
      expect(result.current.activeTab).toBe("prompts");
    });

    it("should default to ping when no capabilities available", () => {
      window.location.hash = "invalid-tab";

      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: createMockCapabilities({}),
          isConnected: true,
        }),
      );

      expect(result.current.activeTab).toBe("ping");
    });
  });

  describe("refs", () => {
    it("should expose currentTabRef", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      expect(result.current.currentTabRef.current).toBe(
        result.current.activeTab,
      );
    });

    it("should expose lastToolCallOriginTabRef", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      expect(result.current.lastToolCallOriginTabRef).toBeDefined();
      expect(typeof result.current.lastToolCallOriginTabRef.current).toBe(
        "string",
      );
    });
  });

  describe("hash change handling", () => {
    it("should update tab when hash changes externally", () => {
      const { result } = renderHook(() =>
        useTabState({
          serverCapabilities: null,
          isConnected: false,
        }),
      );

      // Simulate external hash change
      act(() => {
        window.location.hash = "sampling";
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      });

      expect(result.current.activeTab).toBe("sampling");
    });
  });

  describe("connection state", () => {
    it("should clear hash when disconnected", () => {
      window.location.hash = "tools";

      // Mock replaceState
      const replaceStateSpy = jest.spyOn(window.history, "replaceState");

      const { rerender } = renderHook(
        ({ serverCapabilities, isConnected }) =>
          useTabState({ serverCapabilities, isConnected }),
        {
          initialProps: {
            serverCapabilities: createMockCapabilities({ tools: {} }),
            isConnected: true,
          },
        },
      );

      // Disconnect
      rerender({
        serverCapabilities: null,
        isConnected: false,
      });

      expect(replaceStateSpy).toHaveBeenCalled();
      replaceStateSpy.mockRestore();
    });
  });
});
