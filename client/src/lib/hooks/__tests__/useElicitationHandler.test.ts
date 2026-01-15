import { renderHook, act } from "@testing-library/react";
import { useElicitationHandler } from "../useElicitationHandler";
import { ElicitationResponse } from "@/components/ElicitationTab";
import { ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";

describe("useElicitationHandler", () => {
  const createMockOptions = (overrides?: {
    serverCapabilities?: ServerCapabilities | null;
  }) => {
    const setActiveTab = jest.fn();
    const lastToolCallOriginTabRef = { current: "tools" };
    return {
      setActiveTab,
      lastToolCallOriginTabRef,
      serverCapabilities: overrides?.serverCapabilities ?? null,
    };
  };

  const createMockRequest = () => ({
    params: {
      message: "Please provide input",
      requestedSchema: {
        type: "object" as const,
        properties: {
          name: { type: "string" as const },
        },
      },
    },
  });

  const createMockResponse = (): ElicitationResponse => ({
    action: "accept",
    content: { name: "Test" },
  });

  beforeEach(() => {
    window.location.hash = "";
  });

  describe("initial state", () => {
    it("should return empty pending requests initially", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));

      expect(result.current.pendingRequests).toEqual([]);
    });
  });

  describe("handleElicitationRequest", () => {
    it("should add a new pending request", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));
      const request = createMockRequest();
      const resolve = jest.fn();

      act(() => {
        result.current.handleElicitationRequest(request, resolve);
      });

      expect(result.current.pendingRequests).toHaveLength(1);
      expect(result.current.pendingRequests[0].request.message).toBe(
        request.params.message,
      );
    });

    it("should switch to elicitations tab", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      expect(options.setActiveTab).toHaveBeenCalledWith("elicitations");
      expect(window.location.hash).toBe("#elicitations");
    });

    it("should capture originating tab", () => {
      const options = createMockOptions();
      options.lastToolCallOriginTabRef.current = "resources";

      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      expect(result.current.pendingRequests[0].originatingTab).toBe(
        "resources",
      );
    });

    it("should assign unique IDs to requests", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      const ids = result.current.pendingRequests.map((r) => r.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe("resolveRequest", () => {
    it("should resolve the request and remove it from pending", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));
      const resolve = jest.fn();

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), resolve);
      });

      const requestId = result.current.pendingRequests[0].id;
      const mockResponse = createMockResponse();

      act(() => {
        result.current.resolveRequest(requestId, mockResponse);
      });

      expect(resolve).toHaveBeenCalledWith(mockResponse);
      expect(result.current.pendingRequests).toHaveLength(0);
    });

    it("should navigate back to originating tab if valid", () => {
      const options = createMockOptions({
        serverCapabilities: { tools: {} },
      });
      options.lastToolCallOriginTabRef.current = "tools";

      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      // Clear the setActiveTab calls from handleElicitationRequest
      options.setActiveTab.mockClear();

      const requestId = result.current.pendingRequests[0].id;

      act(() => {
        result.current.resolveRequest(requestId, createMockResponse());
      });

      expect(options.setActiveTab).toHaveBeenCalledWith("tools");
    });

    it("should only remove the resolved request", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));
      const resolve1 = jest.fn();
      const resolve2 = jest.fn();

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), resolve1);
        result.current.handleElicitationRequest(createMockRequest(), resolve2);
      });

      const firstRequestId = result.current.pendingRequests[0].id;

      act(() => {
        result.current.resolveRequest(firstRequestId, createMockResponse());
      });

      expect(result.current.pendingRequests).toHaveLength(1);
      expect(resolve1).toHaveBeenCalled();
      expect(resolve2).not.toHaveBeenCalled();
    });
  });

  describe("getNextRequestId", () => {
    it("should return incrementing IDs", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));

      let id1: number, id2: number, id3: number;

      act(() => {
        id1 = result.current.getNextRequestId();
        id2 = result.current.getNextRequestId();
        id3 = result.current.getNextRequestId();
      });

      expect(id2!).toBeGreaterThan(id1!);
      expect(id3!).toBeGreaterThan(id2!);
    });
  });

  describe("FIX-001: Request ID consistency (validates off-by-one fix)", () => {
    it("should use identical request ID for both outer id and inner request.id", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));
      const request = createMockRequest();
      const resolve = jest.fn();

      act(() => {
        result.current.handleElicitationRequest(request, resolve);
      });

      const pendingRequest = result.current.pendingRequests[0];

      // Both outer ID and inner request.id should be identical
      expect(pendingRequest.id).toBe(pendingRequest.request.id);
      expect(pendingRequest.id).toBe(0);
    });

    it("should have sequential and matching IDs for multiple requests", () => {
      const options = createMockOptions();
      const { result } = renderHook(() => useElicitationHandler(options));
      const request = createMockRequest();
      const resolve = jest.fn();

      act(() => {
        result.current.handleElicitationRequest(request, resolve);
        result.current.handleElicitationRequest(request, resolve);
        result.current.handleElicitationRequest(request, resolve);
      });

      const requests = result.current.pendingRequests;
      expect(requests).toHaveLength(3);

      requests.forEach((req, index) => {
        // Outer ID and inner request.id should match
        expect(req.id).toBe(req.request.id);
        // IDs should be sequential
        expect(req.id).toBe(index);
      });
    });
  });

  describe("FIX-002: Metadata tab navigation", () => {
    it("should navigate back to metadata tab when it was the originating tab", () => {
      const options = createMockOptions({ serverCapabilities: {} });
      options.lastToolCallOriginTabRef.current = "metadata";

      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      const requestId = result.current.pendingRequests[0].id;

      // Clear the setActiveTab calls from handleElicitationRequest
      options.setActiveTab.mockClear();

      act(() => {
        result.current.resolveRequest(requestId, createMockResponse());
      });

      // Should have navigated back to metadata tab
      expect(options.setActiveTab).toHaveBeenCalledWith("metadata");
    });

    it("should recognize all static tabs as valid tabs", () => {
      const staticTabs = [
        "resources",
        "prompts",
        "tools",
        "ping",
        "sampling",
        "elicitations",
        "roots",
        "auth",
        "metadata",
      ];

      staticTabs.forEach((tab) => {
        // Provide full capabilities to ensure all tabs are valid
        const options = createMockOptions({
          serverCapabilities: { resources: {}, prompts: {}, tools: {} },
        });
        options.lastToolCallOriginTabRef.current = tab;

        const { result } = renderHook(() => useElicitationHandler(options));

        act(() => {
          result.current.handleElicitationRequest(
            createMockRequest(),
            jest.fn(),
          );
        });

        const requestId = result.current.pendingRequests[0].id;
        options.setActiveTab.mockClear();

        act(() => {
          result.current.resolveRequest(requestId, createMockResponse());
        });

        // Should have navigated back to the originating tab
        expect(options.setActiveTab).toHaveBeenCalledWith(tab);
      });
    });

    it("should not navigate back to invalid tabs", () => {
      const options = createMockOptions({ serverCapabilities: {} });
      options.lastToolCallOriginTabRef.current = "invalid-tab";

      const { result } = renderHook(() => useElicitationHandler(options));

      act(() => {
        result.current.handleElicitationRequest(createMockRequest(), jest.fn());
      });

      const requestId = result.current.pendingRequests[0].id;
      options.setActiveTab.mockClear();

      act(() => {
        result.current.resolveRequest(requestId, createMockResponse());
      });

      // Should not have called setActiveTab for navigation back (invalid tab)
      expect(options.setActiveTab).not.toHaveBeenCalledWith("invalid-tab");
    });
  });
});
