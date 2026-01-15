import { renderHook, act } from "@testing-library/react";
import { useSamplingHandler } from "../useSamplingHandler";
import { CreateMessageResult } from "@modelcontextprotocol/sdk/types.js";

describe("useSamplingHandler", () => {
  const createMockRequest = () => ({
    method: "sampling/createMessage" as const,
    params: {
      messages: [
        {
          role: "user" as const,
          content: { type: "text" as const, text: "Hello" },
        },
      ],
      maxTokens: 100,
    },
  });

  const createMockResult = (): CreateMessageResult => ({
    role: "assistant",
    content: { type: "text", text: "Response" },
    model: "test-model",
  });

  describe("initial state", () => {
    it("should return empty pending requests initially", () => {
      const { result } = renderHook(() => useSamplingHandler());

      expect(result.current.pendingRequests).toEqual([]);
    });
  });

  describe("handleSamplingRequest", () => {
    it("should add a new pending request", () => {
      const { result } = renderHook(() => useSamplingHandler());
      const request = createMockRequest();
      const resolve = jest.fn();
      const reject = jest.fn();

      act(() => {
        result.current.handleSamplingRequest(request, resolve, reject);
      });

      expect(result.current.pendingRequests).toHaveLength(1);
      expect(result.current.pendingRequests[0].request).toEqual(request);
    });

    it("should assign unique IDs to requests", () => {
      const { result } = renderHook(() => useSamplingHandler());
      const resolve = jest.fn();
      const reject = jest.fn();

      act(() => {
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve,
          reject,
        );
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve,
          reject,
        );
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve,
          reject,
        );
      });

      const ids = result.current.pendingRequests.map((r) => r.id);
      const uniqueIds = new Set(ids);
      expect(uniqueIds.size).toBe(ids.length);
    });
  });

  describe("approveRequest", () => {
    it("should resolve the request and remove it from pending", () => {
      const { result } = renderHook(() => useSamplingHandler());
      const resolve = jest.fn();
      const reject = jest.fn();

      act(() => {
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve,
          reject,
        );
      });

      const requestId = result.current.pendingRequests[0].id;
      const mockResult = createMockResult();

      act(() => {
        result.current.approveRequest(requestId, mockResult);
      });

      expect(resolve).toHaveBeenCalledWith(mockResult);
      expect(result.current.pendingRequests).toHaveLength(0);
    });

    it("should only remove the approved request", () => {
      const { result } = renderHook(() => useSamplingHandler());
      const resolve1 = jest.fn();
      const resolve2 = jest.fn();
      const reject = jest.fn();

      act(() => {
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve1,
          reject,
        );
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve2,
          reject,
        );
      });

      const firstRequestId = result.current.pendingRequests[0].id;

      act(() => {
        result.current.approveRequest(firstRequestId, createMockResult());
      });

      expect(result.current.pendingRequests).toHaveLength(1);
      expect(resolve1).toHaveBeenCalled();
      expect(resolve2).not.toHaveBeenCalled();
    });
  });

  describe("rejectRequest", () => {
    it("should reject the request with an error and remove it from pending", () => {
      const { result } = renderHook(() => useSamplingHandler());
      const resolve = jest.fn();
      const reject = jest.fn();

      act(() => {
        result.current.handleSamplingRequest(
          createMockRequest(),
          resolve,
          reject,
        );
      });

      const requestId = result.current.pendingRequests[0].id;

      act(() => {
        result.current.rejectRequest(requestId);
      });

      expect(reject).toHaveBeenCalledWith(expect.any(Error));
      expect(reject.mock.calls[0][0].message).toBe("Sampling request rejected");
      expect(result.current.pendingRequests).toHaveLength(0);
    });
  });

  describe("getNextRequestId", () => {
    it("should return incrementing IDs", () => {
      const { result } = renderHook(() => useSamplingHandler());

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
});
