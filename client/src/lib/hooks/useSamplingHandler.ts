import { useState, useRef, useCallback } from "react";
import { CreateMessageResult } from "@modelcontextprotocol/sdk/types.js";
import { PendingRequest } from "@/components/SamplingTab";

/**
 * Internal type for pending sampling requests with resolve/reject handlers
 */
export interface PendingSamplingRequest extends PendingRequest {
  resolve: (result: CreateMessageResult) => void;
  reject: (error: Error) => void;
}

/**
 * Return type for the useSamplingHandler hook
 */
export interface UseSamplingHandlerReturn {
  /** Array of pending sampling requests */
  pendingRequests: PendingSamplingRequest[];
  /** Handle a new sampling request from the server */
  handleSamplingRequest: (
    request: PendingRequest["request"],
    resolve: (result: CreateMessageResult) => void,
    reject: (error: Error) => void,
  ) => void;
  /** Approve a sampling request with the given result */
  approveRequest: (id: number, result: CreateMessageResult) => void;
  /** Reject a sampling request */
  rejectRequest: (id: number) => void;
  /** Get the next request ID (for external coordination) */
  getNextRequestId: () => number;
}

/**
 * Custom hook for managing sampling request state
 *
 * Handles the lifecycle of sampling requests from MCP servers,
 * including approval and rejection flows.
 *
 * @returns Sampling request state and handlers
 */
export function useSamplingHandler(): UseSamplingHandlerReturn {
  const [pendingRequests, setPendingRequests] = useState<
    PendingSamplingRequest[]
  >([]);
  const nextRequestId = useRef(0);

  const getNextRequestId = useCallback(() => {
    return nextRequestId.current++;
  }, []);

  const handleSamplingRequest = useCallback(
    (
      request: PendingRequest["request"],
      resolve: (result: CreateMessageResult) => void,
      reject: (error: Error) => void,
    ) => {
      setPendingRequests((prev) => [
        ...prev,
        {
          id: nextRequestId.current++,
          request,
          resolve,
          reject,
        },
      ]);
    },
    [],
  );

  const approveRequest = useCallback(
    (id: number, result: CreateMessageResult) => {
      setPendingRequests((prev) => {
        const request = prev.find((r) => r.id === id);
        request?.resolve(result);
        return prev.filter((r) => r.id !== id);
      });
    },
    [],
  );

  const rejectRequest = useCallback((id: number) => {
    setPendingRequests((prev) => {
      const request = prev.find((r) => r.id === id);
      request?.reject(new Error("Sampling request rejected"));
      return prev.filter((r) => r.id !== id);
    });
  }, []);

  return {
    pendingRequests,
    handleSamplingRequest,
    approveRequest,
    rejectRequest,
    getNextRequestId,
  };
}

export default useSamplingHandler;
