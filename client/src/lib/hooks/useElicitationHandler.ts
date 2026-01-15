import { useState, useRef, useCallback } from "react";
import { ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";
import {
  PendingElicitationRequest,
  ElicitationResponse,
  ElicitationRequestData,
} from "@/components/ElicitationTab";

/**
 * Internal type for pending elicitation requests with resolve/decline handlers
 */
export interface PendingElicitationRequestWithHandlers extends PendingElicitationRequest {
  resolve: (response: ElicitationResponse) => void;
  decline: (error: Error) => void;
}

/**
 * Options for the useElicitationHandler hook
 */
export interface UseElicitationHandlerOptions {
  /** Callback to set the active tab when an elicitation request arrives */
  setActiveTab: (tab: string) => void;
  /** Ref to track the current tab for origination tracking */
  lastToolCallOriginTabRef: React.MutableRefObject<string>;
  /** Server capabilities to validate tabs */
  serverCapabilities: ServerCapabilities | null;
}

/**
 * Return type for the useElicitationHandler hook
 */
export interface UseElicitationHandlerReturn {
  /** Array of pending elicitation requests */
  pendingRequests: PendingElicitationRequestWithHandlers[];
  /** Handle a new elicitation request from the server */
  handleElicitationRequest: (
    request: {
      params: {
        message: string;
        requestedSchema: ElicitationRequestData["requestedSchema"];
      };
    },
    resolve: (response: ElicitationResponse) => void,
  ) => void;
  /** Resolve an elicitation request with the given response */
  resolveRequest: (id: number, response: ElicitationResponse) => void;
  /** Get the next request ID (for external coordination) */
  getNextRequestId: () => number;
}

/**
 * Get valid tabs based on server capabilities
 */
const getValidTabs = (
  serverCapabilities: ServerCapabilities | null,
): string[] => {
  return [
    ...(serverCapabilities?.resources ? ["resources"] : []),
    ...(serverCapabilities?.prompts ? ["prompts"] : []),
    ...(serverCapabilities?.tools ? ["tools"] : []),
    "ping",
    "sampling",
    "elicitations",
    "roots",
    "auth",
  ];
};

/**
 * Custom hook for managing elicitation request state
 *
 * Handles the lifecycle of elicitation requests from MCP servers,
 * including response submission and tab navigation.
 *
 * @param options - Hook configuration options
 * @returns Elicitation request state and handlers
 */
export function useElicitationHandler({
  setActiveTab,
  lastToolCallOriginTabRef,
  serverCapabilities,
}: UseElicitationHandlerOptions): UseElicitationHandlerReturn {
  const [pendingRequests, setPendingRequests] = useState<
    PendingElicitationRequestWithHandlers[]
  >([]);
  const nextRequestId = useRef(0);

  const getNextRequestId = useCallback(() => {
    return nextRequestId.current++;
  }, []);

  const handleElicitationRequest = useCallback(
    (
      request: {
        params: {
          message: string;
          requestedSchema: ElicitationRequestData["requestedSchema"];
        };
      },
      resolve: (response: ElicitationResponse) => void,
    ) => {
      const currentTab = lastToolCallOriginTabRef.current;

      setPendingRequests((prev) => [
        ...prev,
        {
          id: nextRequestId.current++,
          request: {
            id: nextRequestId.current,
            message: request.params.message,
            requestedSchema: request.params.requestedSchema,
          },
          originatingTab: currentTab,
          resolve,
          decline: (error: Error) => {
            console.error("Elicitation request rejected:", error);
          },
        },
      ]);

      // Switch to elicitations tab
      setActiveTab("elicitations");
      window.location.hash = "elicitations";
    },
    [setActiveTab, lastToolCallOriginTabRef],
  );

  const resolveRequest = useCallback(
    (id: number, response: ElicitationResponse) => {
      setPendingRequests((prev) => {
        const request = prev.find((r) => r.id === id);
        if (request) {
          request.resolve(response);

          // Navigate back to originating tab if valid
          if (request.originatingTab) {
            const originatingTab = request.originatingTab;
            const validTabs = getValidTabs(serverCapabilities);

            if (validTabs.includes(originatingTab)) {
              setActiveTab(originatingTab);
              window.location.hash = originatingTab;

              // Double-set with timeout for reliability
              setTimeout(() => {
                setActiveTab(originatingTab);
                window.location.hash = originatingTab;
              }, 100);
            }
          }
        }
        return prev.filter((r) => r.id !== id);
      });
    },
    [setActiveTab, serverCapabilities],
  );

  return {
    pendingRequests,
    handleElicitationRequest,
    resolveRequest,
    getNextRequestId,
  };
}

export default useElicitationHandler;
