import { useState, useRef, useCallback } from "react";
import {
  ClientRequest,
  CompatibilityCallToolResult,
  CompatibilityCallToolResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  AnySchema,
  SchemaOutput,
} from "@modelcontextprotocol/sdk/server/zod-compat.js";
import { cleanParams } from "@/utils/paramUtils";
import type { JsonSchemaType } from "@/utils/jsonUtils";

/**
 * Options for the useToolExecution hook
 */
export interface UseToolExecutionOptions {
  /** Function to make MCP requests */
  makeRequest: <T extends AnySchema>(
    request: ClientRequest,
    schema: T,
  ) => Promise<SchemaOutput<T>>;
  /** Available tools (for schema lookup) */
  tools: Tool[];
  /** General metadata to include with tool calls */
  metadata: Record<string, string>;
  /** Ref tracking which tab initiated the tool call */
  lastToolCallOriginTabRef: React.MutableRefObject<string>;
  /** Ref tracking the current tab */
  currentTabRef: React.MutableRefObject<string>;
  /** Callback for clearing errors */
  clearError: (tabKey: "tools") => void;
  /** Callback for setting errors */
  setError: (tabKey: "tools", error: string) => void;
}

/**
 * Return type for the useToolExecution hook
 */
export interface UseToolExecutionReturn {
  /** Result of the last tool call */
  toolResult: CompatibilityCallToolResult | null;
  /** Clear the current tool result */
  clearToolResult: () => void;
  /** Call a tool with the given name and parameters */
  callTool: (
    name: string,
    params: Record<string, unknown>,
    toolMetadata?: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  /** Whether a tool is currently executing */
  isExecuting: boolean;
}

/**
 * Custom hook for managing tool execution state
 *
 * Handles tool calling, parameter cleaning, metadata merging,
 * and result management.
 *
 * @param options - Hook configuration options
 * @returns Tool execution state and call function
 */
export function useToolExecution({
  makeRequest,
  tools,
  metadata,
  lastToolCallOriginTabRef,
  currentTabRef,
  clearError,
}: UseToolExecutionOptions): UseToolExecutionReturn {
  const [toolResult, setToolResult] =
    useState<CompatibilityCallToolResult | null>(null);
  const [isExecuting, setIsExecuting] = useState(false);
  const progressTokenRef = useRef(0);

  const clearToolResult = useCallback(() => {
    setToolResult(null);
  }, []);

  const callTool = useCallback(
    async (
      name: string,
      params: Record<string, unknown>,
      toolMetadata?: Record<string, unknown>,
    ): Promise<CompatibilityCallToolResult> => {
      // Track which tab initiated the call
      lastToolCallOriginTabRef.current = currentTabRef.current;

      setIsExecuting(true);

      try {
        // Find the tool schema to clean parameters properly
        const tool = tools.find((t) => t.name === name);
        const cleanedParams = tool?.inputSchema
          ? cleanParams(params, tool.inputSchema as JsonSchemaType)
          : params;

        // Merge general metadata with tool-specific metadata
        // Tool-specific metadata takes precedence over general metadata
        const mergedMetadata = {
          ...metadata,
          progressToken: progressTokenRef.current++,
          ...toolMetadata,
        };

        const response = await makeRequest(
          {
            method: "tools/call" as const,
            params: {
              name,
              arguments: cleanedParams,
              _meta: mergedMetadata,
            },
          },
          CompatibilityCallToolResultSchema,
        );

        setToolResult(response);
        clearError("tools");
        return response;
      } catch (e) {
        const errorResult: CompatibilityCallToolResult = {
          content: [
            {
              type: "text",
              text: (e as Error).message ?? String(e),
            },
          ],
          isError: true,
        };
        setToolResult(errorResult);
        // Clear validation errors - tool execution errors are shown in ToolResults
        clearError("tools");
        return errorResult;
      } finally {
        setIsExecuting(false);
      }
    },
    [
      makeRequest,
      tools,
      metadata,
      lastToolCallOriginTabRef,
      currentTabRef,
      clearError,
    ],
  );

  return {
    toolResult,
    clearToolResult,
    callTool,
    isExecuting,
  };
}

export default useToolExecution;
