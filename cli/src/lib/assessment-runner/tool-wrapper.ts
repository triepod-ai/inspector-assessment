/**
 * Tool Call Wrapper
 *
 * Creates a wrapper around MCP client.callTool() for assessment context.
 *
 * @module cli/lib/assessment-runner/tool-wrapper
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

import type { CallToolFn } from "./types.js";

/**
 * Create callTool wrapper for assessment context
 *
 * @param client - Connected MCP client
 * @returns Wrapped callTool function
 */
export function createCallToolWrapper(client: Client): CallToolFn {
  return async (
    name: string,
    params: Record<string, unknown>,
  ): Promise<CompatibilityCallToolResult> => {
    try {
      const response = await client.callTool({
        name,
        arguments: params,
      });

      return {
        content: response.content,
        isError: response.isError || false,
        structuredContent: (response as Record<string, unknown>)
          .structuredContent,
      } as CompatibilityCallToolResult;
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      } as CompatibilityCallToolResult;
    }
  };
}
