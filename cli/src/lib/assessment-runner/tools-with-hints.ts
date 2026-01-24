/**
 * Tools With Preserved Hints
 *
 * Issue #155: The MCP SDK's listTools() method validates responses against
 * a Zod schema that strips properties not explicitly defined (like readOnlyHint
 * as a direct property on tools). This module intercepts the raw transport
 * response to preserve these properties.
 *
 * Issue #160: Also preserves non-suffixed annotation property names (readOnly,
 * destructive, idempotent, openWorld) for servers that use the shorter names
 * instead of the *Hint suffix versions required by MCP spec.
 *
 * @module cli/lib/assessment-runner/tools-with-hints
 */

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Hint property names we want to preserve (*Hint suffix - MCP spec)
const HINT_PROPERTIES = [
  "readOnlyHint",
  "destructiveHint",
  "idempotentHint",
  "openWorldHint",
] as const;

// Issue #160: Non-suffixed property names (fallback for servers using shorter names)
const NON_SUFFIXED_PROPERTIES = [
  "readOnly",
  "destructive",
  "idempotent",
  "openWorld",
] as const;

// Mapping from non-suffixed to *Hint versions
const NON_SUFFIXED_TO_HINT: Record<string, string> = {
  readOnly: "readOnlyHint",
  destructive: "destructiveHint",
  idempotent: "idempotentHint",
  openWorld: "openWorldHint",
};

type HintProperty = (typeof HINT_PROPERTIES)[number];
type NonSuffixedProperty = (typeof NON_SUFFIXED_PROPERTIES)[number];

// Raw tool from MCP response (before Zod validation strips properties)
interface RawTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  // Direct hint properties that may be stripped by SDK (*Hint suffix)
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  // Issue #160: Direct non-suffixed properties (also stripped by SDK)
  readOnly?: boolean;
  destructive?: boolean;
  idempotent?: boolean;
  openWorld?: boolean;
  // Standard locations - annotations object may have either variant
  annotations?: {
    // *Hint suffix (MCP spec)
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    // Issue #160: Non-suffixed variants (also valid in raw response)
    readOnly?: boolean;
    destructive?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
  };
  metadata?: Record<string, unknown>;
  _meta?: Record<string, unknown>;
}

// Tool with preserved hint properties
export interface ToolWithHints extends Tool {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
  // Issue #207: Preserve complete annotations object from raw response
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    // Non-suffixed variants (Issue #160)
    readOnly?: boolean;
    destructive?: boolean;
    idempotent?: boolean;
    openWorld?: boolean;
    title?: string;
  };
}

/**
 * Get tools from MCP server with hint properties preserved.
 *
 * The MCP SDK's listTools() validates against a Zod schema that may strip
 * direct hint properties (readOnlyHint, etc.) that aren't in the schema.
 * This function intercepts the raw transport response to preserve them.
 *
 * @param client - Connected MCP client
 * @returns Tools with hint properties preserved from raw response
 */
export async function getToolsWithPreservedHints(
  client: Client,
): Promise<ToolWithHints[]> {
  let rawTools: RawTool[] = [];

  // Get the underlying transport
  const transport = client.transport;

  if (!transport) {
    // Fallback: just use SDK listTools if transport not accessible
    const response = await client.listTools();
    return response.tools || [];
  }

  // Store original message handler
  const originalOnMessage = transport.onmessage;

  // Intercept messages to capture raw tools/list response
  transport.onmessage = (message: unknown, extra?: unknown) => {
    // Check if this is a tools/list response
    const msg = message as { result?: { tools?: RawTool[] } };
    if (msg?.result?.tools && Array.isArray(msg.result.tools)) {
      rawTools = msg.result.tools;
    }

    // Call original handler (cast to any to preserve original typing)
    if (originalOnMessage) {
      (originalOnMessage as (msg: unknown, extra?: unknown) => void)(
        message,
        extra,
      );
    }
  };

  try {
    // Make SDK call (triggers our interceptor)
    const sdkResponse = await client.listTools();
    const sdkTools = sdkResponse.tools || [];

    // Restore original handler
    transport.onmessage = originalOnMessage;

    // If we didn't capture raw tools, just return SDK tools
    if (rawTools.length === 0) {
      return sdkTools;
    }

    // Merge preserved hint properties from raw into SDK tools
    return sdkTools.map((sdkTool) => {
      // Find matching raw tool by name
      const rawTool = rawTools.find((rt) => rt.name === sdkTool.name);
      if (!rawTool) {
        return sdkTool;
      }

      // Start with SDK tool
      const enrichedTool: ToolWithHints = { ...sdkTool };

      // Issue #207: Preserve complete annotations object from raw response
      // This ensures runtime-defined annotations are not lost when SDK strips them
      if (rawTool.annotations && Object.keys(rawTool.annotations).length > 0) {
        enrichedTool.annotations = {
          ...sdkTool.annotations, // Keep any SDK-preserved annotations
          ...rawTool.annotations, // Override with raw response annotations
        };

        // Debug logging when DEBUG_ANNOTATIONS env var is set
        if (process.env.DEBUG_ANNOTATIONS) {
          // eslint-disable-next-line no-console
          console.log(
            `[DEBUG-HINTS] ${rawTool.name}: Preserved annotations object:`,
            JSON.stringify(enrichedTool.annotations),
          );
        }
      }

      // Preserve hint properties from raw response (priority order)
      for (const hint of HINT_PROPERTIES) {
        // Skip if SDK already has it via annotations
        if (sdkTool.annotations?.[hint] !== undefined) {
          continue;
        }

        // Check raw tool locations in priority order:
        // 1. Direct property on raw tool (*Hint)
        // 2. Direct property on raw tool (non-suffixed, Issue #160)
        // 3. annotations object (*Hint)
        // 4. annotations object (non-suffixed, Issue #160)
        // 5. metadata object (*Hint)
        // 6. metadata object (non-suffixed, Issue #160)
        // 7. _meta object (*Hint)
        // 8. _meta object (non-suffixed, Issue #160)
        let value: boolean | undefined;

        // Get the non-suffixed equivalent (e.g., readOnlyHint -> readOnly)
        const nonSuffixed = hint.replace("Hint", "") as NonSuffixedProperty;

        // Check direct properties
        if (typeof rawTool[hint] === "boolean") {
          value = rawTool[hint];
        } else if (typeof rawTool[nonSuffixed] === "boolean") {
          value = rawTool[nonSuffixed];
        }
        // Check annotations object
        else if (typeof rawTool.annotations?.[hint] === "boolean") {
          value = rawTool.annotations[hint];
        } else if (typeof rawTool.annotations?.[nonSuffixed] === "boolean") {
          value = rawTool.annotations[nonSuffixed];
        }
        // Check metadata object
        else if (typeof rawTool.metadata?.[hint] === "boolean") {
          value = rawTool.metadata[hint] as boolean;
        } else if (typeof rawTool.metadata?.[nonSuffixed] === "boolean") {
          value = rawTool.metadata[nonSuffixed] as boolean;
        }
        // Check _meta object
        else if (typeof rawTool._meta?.[hint] === "boolean") {
          value = rawTool._meta[hint] as boolean;
        } else if (typeof rawTool._meta?.[nonSuffixed] === "boolean") {
          value = rawTool._meta[nonSuffixed] as boolean;
        }

        if (value !== undefined) {
          enrichedTool[hint] = value;
        }
      }

      return enrichedTool;
    });
  } catch (error) {
    // Restore original handler on error
    transport.onmessage = originalOnMessage;
    throw error;
  }
}
