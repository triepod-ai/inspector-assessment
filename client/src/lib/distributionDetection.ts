/**
 * Distribution Detection Utility
 *
 * Detects how MCP servers are distributed (local bundle, remote, hybrid)
 * and recommends appropriate audit workflow.
 *
 * This is a lightweight utility function, NOT a full assessor.
 */

export type DistributionType =
  | "local_bundle" // Has manifest.json, runs via stdio
  | "local_source" // No bundle, direct source execution
  | "remote" // HTTP/SSE transport, no local source
  | "hybrid" // Uses mcp-remote or @modelcontextprotocol/remote
  | "unknown";

export type TransportType = "stdio" | "http" | "sse" | "unknown";

export interface DistributionInfo {
  type: DistributionType;
  hasManifest: boolean;
  isHybrid: boolean;
  hybridPattern?: "mcp-remote" | "modelcontextprotocol-remote";
  transport: TransportType;
  recommendedWorkflow: "local" | "remote" | "hybrid";
}

/**
 * Hybrid detection patterns for remote proxy servers
 */
const HYBRID_PATTERNS = [
  { name: "mcp-remote" as const, pattern: /mcp-remote/i },
  {
    name: "modelcontextprotocol-remote" as const,
    pattern: /@modelcontextprotocol\/remote/i,
  },
];

/**
 * Detect distribution type from context
 *
 * @param context - Context with manifest, transport, and command info
 * @returns Distribution information with type and recommended workflow
 */
export function detectDistribution(context: {
  manifestJson?: unknown;
  transport?: string;
  command?: string;
  args?: string[];
}): DistributionInfo {
  const hasManifest = !!context.manifestJson;
  const transport = normalizeTransport(context.transport);
  const isRemote = transport === "http" || transport === "sse";

  // Check for hybrid patterns in command/args
  const fullCommand = [context.command || "", ...(context.args || [])].join(
    " ",
  );
  const hybridMatch = detectHybridPattern(fullCommand);

  // Classify distribution type
  let type: DistributionType = "unknown";
  if (hybridMatch.isHybrid) {
    type = "hybrid";
  } else if (isRemote) {
    type = "remote";
  } else if (hasManifest) {
    type = "local_bundle";
  } else if (transport === "stdio") {
    type = "local_source";
  }

  // Recommend workflow based on type
  const recommendedWorkflow = hybridMatch.isHybrid
    ? "hybrid"
    : isRemote
      ? "remote"
      : "local";

  return {
    type,
    hasManifest,
    isHybrid: hybridMatch.isHybrid,
    hybridPattern: hybridMatch.pattern,
    transport,
    recommendedWorkflow,
  };
}

/**
 * Normalize transport string to known type
 */
function normalizeTransport(transport?: string): TransportType {
  if (!transport) return "unknown";
  const normalized = transport.toLowerCase();
  if (normalized === "stdio") return "stdio";
  if (normalized === "http" || normalized === "streamable-http") return "http";
  if (normalized === "sse") return "sse";
  return "unknown";
}

/**
 * Detect hybrid remote proxy patterns
 */
function detectHybridPattern(command: string): {
  isHybrid: boolean;
  pattern?: "mcp-remote" | "modelcontextprotocol-remote";
} {
  for (const { name, pattern } of HYBRID_PATTERNS) {
    if (pattern.test(command)) {
      return { isHybrid: true, pattern: name };
    }
  }
  return { isHybrid: false };
}
