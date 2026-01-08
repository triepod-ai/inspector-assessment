/**
 * Architecture Detector
 *
 * Detects server architecture characteristics including:
 * - Database backends (Neo4j, MongoDB, PostgreSQL, etc.)
 * - Transport modes (stdio, HTTP, SSE)
 * - Server type classification (local, hybrid, remote)
 * - Network access requirements
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import type {
  ArchitectureAnalysis,
  DatabaseBackend,
  TransportMode,
  ServerArchitectureType,
} from "@/lib/assessment/extendedTypes";
import {
  detectDatabasesFromContent,
  detectTransportsFromContent,
  checkNetworkAccess,
  detectExternalServices,
} from "../../config/architecturePatterns";

/**
 * Tool definition for analysis
 */
export interface Tool {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/**
 * Context provided for architecture detection
 */
export interface ArchitectureContext {
  /** Tools provided by the server */
  tools: Tool[];
  /** Transport type if known (from connection) */
  transportType?: string;
  /** Source code files (filename -> content) */
  sourceCodeFiles?: Map<string, string>;
  /** Manifest JSON content */
  manifestJson?: {
    name?: string;
    description?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  /** Package.json content if available */
  packageJson?: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  /** Requirements.txt content if available */
  requirementsTxt?: string;
}

/**
 * Detect architecture characteristics from the provided context.
 *
 * @param context - Architecture context with tools, source code, etc.
 * @returns ArchitectureAnalysis with detected characteristics
 */
export function detectArchitecture(
  context: ArchitectureContext,
): ArchitectureAnalysis {
  const evidence = {
    databaseIndicators: [] as string[],
    transportIndicators: [] as string[],
    networkIndicators: [] as string[],
  };

  // Collect all text content for analysis
  const allContent = collectAnalyzableContent(context);

  // Detect databases
  const databaseResults = detectDatabasesFromContent(allContent);
  const databaseBackends = databaseResults.map((r) => r.backend);
  const primaryDatabase = databaseBackends[0] as DatabaseBackend | undefined;
  evidence.databaseIndicators = databaseResults.map((r) => r.evidence);

  // Detect transports
  const detectedTransports = detectTransportsFromContent(allContent);

  // Include transport from connection if known
  if (context.transportType) {
    const normalized = normalizeTransport(context.transportType);
    if (normalized && !detectedTransports.includes(normalized)) {
      detectedTransports.push(normalized);
    }
    evidence.transportIndicators.push(`Connection transport: ${normalized}`);
  }

  // Detect network access requirements
  const networkCheck = checkNetworkAccess(allContent);
  if (networkCheck.requiresNetwork) {
    evidence.networkIndicators = networkCheck.indicators;
  }

  // Detect external services
  const externalServices = detectExternalServices(allContent);

  // Classify server type
  const serverType = classifyServerType(
    detectedTransports,
    networkCheck.requiresNetwork,
    networkCheck.localOnly,
    externalServices,
  );

  // Calculate confidence
  const confidence = calculateConfidence(
    databaseResults,
    detectedTransports,
    evidence,
    context,
  );

  return {
    serverType,
    databaseBackend: primaryDatabase,
    databaseBackends: databaseBackends.length > 0 ? databaseBackends : [],
    transportModes:
      detectedTransports.length > 0 ? detectedTransports : ["stdio"],
    externalDependencies: externalServices,
    requiresNetworkAccess:
      networkCheck.requiresNetwork || externalServices.length > 0,
    confidence,
    evidence,
  };
}

/**
 * Collect all analyzable text content from context.
 */
function collectAnalyzableContent(context: ArchitectureContext): string {
  const parts: string[] = [];

  // Tool names and descriptions
  for (const tool of context.tools) {
    parts.push(tool.name);
    if (tool.description) {
      parts.push(tool.description);
    }
    // Include schema as stringified JSON for pattern matching
    if (tool.inputSchema) {
      try {
        parts.push(JSON.stringify(tool.inputSchema));
      } catch {
        // Ignore stringify errors
      }
    }
  }

  // Manifest content
  if (context.manifestJson) {
    if (context.manifestJson.name) parts.push(context.manifestJson.name);
    if (context.manifestJson.description)
      parts.push(context.manifestJson.description);
    if (context.manifestJson.dependencies) {
      parts.push(Object.keys(context.manifestJson.dependencies).join(" "));
    }
    if (context.manifestJson.devDependencies) {
      parts.push(Object.keys(context.manifestJson.devDependencies).join(" "));
    }
  }

  // Package.json dependencies
  if (context.packageJson) {
    if (context.packageJson.dependencies) {
      parts.push(Object.keys(context.packageJson.dependencies).join(" "));
    }
    if (context.packageJson.devDependencies) {
      parts.push(Object.keys(context.packageJson.devDependencies).join(" "));
    }
  }

  // Requirements.txt
  if (context.requirementsTxt) {
    parts.push(context.requirementsTxt);
  }

  // Source code files (limited to avoid overwhelming)
  if (context.sourceCodeFiles) {
    let charCount = 0;
    const maxChars = 100000; // Limit to ~100KB of source
    for (const [filename, content] of context.sourceCodeFiles) {
      parts.push(filename);
      if (charCount + content.length <= maxChars) {
        parts.push(content);
        charCount += content.length;
      }
    }
  }

  return parts.join("\n");
}

/**
 * Normalize transport type string to TransportMode.
 */
function normalizeTransport(transport: string): TransportMode | null {
  const lower = transport.toLowerCase();
  if (lower.includes("stdio")) return "stdio";
  if (lower.includes("sse")) return "sse";
  if (lower.includes("http")) return "http";
  return null;
}

/**
 * Classify server architecture type based on detected characteristics.
 */
function classifyServerType(
  transports: TransportMode[],
  requiresNetwork: boolean,
  _localOnly: boolean, // Reserved for future local-only detection enhancement
  externalServices: string[],
): ServerArchitectureType {
  // Remote: HTTP/SSE transport without stdio, or many external services
  if (
    (transports.includes("http") || transports.includes("sse")) &&
    !transports.includes("stdio")
  ) {
    return "remote";
  }

  // Remote: Many external service dependencies
  if (externalServices.length >= 3) {
    return "remote";
  }

  // Hybrid: Both local (stdio) and remote capabilities
  if (
    transports.includes("stdio") &&
    (transports.includes("http") || transports.includes("sse"))
  ) {
    return "hybrid";
  }

  // Hybrid: Local transport but requires network
  if (transports.includes("stdio") && requiresNetwork) {
    return "hybrid";
  }

  // Hybrid: Has some external services
  if (externalServices.length > 0) {
    return "hybrid";
  }

  // Local: stdio-only with no network requirements
  return "local";
}

/**
 * Calculate confidence level based on evidence strength.
 */
function calculateConfidence(
  databaseResults: Array<{
    backend: DatabaseBackend;
    confidence: "high" | "medium" | "low";
  }>,
  transports: TransportMode[],
  _evidence: ArchitectureAnalysis["evidence"], // Reserved for future evidence-based scoring
  context: ArchitectureContext,
): "high" | "medium" | "low" {
  let score = 0;

  // Database detection confidence
  const highConfidenceDbs = databaseResults.filter(
    (r) => r.confidence === "high",
  );
  if (highConfidenceDbs.length > 0) score += 30;
  else if (databaseResults.length > 0) score += 15;

  // Transport detection
  if (context.transportType)
    score += 30; // Known from connection
  else if (transports.length > 0) score += 20; // Detected from patterns

  // Source code analysis
  if (context.sourceCodeFiles && context.sourceCodeFiles.size > 0) score += 20;

  // Package.json/requirements.txt
  if (context.packageJson || context.requirementsTxt) score += 15;

  // Tool descriptions
  const toolsWithDescriptions = context.tools.filter(
    (t) => t.description && t.description.length > 20,
  );
  if (toolsWithDescriptions.length >= 3) score += 15;
  else if (toolsWithDescriptions.length > 0) score += 10;

  // Convert score to confidence level
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

/**
 * Quick check if tools suggest database operations.
 *
 * @param tools - Tools to analyze
 * @returns True if tools suggest database operations
 */
export function hasDatabaseToolPatterns(tools: Tool[]): boolean {
  // Pattern matches database operation keywords at word boundaries or with underscores
  // Uses (?:^|[\s_-]) for start boundary and (?:$|[\s_-]) for end boundary
  // to handle snake_case naming like "select_records"
  const dbPatterns =
    /(?:^|[\s_-])(query|select|insert|update|delete|find|aggregate|create_table|drop_table|migrate|seed|backup)(?:$|[\s_-])/i;

  for (const tool of tools) {
    if (dbPatterns.test(tool.name)) return true;
    if (tool.description && dbPatterns.test(tool.description)) return true;
  }

  return false;
}

/**
 * Extract database types from package.json dependencies.
 *
 * @param dependencies - Package.json dependencies object
 * @returns Array of detected database types
 */
export function extractDatabasesFromDependencies(
  dependencies: Record<string, string>,
): DatabaseBackend[] {
  const results: DatabaseBackend[] = [];
  const depNames = Object.keys(dependencies).join(" ");
  const detected = detectDatabasesFromContent(depNames);

  for (const d of detected) {
    if (!results.includes(d.backend)) {
      results.push(d.backend);
    }
  }

  return results;
}
