/**
 * Stdio Transport Detector
 *
 * Identifies stdio transport support from multiple sources:
 * 1. server.json manifest (packages[0].transport.type)
 * 2. package.json bin entries (indicates CLI/stdio)
 * 3. Source code scanning for transport patterns
 * 4. Runtime transport configuration
 *
 * This fixes Issue #172: C6/F6 incorrectly fails for valid stdio servers
 * because transport detection previously relied solely on serverInfo metadata.
 *
 * @module helpers/StdioTransportDetector
 */

import type { TransportMode } from "../config/architecturePatterns.js";

/**
 * Evidence source for transport detection
 */
export type TransportEvidenceSource =
  | "server.json"
  | "package.json"
  | "source-code"
  | "runtime-config";

/**
 * Individual piece of transport detection evidence
 */
export interface TransportEvidence {
  /** Source of the evidence */
  source: TransportEvidenceSource;
  /** Transport type detected */
  transport: TransportMode;
  /** Confidence level for this evidence */
  confidence: "high" | "medium" | "low";
  /** Human-readable detail about the detection */
  detail: string;
}

/**
 * Transport detection results
 */
export interface TransportDetectionResult {
  /** Set of detected transport modes */
  detectedTransports: Set<TransportMode>;
  /** Overall detection confidence */
  confidence: "high" | "medium" | "low";
  /** All evidence collected during detection */
  evidence: TransportEvidence[];
  /** Whether stdio transport is supported */
  supportsStdio: boolean;
  /** Whether HTTP transport is supported */
  supportsHTTP: boolean;
  /** Whether SSE transport is supported */
  supportsSSE: boolean;
  /** Whether source code was scanned */
  sourceCodeScanned: boolean;
}

/**
 * server.json structure (partial - transport fields only)
 */
export interface ServerJsonTransport {
  packages?: Array<{
    transport?: {
      type?: string;
    };
  }>;
}

/**
 * package.json structure (partial - bin field only)
 */
export interface PackageJsonBin {
  bin?: Record<string, string> | string;
}

/**
 * Detects transport capabilities from multiple sources.
 *
 * Detection priority (highest confidence first):
 * 1. Runtime transport configuration (actual runtime proof)
 * 2. server.json transport declaration (explicit manifest)
 * 3. package.json bin entries (strong CLI/stdio indicator)
 * 4. Source code patterns (StdioServerTransport, mcp.run, etc.)
 *
 * @public
 */
export class StdioTransportDetector {
  /**
   * TypeScript/JavaScript patterns for stdio transport
   */
  private readonly STDIO_CODE_PATTERNS: Array<{
    pattern: RegExp;
    description: string;
  }> = [
    {
      pattern: /StdioServerTransport/,
      description: "Uses StdioServerTransport class",
    },
    {
      pattern: /from\s*['"]@modelcontextprotocol\/sdk\/server\/stdio/,
      description: "Imports MCP SDK stdio module",
    },
    {
      pattern: /from\s*['"].*\/stdio/,
      description: "Imports stdio transport module",
    },
    {
      pattern: /transport\s*[:=]\s*['"]stdio['"]/i,
      description: "Declares transport as stdio",
    },
    {
      pattern: /createStdioTransport/,
      description: "Creates stdio transport",
    },
  ];

  /**
   * Python/FastMCP patterns for stdio transport
   */
  private readonly PYTHON_STDIO_PATTERNS: Array<{
    pattern: RegExp;
    description: string;
  }> = [
    {
      pattern: /mcp\.run\s*\(\s*transport\s*=\s*['"]stdio['"]/,
      description: "FastMCP run with stdio transport",
    },
    {
      pattern: /StdioTransport/,
      description: "Uses StdioTransport class",
    },
    {
      pattern: /transport\s*=\s*['"]stdio['"]/i,
      description: "Python stdio transport declaration",
    },
    {
      pattern: /from\s+mcp\.server\.stdio\s+import/,
      description: "Imports MCP stdio module (Python)",
    },
  ];

  /**
   * HTTP/SSE transport patterns
   */
  private readonly HTTP_CODE_PATTERNS: Array<{
    pattern: RegExp;
    transport: "http" | "sse";
    description: string;
  }> = [
    {
      pattern: /StreamableHTTPServerTransport/,
      transport: "http",
      description: "Uses StreamableHTTPServerTransport",
    },
    {
      pattern: /SSEServerTransport/,
      transport: "sse",
      description: "Uses SSEServerTransport",
    },
    {
      pattern: /transport\s*[:=]\s*['"]http['"]/i,
      transport: "http",
      description: "Declares transport as http",
    },
    {
      pattern: /transport\s*[:=]\s*['"]sse['"]/i,
      transport: "sse",
      description: "Declares transport as sse",
    },
    {
      pattern: /transport\s*[:=]\s*['"]streamable-http['"]/i,
      transport: "http",
      description: "Declares transport as streamable-http",
    },
    {
      pattern: /express|fastify|koa|hono/i,
      transport: "http",
      description: "Uses HTTP framework",
    },
    {
      pattern: /app\.listen\s*\(/,
      transport: "http",
      description: "HTTP server listen call",
    },
  ];

  /**
   * File patterns to skip during source code scanning
   */
  private readonly SKIP_FILE_PATTERNS: RegExp[] = [
    /node_modules/i,
    /\.test\.(ts|js|tsx|jsx|py)$/i,
    /\.spec\.(ts|js|tsx|jsx|py)$/i,
    /\.d\.ts$/i,
    /package-lock\.json$/i,
    /yarn\.lock$/i,
    /\.map$/i,
    /\.git\//i,
    /dist\//i,
    /build\//i,
    /__tests__\//i,
    /__mocks__\//i,
    /__pycache__\//i,
    /\.pytest_cache\//i,
  ];

  /** Maximum file size for source scanning (500KB) */
  private readonly MAX_FILE_SIZE = 500_000;

  /**
   * Detect transport capabilities from all available sources.
   *
   * @param sourceCodeFiles - Map of file paths to content
   * @param packageJson - Parsed package.json content
   * @param serverJson - Parsed server.json content
   * @param runtimeTransport - Transport type from runtime config
   * @returns Transport detection results
   */
  detect(
    sourceCodeFiles?: Map<string, string>,
    packageJson?: PackageJsonBin,
    serverJson?: ServerJsonTransport,
    runtimeTransport?: TransportMode,
  ): TransportDetectionResult {
    const evidence: TransportEvidence[] = [];
    const detectedTransports = new Set<TransportMode>();

    // 1. Runtime transport config (highest confidence)
    if (runtimeTransport) {
      detectedTransports.add(runtimeTransport);
      evidence.push({
        source: "runtime-config",
        transport: runtimeTransport,
        confidence: "high",
        detail: `Runtime transport configured as ${runtimeTransport}`,
      });
    }

    // 2. server.json transport declaration
    if (serverJson?.packages?.[0]?.transport?.type) {
      const transportType = serverJson.packages[0].transport
        .type as TransportMode;
      if (this.isValidTransport(transportType)) {
        detectedTransports.add(transportType);
        evidence.push({
          source: "server.json",
          transport: transportType,
          confidence: "high",
          detail: `server.json declares transport.type="${transportType}"`,
        });
      }
    }

    // 3. package.json bin entries (strong stdio indicator)
    if (packageJson?.bin) {
      const binEntry =
        typeof packageJson.bin === "string"
          ? packageJson.bin
          : Object.keys(packageJson.bin)[0];
      if (binEntry) {
        detectedTransports.add("stdio");
        evidence.push({
          source: "package.json",
          transport: "stdio",
          confidence: "high",
          detail: `package.json has bin entry (CLI tools use stdio)`,
        });
      }
    }

    // 4. Source code scanning
    const sourceCodeScanned =
      sourceCodeFiles !== undefined && sourceCodeFiles.size > 0;
    if (sourceCodeFiles !== undefined && sourceCodeFiles.size > 0) {
      const sourceEvidence = this.scanSourceCode(sourceCodeFiles);
      for (const ev of sourceEvidence) {
        evidence.push(ev);
        detectedTransports.add(ev.transport);
      }
    }

    // Compute overall confidence
    const confidence = this.computeConfidence(evidence);

    return {
      detectedTransports,
      confidence,
      evidence,
      supportsStdio: detectedTransports.has("stdio"),
      supportsHTTP: detectedTransports.has("http"),
      supportsSSE: detectedTransports.has("sse"),
      sourceCodeScanned,
    };
  }

  /**
   * Scan source code files for transport patterns.
   *
   * @param sourceCodeFiles - Map of file paths to content
   * @returns Array of evidence from source code analysis
   */
  private scanSourceCode(
    sourceCodeFiles: Map<string, string>,
  ): TransportEvidence[] {
    const evidence: TransportEvidence[] = [];
    const foundPatterns = new Set<string>(); // Deduplicate

    sourceCodeFiles.forEach((content, filePath) => {
      // Skip test files, node_modules, etc.
      if (this.shouldSkipFile(filePath)) return;

      // Skip oversized files
      if (content.length > this.MAX_FILE_SIZE) return;

      // Check stdio patterns (TypeScript/JavaScript)
      for (const { pattern, description } of this.STDIO_CODE_PATTERNS) {
        const key = `stdio:${description}`;
        if (!foundPatterns.has(key) && pattern.test(content)) {
          foundPatterns.add(key);
          evidence.push({
            source: "source-code",
            transport: "stdio",
            confidence: "medium",
            detail: `${description} in ${this.shortenPath(filePath)}`,
          });
        }
      }

      // Check stdio patterns (Python)
      for (const { pattern, description } of this.PYTHON_STDIO_PATTERNS) {
        const key = `stdio-py:${description}`;
        if (!foundPatterns.has(key) && pattern.test(content)) {
          foundPatterns.add(key);
          evidence.push({
            source: "source-code",
            transport: "stdio",
            confidence: "medium",
            detail: `${description} in ${this.shortenPath(filePath)}`,
          });
        }
      }

      // Check HTTP/SSE patterns
      for (const { pattern, transport, description } of this
        .HTTP_CODE_PATTERNS) {
        const key = `${transport}:${description}`;
        if (!foundPatterns.has(key) && pattern.test(content)) {
          foundPatterns.add(key);
          evidence.push({
            source: "source-code",
            transport,
            confidence: "medium",
            detail: `${description} in ${this.shortenPath(filePath)}`,
          });
        }
      }
    });

    return evidence;
  }

  /**
   * Check if a transport type is valid.
   */
  private isValidTransport(transport: string): transport is TransportMode {
    return ["stdio", "http", "sse"].includes(transport);
  }

  /**
   * Check if a file should be skipped during scanning.
   */
  private shouldSkipFile(filePath: string): boolean {
    return this.SKIP_FILE_PATTERNS.some((pattern) => pattern.test(filePath));
  }

  /**
   * Shorten file path for display.
   */
  private shortenPath(filePath: string): string {
    const parts = filePath.split("/");
    if (parts.length > 2) {
      return `.../${parts.slice(-2).join("/")}`;
    }
    return filePath;
  }

  /**
   * Compute overall confidence from collected evidence.
   *
   * Confidence rules:
   * - High: Any high-confidence evidence present
   * - Medium: Only medium-confidence evidence OR multiple sources agree
   * - Low: No evidence or only weak patterns
   */
  private computeConfidence(
    evidence: TransportEvidence[],
  ): "high" | "medium" | "low" {
    if (evidence.length === 0) {
      return "low";
    }

    // Any high-confidence evidence = overall high
    if (evidence.some((e) => e.confidence === "high")) {
      return "high";
    }

    // Multiple sources agreeing boosts confidence
    const uniqueSources = new Set(evidence.map((e) => e.source));
    if (uniqueSources.size >= 2) {
      return "high";
    }

    // Multiple medium-confidence findings = overall medium
    if (evidence.length >= 2) {
      return "medium";
    }

    // Single medium-confidence finding
    return "medium";
  }
}
