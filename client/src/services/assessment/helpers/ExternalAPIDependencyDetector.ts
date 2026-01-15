/**
 * External API Dependency Detector
 *
 * Identifies tools that depend on external APIs based on:
 * 1. Tool name and description patterns (fast, always available)
 * 2. Source code scanning for API calls (more accurate, when source available)
 *
 * This information enables downstream assessors to adjust their behavior:
 * - TemporalAssessor: Relaxed variance thresholds for external API tools
 * - FunctionalityAssessor: Accept API errors as valid responses
 * - ErrorHandlingAssessor: Account for external service failures
 *
 * Issue #168: Enhanced with source code scanning support
 *
 * @module helpers/ExternalAPIDependencyDetector
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Implications of external API dependencies for downstream assessors
 * @public
 */
export interface ExternalAPIImplications {
  /** Expected temporal variance behavior */
  temporalVariance: string;
  /** Dependency on external service availability */
  availabilityDependency: string;
  /** Potential rate limiting from external services */
  rateLimitingRisk?: string;
}

/**
 * External API dependency detection results
 * @public
 */
export interface ExternalAPIDependencyInfo {
  /** Set of tool names that depend on external APIs */
  toolsWithExternalAPIDependency: Set<string>;
  /** Number of tools detected with external API dependencies */
  detectedCount: number;
  /** Detection confidence based on pattern strength */
  confidence: "high" | "medium" | "low";
  /** List of detected tool names (for serialization) */
  detectedTools: string[];
  /** Extracted domains from source code scanning (e.g., ["api.worldbank.org"]) */
  domains?: string[];
  /** Whether source code was available and scanned */
  sourceCodeScanned?: boolean;
  /** Implications for downstream assessors when external APIs are detected */
  implications?: ExternalAPIImplications;
}

/**
 * Detects external API dependencies in MCP tools based on name and description patterns.
 * Designed to run during context preparation before assessors execute.
 *
 * @public
 */
export class ExternalAPIDependencyDetector {
  /**
   * Tool name patterns that suggest external API dependency.
   * Uses word-boundary matching to prevent false positives.
   *
   * Extracted from VarianceClassifier (Issue #166) for reuse across modules.
   */
  private readonly EXTERNAL_API_PATTERNS = [
    // API-related prefixes
    "api",
    "external",
    "remote",
    "live",
    // Data type patterns (typically from external sources)
    "weather",
    "stock",
    "price",
    "market",
    "currency",
    "exchange",
    "rate",
    "forex",
    // Service-specific prefixes
    "wb", // World Bank
    "worldbank",
    // Action patterns suggesting external fetch
    "fetch_from",
    "poll",
    "realtime",
    "current",
  ];

  /**
   * Description patterns that suggest external API dependency.
   * Regex patterns for more flexible matching.
   */
  private readonly EXTERNAL_API_DESCRIPTION_PATTERNS = [
    /external\s*(api|service)/i,
    /fetche?s?\s*(from|data\s+from)/i,
    /calls?\s*(external|remote)/i,
    /live\s*(data|feed|stream)/i,
    /real[- ]?time/i,
    /world\s*bank/i,
    /third[- ]?party\s*(api|service)/i,
  ];

  /**
   * Source code patterns that indicate external API calls.
   * Each pattern captures the URL in group 1.
   *
   * Issue #168: Patterns from proposal for source code scanning
   */
  private readonly SOURCE_CODE_API_PATTERNS: RegExp[] = [
    // fetch() calls - JavaScript/TypeScript
    /fetch\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // axios HTTP client calls
    /axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // URL construction
    /new\s+URL\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // Common API base URL constants
    /(?:API_BASE_URL|BASE_URL|API_URL|ENDPOINT)\s*=\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // Generic HTTP client .get/.post calls
    /\.\s*(?:get|post)\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // Python requests library
    /requests\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
    // Python httpx library
    /httpx\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`](https?:\/\/[^'"`\s]+)/gi,
  ];

  /**
   * URL patterns to skip (localhost, local networks, documentation)
   */
  private readonly LOCALHOST_PATTERNS: RegExp[] = [
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /192\.168\./,
    /10\.\d+\./,
    /172\.(?:1[6-9]|2[0-9]|3[01])\./,
    /\.local\b/i,
    /example\.com/i,
    /test\.com/i,
  ];

  /**
   * File patterns to skip during source code scanning
   */
  private readonly SKIP_FILE_PATTERNS: RegExp[] = [
    /node_modules/i,
    /\.test\.(ts|js|tsx|jsx)$/i,
    /\.spec\.(ts|js|tsx|jsx)$/i,
    /\.d\.ts$/i,
    /package-lock\.json$/i,
    /yarn\.lock$/i,
    /\.map$/i,
    /\.git\//i,
    /dist\//i,
    /build\//i,
    /__tests__\//i,
    /__mocks__\//i,
  ];

  /**
   * Detect external API dependencies from tools and optionally source code.
   *
   * Detection strategy:
   * 1. Always analyze tool names and descriptions (fast, no source needed)
   * 2. If sourceCodeFiles provided, scan for actual API calls (more accurate)
   * 3. Combine results and compute confidence
   *
   * @param tools - List of MCP tools to analyze
   * @param sourceCodeFiles - Optional map of file paths to content for source scanning
   * @returns Detection results with tool names, domains, and implications
   */
  detect(
    tools: Tool[],
    sourceCodeFiles?: Map<string, string>,
  ): ExternalAPIDependencyInfo {
    // Phase 1: Name/description pattern matching (always runs)
    const toolsWithExternalAPI = new Set<string>();

    for (const tool of tools) {
      if (this.isExternalAPITool(tool)) {
        toolsWithExternalAPI.add(tool.name);
      }
    }

    const detectedCount = toolsWithExternalAPI.size;

    // Phase 2: Source code scanning (when available)
    let domains: string[] | undefined;
    let sourceCodeScanned = false;

    if (sourceCodeFiles && sourceCodeFiles.size > 0) {
      sourceCodeScanned = true;
      domains = this.scanSourceCode(sourceCodeFiles);
    }

    // Compute confidence based on both detection methods
    const confidence = this.computeConfidence(detectedCount, domains);

    // Generate implications if any external APIs were detected
    const hasExternalDependencies =
      detectedCount > 0 || (domains && domains.length > 0);
    const implications = hasExternalDependencies
      ? this.generateImplications(domains)
      : undefined;

    return {
      toolsWithExternalAPIDependency: toolsWithExternalAPI,
      detectedCount,
      confidence,
      detectedTools: Array.from(toolsWithExternalAPI),
      domains,
      sourceCodeScanned,
      implications,
    };
  }

  /** Maximum content length per file (500KB) - prevents ReDoS attacks */
  private readonly MAX_CONTENT_LENGTH = 500_000;

  /** Maximum matches per file - prevents runaway matching */
  private readonly MAX_MATCHES_PER_FILE = 100;

  /**
   * Scan source code files for external API URLs.
   * Returns unique external domains found in the code.
   *
   * @param sourceCodeFiles - Map of file paths to content
   * @returns Array of unique external domain names
   */
  scanSourceCode(sourceCodeFiles: Map<string, string>): string[] {
    const domains = new Set<string>();

    sourceCodeFiles.forEach((content, filePath) => {
      // Skip test files, node_modules, etc.
      if (this.shouldSkipFile(filePath)) return;

      // Skip oversized files to prevent ReDoS
      if (content.length > this.MAX_CONTENT_LENGTH) return;

      // Try each API call pattern using matchAll (thread-safe, no lastIndex issues)
      for (const pattern of this.SOURCE_CODE_API_PATTERNS) {
        // Use Array.from for compatibility with older TS targets
        const matches = Array.from(content.matchAll(pattern));
        let matchCount = 0;
        for (const match of matches) {
          if (matchCount >= this.MAX_MATCHES_PER_FILE) break;
          matchCount++;

          const url = match[1];

          // Skip localhost and local network URLs
          if (this.isLocalhost(url)) continue;

          // Extract domain from URL
          const domain = this.extractDomain(url);
          if (domain) {
            domains.add(domain);
          }
        }
      }
    });

    return Array.from(domains);
  }

  /**
   * Extract the hostname from a URL string.
   *
   * @param url - URL string (may be partial)
   * @returns Hostname or null if extraction fails
   */
  private extractDomain(url: string): string | null {
    try {
      // Handle URLs that may not have protocol
      const fullUrl = url.startsWith("http") ? url : `https://${url}`;
      return new URL(fullUrl).hostname;
    } catch {
      return null;
    }
  }

  /**
   * Check if a URL points to localhost or local network.
   *
   * @param url - URL string to check
   * @returns true if URL is local
   */
  private isLocalhost(url: string): boolean {
    return this.LOCALHOST_PATTERNS.some((pattern) => pattern.test(url));
  }

  /**
   * Check if a file should be skipped during source scanning.
   *
   * @param filePath - Path to check
   * @returns true if file should be skipped
   */
  private shouldSkipFile(filePath: string): boolean {
    return this.SKIP_FILE_PATTERNS.some((pattern) => pattern.test(filePath));
  }

  /**
   * Compute detection confidence based on both methods.
   * Source code confirmation boosts confidence.
   *
   * @param toolCount - Number of tools detected via name/description
   * @param domains - Domains found in source code
   * @returns Confidence level
   */
  private computeConfidence(
    toolCount: number,
    domains?: string[],
  ): "high" | "medium" | "low" {
    const domainCount = domains?.length ?? 0;

    // Both methods agree = high confidence
    if (toolCount > 0 && domainCount > 0) {
      return "high";
    }

    // Either method found multiple = high confidence
    if (toolCount >= 3 || domainCount >= 3) {
      return "high";
    }

    // Either method found something = medium confidence
    if (toolCount > 0 || domainCount > 0) {
      return "medium";
    }

    // Nothing found = low confidence (no external APIs)
    return "low";
  }

  /**
   * Generate implications for downstream assessors.
   *
   * @param domains - External domains found
   * @returns Implications object
   */
  private generateImplications(domains?: string[]): ExternalAPIImplications {
    const domainList =
      domains && domains.length > 0 ? domains.join(", ") : "external services";

    return {
      temporalVariance: "Expected - external data changes between invocations",
      availabilityDependency: `Server depends on ${domainList} uptime`,
      rateLimitingRisk:
        domains && domains.length > 0
          ? `May encounter rate limits from ${domainList}`
          : undefined,
    };
  }

  /**
   * Check if a single tool depends on external APIs.
   * Uses BOTH name patterns AND description analysis for detection.
   *
   * @param tool - MCP tool to check
   * @returns true if tool appears to depend on external APIs
   */
  isExternalAPITool(tool: Tool): boolean {
    const toolName = tool.name.toLowerCase();
    const description = (tool.description || "").toLowerCase();

    // Check name patterns with word-boundary matching
    // "weather_api" matches "api" but "capital_gains" doesn't match "api"
    const nameMatch = this.EXTERNAL_API_PATTERNS.some((pattern) => {
      const wordBoundaryRegex = new RegExp(`(^|_|-)${pattern}($|_|-|s)`);
      return wordBoundaryRegex.test(toolName);
    });

    // Check description for external API indicators
    const descriptionMatch = this.EXTERNAL_API_DESCRIPTION_PATTERNS.some(
      (regex) => regex.test(description),
    );

    return nameMatch || descriptionMatch;
  }

  /**
   * Get the list of name patterns used for detection.
   * Useful for debugging and documentation.
   */
  getNamePatterns(): readonly string[] {
    return this.EXTERNAL_API_PATTERNS;
  }

  /**
   * Get the list of description patterns used for detection.
   * Useful for debugging and documentation.
   */
  getDescriptionPatterns(): readonly RegExp[] {
    return this.EXTERNAL_API_DESCRIPTION_PATTERNS;
  }
}
