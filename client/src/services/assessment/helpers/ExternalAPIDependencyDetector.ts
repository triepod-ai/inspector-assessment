/**
 * External API Dependency Detector
 *
 * Identifies tools that depend on external APIs based on name and description patterns.
 * This information enables downstream assessors to adjust their behavior:
 * - TemporalAssessor: Relaxed variance thresholds for external API tools
 * - FunctionalityAssessor: Accept API errors as valid responses
 * - ErrorHandlingAssessor: Account for external service failures
 *
 * Issue #168: New module for external API dependency detection
 *
 * @module helpers/ExternalAPIDependencyDetector
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";

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
   * Detect external API dependencies from a list of tools.
   *
   * @param tools - List of MCP tools to analyze
   * @returns Detection results with tool names and confidence
   */
  detect(tools: Tool[]): ExternalAPIDependencyInfo {
    const toolsWithExternalAPI = new Set<string>();

    for (const tool of tools) {
      if (this.isExternalAPITool(tool)) {
        toolsWithExternalAPI.add(tool.name);
      }
    }

    const detectedCount = toolsWithExternalAPI.size;

    // Determine confidence based on detection count
    // More detections = higher confidence in pattern accuracy
    let confidence: "high" | "medium" | "low";
    if (detectedCount === 0) {
      confidence = "low";
    } else if (detectedCount >= 3) {
      confidence = "high";
    } else {
      confidence = "medium";
    }

    return {
      toolsWithExternalAPIDependency: toolsWithExternalAPI,
      detectedCount,
      confidence,
      detectedTools: Array.from(toolsWithExternalAPI),
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
