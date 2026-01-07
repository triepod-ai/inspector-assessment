/**
 * Tool Classifier
 * Categorizes MCP tools based on name/description to select appropriate security test patterns
 *
 * Validated against broken-mcp server with 16 tools (6 HIGH, 4 MEDIUM, 6 SAFE)
 *
 * ## Pattern Matching Design
 *
 * This classifier uses two types of regex patterns intentionally:
 *
 * 1. **Substring patterns** (e.g., `/calculator/i`): Match anywhere in the text.
 *    Used for HIGH-risk category keywords that should trigger even when embedded.
 *    Example: "recalculator_v2" matches CALCULATOR because any calculator-like
 *    tool warrants security scrutiny.
 *
 * 2. **Word boundary patterns** (e.g., `/\bget\b/i`): Match isolated words only.
 *    Used for common words that would cause false positives as substrings.
 *    Example: "target_selector" should NOT match DATA_ACCESS's `/\bget\b/` pattern.
 *
 * **Underscore vs Hyphen Behavior:**
 * - Word boundaries (`\b`) treat hyphens as boundaries but underscores as word characters
 * - `api-get-data` matches `/\bget\b/` (hyphen is boundary)
 * - `api_get_data` does NOT match `/\bget\b/` (underscore is word char)
 * - This is intentional: underscore-joined names are typically single identifiers
 *
 * See tests in ToolClassifier.test.ts for comprehensive pattern behavior validation.
 *
 * @module ToolClassifier
 */

import {
  CATEGORY_PATTERNS,
  CATEGORY_CHECK_ORDER,
  GENERIC_CONFIG,
  ToolCategory,
  type RiskLevel,
} from "./tool-classifier-patterns";

// Re-export ToolCategory for backwards compatibility
export { ToolCategory };

/**
 * Result of classifying a tool into security categories.
 *
 * @example
 * ```typescript
 * const result: ToolClassification = {
 *   toolName: 'vulnerable_calculator_tool',
 *   categories: [ToolCategory.CALCULATOR],
 *   confidence: 90,
 *   reasoning: 'Calculator pattern detected (arithmetic execution risk)'
 * };
 * ```
 */
export interface ToolClassification {
  /** The original tool name that was classified */
  toolName: string;
  /** One or more categories the tool was classified into */
  categories: ToolCategory[];
  /** Confidence score from 0-100 (averaged if multiple categories) */
  confidence: number;
  /** Human-readable explanation of why these categories were assigned */
  reasoning: string;
}

/**
 * Classifies MCP tools into vulnerability categories based on naming patterns
 * and descriptions. Uses pre-compiled patterns for optimal performance.
 *
 * The classifier is stateless and thread-safe - multiple classifications can
 * run concurrently without interference.
 *
 * @example
 * ```typescript
 * const classifier = new ToolClassifier();
 *
 * // Single classification
 * const result = classifier.classify('vulnerable_calculator_tool');
 * console.log(result.categories);  // [ToolCategory.CALCULATOR]
 * console.log(result.confidence);  // 90
 *
 * // Batch classification
 * const tools = [
 *   { name: 'calculator_tool' },
 *   { name: 'search_api', description: 'Search for documents' }
 * ];
 * const results = classifier.classifyBatch(tools);
 * ```
 */
export class ToolClassifier {
  /** Maximum input length to prevent ReDoS with pathological inputs */
  private static readonly MAX_INPUT_LENGTH = 10000;

  /**
   * Classify a tool into one or more security risk categories.
   *
   * The classifier analyzes both the tool name and optional description,
   * matching against pre-compiled regex patterns for each category.
   * A tool may match multiple categories if it contains multiple patterns.
   *
   * @param toolName - The MCP tool name to classify (e.g., "vulnerable_calculator_tool")
   * @param description - Optional tool description for additional pattern matching
   * @returns Classification result with categories, confidence score (0-100), and reasoning
   *
   * @example
   * ```typescript
   * const classifier = new ToolClassifier();
   *
   * // Basic classification by name
   * const calc = classifier.classify('calculator_tool');
   * // { toolName: 'calculator_tool', categories: ['calculator'], confidence: 90, ... }
   *
   * // Classification with description
   * const tool = classifier.classify('my_tool', 'Executes shell commands');
   * // { toolName: 'my_tool', categories: ['system_exec'], confidence: 95, ... }
   *
   * // Multi-category match
   * const multi = classifier.classify('calc_exec_command');
   * // { categories: ['calculator', 'system_exec'], confidence: 92, ... }
   * ```
   *
   * @throws Never throws - returns GENERIC category for invalid inputs
   */
  classify(toolName: string, description?: string): ToolClassification {
    // Defensive validation for runtime safety (handles JS callers, deserialized data)
    const safeName = typeof toolName === "string" ? toolName : "";
    const safeDesc = typeof description === "string" ? description : "";

    // Handle invalid or empty tool name
    if (!safeName.trim()) {
      return {
        toolName: safeName,
        categories: [ToolCategory.GENERIC],
        confidence: 0,
        reasoning: "Invalid or empty tool name provided",
      };
    }

    const categories: ToolCategory[] = [];
    const confidenceScores: number[] = [];
    const reasons: string[] = [];

    const toolText = `${safeName} ${safeDesc}`.toLowerCase();

    // Check each category in defined order (HIGH -> MEDIUM -> LOW)
    for (const category of CATEGORY_CHECK_ORDER) {
      const config = CATEGORY_PATTERNS[category];
      if (this.matchesPattern(toolText, config.patterns)) {
        categories.push(category);
        confidenceScores.push(config.confidence);
        reasons.push(config.reasoning);
      }
    }

    // Default to generic if no specific matches
    if (categories.length === 0) {
      categories.push(ToolCategory.GENERIC);
      confidenceScores.push(GENERIC_CONFIG.confidence);
      reasons.push(GENERIC_CONFIG.reasoning);
    }

    // Calculate overall confidence (average of matched pattern confidences)
    const avgConfidence =
      confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length;

    return {
      toolName,
      categories,
      confidence: Math.round(avgConfidence),
      reasoning: reasons.join("; "),
    };
  }

  /**
   * Check if text matches any of the provided patterns.
   * Limits input length to prevent ReDoS attacks with very long strings.
   *
   * @param text - The text to search in (tool name + description)
   * @param patterns - Pre-compiled regex patterns to match against
   * @returns True if any pattern matches
   */
  private matchesPattern(text: string, patterns: readonly RegExp[]): boolean {
    // Truncate to prevent ReDoS with pathological inputs
    const safeText =
      text.length > ToolClassifier.MAX_INPUT_LENGTH
        ? text.slice(0, ToolClassifier.MAX_INPUT_LENGTH)
        : text;
    return patterns.some((pattern) => pattern.test(safeText));
  }

  /**
   * Get all available tool categories.
   *
   * Useful for testing, debugging, or building UI components that need
   * to display all possible categories.
   *
   * @returns Array of all ToolCategory enum values
   *
   * @example
   * ```typescript
   * const allCategories = ToolClassifier.getAllCategories();
   * console.log(allCategories.length); // 17
   * ```
   */
  static getAllCategories(): ToolCategory[] {
    return Object.values(ToolCategory);
  }

  /**
   * Get the security risk level for a category.
   *
   * Risk levels help prioritize security testing:
   * - **HIGH**: Requires thorough security testing (code execution, data access)
   * - **MEDIUM**: Requires moderate security testing (encoding bypass, supply chain)
   * - **LOW**: Safe categories that typically don't need security testing
   *
   * @param category - The category to get the risk level for
   * @returns Risk level: "HIGH", "MEDIUM", or "LOW"
   *
   * @example
   * ```typescript
   * ToolClassifier.getRiskLevel(ToolCategory.SYSTEM_EXEC); // "HIGH"
   * ToolClassifier.getRiskLevel(ToolCategory.JSON_PARSER); // "MEDIUM"
   * ToolClassifier.getRiskLevel(ToolCategory.SAFE_STORAGE); // "LOW"
   * ```
   */
  static getRiskLevel(category: ToolCategory): RiskLevel {
    if (category === ToolCategory.GENERIC) {
      return GENERIC_CONFIG.risk;
    }
    // Type assertion needed because TypeScript doesn't narrow the type after the GENERIC check
    const config =
      CATEGORY_PATTERNS[
        category as Exclude<ToolCategory, ToolCategory.GENERIC>
      ];
    // Handle unknown categories gracefully (defensive programming)
    return config?.risk ?? "LOW";
  }

  /**
   * Classify multiple tools at once.
   *
   * More efficient than calling classify() in a loop when you have
   * many tools to process. The classifier is stateless, so batch
   * processing produces identical results to individual calls.
   *
   * @param tools - Array of tools with name and optional description
   * @returns Array of classification results in the same order as input
   *
   * @example
   * ```typescript
   * const classifier = new ToolClassifier();
   * const tools = [
   *   { name: 'calculator_tool' },
   *   { name: 'search_api', description: 'Search documents' },
   *   { name: 'unknown_tool' }
   * ];
   *
   * const results = classifier.classifyBatch(tools);
   * // [
   * //   { toolName: 'calculator_tool', categories: ['calculator'], ... },
   * //   { toolName: 'search_api', categories: ['search_retrieval'], ... },
   * //   { toolName: 'unknown_tool', categories: ['generic'], ... }
   * // ]
   * ```
   */
  classifyBatch(
    tools: Array<{ name: string; description?: string }>,
  ): ToolClassification[] {
    return tools.map((tool) => this.classify(tool.name, tool.description));
  }
}
