/**
 * Tool Category Test Data
 *
 * Category-specific test values and field patterns for context-aware
 * test data generation based on tool classification.
 *
 * @module assessment/testdata/tool-category-data
 */

/**
 * Tool category-specific data pools for when field name doesn't help identify
 * the expected input type. Used as fallback after field-name detection.
 *
 * Keys must match ToolClassifier category names (lowercase).
 */
export const TOOL_CATEGORY_DATA: Record<string, Record<string, string[]>> = {
  calculator: {
    default: ["2+2", "10*5", "100/4", "sqrt(16)", "15-7"],
  },
  search_retrieval: {
    default: [
      "hello world",
      "example query",
      "recent changes",
      "find documents",
    ],
  },
  system_exec: {
    default: ["echo hello", "pwd", "date", "whoami"],
  },
  url_fetcher: {
    default: [
      "https://api.github.com",
      "https://httpbin.org/get",
      "https://jsonplaceholder.typicode.com/posts/1",
    ],
  },
};

/**
 * Field names that indicate specific data types regardless of tool category.
 * These take precedence over category-specific generation.
 *
 * Used to identify when field-name-based generation should be used
 * instead of category-based generation.
 */
export const SPECIFIC_FIELD_PATTERNS = [
  /url/i,
  /endpoint/i,
  /link/i,
  /email/i,
  /mail/i,
  /path/i,
  /file/i,
  /directory/i,
  /folder/i,
  /uuid/i,
  /page_id/i,
  /database_id/i,
  /user_id/i,
  /block_id/i,
] as const;

/**
 * Type for the SPECIFIC_FIELD_PATTERNS array.
 */
export type SpecificFieldPatternsType = typeof SPECIFIC_FIELD_PATTERNS;
