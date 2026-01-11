/**
 * Realistic Test Data Pools
 *
 * Context-aware test values for generating realistic test data.
 * Used by TestDataGenerator to produce meaningful test inputs.
 *
 * @module assessment/testdata/realistic-values
 */

/**
 * Realistic URLs for testing URL-related parameters.
 * Includes public, stable endpoints that are commonly accessible.
 */
export const REALISTIC_URLS = [
  "https://www.google.com", // Public, always accessible
  "https://api.github.com/users/octocat", // Public API endpoint that exists
  "https://jsonplaceholder.typicode.com/posts/1", // Test API that always works
  "https://httpbin.org/get", // HTTP testing service
  "https://example.com", // RFC 2606 reserved domain for examples
  "https://www.wikipedia.org", // Public, stable site
  "https://api.openweathermap.org/data/2.5/weather?q=London", // Public API
] as const;

/**
 * Realistic email addresses for testing email-related parameters.
 * Uses common patterns and the example.com domain for safety.
 */
export const REALISTIC_EMAILS = [
  "admin@example.com", // Common admin email
  "support@example.com", // Common support email
  "info@example.com", // Common info email
  "test@test.com", // Generic test email
  "user@domain.com", // Generic user email
  "noreply@example.com", // Common no-reply format
  "hello@world.com", // Simple, memorable
] as const;

/**
 * Realistic names for testing name/title parameters.
 * Includes common default and placeholder names.
 */
export const REALISTIC_NAMES = [
  "Default", // Common default name
  "Admin", // Common admin user
  "Test User", // Clear test user
  "Sample Item", // Generic sample
  "Example Project", // Clear example
  "Demo Application", // Common demo name
  "Main", // Common main/primary name
] as const;

/**
 * Realistic IDs for testing identifier parameters.
 * Includes various formats: numeric, UUID, and string IDs.
 */
export const REALISTIC_IDS = [
  "1", // Simple numeric ID that often exists
  "123", // Common test ID
  "550e8400-e29b-41d4-a716-446655440000", // Valid UUID v4 (replaces "test")
  "default", // Common default ID
  "main", // Common main ID
  "264051cd-48ab-80ff-864e-d1aa9bc41429", // Valid UUID from realistic data
  "00000000-0000-0000-0000-000000000000", // Nil UUID (often used as placeholder)
  "admin", // Common admin ID
  "user1", // Common user ID pattern
] as const;

/**
 * Realistic file paths for testing path/file parameters.
 * Includes common directories and file locations.
 */
export const REALISTIC_PATHS = [
  "/tmp/test.txt", // Common temp file path (usually writable)
  "/home", // Common home directory
  "./README.md", // Often exists in projects
  "./package.json", // Common in Node projects
  "./src", // Common source directory
  "./test", // Common test directory
  "./config", // Common config directory
  "/var/log", // Common log directory (readable)
  "/etc", // Common config directory (readable)
] as const;

/**
 * Realistic search queries for testing search/filter parameters.
 * Includes various query formats and patterns.
 */
export const REALISTIC_QUERIES = [
  "test", // Simple search term
  "hello", // Common greeting
  "*", // Wildcard that matches everything
  "name", // Common field name
  "id:1", // Common ID search
  "status:active", // Common status filter
  "type:user", // Common type filter
  "limit:10", // Common pagination
  '{"match_all": {}}', // Elasticsearch match all
] as const;

/**
 * Realistic numbers for testing numeric parameters.
 * Includes common values, boundaries, and HTTP status codes.
 */
export const REALISTIC_NUMBERS = [
  0, 1, 10, 100, 1000, 5, 50, 200, 404, 500,
] as const;

/**
 * Boolean values for testing boolean parameters.
 */
export const REALISTIC_BOOLEANS = [true, false] as const;

/**
 * Realistic JSON objects for testing object parameters.
 * Includes common response patterns and simple entities.
 */
export const REALISTIC_JSON_OBJECTS = [
  { message: "Hello World" }, // Simple message object
  { status: "ok", code: 200 }, // Common status response
  { data: [], total: 0 }, // Empty result set
  { id: 1, name: "Test" }, // Simple entity
  { success: true }, // Common success response
  { error: false }, // Common no-error response
  { results: [] }, // Common empty results
  {}, // Empty object (often valid)
] as const;

/**
 * Realistic arrays for testing array parameters.
 * Includes various array types and sizes.
 */
export const REALISTIC_ARRAYS = [
  [], // Empty array (often valid)
  [1], // Single item
  ["a", "b", "c"], // Simple string array
  [1, 2, 3], // Simple number array
  [{ id: 1 }, { id: 2 }], // Simple object array
  ["test"], // Single test item
  [true, false], // Boolean array
] as const;

/**
 * Generate realistic timestamps for testing date/time parameters.
 * Returns an array of ISO 8601 formatted timestamps.
 */
export function generateRealisticTimestamps(): string[] {
  return [
    new Date().toISOString(), // Current time (always valid)
    new Date(Date.now() - 86400000).toISOString(), // Yesterday
    new Date(Date.now() + 86400000).toISOString(), // Tomorrow
    "2024-01-01T00:00:00Z", // New Year 2024
    "2023-12-31T23:59:59Z", // End of 2023
    new Date(0).toISOString(), // Unix epoch
    "2024-06-15T12:00:00Z", // Midday mid-year
  ];
}

/**
 * Composed object containing all realistic data pools.
 * Used by TestDataGenerator for backward compatibility.
 */
export const REALISTIC_DATA = {
  urls: [...REALISTIC_URLS],
  emails: [...REALISTIC_EMAILS],
  names: [...REALISTIC_NAMES],
  ids: [...REALISTIC_IDS],
  paths: [...REALISTIC_PATHS],
  queries: [...REALISTIC_QUERIES],
  numbers: [...REALISTIC_NUMBERS],
  booleans: [...REALISTIC_BOOLEANS],
  jsonObjects: [...REALISTIC_JSON_OBJECTS],
  arrays: [...REALISTIC_ARRAYS],
  timestamps: generateRealisticTimestamps(),
} as const;

/**
 * Type for the REALISTIC_DATA structure.
 */
export type RealisticDataType = typeof REALISTIC_DATA;
