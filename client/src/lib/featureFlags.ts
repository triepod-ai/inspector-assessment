/**
 * Feature Flags
 *
 * Centralized feature flag configuration for the MCP Inspector.
 * These flags allow optional features to be enabled/disabled without
 * modifying the core codebase.
 *
 * Environment Variables:
 * - VITE_ENABLE_ASSESSMENT: Enable/disable the Assessment tab (default: true)
 *
 * @module lib/featureFlags
 */

// Default feature states - these can be overridden at build time
// In Vite, use define in vite.config.ts to override
// In tests, these defaults are used directly

/**
 * Feature flag configuration
 *
 * These are compile-time constants that can be overridden via Vite's define config:
 * ```ts
 * // vite.config.ts
 * export default defineConfig({
 *   define: {
 *     __ENABLE_ASSESSMENT__: JSON.stringify(process.env.VITE_ENABLE_ASSESSMENT !== 'false')
 *   }
 * })
 * ```
 */
export const FEATURES = {
  /**
   * Enable the Assessment tab for MCP server evaluation
   * Default: true (assessment is enabled)
   * To disable: Set VITE_ENABLE_ASSESSMENT=false in your environment
   */
  ASSESSMENT_TAB: true,
} as const;

/**
 * Type for feature flag keys
 */
export type FeatureKey = keyof typeof FEATURES;

/**
 * Check if a feature is enabled
 */
export function isFeatureEnabled(feature: FeatureKey): boolean {
  return FEATURES[feature];
}
