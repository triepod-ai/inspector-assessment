/**
 * Static Analysis Module Definitions
 *
 * Defines which assessment modules can run without a server connection.
 * These modules analyze source code, manifest, package.json, and documentation
 * without requiring tool execution or server interaction.
 *
 * @module cli/lib/static-modules
 * @see Issue #213
 */

/**
 * Modules that can run in static-only mode (no server connection required).
 *
 * These modules have `contextRequirements.needsCallTool: false` and operate on:
 * - Source code files (sourceCodeFiles)
 * - Package metadata (packageJson, manifestJson)
 * - Documentation (readmeContent)
 * - Tool schemas (tools - extracted from manifest if available)
 */
export const STATIC_MODULES = [
  "manifestValidation", // MCPB manifest.json schema validation
  "documentation", // Documentation quality (legacy name for DeveloperExperience)
  "usability", // Usability assessment (legacy name for DeveloperExperience)
  "prohibitedLibraries", // Banned dependency detection
  "portability", // Platform-specific pattern detection
  "externalAPIScanner", // External API dependency detection
  "fileModularization", // Code structure metrics
  "conformance", // Code quality checks
  "toolAnnotations", // Annotation presence in source
  "authentication", // Credential pattern detection
  "aupCompliance", // AUP keyword analysis
] as const;

/**
 * Type for static module names
 */
export type StaticModuleName = (typeof STATIC_MODULES)[number];

/**
 * Modules that require a running server (cannot run in static mode).
 *
 * These modules have `contextRequirements.needsCallTool: true` and require:
 * - Active tool execution (callTool function)
 * - Server connection and response validation
 * - Real-time behavior testing
 */
export const RUNTIME_MODULES = [
  "functionality", // Tests actual tool execution
  "security", // Tests security vulnerabilities via tool calls
  "temporal", // Tests for rug pulls (baseline + post-call comparison)
  "protocolCompliance", // Tests protocol compliance via tool calls
  "resources", // Tests resource accessibility
  "prompts", // Tests prompt behavior and injection
  "crossCapability", // Tests tool chaining attacks
  "errorHandling", // Tests error response handling (legacy, merged into protocolCompliance)
  "dependencyVulnerability", // npm/yarn/pnpm audit (requires live server)
] as const;

/**
 * Type for runtime module names
 */
export type RuntimeModuleName = (typeof RUNTIME_MODULES)[number];

/**
 * Check if a module can run in static-only mode
 *
 * @param moduleName - Name of the assessment module
 * @returns true if the module can run without server connection
 */
export function isStaticModule(moduleName: string): boolean {
  return STATIC_MODULES.includes(moduleName as StaticModuleName);
}

/**
 * Check if a module requires a running server
 *
 * @param moduleName - Name of the assessment module
 * @returns true if the module requires server connection
 */
export function isRuntimeModule(moduleName: string): boolean {
  return RUNTIME_MODULES.includes(moduleName as RuntimeModuleName);
}

/**
 * Get all static module names as an array
 *
 * @returns Array of static module names
 */
export function getStaticModules(): readonly StaticModuleName[] {
  return STATIC_MODULES;
}

/**
 * Get all runtime module names as an array
 *
 * @returns Array of runtime module names
 */
export function getRuntimeModules(): readonly RuntimeModuleName[] {
  return RUNTIME_MODULES;
}

/**
 * Filter a list of module names to only include static-capable modules
 *
 * @param modules - Array of module names to filter
 * @returns Array of modules that can run in static mode
 */
export function filterToStaticModules(modules: string[]): string[] {
  return modules.filter(isStaticModule);
}

/**
 * Filter a list of module names to only include runtime-required modules
 *
 * @param modules - Array of module names to filter
 * @returns Array of modules that require server connection
 */
export function filterToRuntimeModules(modules: string[]): string[] {
  return modules.filter(isRuntimeModule);
}
