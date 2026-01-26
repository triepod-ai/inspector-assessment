/**
 * Native Module Detection
 *
 * Detects native modules that can cause issues on macOS/Windows due to:
 * - Unsigned binaries blocked by macOS Gatekeeper
 * - Platform-specific compilation requirements
 * - Missing system libraries
 *
 * When these modules are detected in package.json, warnings are emitted
 * before server connection to help diagnose potential hang/timeout issues.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/212
 */

/**
 * Category of native module
 */
export type NativeModuleCategory =
  | "image"
  | "database"
  | "graphics"
  | "system"
  | "crypto";

/**
 * Severity level for native module warnings
 */
export type NativeModuleSeverity = "HIGH" | "MEDIUM";

/**
 * Definition of a known native module that may cause issues
 */
export interface NativeModule {
  /** Module name (for display) */
  name: string;
  /** Regex patterns to match dependency names */
  patterns: RegExp[];
  /** Category of module */
  category: NativeModuleCategory;
  /** Severity level */
  severity: NativeModuleSeverity;
  /** Human-readable warning message */
  warningMessage: string;
  /** Suggested environment variables to mitigate issues */
  suggestedEnvVars?: Record<string, string>;
  /** Link to documentation */
  documentation?: string;
}

/**
 * Result of checking a dependency against native modules
 */
export interface NativeModuleMatch {
  /** The matched native module definition */
  module: NativeModule;
  /** Where the dependency was found */
  dependencyType: "dependencies" | "devDependencies" | "optionalDependencies";
  /** Version specifier from package.json */
  version: string;
}

/**
 * Known native modules that may cause issues during MCP server startup.
 *
 * These modules compile native binaries that can be:
 * - Blocked by macOS Gatekeeper when unsigned
 * - Missing required system libraries
 * - Incompatible with certain platforms
 */
export const NATIVE_MODULES: NativeModule[] = [
  // ============================================================================
  // Image Processing - HIGH severity (most common issues)
  // ============================================================================
  {
    name: "canvas",
    patterns: [/^canvas$/, /^node-canvas$/],
    category: "image",
    severity: "HIGH",
    warningMessage:
      "Canvas requires native Cairo binaries that may be blocked by macOS Gatekeeper",
    suggestedEnvVars: { CANVAS_BACKEND: "mock" },
    documentation: "https://github.com/Automattic/node-canvas#compiling",
  },
  {
    name: "sharp",
    patterns: [/^sharp$/],
    category: "image",
    severity: "HIGH",
    warningMessage:
      "Sharp uses libvips native binaries that may cause Gatekeeper issues",
    suggestedEnvVars: { SHARP_IGNORE_GLOBAL_LIBVIPS: "1" },
    documentation: "https://sharp.pixelplumbing.com/install",
  },

  // ============================================================================
  // Database - HIGH severity for better-sqlite3, MEDIUM for others
  // ============================================================================
  {
    name: "better-sqlite3",
    patterns: [/^better-sqlite3$/],
    category: "database",
    severity: "HIGH",
    warningMessage:
      "better-sqlite3 compiles native SQLite bindings that may fail on some platforms",
    documentation:
      "https://github.com/WiseLibs/better-sqlite3/blob/master/docs/troubleshooting.md",
  },
  {
    name: "sqlite3",
    patterns: [/^sqlite3$/],
    category: "database",
    severity: "MEDIUM",
    warningMessage:
      "sqlite3 compiles native bindings - may fail without build tools",
    documentation: "https://github.com/TryGhost/node-sqlite3",
  },
  {
    name: "leveldown",
    patterns: [/^leveldown$/, /^leveldb$/],
    category: "database",
    severity: "MEDIUM",
    warningMessage: "LevelDB native bindings require compilation",
    documentation: "https://github.com/Level/leveldown",
  },

  // ============================================================================
  // Graphics/Maps - HIGH severity
  // ============================================================================
  {
    name: "maplibre-gl-native",
    patterns: [/maplibre.*native/i, /@maplibre\/.*native/],
    category: "graphics",
    severity: "HIGH",
    warningMessage:
      "MapLibre native bindings may hang or timeout due to Gatekeeper blocking mbgl.node",
    suggestedEnvVars: { ENABLE_DYNAMIC_MAPS: "false" },
    documentation: "https://github.com/maptiler/maplibre-gl-native",
  },

  // ============================================================================
  // Crypto - MEDIUM severity
  // ============================================================================
  {
    name: "bcrypt",
    patterns: [/^bcrypt$/],
    category: "crypto",
    severity: "MEDIUM",
    warningMessage:
      "bcrypt compiles native bindings - consider bcryptjs as a pure JS alternative",
    documentation: "https://github.com/kelektiv/node.bcrypt.js",
  },

  // ============================================================================
  // System/Build Tools - MEDIUM severity
  // ============================================================================
  {
    name: "node-gyp",
    patterns: [/^node-gyp$/],
    category: "system",
    severity: "MEDIUM",
    warningMessage:
      "node-gyp compiles native addons - ensure build tools (Python, make, C++ compiler) are available",
    documentation: "https://github.com/nodejs/node-gyp#installation",
  },
];

/**
 * All native modules combined (for iteration)
 */
export const ALL_NATIVE_MODULES = NATIVE_MODULES;

/**
 * Check a dependency name against known native modules
 *
 * @param depName - The dependency name to check
 * @returns The matching NativeModule or null if not found
 */
export function checkNativeModule(depName: string): NativeModule | null {
  for (const mod of NATIVE_MODULES) {
    for (const pattern of mod.patterns) {
      if (pattern.test(depName)) {
        return mod;
      }
    }
  }
  return null;
}

/**
 * Check package.json dependencies for native modules
 *
 * Scans dependencies, devDependencies, and optionalDependencies for
 * known native modules that may cause issues during server startup.
 *
 * @param packageJson - Parsed package.json content
 * @returns Array of matches with module info and dependency type
 */
export function checkPackageJsonNativeModules(packageJson: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}): NativeModuleMatch[] {
  const matches: NativeModuleMatch[] = [];

  const depTypes = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
  ] as const;

  for (const depType of depTypes) {
    const deps = packageJson[depType];
    if (!deps) continue;

    for (const [depName, version] of Object.entries(deps)) {
      const nativeMod = checkNativeModule(depName);
      if (nativeMod) {
        matches.push({
          module: nativeMod,
          dependencyType: depType,
          version,
        });
      }
    }
  }

  return matches;
}

/**
 * Get native modules by severity level
 */
export function getNativeModulesBySeverity(
  severity: NativeModuleSeverity,
): NativeModule[] {
  return NATIVE_MODULES.filter((mod) => mod.severity === severity);
}

/**
 * Get native modules by category
 */
export function getNativeModulesByCategory(
  category: NativeModuleCategory,
): NativeModule[] {
  return NATIVE_MODULES.filter((mod) => mod.category === category);
}
