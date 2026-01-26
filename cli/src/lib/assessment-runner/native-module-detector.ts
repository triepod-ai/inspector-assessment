/**
 * Native Module Detector
 *
 * Pre-flight detection of native modules that may cause issues
 * during MCP server connection (hangs, Gatekeeper blocks, etc.)
 *
 * This runs BEFORE server connection to warn users about potential
 * issues with native binaries that may be blocked by macOS Gatekeeper
 * or require platform-specific compilation.
 *
 * @module cli/lib/assessment-runner/native-module-detector
 * @see https://github.com/triepod-ai/inspector-assessment/issues/212
 */

import {
  checkPackageJsonNativeModules,
  type NativeModule,
  type NativeModuleCategory,
  type NativeModuleSeverity,
} from "../../../../client/lib/lib/nativeModules.js";
import { emitNativeModuleWarning } from "../jsonl-events.js";
import type { PackageJson } from "../../../../client/lib/lib/assessmentTypes.js";

/**
 * Detected native module info (for result aggregation)
 */
export interface DetectedNativeModule {
  /** Module name */
  name: string;
  /** Module category */
  category: NativeModuleCategory;
  /** Severity level */
  severity: NativeModuleSeverity;
  /** Warning message */
  warningMessage: string;
  /** Suggested environment variables */
  suggestedEnvVars?: Record<string, string>;
  /** Where found in package.json */
  dependencyType: string;
  /** Version specifier */
  version: string;
}

/**
 * Result of native module detection
 */
export interface NativeModuleDetectionResult {
  /** Whether any native modules were detected */
  detected: boolean;
  /** Count of detected native modules */
  count: number;
  /** Detected module details */
  modules: DetectedNativeModule[];
  /** Aggregated suggested environment variables from all detected modules */
  suggestedEnvVars: Record<string, string>;
}

/**
 * Options for native module detection
 */
export interface DetectionOptions {
  /** If true, suppress console output (JSONL events only) */
  jsonOnly?: boolean;
  /** Server name for context in messages */
  serverName?: string;
}

/**
 * Detect native modules in package.json and emit warnings
 *
 * This function should be called BEFORE attempting to connect to an MCP server.
 * It scans package.json for known problematic native modules and:
 * 1. Emits JSONL warning events for each detected module
 * 2. Prints console warnings (unless jsonOnly is true)
 * 3. Returns aggregated results for potential use in error messages
 *
 * @param packageJson - Parsed package.json content (or undefined if not available)
 * @param options - Detection options
 * @returns Detection result with warnings and suggestions
 *
 * @example
 * ```typescript
 * const result = detectNativeModules(sourceFiles.packageJson, {
 *   jsonOnly: options.jsonOnly,
 *   serverName: options.serverName,
 * });
 *
 * if (result.detected) {
 *   // Native modules found - warnings have been emitted
 *   // result.suggestedEnvVars contains mitigation suggestions
 * }
 * ```
 */
export function detectNativeModules(
  packageJson: PackageJson | undefined,
  options: DetectionOptions = {},
): NativeModuleDetectionResult {
  const result: NativeModuleDetectionResult = {
    detected: false,
    count: 0,
    modules: [],
    suggestedEnvVars: {},
  };

  // No package.json available - nothing to check
  if (!packageJson) {
    return result;
  }

  // Check for native modules
  const matches = checkPackageJsonNativeModules(packageJson);

  if (matches.length === 0) {
    return result;
  }

  // Found native modules
  result.detected = true;
  result.count = matches.length;

  // Process each match
  for (const match of matches) {
    // Add to result modules list
    result.modules.push({
      name: match.module.name,
      category: match.module.category,
      severity: match.module.severity,
      warningMessage: match.module.warningMessage,
      suggestedEnvVars: match.module.suggestedEnvVars,
      dependencyType: match.dependencyType,
      version: match.version,
    });

    // Collect suggested env vars
    if (match.module.suggestedEnvVars) {
      Object.assign(result.suggestedEnvVars, match.module.suggestedEnvVars);
    }

    // Emit JSONL event for each native module
    emitNativeModuleWarning(
      match.module.name,
      match.module.category,
      match.module.severity,
      match.module.warningMessage,
      match.dependencyType,
      match.version,
      match.module.suggestedEnvVars,
    );
  }

  // Print console warnings if not in JSON-only mode
  if (!options.jsonOnly) {
    printConsoleWarnings(matches, options.serverName);
  }

  return result;
}

/**
 * Print formatted console warnings for detected native modules
 */
function printConsoleWarnings(
  matches: Array<{ module: NativeModule; dependencyType: string }>,
  serverName?: string,
): void {
  console.log("");
  console.log(
    `\x1b[33m\u26a0\ufe0f  Native Module Warning: Detected ${matches.length} native module(s) that may cause issues:\x1b[0m`,
  );

  for (const match of matches) {
    const severityIcon =
      match.module.severity === "HIGH" ? "\u{1F534}" : "\u{1F7E1}";
    console.log(
      `   ${severityIcon} \x1b[1m${match.module.name}\x1b[0m (${match.dependencyType})`,
    );
    console.log(`      ${match.module.warningMessage}`);

    if (match.module.suggestedEnvVars) {
      const envVars = Object.entries(match.module.suggestedEnvVars)
        .map(([k, v]) => `${k}=${v}`)
        .join(" ");
      console.log(`      \x1b[36mSuggested:\x1b[0m ${envVars}`);
    }
  }

  console.log("");
  console.log(
    "   If server hangs or times out, native binaries may be blocked by macOS Gatekeeper.",
  );
  console.log("   See: https://support.apple.com/en-us/HT202491");
  console.log("");
}
