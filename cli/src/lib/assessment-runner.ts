/**
 * Assessment Runner Module (Facade)
 *
 * This file provides backward-compatible exports by re-exporting from the
 * modular assessment-runner/ directory structure.
 *
 * Refactored as part of Issue #94.
 *
 * @module cli/lib/assessment-runner
 */

// Re-export all public APIs from the modular structure
export * from "./assessment-runner/index.js";
