/**
 * Assessment Runner Module
 *
 * Aggregates and exports all assessment-runner submodules.
 * This is the main entry point for the modular assessment-runner.
 *
 * @module cli/lib/assessment-runner
 */

// Types
export type { SourceFiles, CallToolFn } from "./types.js";

// Server Configuration
export { loadServerConfig } from "./server-config.js";

// Source File Loading
export { loadSourceFiles } from "./source-loader.js";

// Server Connection
export { connectToServer } from "./server-connection.js";

// Tool Wrapper
export { createCallToolWrapper } from "./tool-wrapper.js";

// Configuration Building
export { buildConfig } from "./config-builder.js";

// Assessment Execution
export { runFullAssessment } from "./assessment-executor.js";
