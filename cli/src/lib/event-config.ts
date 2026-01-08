/**
 * Event Configuration Utilities for Assessment CLI
 *
 * Provides scoped EventEmitter configuration to replace global modification
 * of defaultMaxListeners. This addresses the anti-pattern documented in
 * GitHub Issue #33.
 *
 * Why this exists:
 * - MCP SDK's StdioClientTransport creates 6-7 listeners per transport
 * - Node.js default maxListeners is 10, which triggers warnings
 * - Global modification (EventEmitter.defaultMaxListeners = 300) is an anti-pattern
 * - This module provides scoped configuration that restores original values
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/33
 */

import { EventEmitter } from "events";

/**
 * Default max listeners for event emitters in CLI operations.
 * This value matches PerformanceConfig.eventEmitterMaxListeners from Issue #37.
 * Defined locally to avoid cross-workspace import issues in the monorepo.
 */
const CLI_DEFAULT_MAX_LISTENERS = 50;

/**
 * Expected listener counts for different transport types and CLI operations.
 * These values are derived from analysis of the MCP SDK source code.
 */
export const LISTENER_BUDGETS = {
  /**
   * StdioClientTransport listeners (from @modelcontextprotocol/sdk):
   * - process.on('error')
   * - process.on('spawn')
   * - process.on('close')
   * - stdin.on('error')
   * - stdout.on('data')
   * - stdout.on('error')
   * - stderr.pipe() (when stderr: "pipe")
   */
  sdkStdioTransport: 7,

  /**
   * HTTP transport listeners (connection-based)
   */
  sdkHttpTransport: 3,

  /**
   * SSE transport listeners (Server-Sent Events stream)
   */
  sdkSseTransport: 4,

  /**
   * CLI-specific listeners:
   * - stderr data capture
   * - SIGINT handler
   * - SIGTERM handler
   */
  cliOverhead: 3,

  /**
   * Safety margin for unexpected listeners
   */
  margin: 10,
} as const;

/**
 * Calculate the recommended max listeners for a transport type.
 *
 * @param transportType - The type of MCP transport being used
 * @returns Recommended max listeners value
 */
export function calculateMaxListeners(
  transportType: "stdio" | "http" | "sse",
): number {
  const sdkListeners =
    transportType === "stdio"
      ? LISTENER_BUDGETS.sdkStdioTransport
      : transportType === "http"
        ? LISTENER_BUDGETS.sdkHttpTransport
        : LISTENER_BUDGETS.sdkSseTransport;

  return sdkListeners + LISTENER_BUDGETS.cliOverhead + LISTENER_BUDGETS.margin;
}

/**
 * Scoped configuration for EventEmitter max listeners.
 *
 * Usage:
 * ```typescript
 * const config = new ScopedListenerConfig(50);
 * config.apply();
 * try {
 *   // ... code that needs higher listener limit ...
 * } finally {
 *   config.restore();
 * }
 * ```
 *
 * This ensures that global state is properly restored even if an error occurs.
 */
export class ScopedListenerConfig {
  private originalDefault: number;
  private originalProcess: number;
  private applied: boolean = false;

  /**
   * Create a new scoped listener configuration.
   *
   * @param maxListeners - The max listeners value to use (default: 50)
   * @see PerformanceConfig.eventEmitterMaxListeners (Issue #37)
   */
  constructor(private maxListeners: number = CLI_DEFAULT_MAX_LISTENERS) {
    this.originalDefault = EventEmitter.defaultMaxListeners;
    this.originalProcess = process.getMaxListeners();
  }

  /**
   * Apply the scoped configuration.
   * Call this before operations that need higher listener limits.
   */
  apply(): void {
    if (this.applied) {
      return; // Idempotent - don't apply twice
    }
    EventEmitter.defaultMaxListeners = this.maxListeners;
    process.setMaxListeners(this.maxListeners);
    this.applied = true;
  }

  /**
   * Restore the original configuration.
   * Call this in a finally block to ensure cleanup.
   */
  restore(): void {
    if (!this.applied) {
      return; // Nothing to restore
    }
    EventEmitter.defaultMaxListeners = this.originalDefault;
    process.setMaxListeners(this.originalProcess);
    this.applied = false;
  }

  /**
   * Check if the configuration is currently applied.
   */
  isApplied(): boolean {
    return this.applied;
  }
}

/**
 * Get the total listener count across all events on an emitter.
 * Useful for debugging and leak detection tests.
 *
 * @param emitter - The EventEmitter to inspect
 * @returns Total number of listeners across all events
 */
export function getListenerCount(emitter: EventEmitter): number {
  return emitter.eventNames().reduce((sum, event) => {
    return sum + emitter.listenerCount(event);
  }, 0);
}

/**
 * Get the listener count on the process global.
 * Useful for leak detection tests.
 *
 * @returns Total number of listeners on process
 */
export function getProcessListenerCount(): number {
  return getListenerCount(process as unknown as EventEmitter);
}
