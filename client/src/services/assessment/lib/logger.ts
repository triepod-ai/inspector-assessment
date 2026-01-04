/**
 * Structured Logger for Assessment Modules
 *
 * Provides configurable logging with level filtering, structured context,
 * and consistent formatting across all assessment modules.
 *
 * IMPORTANT: This logger outputs to stdout. JSONL events (module_started,
 * module_complete, etc.) use stderr via console.error() and should NOT
 * be routed through this logger.
 */

export type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

/**
 * Logging configuration for assessment runs.
 * Controls verbosity and output format of diagnostic messages.
 */
export interface LoggingConfig {
  /**
   * Log level threshold. Messages below this level are suppressed.
   * - 'silent': No output
   * - 'error': Only errors
   * - 'warn': Errors and warnings
   * - 'info': Normal operational messages (default)
   * - 'debug': Detailed diagnostic output
   */
  level: LogLevel;

  /**
   * Output format.
   * - 'text': Human-readable prefixed messages (default)
   * - 'json': Machine-parseable JSON lines
   */
  format?: "text" | "json";

  /**
   * Include ISO timestamp in each message.
   * Default: false
   */
  includeTimestamp?: boolean;
}

/**
 * Logger interface for assessment modules.
 * Provides structured logging with context support.
 */
export interface Logger {
  /**
   * Log debug-level message (most verbose).
   * Use for detailed diagnostic information during development.
   */
  debug(message: string, context?: Record<string, unknown>): void;

  /**
   * Log info-level message (normal operations).
   * Use for significant events during normal operation.
   */
  info(message: string, context?: Record<string, unknown>): void;

  /**
   * Log warning-level message (potential issues).
   * Use for recoverable issues or unexpected but handled conditions.
   */
  warn(message: string, context?: Record<string, unknown>): void;

  /**
   * Log error-level message (failures).
   * Use for errors that may affect assessment results.
   */
  error(message: string, context?: Record<string, unknown>): void;

  /**
   * Create a child logger with a combined prefix.
   * Useful for sub-components that need their own namespace.
   */
  child(name: string): Logger;

  /**
   * Check if a level would be logged.
   * Use to avoid expensive operations when logging is disabled.
   */
  isLevelEnabled(level: LogLevel): boolean;
}

/**
 * Default configuration for logging.
 */
export const DEFAULT_LOGGING_CONFIG: LoggingConfig = {
  level: "info",
  format: "text",
  includeTimestamp: false,
};

/**
 * Log level priority mapping.
 * Higher numbers are more verbose.
 */
const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
  silent: 0,
  error: 1,
  warn: 2,
  info: 3,
  debug: 4,
};

/**
 * Safely serialize a value for logging.
 * Handles circular references and error objects.
 */
function safeSerialize(value: unknown): unknown {
  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }
  return value;
}

/**
 * Format context object for text output.
 */
function formatContext(context?: Record<string, unknown>): string {
  if (!context || Object.keys(context).length === 0) {
    return "";
  }

  try {
    // Serialize with safe handling of special values
    const serializable: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(context)) {
      serializable[key] = safeSerialize(value);
    }
    return " " + JSON.stringify(serializable);
  } catch {
    return " [context serialization failed]";
  }
}

/**
 * Create a logger instance with the given prefix and configuration.
 *
 * @param prefix - Logger prefix (typically module name)
 * @param config - Optional logging configuration
 * @returns Logger instance
 *
 * @example
 * ```typescript
 * const logger = createLogger('SecurityAssessor', { level: 'debug' });
 * logger.info('Starting assessment', { toolCount: 5 });
 * // Output: [SecurityAssessor] Starting assessment {"toolCount":5}
 * ```
 */
export function createLogger(
  prefix: string,
  config?: Partial<LoggingConfig>,
): Logger {
  const finalConfig: LoggingConfig = {
    ...DEFAULT_LOGGING_CONFIG,
    ...config,
  };

  const threshold = LOG_LEVEL_PRIORITY[finalConfig.level];

  function shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] <= threshold;
  }

  function emit(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>,
  ): void {
    if (!shouldLog(level)) {
      return;
    }

    const timestamp = finalConfig.includeTimestamp
      ? new Date().toISOString()
      : null;

    if (finalConfig.format === "json") {
      // JSON format for machine parsing
      const logEntry: Record<string, unknown> = {
        level,
        prefix,
        message,
      };

      if (timestamp) {
        logEntry.timestamp = timestamp;
      }

      if (context && Object.keys(context).length > 0) {
        const serializable: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(context)) {
          serializable[key] = safeSerialize(value);
        }
        logEntry.context = serializable;
      }

      // Output to stdout (NOT stderr - that's reserved for JSONL events)
      console.log(JSON.stringify(logEntry));
    } else {
      // Text format for human reading
      let output = "";

      if (timestamp) {
        output += `[${timestamp}] `;
      }

      output += `[${prefix}] ${message}`;
      output += formatContext(context);

      // Output to stdout (NOT stderr - that's reserved for JSONL events)
      console.log(output);
    }
  }

  const logger: Logger = {
    debug(message: string, context?: Record<string, unknown>): void {
      emit("debug", message, context);
    },

    info(message: string, context?: Record<string, unknown>): void {
      emit("info", message, context);
    },

    warn(message: string, context?: Record<string, unknown>): void {
      emit("warn", message, context);
    },

    error(message: string, context?: Record<string, unknown>): void {
      emit("error", message, context);
    },

    child(name: string): Logger {
      return createLogger(`${prefix}:${name}`, finalConfig);
    },

    isLevelEnabled(level: LogLevel): boolean {
      return shouldLog(level);
    },
  };

  return logger;
}

/**
 * Create a silent logger that produces no output.
 * Useful for tests or when logging should be completely disabled.
 */
export function createSilentLogger(): Logger {
  return createLogger("", { level: "silent" });
}
