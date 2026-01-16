# MCP Inspector Logging Guide

**Version**: 1.23.1
**Added**: v1.23.1 (2026-01-04)
**Status**: Stable

This guide covers the structured logging system in MCP Inspector, including configuration options, CLI flags, and integration patterns.

---

## Overview

MCP Inspector v1.23.1 introduced structured logging with configurable verbosity levels. The logging system provides:

- **Five log levels**: `silent`, `error`, `warn`, `info`, `debug`
- **Multiple configuration methods**: CLI flags, environment variables, config presets
- **Structured output**: Consistent `[ModuleName] message` format with optional context
- **Stream separation**: Logger output on stdout, JSONL events on stderr

---

## Quick Reference

| Goal                 | Command                                       |
| -------------------- | --------------------------------------------- |
| Enable debug logging | `mcp-assess-full --server S --verbose`        |
| Suppress all logs    | `mcp-assess-full --server S --silent`         |
| Set specific level   | `mcp-assess-full --server S --log-level warn` |
| Use environment      | `LOG_LEVEL=debug mcp-assess-full --server S`  |

---

## Log Levels

The logging system supports five levels, from most restrictive to most verbose:

| Level    | Priority | What's Logged                     | Typical Use Case                  |
| -------- | -------- | --------------------------------- | --------------------------------- |
| `silent` | 0        | Nothing                           | CI/CD pipelines, batch processing |
| `error`  | 1        | Critical errors only              | Production monitoring             |
| `warn`   | 2        | Warnings + errors                 | Normal production use             |
| `info`   | 3        | Progress info + warnings + errors | Development (default)             |
| `debug`  | 4        | All diagnostic output             | Troubleshooting, debugging        |

### Level Filtering

Each level includes all messages from higher-priority (lower number) levels:

- `debug` shows: debug + info + warn + error
- `info` shows: info + warn + error
- `warn` shows: warn + error
- `error` shows: error only
- `silent` shows: nothing

---

## CLI Flags

### --verbose / -v

Enables debug-level logging (most verbose):

```bash
mcp-assess-full --server my-server --verbose
mcp-assess-full --server my-server -v
```

### --silent

Suppresses all diagnostic logging:

```bash
mcp-assess-full --server my-server --silent
```

### --log-level \<level\>

Sets a specific log level:

```bash
mcp-assess-full --server my-server --log-level debug
mcp-assess-full --server my-server --log-level info
mcp-assess-full --server my-server --log-level warn
mcp-assess-full --server my-server --log-level error
mcp-assess-full --server my-server --log-level silent
```

**Valid levels**: `silent`, `error`, `warn`, `info`, `debug`

Invalid levels produce an error:

```
Invalid log level: verbose. Valid options: silent, error, warn, info, debug
```

---

## Environment Variable

### LOG_LEVEL

Set the log level via environment variable:

```bash
# Single command
LOG_LEVEL=debug mcp-assess-full --server my-server

# Export for session
export LOG_LEVEL=warn
mcp-assess-full --server my-server
mcp-assess-full --server another-server

# In shell scripts
#!/bin/bash
export LOG_LEVEL=silent
for server in server1 server2 server3; do
  mcp-assess-full --server $server --json
done
```

---

## Configuration Precedence

When multiple logging configurations are provided, they are applied in this order:

1. **CLI flags** (highest priority)
   - `--verbose` sets level to `debug`
   - `--silent` sets level to `silent`
   - `--log-level <level>` sets explicit level

2. **Environment variable**
   - `LOG_LEVEL=<level>`

3. **Default**
   - `info` level

### Examples

```bash
# CLI wins over environment
LOG_LEVEL=debug mcp-assess-full --server my-server --silent
# Result: silent (CLI flag takes precedence)

# Environment used when no CLI flag
LOG_LEVEL=debug mcp-assess-full --server my-server
# Result: debug (from environment)

# Default when nothing specified
mcp-assess-full --server my-server
# Result: info (default)
```

---

## Output Format

### Text Format (Default)

Logger messages use a consistent format:

```
[ModuleName] message
[ModuleName] message {"context": "data"}
```

**Examples:**

```
[TemporalAssessor] Starting temporal assessment with 3 invocations per tool
[FunctionalityAssessor] Testing tool: add_memory with params: {"key":"test"}
[SecurityAssessor] Testing add_memory with all attack patterns
[AssessmentOrchestrator] Claude Code Bridge initialized
```

### With Context Objects

When context data is provided, it's serialized as JSON:

```
[SecurityAssessor] Vulnerability detected {"tool":"exec","pattern":"Command Injection","confidence":"high"}
[AssessmentOrchestrator] Test counts by assessor {"functionality":290,"security":580,"temporal":725}
```

---

## Output Streams

MCP Inspector uses two distinct output streams:

| Stream           | Destination | Content                    | Control                                |
| ---------------- | ----------- | -------------------------- | -------------------------------------- |
| **Logger**       | stdout      | Human-readable diagnostics | `--verbose`, `--silent`, `--log-level` |
| **JSONL Events** | stderr      | Machine-parseable events   | Always emitted                         |

### Why Two Streams?

This separation allows:

1. **Humans** can read diagnostic output on stdout
2. **Machines** can parse JSONL events on stderr
3. **Both** can work simultaneously without interference

### Stream Examples

```bash
# Capture only JSONL events (suppress logger to /dev/null)
mcp-assess-full --server my-server --silent 2>events.jsonl

# Capture only logger output (suppress JSONL)
mcp-assess-full --server my-server 2>/dev/null

# Separate both streams
mcp-assess-full --server my-server >logs.txt 2>events.jsonl

# View JSONL events inline
mcp-assess-full --server my-server 2>&1 | grep '{"event"'
```

---

## Configuration Presets

The assessment configuration includes logging presets for different use cases:

### DEFAULT_ASSESSMENT_CONFIG

```typescript
logging: {
  level: "info";
}
```

Standard verbosity for normal development use.

### REVIEWER_MODE_CONFIG

```typescript
logging: {
  level: "warn";
}
```

Minimal output for fast MCP directory reviews.

### DEVELOPER_MODE_CONFIG

```typescript
logging: {
  level: "debug";
}
```

Full diagnostic output for debugging.

### AUDIT_MODE_CONFIG

```typescript
logging: {
  level: "info";
}
```

Standard verbosity for compliance audits.

### CLAUDE_ENHANCED_AUDIT_CONFIG

```typescript
logging: {
  level: "info";
}
```

Standard verbosity (Claude output is already verbose).

---

## Programmatic Configuration

When using the inspector programmatically, configure logging via `AssessmentConfiguration`:

```typescript
import { AssessmentOrchestrator } from "@bryan-thompson/inspector-assessment";

const config = {
  testTimeout: 30000,
  logging: {
    level: "debug", // 'silent' | 'error' | 'warn' | 'info' | 'debug'
  },
  assessmentCategories: {
    functionality: true,
    security: true,
    // ...
  },
};

const orchestrator = new AssessmentOrchestrator(config);
```

### LoggingConfig Interface

```typescript
interface LoggingConfig {
  level: LogLevel; // Required: 'silent' | 'error' | 'warn' | 'info' | 'debug'
}

type LogLevel = "silent" | "error" | "warn" | "info" | "debug";
```

---

## Logger API (For Module Developers)

Assessment modules inherit logging from `BaseAssessor`:

### Available Methods

```typescript
// In any assessor extending BaseAssessor:

// Log at different levels
this.logger.debug("Detailed diagnostic info", { context: "data" });
this.logger.info("Progress message");
this.logger.warn("Warning message", { issue: "details" });
this.logger.error("Error occurred", { error: errorObject });

// Create child logger with extended prefix
const childLogger = this.logger.child("SubModule");
// Output: [ParentModule:SubModule] message

// Check if level is enabled (for expensive operations)
if (this.logger.isLevelEnabled("debug")) {
  const expensiveData = computeExpensiveDebugInfo();
  this.logger.debug("Debug info", expensiveData);
}
```

### Legacy Methods (Deprecated)

For backward compatibility, these methods still work but are deprecated:

```typescript
// Deprecated - use this.logger.info() instead
this.log("message");

// Deprecated - use this.logger.error() instead
this.logError("message", error);
```

---

## Common Scenarios

### Troubleshooting Connection Issues

```bash
# Enable verbose logging to see connection details
mcp-assess-full --server my-server --verbose 2>&1 | head -50
```

### CI/CD Integration

```bash
# Silent mode with JSON output for automated pipelines
mcp-assess-full --server my-server --silent --json

# Capture events for monitoring
mcp-assess-full --server my-server --silent 2>events.jsonl
result=$?
cat events.jsonl | jq 'select(.event == "vulnerability_found")'
exit $result
```

### Development Debugging

```bash
# Maximum verbosity
LOG_LEVEL=debug mcp-assess-full --server my-server

# Or
mcp-assess-full --server my-server --verbose
```

### Production Assessments

```bash
# Warnings and errors only
mcp-assess-full --server my-server --log-level warn
```

### Batch Processing

```bash
#!/bin/bash
export LOG_LEVEL=silent

servers=("server1" "server2" "server3")
for server in "${servers[@]}"; do
  output=$(mcp-assess-full --server $server --json)
  echo "$server: $output"
done
```

---

## Troubleshooting

### Logs Not Appearing

1. Check log level isn't set to `silent`
2. Verify environment variable isn't overriding: `echo $LOG_LEVEL`
3. Ensure you're not redirecting stdout: `mcp-assess-full ... 2>&1`

### Too Much Output

Use a higher log level:

```bash
mcp-assess-full --server my-server --log-level warn
```

### JSONL Events Missing

JSONL events go to stderr, not stdout:

```bash
# Correct: capture stderr
mcp-assess-full --server my-server 2>events.jsonl

# Wrong: this captures stdout (logger output)
mcp-assess-full --server my-server >events.jsonl
```

### Log Level Not Taking Effect

Check precedence - CLI flags override environment:

```bash
# This will use 'silent', not 'debug'
LOG_LEVEL=debug mcp-assess-full --server my-server --silent
```

---

## Related Documentation

- [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md) - Complete CLI reference
- [JSONL Events API](JSONL_EVENTS_API.md) - Machine-parseable event stream
- [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom modules

---

**Version**: 1.23.1
**Last Updated**: 2026-01-04
