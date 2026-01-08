# Performance Tuning Guide

**Module**: `PerformanceConfig`
**Location**: `client/src/services/assessment/config/performanceConfig.ts`
**Added in**: Issue #37

---

## Overview

The Performance Configuration system allows tuning of assessment execution parameters:

- Batch sizes for progress reporting
- Timeouts for individual tests
- Queue depth monitoring
- Event emitter limits

This enables optimization for different hardware, network conditions, and MCP server characteristics.

---

## Quick Start

### Using CLI Flag

```bash
# Use custom performance config
mcp-assess-full --server my-server --config server.json --performance-config /path/to/perf.json

# Use a preset
echo '{"functionalityBatchSize": 10, "securityBatchSize": 20}' > /tmp/fast.json
mcp-assess-full --server my-server --config server.json --performance-config /tmp/fast.json
```

### Using Programmatically

```typescript
import {
  loadPerformanceConfig,
  PERFORMANCE_PRESETS,
} from "@bryan-thompson/inspector-assessment/client/dist/lib";

// Load from file
const config = loadPerformanceConfig("/path/to/config.json");

// Or use a preset
const fastConfig = PERFORMANCE_PRESETS.fast;
```

---

## Configuration Parameters

### `batchFlushIntervalMs`

**Purpose**: Interval between progress event batches.

| Property | Value        |
| -------- | ------------ |
| Default  | 500          |
| Range    | 50-10000     |
| Unit     | milliseconds |

**When to Adjust**:

- **Increase** (1000-2000ms) for slow networks or high-latency servers
- **Decrease** (100-200ms) for real-time progress feedback

**Impact**: Higher values reduce event overhead but delay progress updates.

---

### `functionalityBatchSize`

**Purpose**: Number of functionality test results to batch before emitting.

| Property | Value |
| -------- | ----- |
| Default  | 5     |
| Range    | 1-100 |

**When to Adjust**:

- **Increase** (10-20) for large tool sets to reduce event volume
- **Decrease** (1-3) for detailed per-test progress feedback

**Impact**: Higher values improve throughput but reduce granularity.

---

### `securityBatchSize`

**Purpose**: Number of security test results to batch before emitting.

| Property | Value |
| -------- | ----- |
| Default  | 10    |
| Range    | 1-100 |

**When to Adjust**:

- **Increase** (20-50) for servers with many tools (reduces overhead)
- **Decrease** (3-5) for resource-constrained environments

**Impact**: Higher values improve throughput for large security scans.

---

### `testTimeoutMs`

**Purpose**: Timeout for individual functionality test scenarios.

| Property | Value        |
| -------- | ------------ |
| Default  | 5000         |
| Range    | 100-300000   |
| Unit     | milliseconds |

**When to Adjust**:

- **Increase** (10000-30000ms) for slow MCP servers or complex operations
- **Decrease** (1000-2000ms) for fast CI/CD pipelines

**Impact**: Lower values fail slow tests faster; higher values allow completion.

---

### `securityTestTimeoutMs`

**Purpose**: Timeout for individual security payload tests.

| Property | Value        |
| -------- | ------------ |
| Default  | 5000         |
| Range    | 100-300000   |
| Unit     | milliseconds |

**When to Adjust**:

- **Increase** for servers that do complex validation on payloads
- **Decrease** for quick security scans in CI/CD

**Impact**: Same as `testTimeoutMs` but for security tests.

---

### `queueWarningThreshold`

**Purpose**: Task queue depth at which warnings are triggered.

| Property | Value       |
| -------- | ----------- |
| Default  | 10000       |
| Range    | 100-1000000 |

**Derivation**: Advanced security assessments can queue:

- 29 tools × 140 payloads = 4,060 tasks
- Default 10,000 provides ~146% headroom

**When to Adjust**:

- **Increase** (20000-50000) for servers with 100+ tools
- **Decrease** (5000) for resource-constrained environments

**Impact**: Lower values catch runaway scenarios earlier.

---

### `eventEmitterMaxListeners`

**Purpose**: Maximum EventEmitter listeners to prevent Node.js warnings.

| Property | Value   |
| -------- | ------- |
| Default  | 50      |
| Range    | 10-1000 |

**When to Adjust**:

- **Increase** (100-200) if seeing MaxListenersExceededWarning
- Rarely needs decreasing

**Impact**: Prevents false-positive memory leak warnings.

---

## Presets

### `default`

Balanced configuration for general use.

```json
{
  "batchFlushIntervalMs": 500,
  "functionalityBatchSize": 5,
  "securityBatchSize": 10,
  "testTimeoutMs": 5000,
  "securityTestTimeoutMs": 5000,
  "queueWarningThreshold": 10000,
  "eventEmitterMaxListeners": 50
}
```

### `fast`

Optimized for speed with larger batches.

```json
{
  "batchFlushIntervalMs": 500,
  "functionalityBatchSize": 10,
  "securityBatchSize": 20,
  "testTimeoutMs": 5000,
  "securityTestTimeoutMs": 5000,
  "queueWarningThreshold": 10000,
  "eventEmitterMaxListeners": 50
}
```

**Use case**: CI/CD pipelines, fast servers, quick validation.

### `resourceConstrained`

Conservative settings for limited resources.

```json
{
  "batchFlushIntervalMs": 500,
  "functionalityBatchSize": 3,
  "securityBatchSize": 5,
  "testTimeoutMs": 5000,
  "securityTestTimeoutMs": 5000,
  "queueWarningThreshold": 5000,
  "eventEmitterMaxListeners": 50
}
```

**Use case**: Low-memory environments, shared CI runners.

---

## Example Configuration Files

### CI/CD Pipeline (Fast)

`/config/perf-ci.json`:

```json
{
  "functionalityBatchSize": 15,
  "securityBatchSize": 25,
  "testTimeoutMs": 3000,
  "securityTestTimeoutMs": 3000
}
```

### Large Tool Set (100+ tools)

`/config/perf-large.json`:

```json
{
  "functionalityBatchSize": 20,
  "securityBatchSize": 50,
  "queueWarningThreshold": 50000,
  "testTimeoutMs": 10000
}
```

### High-Latency Network

`/config/perf-slow-network.json`:

```json
{
  "batchFlushIntervalMs": 2000,
  "testTimeoutMs": 30000,
  "securityTestTimeoutMs": 30000
}
```

### Resource-Constrained (512MB RAM)

`/config/perf-minimal.json`:

```json
{
  "functionalityBatchSize": 2,
  "securityBatchSize": 3,
  "queueWarningThreshold": 3000,
  "eventEmitterMaxListeners": 30
}
```

---

## API Reference

### `loadPerformanceConfig(configPath?, logger?)`

Load configuration from a JSON file.

```typescript
function loadPerformanceConfig(
  configPath?: string,
  logger?: Logger,
): Required<PerformanceConfig>;
```

**Behavior**:

- Returns defaults if no path provided
- Validates config values against bounds
- Merges partial config with defaults
- Throws on validation errors

**Example**:

```typescript
const config = loadPerformanceConfig("/path/to/config.json");
console.log(config.testTimeoutMs); // 5000 (or custom value)
```

### `validatePerformanceConfig(config)`

Validate a partial configuration.

```typescript
function validatePerformanceConfig(
  config: Partial<PerformanceConfig>,
): string[];
```

**Returns**: Array of error messages (empty if valid).

**Example**:

```typescript
const errors = validatePerformanceConfig({ testTimeoutMs: 50 });
// ["testTimeoutMs must be between 100 and 300000"]
```

### `mergeWithDefaults(partial)`

Merge partial config with defaults.

```typescript
function mergeWithDefaults(
  partial: Partial<PerformanceConfig>,
): Required<PerformanceConfig>;
```

**Example**:

```typescript
const config = mergeWithDefaults({ testTimeoutMs: 10000 });
// All other values use defaults
```

---

## Troubleshooting

### Queue Warning Messages

**Symptom**: `Warning: Task queue depth exceeds threshold (10000)`

**Causes**:

- Server has many tools (50+)
- Security assessment generating many payloads

**Solutions**:

1. Increase `queueWarningThreshold` to 20000-50000
2. Use `fast` preset with larger batch sizes
3. Run security assessment on tool subsets

### Timeout Errors

**Symptom**: Tests failing with timeout errors

**Causes**:

- Slow MCP server
- Network latency
- Complex tool operations

**Solutions**:

1. Increase `testTimeoutMs` to 10000-30000ms
2. Increase `securityTestTimeoutMs` similarly
3. Check server response times directly

### Memory Usage

**Symptom**: High memory consumption during assessment

**Causes**:

- Large batch sizes accumulating results
- Many queued tasks

**Solutions**:

1. Decrease batch sizes (3-5)
2. Lower `queueWarningThreshold`
3. Use `resourceConstrained` preset

### MaxListenersExceededWarning

**Symptom**: Node.js warning about EventEmitter max listeners

**Causes**:

- Assessment creates many listeners
- Multiple concurrent assessments

**Solutions**:

1. Increase `eventEmitterMaxListeners` to 100-200
2. This is a warning, not an error - assessment continues

---

## CLI Usage

### Basic Usage

```bash
mcp-assess-full --server my-server \
  --config /path/to/server-config.json \
  --performance-config /path/to/perf-config.json
```

### With Security Assessment

```bash
mcp-assess-security --server my-server \
  --config /path/to/server-config.json \
  --performance-config /path/to/perf-config.json
```

### Quick Inline Config

```bash
# Create temp config
echo '{"testTimeoutMs": 10000}' > /tmp/perf.json

# Use it
mcp-assess-full --server slow-server --config server.json --performance-config /tmp/perf.json
```

---

## Related Documentation

- [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md) - Complete CLI usage
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - Assessment module reference
- [Architecture Detection Guide](ARCHITECTURE_DETECTION_GUIDE.md) - Server analysis

---

## Type Definitions

```typescript
interface PerformanceConfig {
  batchFlushIntervalMs: number; // 50-10000, default 500
  functionalityBatchSize: number; // 1-100, default 5
  securityBatchSize: number; // 1-100, default 10
  testTimeoutMs: number; // 100-300000, default 5000
  securityTestTimeoutMs: number; // 100-300000, default 5000
  queueWarningThreshold: number; // 100-1000000, default 10000
  eventEmitterMaxListeners: number; // 10-1000, default 50
}
```

---

## Import Paths

```typescript
// From published package
import {
  loadPerformanceConfig,
  validatePerformanceConfig,
  mergeWithDefaults,
  DEFAULT_PERFORMANCE_CONFIG,
  PERFORMANCE_PRESETS,
} from "@bryan-thompson/inspector-assessment/client/dist/lib";

// Types
import type { PerformanceConfig } from "@bryan-thompson/inspector-assessment/client/dist/lib";
```
