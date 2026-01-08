# Deprecation API Reference

**Version**: 1.25.2+
**Status**: Detailed API specification for deprecation system

This document provides a complete technical reference for the deprecation warning system, including emission points, metadata structures, and programmatic handling.

## Table of Contents

1. [Deprecation Emission Architecture](#deprecation-emission-architecture)
2. [Warning Message Formats](#warning-message-formats)
3. [Implementation Details](#implementation-details)
4. [Programmatic Handling](#programmatic-handling)
5. [Testing Deprecations](#testing-deprecations)
6. [Metrics and Telemetry](#metrics-and-telemetry)

---

## Deprecation Emission Architecture

### Emission Points

Deprecation warnings are emitted from three primary locations:

#### 1. Module Constructors

**Location**: Module constructor methods
**When**: During `new ModuleClass(config)` instantiation
**Triggered By**: `super(config)` call in subclass constructor
**Frequency**: Once per instance creation

**Modules**:

- `DocumentationAssessor` (line 20-31)
- `UsabilityAssessor` (line 26-37)
- `MCPSpecComplianceAssessor` (line 29-43)
- `ProtocolConformanceAssessor` (line 44-55)

```typescript
// Example: DocumentationAssessor constructor
export class DocumentationAssessor extends BaseAssessor {
  constructor(config: AssessmentConfiguration) {
    super(config);
    this.logger.warn(
      "DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead. " +
        "This module will be removed in v2.0.0.",
      {
        module: "DocumentationAssessor",
        replacement: "DeveloperExperienceAssessor",
      },
    );
  }
}
```

#### 2. AssessmentOrchestrator Initialization

**Location**: `AssessmentOrchestrator` constructor (lines 213-227)
**When**: During `new AssessmentOrchestrator(config)` instantiation
**Triggered By**: Config flag detection
**Frequency**: Once per deprecated flag found

**Config flags**:

- `assessmentCategories.mcpSpecCompliance` (line 214-220)
- `assessmentCategories.protocolConformance` (line 221-227)

```typescript
// Example: Configuration flag deprecation
if (this.config.assessmentCategories?.mcpSpecCompliance !== undefined) {
  this.logger.warn(
    "Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead. " +
      "This flag will be removed in v2.0.0.",
    { flag: "mcpSpecCompliance", replacement: "protocolCompliance" },
  );
}

if (this.config.assessmentCategories?.protocolConformance !== undefined) {
  this.logger.warn(
    "Config flag 'protocolConformance' is deprecated. Use 'protocolCompliance' instead. " +
      "This flag will be removed in v2.0.0.",
    { flag: "protocolConformance", replacement: "protocolCompliance" },
  );
}
```

#### 3. BaseAssessor Method First Call

**Location**: `BaseAssessor` protected methods (lines 66-93)
**When**: First invocation of deprecated method
**Triggered By**: `this.log()` or `this.logError()` call
**Frequency**: Once per method per instance (tracked internally)

**Methods**:

- `this.log(message: string)` (line 66-75)
- `this.logError(message: string, error?: unknown)` (line 84-93)

```typescript
// Example: Method-level deprecation tracking
private deprecationWarningsEmitted = {
  log: false,
  logError: false,
};

protected log(message: string): void {
  if (!this.deprecationWarningsEmitted.log) {
    this.logger.warn(
      "BaseAssessor.log() is deprecated. Use this.logger.info() instead. " +
        "This method will be removed in v2.0.0.",
    );
    this.deprecationWarningsEmitted.log = true;  // Emit only once
  }
  this.logger.info(message);
}
```

---

## Warning Message Formats

### Standard Warning Structure

All deprecation warnings follow a consistent format:

```
[WARN] {Primary message}. {Secondary message}.
       {Structured metadata (JSON)}
```

### Message Components

**Module Deprecation Messages**:

```
Message: "{ModuleName} is deprecated. Use {Replacement} instead. This module will be removed in v2.0.0."
Metadata:
  module: string        // Deprecated module name
  replacement: string   // Replacement module name
Level: warn
Context: Module constructor
```

**Config Flag Deprecation Messages**:

```
Message: "Config flag '{FlagName}' is deprecated. Use '{Replacement}' instead. This flag will be removed in v2.0.0."
Metadata:
  flag: string          // Deprecated flag name
  replacement: string   // Replacement flag name
Level: warn
Context: Orchestrator initialization
```

**Method Deprecation Messages**:

```
Message: "BaseAssessor.{MethodName}() is deprecated. Use {Replacement} instead. This method will be removed in v2.0.0."
Metadata: (none)
Level: warn
Context: First method invocation
Tracking: Per-instance (one warning per assessor instance)
```

### Example Warning Output

**CLI Output** (with logging enabled):

```
$ npm run assess -- --server test-server --config config.json

[13:45:23.421] INFO    AssessmentOrchestrator: Starting assessment for test-server
[13:45:23.512] WARN    AssessmentOrchestrator: Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead. This flag will be removed in v2.0.0.
                       {
                         flag: 'mcpSpecCompliance',
                         replacement: 'protocolCompliance'
                       }
[13:45:23.523] WARN    DocumentationAssessor: DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead. This module will be removed in v2.0.0.
                       {
                         module: 'DocumentationAssessor',
                         replacement: 'DeveloperExperienceAssessor'
                       }
[13:45:23.623] WARN    DocumentationAssessor: BaseAssessor.log() is deprecated. Use this.logger.info() instead. This method will be removed in v2.0.0.
[13:45:24.123] INFO    FunctionalityAssessor: Functionality assessment complete
```

---

## Implementation Details

### Module Deprecation Implementation

Each deprecated module emits a warning in its constructor:

**Template Structure**:

```typescript
export class DeprecatedModule extends BaseAssessor {
  constructor(config: AssessmentConfiguration) {
    super(config);
    // Emit deprecation warning
    this.logger.warn(
      "DeprecatedModule is deprecated. Use ReplacementModule instead. " +
        "This module will be removed in v2.0.0.",
      {
        module: "DeprecatedModule",
        replacement: "ReplacementModule",
      },
    );
  }

  // Rest of module implementation unchanged
  async assess(context: AssessmentContext): Promise<AssessmentResult> {
    // ... implementation ...
  }
}
```

**Inheritance Chain**:

```
BaseAssessor (has logger)
  ↓
DeprecatedModule
  constructor() {
    super(config)  ← Logger available here
    this.logger.warn(...)
  }
```

### Config Flag Deprecation Implementation

Config flags are checked during orchestrator initialization:

**Template Structure**:

```typescript
export class AssessmentOrchestrator {
  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };
    this.logger = createLogger(
      "AssessmentOrchestrator",
      this.config.logging ?? DEFAULT_LOGGING_CONFIG,
    );

    // Check deprecated flag 1
    if (this.config.assessmentCategories?.deprecatedFlag1 !== undefined) {
      this.logger.warn(
        "Config flag 'deprecatedFlag1' is deprecated. Use 'newFlag1' instead. " +
          "This flag will be removed in v2.0.0.",
        { flag: "deprecatedFlag1", replacement: "newFlag1" },
      );
    }

    // Check deprecated flag 2
    if (this.config.assessmentCategories?.deprecatedFlag2 !== undefined) {
      this.logger.warn(
        "Config flag 'deprecatedFlag2' is deprecated. Use 'newFlag2' instead. " +
          "This flag will be removed in v2.0.0.",
        { flag: "deprecatedFlag2", replacement: "newFlag2" },
      );
    }

    // ... rest of initialization ...
  }
}
```

### Method Deprecation Implementation

Method-level deprecations use instance-level tracking:

**Template Structure**:

```typescript
export abstract class BaseAssessor<T = unknown> {
  // Track deprecation warnings per instance
  private deprecationWarningsEmitted = {
    log: false,
    logError: false,
  };

  protected log(message: string): void {
    // Emit warning only on first call
    if (!this.deprecationWarningsEmitted.log) {
      this.logger.warn(
        "BaseAssessor.log() is deprecated. Use this.logger.info() instead. " +
          "This method will be removed in v2.0.0.",
      );
      this.deprecationWarningsEmitted.log = true;
    }
    // Forward to actual implementation
    this.logger.info(message);
  }

  protected logError(message: string, error?: unknown): void {
    // Emit warning only on first call
    if (!this.deprecationWarningsEmitted.logError) {
      this.logger.warn(
        "BaseAssessor.logError() is deprecated. Use this.logger.error() instead. " +
          "This method will be removed in v2.0.0.",
      );
      this.deprecationWarningsEmitted.logError = true;
    }
    // Forward to actual implementation
    this.logger.error(message, error ? { error: String(error) } : undefined);
  }
}
```

---

## Programmatic Handling

### Detecting Deprecation Warnings

**Via Log Level Filtering**:

```typescript
import { Logger, createLogger } from "@/services/assessment/lib/logger";

const logger = createLogger("MyModule", { level: "warn" });

// Only deprecation warnings (level: warn) and errors will be logged
logger.info("This is ignored"); // Not logged
logger.warn("Deprecation notice"); // Logged
logger.error("Critical error"); // Logged
```

**Via Custom Logger Implementation**:

```typescript
// Capture deprecation warnings programmatically
class DeprecationTracker {
  private deprecations: Array<{
    module?: string;
    flag?: string;
    method?: string;
    replacement: string;
    timestamp: Date;
  }> = [];

  captureWarning(message: string, context?: Record<string, unknown>) {
    // Parse warning message and context
    if (message.includes("is deprecated")) {
      this.deprecations.push({
        module: context?.module as string,
        flag: context?.flag as string,
        method: message.match(/BaseAssessor\.(\w+)\(\)/)?.[1],
        replacement: context?.replacement as string,
        timestamp: new Date(),
      });
    }
  }

  getDeprecationReport() {
    return {
      total: this.deprecations.length,
      byType: {
        modules: this.deprecations.filter((d) => d.module).length,
        flags: this.deprecations.filter((d) => d.flag).length,
        methods: this.deprecations.filter((d) => d.method).length,
      },
      items: this.deprecations,
    };
  }
}
```

### Suppressing Deprecation Warnings

**Method 1: Set Log Level to Error**:

```typescript
const config: AssessmentConfiguration = {
  logging: {
    level: "error", // Only show errors, suppress warnings
  },
  assessmentCategories: {
    /* ... */
  },
};

const orchestrator = new AssessmentOrchestrator(config);
// Deprecation warnings will not be logged
```

**Method 2: Filter by Module**:

```typescript
// Custom logger that filters deprecation messages
const logger = createLogger("MyModule", {
  level: "warn",
  filterFn: (message) => !message.includes("is deprecated"),
});
```

**Method 3: Migrate Before Logging**:

```typescript
// Simply use new APIs - no warnings will be emitted
const config: AssessmentConfiguration = {
  assessmentCategories: {
    protocolCompliance: true, // New API, no warning
    // Don't use deprecated flags
  },
};

export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    // Use new API directly
    this.logger.info("Assessment started"); // No warning
  }
}
```

### Testing for Deprecation Warnings

**Unit Test Example**:

```typescript
import { AssessmentOrchestrator } from "@/services/assessment";

describe("Deprecation Warnings", () => {
  it("should emit warning for mcpSpecCompliance flag", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation();

    const orchestrator = new AssessmentOrchestrator({
      assessmentCategories: {
        mcpSpecCompliance: true, // Deprecated flag
      },
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("mcpSpecCompliance"),
    );
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("protocolCompliance"),
    );

    warnSpy.mockRestore();
  });

  it("should emit warning for DocumentationAssessor", () => {
    const logSpy = jest.spyOn(logger, "warn").mockImplementation();

    const assessor = new DocumentationAssessor(defaultConfig);

    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining("DocumentationAssessor"),
      expect.objectContaining({
        module: "DocumentationAssessor",
        replacement: "DeveloperExperienceAssessor",
      }),
    );

    logSpy.mockRestore();
  });

  it("should emit warning for log() method on first call only", () => {
    const logSpy = jest.spyOn(logger, "warn").mockImplementation();

    const assessor = new TestAssessor(defaultConfig);

    // First call
    assessor.callLog("First message");
    expect(logSpy).toHaveBeenCalledTimes(1);

    // Second call
    assessor.callLog("Second message");
    expect(logSpy).toHaveBeenCalledTimes(1); // Still 1, not 2

    logSpy.mockRestore();
  });
});
```

---

## Testing Deprecations

### Test Scenarios

#### 1. Module Deprecation Warnings

```typescript
describe("Module Deprecation Warnings", () => {
  const config = { logging: { level: "warn" } };

  it("DocumentationAssessor emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new DocumentationAssessor(config);
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("DocumentationAssessor is deprecated"),
      expect.objectContaining({
        module: "DocumentationAssessor",
        replacement: "DeveloperExperienceAssessor",
      }),
    );
  });

  it("UsabilityAssessor emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new UsabilityAssessor(config);
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("UsabilityAssessor is deprecated"),
      expect.objectContaining({
        module: "UsabilityAssessor",
        replacement: "DeveloperExperienceAssessor",
      }),
    );
  });

  it("MCPSpecComplianceAssessor emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new MCPSpecComplianceAssessor(config);
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("MCPSpecComplianceAssessor is deprecated"),
      expect.objectContaining({
        module: "MCPSpecComplianceAssessor",
        replacement: "ProtocolComplianceAssessor",
      }),
    );
  });

  it("ProtocolConformanceAssessor emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new ProtocolConformanceAssessor(config);
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("ProtocolConformanceAssessor is deprecated"),
      expect.objectContaining({
        module: "ProtocolConformanceAssessor",
        replacement: "ProtocolComplianceAssessor",
      }),
    );
  });
});
```

#### 2. Config Flag Deprecation Warnings

```typescript
describe("Config Flag Deprecation Warnings", () => {
  it("mcpSpecCompliance flag emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new AssessmentOrchestrator({
      assessmentCategories: {
        mcpSpecCompliance: true,
      },
    });
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("'mcpSpecCompliance' is deprecated"),
      expect.objectContaining({
        flag: "mcpSpecCompliance",
        replacement: "protocolCompliance",
      }),
    );
  });

  it("protocolConformance flag emits warning", () => {
    const spy = jest.spyOn(logger, "warn");
    new AssessmentOrchestrator({
      assessmentCategories: {
        protocolConformance: true,
      },
    });
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("'protocolConformance' is deprecated"),
      expect.objectContaining({
        flag: "protocolConformance",
        replacement: "protocolCompliance",
      }),
    );
  });

  it("both deprecated flags emit two warnings", () => {
    const spy = jest.spyOn(logger, "warn");
    new AssessmentOrchestrator({
      assessmentCategories: {
        mcpSpecCompliance: true,
        protocolConformance: true,
      },
    });
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("no warnings with new protocolCompliance flag", () => {
    const spy = jest.spyOn(logger, "warn");
    new AssessmentOrchestrator({
      assessmentCategories: {
        protocolCompliance: true, // New API
      },
    });
    // Warnings about deprecations, but not about flags
    expect(spy).not.toHaveBeenCalledWith(
      expect.stringContaining("is deprecated"),
      expect.anything(),
    );
  });
});
```

#### 3. Method Deprecation Warnings

```typescript
describe("Method Deprecation Warnings", () => {
  class TestAssessor extends BaseAssessor {
    public testLog(msg: string) {
      this.log(msg);
    }
    public testLogError(msg: string, err?: unknown) {
      this.logError(msg, err);
    }
    async assess() {
      return {};
    }
  }

  it("log() emits warning on first call only", () => {
    const spy = jest.spyOn(logger, "warn");
    const assessor = new TestAssessor(defaultConfig);

    assessor.testLog("First call");
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("BaseAssessor.log() is deprecated"),
    );

    assessor.testLog("Second call");
    expect(spy).toHaveBeenCalledTimes(1); // Still 1
  });

  it("logError() emits warning on first call only", () => {
    const spy = jest.spyOn(logger, "warn");
    const assessor = new TestAssessor(defaultConfig);

    assessor.testLogError("First call", new Error("test"));
    expect(spy).toHaveBeenCalledWith(
      expect.stringContaining("BaseAssessor.logError() is deprecated"),
    );

    assessor.testLogError("Second call", new Error("test"));
    expect(spy).toHaveBeenCalledTimes(1); // Still 1
  });

  it("separate instances have separate tracking", () => {
    const spy = jest.spyOn(logger, "warn");
    const assessor1 = new TestAssessor(defaultConfig);
    const assessor2 = new TestAssessor(defaultConfig);

    assessor1.testLog("Call 1");
    assessor2.testLog("Call 2");

    // Each instance emits warning once
    expect(spy).toHaveBeenCalledTimes(2);
  });
});
```

---

## Metrics and Telemetry

### Deprecation Tracking

**Data Structure**:

```typescript
interface DeprecationMetrics {
  timestamp: Date;
  type: "module" | "flag" | "method";
  deprecated: string;
  replacement: string;
  instance?: string; // For module/method tracking
  serverName?: string; // For assessment context
}
```

### Collecting Deprecation Metrics

```typescript
class DeprecationMetricsCollector {
  private metrics: DeprecationMetrics[] = [];

  recordDeprecation(
    type: "module" | "flag" | "method",
    deprecated: string,
    replacement: string,
    instance?: string,
  ) {
    this.metrics.push({
      timestamp: new Date(),
      type,
      deprecated,
      replacement,
      instance,
    });
  }

  getSummary() {
    return {
      total: this.metrics.length,
      byType: {
        module: this.metrics.filter((m) => m.type === "module").length,
        flag: this.metrics.filter((m) => m.type === "flag").length,
        method: this.metrics.filter((m) => m.type === "method").length,
      },
      items: this.metrics,
      recommendations: this.generateRecommendations(),
    };
  }

  private generateRecommendations() {
    const deprecated = new Map<
      string,
      { replacement: string; count: number }
    >();

    for (const metric of this.metrics) {
      const key = metric.deprecated;
      deprecated.set(key, {
        replacement: metric.replacement,
        count: (deprecated.get(key)?.count || 0) + 1,
      });
    }

    return Array.from(deprecated.entries())
      .map(([name, data]) => ({
        from: name,
        to: data.replacement,
        frequency: data.count,
        priority: data.count >= 5 ? "high" : "medium",
      }))
      .sort((a, b) => b.frequency - a.frequency);
  }
}
```

### Usage Example

```typescript
const collector = new DeprecationMetricsCollector();

// Capture deprecations from orchestrator creation
const originalWarn = logger.warn;
logger.warn = (message, context) => {
  if (message.includes("deprecated")) {
    if (context?.module) {
      collector.recordDeprecation(
        "module",
        context.module,
        context.replacement,
      );
    } else if (context?.flag) {
      collector.recordDeprecation("flag", context.flag, context.replacement);
    } else if (message.includes("BaseAssessor")) {
      const methodMatch = message.match(/BaseAssessor\.(\w+)\(\)/);
      if (methodMatch) {
        collector.recordDeprecation(
          "method",
          methodMatch[1],
          "logger." + methodMatch[1],
        );
      }
    }
  }
  originalWarn(message, context);
};

// ... run assessment ...

// Get metrics
const summary = collector.getSummary();
console.log("Deprecation Summary:", summary);
/* Output:
{
  total: 6,
  byType: { module: 2, flag: 2, method: 2 },
  items: [...],
  recommendations: [
    { from: 'mcpSpecCompliance', to: 'protocolCompliance', frequency: 1, priority: 'medium' },
    { from: 'DocumentationAssessor', to: 'DeveloperExperienceAssessor', frequency: 1, priority: 'medium' }
  ]
}
*/
```

---

## Integration with CI/CD

### Deprecation Check in Pipeline

```yaml
# .github/workflows/check-deprecations.yml
name: Check Deprecations

on: [push, pull_request]

jobs:
  deprecations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: "18"

      - run: npm ci
      - run: npm run build

      - name: Run assessment with deprecation check
        run: |
          npm run assess -- \
            --server test-server \
            --config config.json \
            --log-level warn 2>&1 | tee assessment.log

      - name: Check for deprecations
        run: |
          if grep -q "is deprecated" assessment.log; then
            echo "Deprecations found in code:"
            grep "is deprecated" assessment.log
            echo ""
            echo "Please migrate to new APIs before v2.0.0"
            exit 1
          fi
```

### Deprecation Trend Tracking

```bash
#!/bin/bash
# Track deprecation warnings over time

for version in v1.24.0 v1.25.0 v1.25.2; do
  echo "=== $version ==="
  npm run assess -- --server test-server 2>&1 | \
    grep "is deprecated" | \
    wc -l
done

# Output:
# === v1.24.0 ===
# 0
# === v1.25.0 ===
# 4
# === v1.25.2 ===
# 6
```

---

## Related Documentation

- [Deprecation Guide](/docs/DEPRECATION_GUIDE.md) - User-facing migration guide
- [Logging Guide](/docs/LOGGING_GUIDE.md) - Logger API and configuration
- [Assessment Module Developer Guide](/docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom assessors
- [PROJECT_STATUS.md](PROJECT_STATUS.md#deprecation-system) - Issue #35 implementation details
