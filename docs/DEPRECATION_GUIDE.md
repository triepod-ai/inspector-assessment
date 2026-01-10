# Deprecation Guide

**Status**: Version 1.25.2+ - Deprecation warnings active
**Removal Target**: Version 2.0.0
**Timeline**: ~6 months (estimated Q2 2026)

This guide documents the planned deprecations in the MCP Inspector Assessment system, with migration paths for each deprecated item.

## Overview

The deprecation system uses structured logging to warn developers about outdated APIs. All deprecation warnings include:

- **Clear message**: What is deprecated and why
- **Replacement**: What to use instead
- **Timeline**: When it will be removed (v2.0.0)
- **Migration path**: Step-by-step instructions with code examples

Warnings are emitted:

- **Once per instance** (BaseAssessor methods)
- **At startup** (AssessmentOrchestrator config flags)
- **On construction** (deprecated modules)

All warnings use the `logger.warn()` interface with structured metadata for programmatic parsing.

---

## Config Schema Versioning

**Introduced**: v1.27.0
**Required**: v2.0.0

### Overview

`AssessmentConfiguration` now includes a `configVersion` field to enable graceful schema migrations. This allows the system to detect old configurations and provide appropriate warnings or automatic migrations in future versions.

### Current Version

**configVersion: 2**

All built-in preset configurations include `configVersion: 2`:

- `DEFAULT_ASSESSMENT_CONFIG`
- `REVIEWER_MODE_CONFIG`
- `DEVELOPER_MODE_CONFIG`
- `AUDIT_MODE_CONFIG`
- `CLAUDE_ENHANCED_AUDIT_CONFIG`

### Migration Path

#### For CLI Users

No action needed. The CLI automatically uses preset configurations with the correct version.

#### For Library Users (Custom Configs)

If you're building custom `AssessmentConfiguration` objects:

```typescript
// Before (v1.26.x and earlier)
const myConfig: AssessmentConfiguration = {
  testTimeout: 30000,
  skipBrokenTools: false,
  // ... other fields
};

// After (v1.27.0+)
const myConfig: AssessmentConfiguration = {
  configVersion: 2, // Add this field
  testTimeout: 30000,
  skipBrokenTools: false,
  // ... other fields
};
```

#### Recommended: Spread from Defaults

The safest approach is to spread from a preset config:

```typescript
import { DEFAULT_ASSESSMENT_CONFIG } from "@bryan-thompson/inspector-assessment";

const myConfig: AssessmentConfiguration = {
  ...DEFAULT_ASSESSMENT_CONFIG,
  testTimeout: 60000, // Override specific fields
};
```

This ensures you inherit the correct `configVersion` and any future required fields.

### Timeline

| Version | Status                               |
| ------- | ------------------------------------ |
| v1.27.0 | `configVersion` introduced, optional |
| v2.0.0  | `configVersion` required             |

### Version History

| configVersion | Introduced | Description                                  |
| ------------- | ---------- | -------------------------------------------- |
| 2             | v1.27.0    | Initial versioning after deprecation cleanup |

---

## Deprecation Categories

### 1. Deprecated Assessment Modules (4 modules)

These modules are being consolidated into two more focused replacements:

| Deprecated Module             | Replacement                   | Reason                                                      |
| ----------------------------- | ----------------------------- | ----------------------------------------------------------- |
| `DocumentationAssessor`       | `DeveloperExperienceAssessor` | Consolidate documentation + usability into single DX module |
| `UsabilityAssessor`           | `DeveloperExperienceAssessor` | Consolidate documentation + usability into single DX module |
| `MCPSpecComplianceAssessor`   | `ProtocolComplianceAssessor`  | Unified protocol compliance with better test coverage       |
| `ProtocolConformanceAssessor` | `ProtocolComplianceAssessor`  | Unified protocol compliance with better test coverage       |

### 2. Deprecated Config Flags (2 flags)

Configuration flags that are being unified:

| Deprecated Flag                            | Replacement                               | Location                                       |
| ------------------------------------------ | ----------------------------------------- | ---------------------------------------------- |
| `assessmentCategories.mcpSpecCompliance`   | `assessmentCategories.protocolCompliance` | `AssessmentConfiguration.assessmentCategories` |
| `assessmentCategories.protocolConformance` | `assessmentCategories.protocolCompliance` | `AssessmentConfiguration.assessmentCategories` |

### 3. Deprecated BaseAssessor Methods (2 methods)

Protected logging methods in `BaseAssessor`:

| Deprecated Method                                 | Replacement                            | Impact           |
| ------------------------------------------------- | -------------------------------------- | ---------------- |
| `this.log(message: string)`                       | `this.logger.info(message)`            | Protected method |
| `this.logError(message: string, error?: unknown)` | `this.logger.error(message, context?)` | Protected method |

---

## Detailed Migrations

### Assessment Modules Migration

#### From DocumentationAssessor to DeveloperExperienceAssessor

**What's changing**:

- `DocumentationAssessor` is being merged with `UsabilityAssessor` into a single module
- The new `DeveloperExperienceAssessor` provides unified assessment of both areas
- All existing functionality is preserved with improved test coverage

**Warning message**:

```
DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead.
This module will be removed in v2.0.0.
```

**When it happens**: Constructor call

```typescript
// AssessmentOrchestrator.ts, line 241-242
if (this.config.assessmentCategories?.documentation !== false) {
  this.documentationAssessor = new DocumentationAssessor(this.config);
}
```

**Migration steps**:

1. **In configuration**: No code changes needed yet
   - The orchestrator will automatically use the new module
   - Both flags still work for backward compatibility

2. **For custom assessor instantiation** (if you're using directly):

   ```typescript
   // OLD (v1.25.x)
   import { DocumentationAssessor } from "@/services/assessment/modules";
   const docAssessor = new DocumentationAssessor(config);
   const result = await docAssessor.assess(context);

   // NEW (v1.26.0+)
   import { DeveloperExperienceAssessor } from "@/services/assessment/modules";
   const dxAssessor = new DeveloperExperienceAssessor(config);
   const result = await dxAssessor.assess(context);
   ```

3. **Result handling**: Identical response types (backward compatible)
   ```typescript
   // Response type unchanged
   result: DocumentationAssessment {
     metrics: DocumentationMetrics;
     status: AssessmentStatus;
     explanation: string;
     recommendations: string[];
   }
   ```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

#### From UsabilityAssessor to DeveloperExperienceAssessor

**What's changing**:

- `UsabilityAssessor` is being merged with `DocumentationAssessor`
- The new `DeveloperExperienceAssessor` provides unified assessment
- No loss of functionality

**Warning message**:

```
UsabilityAssessor is deprecated. Use DeveloperExperienceAssessor instead.
This module will be removed in v2.0.0.
```

**When it happens**: Constructor call

**Migration steps**:

1. **Configuration**: No changes needed
   - Orchestrator handles automatic migration

2. **Direct instantiation**:

   ```typescript
   // OLD (v1.25.x)
   import { UsabilityAssessor } from "@/services/assessment/modules";
   const usabilityAssessor = new UsabilityAssessor(config);
   const result = await usabilityAssessor.assess(context);

   // NEW (v1.26.0+)
   import { DeveloperExperienceAssessor } from "@/services/assessment/modules";
   const dxAssessor = new DeveloperExperienceAssessor(config);
   const result = await dxAssessor.assess(context);
   ```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

#### From MCPSpecComplianceAssessor to ProtocolComplianceAssessor

**What's changing**:

- Unified protocol compliance assessment
- Improved test coverage combining spec and conformance checks
- Better compliance detection accuracy

**Warning message**:

```
MCPSpecComplianceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
This module will be removed in v2.0.0.
```

**When it happens**: Constructor call + config initialization

**Migration steps**:

1. **Configuration migration** (recommended now):

   ```typescript
   // OLD (v1.25.x)
   const config: AssessmentConfiguration = {
     assessmentCategories: {
       mcpSpecCompliance: true, // Deprecated
       // ... other categories
     },
   };

   // NEW (v1.26.0+)
   const config: AssessmentConfiguration = {
     assessmentCategories: {
       protocolCompliance: true, // New unified flag
       // ... other categories
     },
   };
   ```

2. **Direct instantiation** (if applicable):

   ```typescript
   // OLD (v1.25.x)
   import { MCPSpecComplianceAssessor } from "@/services/assessment/modules";
   const specAssessor = new MCPSpecComplianceAssessor(config);
   const result = await specAssessor.assess(context);

   // NEW (v1.26.0+)
   import { ProtocolComplianceAssessor } from "@/services/assessment/modules";
   const protocolAssessor = new ProtocolComplianceAssessor(config);
   const result = await protocolAssessor.assess(context);
   ```

**Timeline**:

- Config warnings start: v1.25.2
- Module warnings start: v1.25.2
- Removal: v2.0.0

---

#### From ProtocolConformanceAssessor to ProtocolComplianceAssessor

**What's changing**:

- Protocol conformance checks merged into unified compliance assessment
- Better separation of concerns: compliance (spec-level) vs. error handling (app-level)
- Improved protocol validation

**Warning message**:

```
ProtocolConformanceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
This module will be removed in v2.0.0.
```

**When it happens**: Constructor call + config initialization

**Migration steps**:

1. **Configuration migration** (recommended now):

   ```typescript
   // OLD (v1.25.x)
   const config: AssessmentConfiguration = {
     assessmentCategories: {
       protocolConformance: true, // Deprecated
       // ... other categories
     },
   };

   // NEW (v1.26.0+)
   const config: AssessmentConfiguration = {
     assessmentCategories: {
       protocolCompliance: true, // Unified flag
       // ... other categories
     },
   };
   ```

2. **Direct instantiation**:

   ```typescript
   // OLD (v1.25.x)
   import { ProtocolConformanceAssessor } from "@/services/assessment/modules";
   const conformAssessor = new ProtocolConformanceAssessor(config);
   const result = await conformAssessor.assess(context);

   // NEW (v1.26.0+)
   import { ProtocolComplianceAssessor } from "@/services/assessment/modules";
   const protocolAssessor = new ProtocolComplianceAssessor(config);
   const result = await protocolAssessor.assess(context);
   ```

**Timeline**:

- Config warnings start: v1.25.2
- Module warnings start: v1.25.2
- Removal: v2.0.0

---

### Configuration Flags Migration

#### From mcpSpecCompliance to protocolCompliance

**Location**: `AssessmentConfiguration.assessmentCategories`

**What's changing**:

- Two separate flags (`mcpSpecCompliance`, `protocolConformance`) are being unified
- Single `protocolCompliance` flag replaces both
- Simpler configuration, clearer intent

**Warning message**:

```
Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead.
This flag will be removed in v2.0.0.
```

**When it happens**: At `AssessmentOrchestrator` construction (line 214-220)

**Before and after**:

```typescript
// OLD (v1.25.x) - Two separate flags
const config: AssessmentConfiguration = {
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // ← Deprecated
    protocolConformance: true, // ← Also deprecated
  },
};

const orchestrator = new AssessmentOrchestrator(config);
// Console output:
// WARN: Config flag 'mcpSpecCompliance' is deprecated...
// WARN: Config flag 'protocolConformance' is deprecated...

// NEW (v1.26.0+) - Single unified flag
const config: AssessmentConfiguration = {
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    protocolCompliance: true, // ← Single unified flag
  },
};

const orchestrator = new AssessmentOrchestrator(config);
// No warnings!
```

**Backward compatibility**:
The orchestrator still accepts the old flags during initialization:

```typescript
// This still works (with warning) in v1.25.2+
const config = {
  assessmentCategories: {
    mcpSpecCompliance: true, // Will warn but still enable protocolCompliance
  },
};
```

**Preset updates**:

Check your config presets if you're using them:

```typescript
// DEFAULT_ASSESSMENT_CONFIG
export const DEFAULT_ASSESSMENT_CONFIG: AssessmentConfiguration = {
  assessmentCategories: {
    mcpSpecCompliance: false, // ← Update to protocolCompliance: false
    protocolCompliance: false, // ← Now preferred
  },
};

// DEVELOPER_MODE_CONFIG
export const DEVELOPER_MODE_CONFIG: AssessmentConfiguration = {
  assessmentCategories: {
    mcpSpecCompliance: true, // ← Update to protocolCompliance: true
    protocolCompliance: true, // ← Now preferred
  },
};
```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

#### From protocolConformance to protocolCompliance

**Location**: `AssessmentConfiguration.assessmentCategories`

**What's changing**:

- `protocolConformance` is being consolidated into `protocolCompliance`
- More intuitive terminology (compliance vs. conformance)
- Unified protocol validation

**Warning message**:

```
Config flag 'protocolConformance' is deprecated. Use 'protocolCompliance' instead.
This flag will be removed in v2.0.0.
```

**When it happens**: At `AssessmentOrchestrator` construction (line 221-227)

**Migration path**: Identical to `mcpSpecCompliance` above - use `protocolCompliance` instead

```typescript
// OLD
const config = {
  assessmentCategories: {
    protocolConformance: true, // ← Deprecated
  },
};

// NEW
const config = {
  assessmentCategories: {
    protocolCompliance: true, // ← Preferred
  },
};
```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

### BaseAssessor Method Migration

#### From this.log() to this.logger.info()

**Location**: `client/src/services/assessment/modules/BaseAssessor.ts` (lines 66-75)

**What's changing**:

- Simple wrapper method removed
- Direct access to structured logger recommended
- Enables better logging context and filtering

**Warning message** (emitted once per assessor instance):

```
BaseAssessor.log() is deprecated. Use this.logger.info() instead.
This method will be removed in v2.0.0.
```

**When it happens**: First call to `this.log()`

**How it works**:

- Warning is tracked internally to emit only once per instance
- After warning, method still works (forwarded to logger.info)
- Allows gradual migration

```typescript
// Tracking mechanism (BaseAssessor.ts, lines 26-29)
private deprecationWarningsEmitted = {
  log: false,
  logError: false,
};

// First call triggers warning
protected log(message: string): void {
  if (!this.deprecationWarningsEmitted.log) {
    this.logger.warn(
      "BaseAssessor.log() is deprecated. Use this.logger.info() instead. " +
        "This method will be removed in v2.0.0.",
    );
    this.deprecationWarningsEmitted.log = true;  // Only emit once
  }
  this.logger.info(message);  // Still works, forwarded to logger
}
```

**Migration examples**:

```typescript
// Example: In a subclass of BaseAssessor

// OLD (v1.25.x) - Protected wrapper method
export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    this.log("Starting assessment"); // ← Deprecated
    // ... assessment code
    this.log("Assessment complete");
  }
}

// NEW (v1.26.0+) - Direct logger access
export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    this.logger.info("Starting assessment"); // ← Preferred
    // ... assessment code
    this.logger.info("Assessment complete");
  }
}
```

**Structured logging with context** (best practice):

```typescript
// OLD - Simple string only
this.log("Tool called successfully");

// NEW - Structured logging with context
this.logger.info("Tool called successfully", {
  toolName: tool.name,
  executionTime: endTime - startTime,
  resultSize: result.length,
});
```

**Logger API reference**:

```typescript
// Available methods on this.logger
this.logger.info(message: string, context?: Record<string, unknown>);
this.logger.warn(message: string, context?: Record<string, unknown>);
this.logger.error(message: string, context?: Record<string, unknown>);
this.logger.debug(message: string, context?: Record<string, unknown>);
```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

#### From this.logError() to this.logger.error()

**Location**: `client/src/services/assessment/modules/BaseAssessor.ts` (lines 84-93)

**What's changing**:

- Simple wrapper removed
- Direct logger access for better error context
- Automatic error categorization available via `handleError()` method

**Warning message** (emitted once per assessor instance):

```
BaseAssessor.logError() is deprecated. Use this.logger.error() instead.
This method will be removed in v2.0.0.
```

**When it happens**: First call to `this.logError()`

**How it works**:

- Warning tracked internally (one per instance)
- Method still functions (forwarded to logger.error)
- Allows gradual code migration

```typescript
// Tracking mechanism (BaseAssessor.ts, lines 26-29)
private deprecationWarningsEmitted = {
  log: false,
  logError: false,
};

// First call triggers warning
protected logError(message: string, error?: unknown): void {
  if (!this.deprecationWarningsEmitted.logError) {
    this.logger.warn(
      "BaseAssessor.logError() is deprecated. Use this.logger.error() instead. " +
        "This method will be removed in v2.0.0.",
    );
    this.deprecationWarningsEmitted.logError = true;  // Only emit once
  }
  this.logger.error(message, error ? { error: String(error) } : undefined);
}
```

**Migration examples**:

```typescript
// Example: Error handling in assessor

// OLD (v1.25.x) - Protected wrapper method
export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    try {
      const result = await this.callTool(tool);
      return { passed: true, result };
    } catch (error) {
      this.logError("Tool call failed", error); // ← Deprecated
      return { passed: false, error };
    }
  }
}

// NEW (v1.26.0+) - Direct logger access
export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    try {
      const result = await this.callTool(tool);
      return { passed: true, result };
    } catch (error) {
      this.logger.error("Tool call failed", {
        error: String(error),
        toolName: tool.name,
      }); // ← Preferred
      return { passed: false, error };
    }
  }
}
```

**Advanced: Using handleError() helper**:

For comprehensive error handling with automatic categorization, use the `handleError()` method:

```typescript
// BEST PRACTICE - Use handleError() helper for full context
export class MyAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    try {
      const result = await this.callTool(tool);
      return { passed: true, result };
    } catch (error) {
      // handleError() includes:
      // - Automatic error categorization
      // - Structured logging
      // - Error info extraction
      return this.handleError(error, `Failed to call tool ${tool.name}`, {
        passed: false,
      });
    }
  }
}
```

**Error logging with context**:

```typescript
// OLD - Simple string
this.logError("Failed to parse response");

// NEW - Structured context
this.logger.error("Failed to parse response", {
  responseText: response.substring(0, 100), // Truncate long responses
  contentType: headers["content-type"],
  statusCode: response.status,
});

// BEST - Use handleError() for automatic categorization
return this.handleError(error, "Failed to parse response", { passed: false });
```

**Timeline**:

- Warnings start: v1.25.2
- Removal: v2.0.0

---

## Migration Checklist

### For CLI Users (No action needed)

The CLI (`mcp-assess-full`, `mcp-assess-security`) automatically handles all deprecations:

- Config flags: Migrated internally
- Modules: Using new modules automatically
- Methods: Only affects custom assessor code

### For Library Users

Follow this checklist to migrate your code:

- [ ] **Update config files** (highest priority):
  - Replace `mcpSpecCompliance: true` → `protocolCompliance: true`
  - Replace `protocolConformance: true` → `protocolCompliance: true`
  - Run your assessment with new config to verify

- [ ] **Update direct module imports** (if applicable):
  - Replace `DocumentationAssessor` → `DeveloperExperienceAssessor`
  - Replace `UsabilityAssessor` → `DeveloperExperienceAssessor`
  - Replace `MCPSpecComplianceAssessor` → `ProtocolComplianceAssessor`
  - Replace `ProtocolConformanceAssessor` → `ProtocolComplianceAssessor`

- [ ] **Update custom assessor code** (if extending BaseAssessor):
  - Replace `this.log()` → `this.logger.info()`
  - Replace `this.logError()` → `this.logger.error()` or better, `this.handleError()`
  - Add structured context to log calls where applicable

- [ ] **Test thoroughly**:
  - Run your assessment suite
  - Verify output is identical to previous version
  - No functional changes, only API updates

- [ ] **Monitor logs**:
  - Deprecation warnings will guide you to any missed updates
  - Warnings will stop in v2.0.0

### For Custom Assessment Modules

If you have custom assessment modules extending `BaseAssessor`:

**Step 1: Replace log methods**

```typescript
// Find all instances of this.log() and this.logError()
grep -r "this\.log\|this\.logError" your-module.ts

// Replace with logger equivalents
this.log("message") → this.logger.info("message")
this.logError("msg", err) → this.logger.error("msg", { error: String(err) })
```

**Step 2: Add structured context**

```typescript
// Before
this.logger.info("Tool executed");

// After
this.logger.info("Tool executed", {
  toolName: tool.name,
  duration: endTime - startTime,
});
```

**Step 3: Consider handleError()**

```typescript
// For error cases, use handleError() for automatic categorization
try {
  await this.callTool(tool);
} catch (error) {
  return this.handleError(error, "Tool call failed", { passed: false });
}
```

---

## Deprecation Timeline

### v1.25.2 (Current) - Warnings Active

- Deprecation warnings emitted for:
  - All 4 modules on construction
  - Both config flags on orchestrator creation
  - BaseAssessor methods on first use
- All deprecated code still functional
- No breaking changes

### v1.26.0+ - Recommended Migration Window

- Same as v1.25.2
- Warnings continue
- Timeframe: Estimated Q1 2026
- Recommendations:
  - Update all config files to use new flags
  - Update direct module imports
  - Update custom assessor code

### v2.0.0 - Breaking Changes

**Expected timeframe**: Q2 2026

Removal of deprecated items:

| Item                              | Status  |
| --------------------------------- | ------- |
| `DocumentationAssessor`           | Removed |
| `UsabilityAssessor`               | Removed |
| `MCPSpecComplianceAssessor`       | Removed |
| `ProtocolConformanceAssessor`     | Removed |
| `mcpSpecCompliance` config flag   | Removed |
| `protocolConformance` config flag | Removed |
| `BaseAssessor.log()` method       | Removed |
| `BaseAssessor.logError()` method  | Removed |

**Migration is mandatory** after v2.0.0 is released.

---

## Warning Message Reference

### Module Deprecation Warnings

**DocumentationAssessor**:

```
[WARN] DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead.
       This module will be removed in v2.0.0.
       module="DocumentationAssessor"
       replacement="DeveloperExperienceAssessor"
```

**UsabilityAssessor**:

```
[WARN] UsabilityAssessor is deprecated. Use DeveloperExperienceAssessor instead.
       This module will be removed in v2.0.0.
       module="UsabilityAssessor"
       replacement="DeveloperExperienceAssessor"
```

**MCPSpecComplianceAssessor**:

```
[WARN] MCPSpecComplianceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
       This module will be removed in v2.0.0.
       module="MCPSpecComplianceAssessor"
       replacement="ProtocolComplianceAssessor"
```

**ProtocolConformanceAssessor**:

```
[WARN] ProtocolConformanceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
       This module will be removed in v2.0.0.
       module="ProtocolConformanceAssessor"
       replacement="ProtocolComplianceAssessor"
```

### Config Flag Deprecation Warnings

**mcpSpecCompliance**:

```
[WARN] Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead.
       This flag will be removed in v2.0.0.
       flag="mcpSpecCompliance"
       replacement="protocolCompliance"
```

**protocolConformance**:

```
[WARN] Config flag 'protocolConformance' is deprecated. Use 'protocolCompliance' instead.
       This flag will be removed in v2.0.0.
       flag="protocolConformance"
       replacement="protocolCompliance"
```

### Method Deprecation Warnings

**this.log()**:

```
[WARN] BaseAssessor.log() is deprecated. Use this.logger.info() instead.
       This method will be removed in v2.0.0.
```

**this.logError()**:

```
[WARN] BaseAssessor.logError() is deprecated. Use this.logger.error() instead.
       This method will be removed in v2.0.0.
```

---

## FAQ

### Q: Do I need to update my code now?

**A**: Not immediately. Deprecation warnings are informational. Your code will continue to work through v1.x. However, we recommend updating at your convenience to prepare for v2.0.0.

### Q: Will the new modules have different behavior?

**A**: No. The new modules preserve all existing functionality. The changes are API improvements only.

### Q: Can I use old and new APIs together?

**A**: Yes, during the transition period. Mix old and new code gradually. However, using both old and new config flags simultaneously (e.g., both `mcpSpecCompliance` and `protocolCompliance`) is not recommended.

### Q: What's the best migration strategy?

**A**:

1. Update config files first (simplest, highest ROI)
2. Update direct module instantiations (if applicable)
3. Update custom assessor code (if extending BaseAssessor)
4. Test and verify output is unchanged

### Q: Can I suppress deprecation warnings?

**A**: Set `logging.level: "error"` to suppress warnings:

```typescript
const config = {
  logging: { level: "error" },  // Only show errors
  assessmentCategories: { ... }
};
```

However, this is not recommended - warnings guide you to necessary updates.

### Q: What happens in v2.0.0?

**A**: Deprecated items are completely removed. Code using old APIs will fail at runtime with "not found" or similar errors. Migration before v2.0.0 is mandatory.

### Q: How long is the transition period?

**A**: Approximately 6 months. Warnings start in v1.25.2, removal in v2.0.0 (estimated Q2 2026).

### Q: Is there a cost to migration?

**A**: No. The new APIs are compatible and usually simpler. No functionality changes, only API updates.

---

## See Also

- [BaseAssessor API Reference](/docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Full method documentation
- [Assessment Module Developer Guide](/docs/ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom assessors
- [Logging Guide](/docs/LOGGING_GUIDE.md) - Detailed logging documentation
- [Configuration Reference](/docs/README.md#assessment-configuration) - Full config options
