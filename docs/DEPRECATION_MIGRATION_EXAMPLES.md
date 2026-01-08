# Deprecation Migration Examples

**Version**: 1.25.2+
**Purpose**: Practical code examples for migrating from deprecated APIs

This document provides copy-paste ready examples for migrating each deprecated item.

## Table of Contents

1. [Configuration Examples](#configuration-examples)
2. [Module Migration Examples](#module-migration-examples)
3. [Custom Assessor Examples](#custom-assessor-examples)
4. [Complete Application Examples](#complete-application-examples)
5. [Testing Examples](#testing-examples)

---

## Configuration Examples

### Example 1: Basic Config Migration

**Before** (v1.25.x):

```typescript
import {
  AssessmentOrchestrator,
  AssessmentConfiguration,
} from "@/services/assessment";

const config: AssessmentConfiguration = {
  testTimeout: 30000,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // ✗ Deprecated
    protocolConformance: true, // ✗ Deprecated
  },
};

const orchestrator = new AssessmentOrchestrator(config);
// Output:
// WARN: Config flag 'mcpSpecCompliance' is deprecated...
// WARN: Config flag 'protocolConformance' is deprecated...
```

**After** (v1.26.0+):

```typescript
import {
  AssessmentOrchestrator,
  AssessmentConfiguration,
} from "@/services/assessment";

const config: AssessmentConfiguration = {
  testTimeout: 30000,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    protocolCompliance: true, // ✓ New unified flag
  },
};

const orchestrator = new AssessmentOrchestrator(config);
// Output: (no deprecation warnings)
```

### Example 2: Extended Assessment Migration

**Before** (v1.25.x):

```typescript
const config: AssessmentConfiguration = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true, // ✗ Deprecated - protocol spec checks
    protocolConformance: true, // ✗ Deprecated - protocol conformance checks
    // New categories
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
  },
};

const orchestrator = new AssessmentOrchestrator(config);
```

**After** (v1.26.0+):

```typescript
const config: AssessmentConfiguration = {
  enableExtendedAssessment: true,
  assessmentCategories: {
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    protocolCompliance: true, // ✓ Unified protocol checks
    // New categories
    aupCompliance: true,
    toolAnnotations: true,
    prohibitedLibraries: true,
  },
};

const orchestrator = new AssessmentOrchestrator(config);
```

### Example 3: Preset Configuration Migration

**Before** (v1.25.x):

```typescript
import { DEVELOPER_MODE_CONFIG } from "@/lib/assessment/configTypes";

const config: AssessmentConfiguration = {
  ...DEVELOPER_MODE_CONFIG,
  // Override deprecated flags
  assessmentCategories: {
    ...DEVELOPER_MODE_CONFIG.assessmentCategories,
    mcpSpecCompliance: true, // ✗ Deprecated
  },
};
```

**After** (v1.26.0+):

```typescript
import { DEVELOPER_MODE_CONFIG } from "@/lib/assessment/configTypes";

const config: AssessmentConfiguration = {
  ...DEVELOPER_MODE_CONFIG,
  // Use new flag
  assessmentCategories: {
    ...DEVELOPER_MODE_CONFIG.assessmentCategories,
    protocolCompliance: true, // ✓ New unified flag
  },
};
```

### Example 4: CLI Configuration File

**Before** (config.json - v1.25.x):

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp",
  "assessmentConfig": {
    "testTimeout": 30000,
    "assessmentCategories": {
      "functionality": true,
      "security": true,
      "documentation": true,
      "errorHandling": true,
      "usability": true,
      "mcpSpecCompliance": true,
      "protocolConformance": true
    }
  }
}
```

**After** (config.json - v1.26.0+):

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp",
  "assessmentConfig": {
    "testTimeout": 30000,
    "assessmentCategories": {
      "functionality": true,
      "security": true,
      "documentation": true,
      "errorHandling": true,
      "usability": true,
      "protocolCompliance": true
    }
  }
}
```

---

## Module Migration Examples

### Example 1: Direct Module Instantiation

**Before** (v1.25.x):

```typescript
import { DocumentationAssessor } from "@/services/assessment/modules";
import { AssessmentConfiguration, AssessmentContext } from "@/lib/assessment";

const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

const assessor = new DocumentationAssessor(config);
// Console output:
// WARN: DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead...

const result = await assessor.assess(context);
console.log("Documentation assessment:", result);
```

**After** (v1.26.0+):

```typescript
import { DeveloperExperienceAssessor } from "@/services/assessment/modules";
import { AssessmentConfiguration, AssessmentContext } from "@/lib/assessment";

const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

const assessor = new DeveloperExperienceAssessor(config);
// No warnings

const result = await assessor.assess(context);
console.log("Developer experience assessment:", result);
```

### Example 2: Multiple Module Replacements

**Before** (v1.25.x):

```typescript
import {
  DocumentationAssessor,
  UsabilityAssessor,
  MCPSpecComplianceAssessor,
  ProtocolConformanceAssessor,
} from "@/services/assessment/modules";

const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

// Create deprecated assessors
const docAssessor = new DocumentationAssessor(config);
const usabilityAssessor = new UsabilityAssessor(config);
const specAssessor = new MCPSpecComplianceAssessor(config);
const conformanceAssessor = new ProtocolConformanceAssessor(config);

// Run assessments
const [docResult, usabilityResult, specResult, conformanceResult] =
  await Promise.all([
    docAssessor.assess(context),
    usabilityAssessor.assess(context),
    specAssessor.assess(context),
    conformanceAssessor.assess(context),
  ]);

console.log("Results:", {
  docResult,
  usabilityResult,
  specResult,
  conformanceResult,
});
// Console output:
// WARN: DocumentationAssessor is deprecated...
// WARN: UsabilityAssessor is deprecated...
// WARN: MCPSpecComplianceAssessor is deprecated...
// WARN: ProtocolConformanceAssessor is deprecated...
```

**After** (v1.26.0+):

```typescript
import {
  DeveloperExperienceAssessor,
  ProtocolComplianceAssessor,
} from "@/services/assessment/modules";

const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

// Create new assessors (4 deprecated modules become 2)
const dxAssessor = new DeveloperExperienceAssessor(config);
const protocolAssessor = new ProtocolComplianceAssessor(config);

// Run assessments
const [dxResult, protocolResult] = await Promise.all([
  dxAssessor.assess(context),
  protocolAssessor.assess(context),
]);

console.log("Results:", { dxResult, protocolResult });
// No warnings
```

### Example 3: Conditional Module Usage

**Before** (v1.25.x):

```typescript
const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

// Conditionally create assessors based on config
const assessors: BaseAssessor[] = [];

if (config.assessmentCategories?.documentation !== false) {
  assessors.push(new DocumentationAssessor(config)); // Deprecated
}

if (config.assessmentCategories?.usability !== false) {
  assessors.push(new UsabilityAssessor(config)); // Deprecated
}

if (config.assessmentCategories?.mcpSpecCompliance) {
  assessors.push(new MCPSpecComplianceAssessor(config)); // Deprecated
}

if (config.assessmentCategories?.protocolConformance) {
  assessors.push(new ProtocolConformanceAssessor(config)); // Deprecated
}

// Run all assessors
const results = await Promise.all(
  assessors.map((assessor) => assessor.assess(context)),
);
```

**After** (v1.26.0+):

```typescript
const config: AssessmentConfiguration = {
  /* ... */
};
const context: AssessmentContext = {
  /* ... */
};

// Cleaner code with unified assessors
const assessors: BaseAssessor[] = [];

// Developer experience (combines documentation + usability)
if (
  config.assessmentCategories?.documentation !== false ||
  config.assessmentCategories?.usability !== false
) {
  assessors.push(new DeveloperExperienceAssessor(config));
}

// Protocol compliance (combines spec + conformance)
if (config.assessmentCategories?.protocolCompliance) {
  assessors.push(new ProtocolComplianceAssessor(config));
}

// Run all assessors
const results = await Promise.all(
  assessors.map((assessor) => assessor.assess(context)),
);
```

---

## Custom Assessor Examples

### Example 1: Updating Logging in Custom Assessor

**Before** (v1.25.x):

```typescript
import { BaseAssessor } from "@/services/assessment/modules";
import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";

export class MyCustomAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    this.log("Starting custom assessment"); // ✗ Deprecated

    try {
      const results = [];
      for (const tool of context.tools) {
        this.log(`Assessing tool: ${tool.name}`); // ✗ Deprecated
        const result = await this.assessTool(tool);
        results.push(result);
      }

      this.log("Custom assessment complete"); // ✗ Deprecated
      return { status: "PASS", results };
    } catch (error) {
      this.logError("Assessment failed", error); // ✗ Deprecated
      return { status: "FAIL", error: String(error) };
    }
  }

  private async assessTool(tool: Tool) {
    // Implementation
  }
}

// Console output:
// WARN: BaseAssessor.log() is deprecated...
// WARN: BaseAssessor.logError() is deprecated...
```

**After** (v1.26.0+):

```typescript
import { BaseAssessor } from "@/services/assessment/modules";
import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";

export class MyCustomAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    this.logger.info("Starting custom assessment"); // ✓ New API

    try {
      const results = [];
      for (const tool of context.tools) {
        this.logger.info(`Assessing tool: ${tool.name}`, {
          // ✓ With context
          toolName: tool.name,
          phase: "assessment",
        });
        const result = await this.assessTool(tool);
        results.push(result);
      }

      this.logger.info("Custom assessment complete", {
        // ✓ With metrics
        toolCount: context.tools.length,
        resultCount: results.length,
      });
      return { status: "PASS", results };
    } catch (error) {
      this.logger.error("Assessment failed", {
        // ✓ New API with context
        error: String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });
      return { status: "FAIL", error: String(error) };
    }
  }

  private async assessTool(tool: Tool) {
    // Implementation
  }
}

// No warnings
```

### Example 2: Using handleError() Helper

**Before** (v1.25.x):

```typescript
export class MyCustomAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    const toolResults = [];

    for (const tool of context.tools) {
      try {
        const result = await context.callTool(tool.name, { test: true });
        toolResults.push({ tool: tool.name, passed: true, result });
      } catch (error) {
        this.logError(`Failed to call tool ${tool.name}`, error); // ✗ Deprecated
        toolResults.push({
          tool: tool.name,
          passed: false,
          error: String(error),
        });
      }
    }

    return { status: "PASS", results: toolResults };
  }
}
```

**After** (v1.26.0+) - Using new logger:

```typescript
export class MyCustomAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    const toolResults = [];

    for (const tool of context.tools) {
      try {
        const result = await context.callTool(tool.name, { test: true });
        toolResults.push({ tool: tool.name, passed: true, result });
      } catch (error) {
        this.logger.error(`Failed to call tool ${tool.name}`, {
          // ✓ New API
          error: String(error),
          toolName: tool.name,
        });
        toolResults.push({
          tool: tool.name,
          passed: false,
          error: String(error),
        });
      }
    }

    return { status: "PASS", results: toolResults };
  }
}
```

**After** (v1.26.0+) - Using handleError() (best practice):

```typescript
export class MyCustomAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    const toolResults = [];

    for (const tool of context.tools) {
      try {
        const result = await context.callTool(tool.name, { test: true });
        this.testCount++;
        toolResults.push({ tool: tool.name, passed: true, result });
      } catch (error) {
        const errorResult = this.handleError(
          error,
          `Failed to call tool ${tool.name}`,
          {
            tool: tool.name,
            passed: false,
          },
        );
        toolResults.push(errorResult);
      }
    }

    return { status: "PASS", results: toolResults };
  }
}
```

### Example 3: Structured Logging with Context

**Before** (v1.25.x):

```typescript
export class MyCustomAssessor extends BaseAssessor {
  private metrics = { passed: 0, failed: 0, total: 0 };

  async assess(context: AssessmentContext) {
    this.log("Assessment started"); // ✗ No context

    for (const tool of context.tools) {
      this.metrics.total++;

      try {
        await this.assessTool(tool);
        this.metrics.passed++;
        this.log("Assessment passed"); // ✗ No context
      } catch (error) {
        this.metrics.failed++;
        this.logError("Assessment failed", error); // ✗ Limited context
      }
    }

    this.log("Assessment complete"); // ✗ No metrics

    return {
      status: this.metrics.passed > this.metrics.failed ? "PASS" : "FAIL",
      metrics: this.metrics,
    };
  }
}
```

**After** (v1.26.0+):

```typescript
export class MyCustomAssessor extends BaseAssessor {
  private metrics = { passed: 0, failed: 0, total: 0 };
  private startTime = 0;

  async assess(context: AssessmentContext) {
    this.startTime = Date.now();
    this.logger.info("Assessment started", {
      // ✓ With context
      toolCount: context.tools.length,
      serverName: context.serverName,
    });

    for (const tool of context.tools) {
      this.metrics.total++;
      const toolStart = Date.now();

      try {
        await this.assessTool(tool);
        this.metrics.passed++;
        this.logger.info("Tool assessment passed", {
          // ✓ Rich context
          toolName: tool.name,
          duration: Date.now() - toolStart,
          passRate: this.metrics.passed / this.metrics.total,
        });
      } catch (error) {
        this.metrics.failed++;
        this.logger.error("Tool assessment failed", {
          // ✓ Full context
          toolName: tool.name,
          duration: Date.now() - toolStart,
          error: String(error),
          stack: error instanceof Error ? error.stack : undefined,
        });
      }
    }

    const totalDuration = Date.now() - this.startTime;
    this.logger.info("Assessment complete", {
      // ✓ Final metrics
      passed: this.metrics.passed,
      failed: this.metrics.failed,
      total: this.metrics.total,
      duration: totalDuration,
      passRate: `${((this.metrics.passed / this.metrics.total) * 100).toFixed(1)}%`,
    });

    return {
      status: this.metrics.passed > this.metrics.failed ? "PASS" : "FAIL",
      metrics: this.metrics,
    };
  }

  private async assessTool(tool: Tool) {
    // Implementation
  }
}
```

---

## Complete Application Examples

### Example 1: Full Assessment with Old APIs

```typescript
// app.ts - Using deprecated APIs (v1.25.x)
import {
  AssessmentOrchestrator,
  AssessmentConfiguration,
  AssessmentContext,
} from "@/services/assessment";

async function runAssessment(serverName: string, tools: Tool[]) {
  // Configuration with deprecated flags
  const config: AssessmentConfiguration = {
    testTimeout: 30000,
    assessmentCategories: {
      functionality: true,
      security: true,
      documentation: true,
      errorHandling: true,
      usability: true,
      mcpSpecCompliance: true, // ✗ Deprecated
      protocolConformance: true, // ✗ Deprecated
    },
  };

  // Create orchestrator (emits warnings)
  const orchestrator = new AssessmentOrchestrator(config);

  // Context
  const context: AssessmentContext = {
    serverName,
    tools,
    callTool: async (name, params) => {
      // Tool calling implementation
    },
    config,
  };

  // Run assessment
  const result = await orchestrator.runFullAssessment(context);

  return result;
}

// Usage
const tools: Tool[] = [
  /* ... */
];
const assessment = await runAssessment("my-server", tools);
console.log("Assessment:", assessment);

// Console output:
// WARN: Config flag 'mcpSpecCompliance' is deprecated...
// WARN: Config flag 'protocolConformance' is deprecated...
```

### Example 2: Full Assessment with New APIs

```typescript
// app.ts - Using new APIs (v1.26.0+)
import {
  AssessmentOrchestrator,
  AssessmentConfiguration,
  AssessmentContext,
} from "@/services/assessment";

async function runAssessment(serverName: string, tools: Tool[]) {
  // Configuration with new unified flags
  const config: AssessmentConfiguration = {
    testTimeout: 30000,
    assessmentCategories: {
      functionality: true,
      security: true,
      documentation: true,
      errorHandling: true,
      usability: true,
      protocolCompliance: true, // ✓ New unified flag
    },
  };

  // Create orchestrator (no warnings)
  const orchestrator = new AssessmentOrchestrator(config);

  // Context
  const context: AssessmentContext = {
    serverName,
    tools,
    callTool: async (name, params) => {
      // Tool calling implementation
    },
    config,
  };

  // Run assessment
  const result = await orchestrator.runFullAssessment(context);

  return result;
}

// Usage
const tools: Tool[] = [
  /* ... */
];
const assessment = await runAssessment("my-server", tools);
console.log("Assessment:", assessment);

// Console output: (no deprecation warnings)
```

### Example 3: Custom Assessor Integration

```typescript
// custom-assessor.ts - New API (v1.26.0+)
import { BaseAssessor } from "@/services/assessment/modules";
import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";

export class CustomComplianceAssessor extends BaseAssessor {
  async assess(context: AssessmentContext) {
    this.logger.info("Starting custom compliance assessment", {
      serverName: context.serverName,
      toolCount: context.tools.length,
    });

    const checks: ComplianceCheck[] = [];

    for (const tool of context.tools) {
      try {
        const check = await this.checkToolCompliance(tool, context);
        checks.push(check);
        this.logger.debug("Tool check completed", {
          toolName: tool.name,
          status: check.status,
        });
      } catch (error) {
        const errorInfo = this.handleError(
          error,
          `Compliance check failed for tool ${tool.name}`,
          {
            toolName: tool.name,
            status: "FAIL",
          },
        );
        checks.push(errorInfo);
      }
    }

    const passed = checks.filter((c) => c.status === "PASS").length;
    const total = checks.length;

    this.logger.info("Custom compliance assessment complete", {
      passed,
      total,
      passRate: `${((passed / total) * 100).toFixed(1)}%`,
    });

    return {
      status: passed / total >= 0.8 ? "PASS" : "FAIL",
      checks,
    };
  }

  private async checkToolCompliance(tool: Tool, context: AssessmentContext) {
    // Implementation
  }
}

// Integration
import { AssessmentOrchestrator } from "@/services/assessment";

const orchestrator = new AssessmentOrchestrator(config);
const assessor = new CustomComplianceAssessor(config);
const result = await assessor.assess(context);
```

---

## Testing Examples

### Example 1: Testing Config Migration

```typescript
// __tests__/deprecation.test.ts
import { AssessmentOrchestrator } from "@/services/assessment";
import { createLogger } from "@/services/assessment/lib/logger";

describe("Config Deprecation Warnings", () => {
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    warnSpy = jest.spyOn(console, "warn").mockImplementation();
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  it("should warn for deprecated mcpSpecCompliance flag", () => {
    new AssessmentOrchestrator({
      assessmentCategories: {
        mcpSpecCompliance: true,
      },
    });

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining("mcpSpecCompliance"),
      expect.stringContaining("protocolCompliance"),
    );
  });

  it("should not warn for new protocolCompliance flag", () => {
    warnSpy.mockClear();

    new AssessmentOrchestrator({
      assessmentCategories: {
        protocolCompliance: true,
      },
    });

    expect(warnSpy).not.toHaveBeenCalledWith(
      expect.stringContaining("is deprecated"),
    );
  });
});
```

### Example 2: Testing Module Migration

```typescript
describe("Module Deprecation Warnings", () => {
  let loggerSpy: jest.SpyInstance;

  beforeEach(() => {
    const logger = createLogger("test", { level: "warn" });
    loggerSpy = jest.spyOn(logger, "warn").mockImplementation();
  });

  it("should warn for DocumentationAssessor", () => {
    new DocumentationAssessor(defaultConfig);

    expect(loggerSpy).toHaveBeenCalledWith(
      expect.stringContaining("DocumentationAssessor"),
      expect.objectContaining({
        replacement: "DeveloperExperienceAssessor",
      }),
    );
  });

  it("should not warn for DeveloperExperienceAssessor", () => {
    loggerSpy.mockClear();
    new DeveloperExperienceAssessor(defaultConfig);

    expect(loggerSpy).not.toHaveBeenCalledWith(
      expect.stringContaining("is deprecated"),
    );
  });
});
```

### Example 3: Testing Method Migration

```typescript
class TestAssessor extends BaseAssessor {
  public callLog(msg: string) {
    this.log(msg);
  }

  async assess() {
    return {};
  }
}

describe("Method Deprecation Warnings", () => {
  let loggerSpy: jest.SpyInstance;

  beforeEach(() => {
    const logger = createLogger("test", { level: "warn" });
    loggerSpy = jest.spyOn(logger, "warn").mockImplementation();
  });

  it("should warn on first log() call", () => {
    const assessor = new TestAssessor(defaultConfig);
    assessor.callLog("Test message");

    expect(loggerSpy).toHaveBeenCalledWith(
      expect.stringContaining("log() is deprecated"),
    );
  });

  it("should not warn on second log() call", () => {
    const assessor = new TestAssessor(defaultConfig);
    assessor.callLog("First call");
    loggerSpy.mockClear();
    assessor.callLog("Second call");

    expect(loggerSpy).not.toHaveBeenCalled();
  });
});
```

---

## Migration Checklist

Use this checklist to track your migration progress:

### Configuration Files

- [ ] Replace `mcpSpecCompliance: true` with `protocolCompliance: true`
- [ ] Replace `protocolConformance: true` with `protocolCompliance: true`
- [ ] Test with new config
- [ ] Verify functionality unchanged

### Direct Module Usage

- [ ] Replace `import DocumentationAssessor` with `DeveloperExperienceAssessor`
- [ ] Replace `import UsabilityAssessor` with `DeveloperExperienceAssessor`
- [ ] Replace `import MCPSpecComplianceAssessor` with `ProtocolComplianceAssessor`
- [ ] Replace `import ProtocolConformanceAssessor` with `ProtocolComplianceAssessor`
- [ ] Update instantiations
- [ ] Test with new modules

### Custom Assessor Code

- [ ] Find all `this.log(` calls
- [ ] Replace with `this.logger.info(` + structured context
- [ ] Find all `this.logError(` calls
- [ ] Replace with `this.logger.error(` + structured context
- [ ] OR use `this.handleError()` for comprehensive error handling
- [ ] Add context metadata to all logging calls
- [ ] Test logging output

### Testing

- [ ] Run full test suite
- [ ] Verify no deprecation warnings in test output
- [ ] Check functionality unchanged
- [ ] Update test expectations if needed

### Documentation

- [ ] Update README with new APIs
- [ ] Update code comments
- [ ] Update example code snippets
- [ ] Update internal documentation
