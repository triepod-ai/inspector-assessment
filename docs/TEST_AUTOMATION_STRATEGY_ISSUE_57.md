# Test Automation Strategy: Issue #57 Architecture Detection & Behavior Inference

## Executive Summary

This document outlines the comprehensive test automation strategy for Issue #57 modules: DescriptionAnalyzer, SchemaAnalyzer, ArchitectureDetector, and inferBehaviorEnhanced. These modules provide multi-signal behavior inference for MCP tool assessment.

**Status**: 119/119 unit tests passing. Integration and E2E test suite expansion proposed.

**Test Coverage Goals**:

- Unit Tests: ✅ 100% coverage (119 tests)
- Integration Tests: 🎯 Target 30+ tests (cross-module scenarios)
- E2E Tests: 🎯 Target 15+ tests (real server assessment)
- CI/CD: 🎯 Automated testbed validation

---

## Table of Contents

1. [Current Test Coverage](#current-test-coverage)
2. [Test Architecture](#test-architecture)
3. [Integration Test Strategy](#integration-test-strategy)
4. [End-to-End Test Strategy](#end-to-end-test-strategy)
5. [Test Data Fixtures](#test-data-fixtures)
6. [CI/CD Integration](#cicd-integration)
7. [Performance Testing](#performance-testing)
8. [Implementation Roadmap](#implementation-roadmap)

---

## Current Test Coverage

### Unit Tests (119 Total - All Passing)

#### DescriptionAnalyzer.test.ts (41 tests)

- ✅ Read-only detection (5 tests)
- ✅ Destructive detection (6 tests)
- ✅ Write detection (4 tests)
- ✅ Negation handling (4 tests)
- ✅ Edge cases (5 tests)
- ✅ Atlas-mcp-server examples (3 tests)
- ✅ Helper functions (14 tests)

#### SchemaAnalyzer.test.ts (46 tests)

- ✅ Input schema analysis (18 tests)
  - Read-only detection (5 tests)
  - Destructive detection (4 tests)
  - Write detection (4 tests)
  - Edge cases (4 tests)
- ✅ Output schema analysis (11 tests)
  - Read-only detection (2 tests)
  - Destructive detection (4 tests)
  - Write detection (2 tests)
  - Edge cases (2 tests)
- ✅ Helper functions (17 tests)

#### ArchitectureDetector.test.ts (32 tests)

- ✅ Database detection (6 tests)
- ✅ Transport detection (6 tests)
- ✅ Server type classification (7 tests)
- ✅ Network access detection (4 tests)
- ✅ External service detection (4 tests)
- ✅ Confidence calculation (3 tests)
- ✅ Helper functions (2 tests)

### Integration Points Identified

1. **ToolAnnotationAssessor** - Orchestrates all four modules
2. **BehaviorInference** - `inferBehaviorEnhanced()` aggregates signals
3. **TestbedConfig** - Real server validation infrastructure
4. **AssessmentContext** - Cross-module data flow

---

## Test Architecture

### Test Pyramid Distribution

```
                    /\
                   /E2\      E2E Tests (15)
                  /----\     Real MCP servers
                 /      \
                /________\   Integration Tests (30)
               /          \  Cross-module scenarios
              /____________\
             /              \ Unit Tests (119)
            /________________\ Module-level isolation
```

### Test Types

#### 1. Unit Tests (Existing)

- **Scope**: Single module, isolated
- **Speed**: <2s for all 119 tests
- **Coverage**: 100% of module logic
- **Pattern**: Pure function testing with mocks

#### 2. Integration Tests (Proposed)

- **Scope**: Cross-module interaction
- **Speed**: 3-5s per test
- **Coverage**: Signal aggregation, ToolAnnotationAssessor
- **Pattern**: Multi-module workflows with test fixtures

#### 3. E2E Tests (Proposed)

- **Scope**: Real MCP server assessment
- **Speed**: 10-30s per test
- **Coverage**: Full assessment pipeline
- **Pattern**: Live server interaction via HTTP/STDIO

---

## Integration Test Strategy

### Test Suite 1: Signal Aggregation Tests

**File**: `client/src/services/assessment/__tests__/BehaviorInference-Integration.test.ts`

**Coverage**: 12 tests

```typescript
describe("inferBehaviorEnhanced - Signal Aggregation", () => {
  // Test 1: All signals agree (high confidence)
  it("should aggregate to high confidence when all signals agree on read-only");
  it(
    "should aggregate to high confidence when all signals agree on destructive",
  );

  // Test 2: Conflicting signals (medium confidence)
  it(
    "should downgrade confidence when name suggests write but description suggests read-only",
  );
  it("should handle name=destructive + schema=read-only conflict");

  // Test 3: Partial signals (varied confidence)
  it("should infer from name+description when schema is missing");
  it("should prioritize schema over description when both present");

  // Test 4: Signal priority rules
  it("should prioritize destructive signals over read-only");
  it("should boost confidence when multiple signals agree");

  // Test 5: Edge cases
  it("should handle tools with no clear signals");
  it("should detect force flags in schema overriding safe description");
  it("should handle pagination parameters correctly");
  it("should respect run + analysis suffix exemption");
});
```

**Test Data**:

- 20 synthetic tool definitions covering all signal combinations
- Expected outputs with confidence scores and reasoning

### Test Suite 2: ToolAnnotationAssessor Integration Tests

**File**: `client/src/services/assessment/__tests__/ToolAnnotationAssessor-Integration.test.ts`

**Coverage**: 10 tests

```typescript
describe("ToolAnnotationAssessor - Multi-Signal Assessment", () => {
  // Test 1: Architecture context flow
  it("should pass architecture context to ArchitectureDetector");
  it("should detect Neo4j from tool descriptions and dependencies");

  // Test 2: Behavior inference metrics
  it("should track namePatternMatches, descriptionMatches, schemaMatches");
  it("should calculate aggregatedConfidenceAvg correctly");

  // Test 3: Annotation deception detection
  it("should flag readOnlyHint=true for tools with 'delete' in name");
  it("should flag destructiveHint=false for tools with 'remove' in name");

  // Test 4: Description poisoning integration
  it("should emit annotation_poisoned events for suspicious patterns");
  it("should increment poisonedDescriptionsDetected counter");

  // Test 5: Extended metadata extraction
  it("should extract rate limits, permissions, return schemas");
  it("should count tools with bulk operation support");
});
```

**Test Data**:

- Mock AssessmentContext with 10-15 tools
- Mixed tool types: database ops, API calls, file ops
- Package.json with Neo4j, PostgreSQL, MongoDB dependencies

### Test Suite 3: Architecture Detection Cross-Validation

**File**: `client/src/services/assessment/__tests__/ArchitectureDetection-CrossValidation.test.ts`

**Coverage**: 8 tests

```typescript
describe("Architecture Detection - Cross-Validation", () => {
  // Test 1: Multi-source validation
  it("should detect database from tool descriptions AND package.json");
  it("should detect transport from sourceCodeFiles AND connection context");

  // Test 2: Confidence calculation
  it("should assign high confidence with 3+ evidence sources");
  it("should assign medium confidence with 2 evidence sources");
  it("should assign low confidence with 1 evidence source");

  // Test 3: Server type inference
  it("should classify as hybrid when stdio + network access detected");
  it("should classify as remote when 3+ external dependencies");

  // Test 4: Evidence aggregation
  it("should aggregate evidence from all detection methods");
});
```

---

## End-to-End Test Strategy

### Test Suite 4: Real MCP Server Assessment

**File**: `client/src/services/assessment/__tests__/Issue57-E2E.integration.test.ts`

**Coverage**: 15 tests

**Testbed Servers**:

1. **vulnerable-mcp** (port 10900) - 10 vulnerable + 6 safe tools
2. **hardened-mcp** (port 10901) - Same tool names, safe implementations
3. **atlas-style-mock** (mock) - Neo4j graph database operations

```typescript
describe("Issue #57 E2E - Real MCP Server Assessment", () => {
  beforeAll(async () => {
    testbedHealth = await checkTestbedHealth();
  });

  describe("Vulnerable-MCP Architecture Detection", () => {
    it("should detect SQLite database backend");
    it("should detect HTTP transport mode");
    it("should classify as local server type");
    it("should detect no external dependencies");
  });

  describe("Vulnerable-MCP Behavior Inference", () => {
    it("should detect vulnerable_calculator_tool as destructive");
    it("should detect vulnerable_system_exec_tool as destructive");
    it("should detect safe_storage_tool_mcp as write (not destructive)");
    it("should detect safe_search_tool_mcp as read-only");

    it("should aggregate namePatternMatches for 10+ vulnerable tools");
    it("should use schema signals for force flag detection");
  });

  describe("Hardened-MCP Validation", () => {
    it("should detect 0 vulnerabilities (same tool names, safe impl)");
    it("should detect readOnlyHint annotations correctly");
    it("should detect destructiveHint annotations correctly");
  });

  describe("Multi-Signal Confidence Validation", () => {
    it("should achieve 90+ aggregatedConfidenceAvg for vulnerable tools");
    it("should show high confidence when all 3 signals agree");
    it("should show medium confidence when signals conflict");
  });
});
```

**Success Criteria**:

- ✅ 100% detection of vulnerable tools (10/10)
- ✅ 0% false positives on safe tools (0/6)
- ✅ Correct architecture detection (SQLite, HTTP, local)
- ✅ Behavior inference metrics: namePatternMatches ≥ 10, descriptionMatches ≥ 5

### Test Suite 5: Atlas-Style Graph Database Assessment

**File**: `client/src/services/assessment/__tests__/Issue57-Atlas-E2E.test.ts`

**Coverage**: 5 tests (mock-based, no live server required)

```typescript
describe("Issue #57 - Atlas Graph Database Pattern", () => {
  it("should detect Neo4j from 'Cypher query' in descriptions");
  it("should detect graph operations from tool names");
  it("should classify atlas_project_create as write (not destructive)");
  it("should classify atlas_project_list as read-only");
  it("should classify atlas_database_clean as destructive");
});
```

---

## Test Data Fixtures

### Fixture 1: Multi-Signal Tool Definitions

**File**: `client/src/services/assessment/__tests__/fixtures/multiSignalTools.ts`

**Content**: 25 tool definitions covering all signal combinations

```typescript
export const MULTI_SIGNAL_FIXTURES = {
  // High confidence scenarios (all signals agree)
  readOnlyAllSignals: {
    name: "atlas_project_list",
    description: "Lists all projects in the Neo4j graph database",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number" },
        offset: { type: "number" },
      },
    },
    outputSchema: {
      type: "array",
      items: { type: "object" },
    },
    expected: {
      readOnly: true,
      destructive: false,
      confidence: 95,
      signals: {
        name: "high",
        description: "high",
        inputSchema: "high",
        outputSchema: "high",
      },
    },
  },

  // Conflicting signals (name vs description)
  conflictingSignals: {
    name: "run_database_cleanup",
    description: "Retrieves list of database cleanup recommendations",
    inputSchema: { type: "object", properties: {} },
    expected: {
      readOnly: true, // run + analysis suffix exempt
      confidence: 70, // conflict reduces confidence
      isAmbiguous: true,
    },
  },

  // ... 23 more fixtures
};
```

### Fixture 2: Architecture Context Scenarios

**File**: `client/src/services/assessment/__tests__/fixtures/architectureScenarios.ts`

**Content**: 10 complete architecture contexts

```typescript
export const ARCHITECTURE_SCENARIOS = {
  neo4jGraphServer: {
    tools: [
      { name: "atlas_query", description: "Query Neo4j with Cypher" },
      { name: "atlas_create_node", description: "Create node in Neo4j" },
    ],
    sourceCodeFiles: new Map([
      ["index.ts", "import neo4j from 'neo4j-driver';"],
    ]),
    packageJson: {
      dependencies: {
        "neo4j-driver": "^5.0.0",
      },
    },
    expected: {
      databaseBackends: ["neo4j"],
      transportModes: ["stdio"],
      serverType: "local",
      confidence: "high",
    },
  },

  // ... 9 more scenarios
};
```

### Fixture 3: Testbed Assessment Snapshots

**File**: `client/src/services/assessment/__tests__/fixtures/testbedSnapshots.json`

**Content**: Pre-recorded assessment results for regression testing

```json
{
  "vulnerable-mcp-snapshot": {
    "timestamp": "2026-01-08T00:00:00Z",
    "toolCount": 17,
    "architectureAnalysis": {
      "databaseBackends": ["sqlite"],
      "transportModes": ["http"],
      "serverType": "local"
    },
    "behaviorInferenceMetrics": {
      "namePatternMatches": 14,
      "descriptionMatches": 8,
      "aggregatedConfidenceAvg": 82
    },
    "vulnerabilities": 10,
    "safeTools": 6
  }
}
```

---

## CI/CD Integration

### GitHub Actions Workflow

**File**: `.github/workflows/test-issue-57.yml`

```yaml
name: Issue #57 Test Suite

on:
  pull_request:
    paths:
      - "client/src/services/assessment/modules/annotations/**"
      - "client/src/services/assessment/__tests__/**"
  push:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: "18"

      - name: Install dependencies
        run: npm ci

      - name: Run Unit Tests
        run: |
          cd client
          npx jest --testPathPattern="DescriptionAnalyzer|SchemaAnalyzer|ArchitectureDetector|BehaviorInference" --coverage

      - name: Upload Coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./client/coverage/lcov.info

  integration-tests:
    runs-on: ubuntu-latest
    services:
      vulnerable-mcp:
        image: ghcr.io/triepod-ai/vulnerable-mcp:latest
        ports:
          - 10900:10900
      hardened-mcp:
        image: ghcr.io/triepod-ai/hardened-mcp:latest
        ports:
          - 10901:10901

    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3

      - name: Wait for testbed
        run: |
          timeout 60 bash -c 'until curl -f http://localhost:10900/mcp; do sleep 2; done'
          timeout 60 bash -c 'until curl -f http://localhost:10901/mcp; do sleep 2; done'

      - name: Run Integration Tests
        run: |
          cd client
          npx jest --testPathPattern="Integration|E2E" --runInBand

      - name: Validate Metrics
        run: |
          # Parse results and verify:
          # - vulnerable-mcp: 10 vulnerabilities detected
          # - hardened-mcp: 0 vulnerabilities detected
          # - 0 false positives on safe tools
          node scripts/validate-issue-57-metrics.js
```

### Pre-Commit Hook

**File**: `.husky/pre-commit`

```bash
#!/bin/sh

# Run quick unit tests for Issue #57 modules
echo "Running Issue #57 unit tests..."
cd client && npx jest --testPathPattern="DescriptionAnalyzer|SchemaAnalyzer|ArchitectureDetector" --bail --silent

if [ $? -ne 0 ]; then
  echo "❌ Issue #57 unit tests failed. Fix errors before committing."
  exit 1
fi

echo "✅ Issue #57 tests passed"
```

---

## Performance Testing

### Benchmark Suite

**File**: `client/src/services/assessment/__tests__/Issue57-Performance.test.ts`

```typescript
describe("Issue #57 Performance Benchmarks", () => {
  it("should analyze 100 tool descriptions in <100ms", async () => {
    const start = performance.now();

    for (let i = 0; i < 100; i++) {
      analyzeDescription(`Tool ${i} retrieves data from database`);
    }

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(100);
  });

  it("should analyze 100 input schemas in <200ms", async () => {
    const schema = { type: "object", properties: { id: { type: "string" } } };
    const start = performance.now();

    for (let i = 0; i < 100; i++) {
      analyzeInputSchema(schema);
    }

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(200);
  });

  it("should run inferBehaviorEnhanced on 50 tools in <500ms", async () => {
    const start = performance.now();

    for (let i = 0; i < 50; i++) {
      inferBehaviorEnhanced(
        `tool_${i}`,
        "A test tool",
        { type: "object", properties: {} },
        { type: "object", properties: {} },
      );
    }

    const duration = performance.now() - start;
    expect(duration).toBeLessThan(500);
  });

  it("should assess full server (17 tools) in <2s", async () => {
    // Load testbed snapshot
    const context = createContextFromSnapshot(VULNERABLE_MCP_SNAPSHOT);

    const start = performance.now();
    const assessor = new ToolAnnotationAssessor(config);
    await assessor.assess(context);
    const duration = performance.now() - start;

    expect(duration).toBeLessThan(2000);
  });
});
```

**Performance Targets**:

- Single tool analysis: <5ms
- 100 tools batch: <500ms
- Full server assessment (17 tools): <2s
- No memory leaks over 1000 iterations

---

## Implementation Roadmap

### Phase 1: Integration Tests (Week 1)

- [ ] Create `BehaviorInference-Integration.test.ts` (12 tests)
- [ ] Create `ToolAnnotationAssessor-Integration.test.ts` (10 tests)
- [ ] Create `ArchitectureDetection-CrossValidation.test.ts` (8 tests)
- [ ] Create test fixtures (multiSignalTools, architectureScenarios)
- [ ] Verify 30/30 integration tests pass

### Phase 2: E2E Tests (Week 2)

- [ ] Create `Issue57-E2E.integration.test.ts` (15 tests)
- [ ] Create `Issue57-Atlas-E2E.test.ts` (5 tests)
- [ ] Set up testbed health checks
- [ ] Create testbed snapshots for regression
- [ ] Verify 20/20 E2E tests pass

### Phase 3: CI/CD Integration (Week 3)

- [ ] Create `.github/workflows/test-issue-57.yml`
- [ ] Set up pre-commit hooks
- [ ] Configure test matrix (Node 18, 20, 22)
- [ ] Add coverage reporting
- [ ] Set up testbed Docker containers in CI

### Phase 4: Performance & Documentation (Week 4)

- [ ] Create `Issue57-Performance.test.ts` benchmarks
- [ ] Document test data generation process
- [ ] Create troubleshooting guide
- [ ] Add metrics validation script
- [ ] Final integration with main test suite

---

## Testing Best Practices

### 1. Test Isolation

- Use `jest.clearAllMocks()` between tests
- No shared mutable state between tests
- Each test creates its own context

### 2. Test Naming Convention

```typescript
it("should [expected behavior] when [condition]", () => {
  // Arrange: Set up test data
  // Act: Execute code under test
  // Assert: Verify expectations
});
```

### 3. Test Data Management

- Use fixtures for complex test data
- Generate synthetic data for edge cases
- Capture real server responses for regression

### 4. Integration Test Pattern

```typescript
describe("Module Integration", () => {
  beforeAll(async () => {
    // Check prerequisites (servers running, etc.)
  });

  it("should work in realistic scenario", async () => {
    // Use createMockAssessmentContext for consistency
    // Test cross-module data flow
    // Verify end-to-end behavior
  });
});
```

### 5. E2E Test Pattern

```typescript
const describeE2E =
  process.env.SKIP_INTEGRATION_TESTS === "true" ? describe.skip : describe;

describeE2E("E2E Scenario", () => {
  beforeAll(async () => {
    testbedHealth = await checkTestbedHealth();
    if (!testbedHealth.vulnerable) {
      console.warn("Testbed not running");
    }
  });

  it("should assess real server", async () => {
    if (!testbedHealth.vulnerable) return; // Skip gracefully
    // Test against real server
  });
});
```

---

## Metrics & Acceptance Criteria

### Unit Test Metrics

- ✅ 119/119 tests passing
- ✅ 100% branch coverage
- ✅ <2s execution time

### Integration Test Metrics (Target)

- 🎯 30 integration tests
- 🎯 90%+ branch coverage of cross-module flows
- 🎯 <10s execution time

### E2E Test Metrics (Target)

- 🎯 15 E2E tests
- 🎯 100% detection of known vulnerabilities (10/10)
- 🎯 0% false positive rate (0/6 safe tools)
- 🎯 <30s execution time per test

### CI/CD Metrics (Target)

- 🎯 All tests run on every PR
- 🎯 Testbed containers start in <60s
- 🎯 Full suite completes in <5min
- 🎯 Coverage reports published automatically

---

## Troubleshooting Guide

### Issue: Integration tests fail with "testbed not running"

**Solution**:

```bash
cd /home/bryan/mcp-servers/mcp-vulnerable-testbed
docker-compose up -d
# Wait 30 seconds for startup
curl http://localhost:10900/mcp
curl http://localhost:10901/mcp
```

### Issue: Tests timeout on CI

**Solution**:

- Increase `testTimeout` in jest config to 30000ms
- Add retry logic for flaky network tests
- Use `jest.retryTimes(2)` for E2E tests

### Issue: Snapshot mismatches after code changes

**Solution**:

```bash
# Review changes first
npm test -- -u  # Update snapshots
# Commit updated snapshots
```

### Issue: Memory leaks in performance tests

**Solution**:

```typescript
afterEach(() => {
  jest.clearAllMocks();
  // Force garbage collection in Node
  if (global.gc) global.gc();
});
```

---

## References

- [Jest Documentation](https://jestjs.io/)
- [Testing Library Best Practices](https://testing-library.com/docs/guiding-principles)
- [MCP Inspector Testing Guide](../docs/README.md)
- [Testbed Setup Guide](../docs/TESTBED_SETUP_GUIDE.md)
- [Issue #57 Implementation](https://github.com/triepod-ai/inspector-assessment/issues/57)

---

**Last Updated**: 2026-01-08
**Status**: Implementation Ready
**Author**: Test Automator Agent
**Review Status**: Pending
