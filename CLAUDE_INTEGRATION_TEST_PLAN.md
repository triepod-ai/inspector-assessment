# Claude Code Integration Test Plan

## Overview

This plan covers testing the Claude Code integration features added to inspector-assessment. The integration enables semantic analysis via `claude --print` shell execution for:

1. Intelligent test parameter generation
2. AUP semantic violation analysis
3. Tool behavior inference for annotation validation
4. Documentation quality assessment

## Files Requiring Testing

### Core Integration

| File                           | Type          | Tests Needed                            |
| ------------------------------ | ------------- | --------------------------------------- |
| `lib/claudeCodeBridge.ts`      | Core Bridge   | Unit tests (created), Integration tests |
| `lib/claudeCodeBridge.test.ts` | Unit Tests    | Run and verify passing                  |
| `AssessmentOrchestrator.ts`    | Orchestration | Integration with Claude bridge          |

### Enhanced Assessors

| File                        | Feature            | Tests Needed                   |
| --------------------------- | ------------------ | ------------------------------ |
| `TestDataGenerator.ts`      | Claude test params | Async generation tests         |
| `AUPComplianceAssessor.ts`  | Semantic analysis  | False positive filtering tests |
| `ToolAnnotationAssessor.ts` | Behavior inference | Misalignment detection tests   |

---

## Phase 1: Unit Test Verification

### 1.1 Run Existing Unit Tests

```bash
cd ~/inspector-assessment
npm test -- --filter claudeCodeBridge
```

**Expected:** All tests in `claudeCodeBridge.test.ts` pass

### 1.2 Fix Any Test Issues

The unit tests mock `child_process.execSync` and `fs` modules. Verify:

- Mock setup is correct for vitest
- All edge cases covered
- Error handling paths tested

---

## Phase 2: TestDataGenerator Integration Tests

### 2.1 Create Test File

Create `TestDataGenerator.test.ts` with:

```typescript
describe("TestDataGenerator with Claude", () => {
  describe("generateTestScenariosAsync", () => {
    it("should generate Claude-enhanced params when bridge available");
    it("should fallback to schema-based when Claude unavailable");
    it("should handle Claude timeout gracefully");
    it(
      "should mark scenarios with correct source (claude-generated vs schema-based)",
    );
  });
});
```

### 2.2 Test Cases

| Test               | Input                    | Expected Output                                      |
| ------------------ | ------------------------ | ---------------------------------------------------- |
| Claude success     | Tool with complex schema | 5 test scenarios with `source: "claude-generated"`   |
| Claude unavailable | Bridge not set           | Schema-based scenarios with `source: "schema-based"` |
| Claude timeout     | Slow response            | Fallback to schema-based                             |
| Mixed results      | Partial Claude response  | Best-effort merge                                    |

---

## Phase 3: AUPComplianceAssessor Integration Tests

### 3.1 Create/Enhance Test File

Enhance `AUPComplianceAssessor.test.ts` with:

```typescript
describe("AUPComplianceAssessor with Claude", () => {
  describe("semantic analysis", () => {
    it("should filter false positives for security tools");
    it("should filter false positives for medical disclaimers");
    it("should confirm true violations with high confidence");
    it("should separate confirmed violations from flagged-for-review");
    it("should fallback to pattern-only when Claude unavailable");
  });
});
```

### 3.2 Test Scenarios

| Scenario                       | Input                                                  | Expected                                       |
| ------------------------------ | ------------------------------------------------------ | ---------------------------------------------- |
| Security tool (false positive) | Tool: "vulnerability_scanner", Flag: "exploit"         | `isConfirmedViolation: false`                  |
| Medical disclaimer             | Description mentions "diagnosis" in disclaimer context | `isConfirmedViolation: false`                  |
| Actual violation               | Tool for "generating malware"                          | `isConfirmedViolation: true, confidence >= 80` |
| Educational content            | "This shows what NOT to do"                            | `isConfirmedViolation: false`                  |

### 3.3 Create Test Fixtures

```typescript
const FALSE_POSITIVE_FIXTURES = [
  {
    name: "security_scanner",
    description: "Scans systems for vulnerabilities to help secure them",
    flaggedPattern: "exploit",
    expectedViolation: false,
    reason: "Legitimate defensive security tool",
  },
  {
    name: "medical_info",
    description: "Provides general health information. Not medical advice.",
    flaggedPattern: "diagnosis",
    expectedViolation: false,
    reason: "Appropriate disclaimer present",
  },
];

const TRUE_VIOLATION_FIXTURES = [
  {
    name: "data_harvester",
    description: "Scrapes personal data without consent",
    flaggedPattern: "personal data without consent",
    expectedViolation: true,
    expectedSeverity: "CRITICAL",
  },
];
```

---

## Phase 4: ToolAnnotationAssessor Integration Tests

### 4.1 Create/Enhance Test File

Enhance `ToolAnnotationAssessor.test.ts` with:

```typescript
describe("ToolAnnotationAssessor with Claude", () => {
  describe("behavior inference", () => {
    it("should infer read-only for get/list/fetch tools");
    it("should infer destructive for delete/remove tools");
    it("should detect misalignment when read-only marked destructive");
    it("should suggest correct annotations with reasoning");
    it("should include idempotentHint suggestions");
  });
});
```

### 4.2 Test Scenarios

| Tool Name       | Current Annotations      | Expected Inference      | Misalignment? |
| --------------- | ------------------------ | ----------------------- | ------------- |
| `get_user`      | `readOnlyHint: true`     | Read-only               | No            |
| `delete_file`   | `readOnlyHint: true`     | Destructive             | Yes           |
| `update_record` | None                     | Write (not destructive) | No            |
| `purge_cache`   | `destructiveHint: false` | Potentially destructive | Yes           |

---

## Phase 5: AssessmentOrchestrator Integration Tests

### 5.1 Create/Enhance Test File

Enhance `AssessmentOrchestrator.test.ts` with:

```typescript
describe("AssessmentOrchestrator with Claude", () => {
  describe("Claude bridge initialization", () => {
    it("should initialize bridge when config.claudeCode.enabled");
    it("should not initialize bridge when disabled");
    it("should wire bridge to AUPComplianceAssessor");
    it("should wire bridge to ToolAnnotationAssessor");
    it("should wire bridge to TestDataGenerator");
  });

  describe("enableClaudeCode()", () => {
    it("should enable Claude after construction");
    it("should use FULL_CLAUDE_CODE_CONFIG defaults");
    it("should allow partial config override");
  });

  describe("runFullAssessment with Claude", () => {
    it("should produce enhanced results when Claude enabled");
    it("should produce standard results when Claude disabled");
    it("should handle Claude failures gracefully");
  });
});
```

---

## Phase 6: End-to-End Integration Tests

### 6.1 Real MCP Server Test

Test against a real MCP server with known characteristics:

```bash
# Start test server
cd ~/mcp-servers/test-server
npm start

# Run assessment with Claude
cd ~/inspector-assessment
npm run assess -- --server test-server --claude-enabled
```

### 6.2 Validation Checklist

- [ ] Assessment completes without errors
- [ ] Claude-enhanced results show `claudeEnhanced: true`
- [ ] AUP findings separated into violations vs flagged-for-review
- [ ] Tool annotations show high-confidence misalignments
- [ ] Test scenarios marked with correct source
- [ ] JSON output matches expected schema
- [ ] Report includes Claude analysis sections

### 6.3 Performance Benchmarks

| Metric       | Without Claude | With Claude | Acceptable |
| ------------ | -------------- | ----------- | ---------- |
| Total time   | ~30s           | ~120s       | < 180s     |
| Memory usage | ~100MB         | ~150MB      | < 300MB    |
| API calls    | 0              | ~20 (shell) | < 50       |

---

## Phase 7: CLI Flag Testing

### 7.1 Test `--claude-enabled` Flag

```bash
# With flag
npx @anthropic/inspector --config config.json --server my-server --claude-enabled

# Without flag (default)
npx @anthropic/inspector --config config.json --server my-server

# Verify in logs
# Expected: "[AssessmentOrchestrator] Claude Code Bridge initialized..."
```

### 7.2 Test Cases

| Command                     | Expected                 |
| --------------------------- | ------------------------ |
| `--claude-enabled`          | Claude features active   |
| No flag                     | Claude features disabled |
| `--claude-enabled` + no CLI | Graceful degradation     |

---

## Phase 8: Error Handling Tests

### 8.1 Claude Unavailable Scenarios

| Scenario                 | Expected Behavior                  |
| ------------------------ | ---------------------------------- |
| Claude CLI not installed | Warning logged, fallback to static |
| Claude times out         | Retry once, then fallback          |
| Invalid JSON response    | Log error, use pattern-based       |
| Partial response         | Extract what's valid               |

### 8.2 Test Commands

```bash
# Simulate Claude unavailable
PATH=/usr/bin npm run assess -- --server test --claude-enabled
# Expected: Warning + fallback

# Simulate timeout (set very short timeout)
# In config: claudeCode.timeout: 1
# Expected: Timeout error + retry + fallback
```

---

## Implementation Order

1. **Phase 1**: Run existing unit tests, fix any issues
2. **Phase 2**: TestDataGenerator async tests
3. **Phase 3**: AUPComplianceAssessor semantic analysis tests
4. **Phase 4**: ToolAnnotationAssessor inference tests
5. **Phase 5**: AssessmentOrchestrator integration tests
6. **Phase 6**: End-to-end real server tests
7. **Phase 7**: CLI flag verification
8. **Phase 8**: Error handling edge cases

---

## Test Data Requirements

### Mock MCP Server

Create a test MCP server with known tools:

```javascript
// test-mcp-server/tools.js
const tools = [
  { name: "get_data", readOnlyHint: true }, // Correct annotation
  { name: "delete_item", readOnlyHint: true }, // Incorrect (misalignment)
  { name: "security_scan" }, // No annotations (AUP false positive)
  { name: "create_report" }, // No annotations
];
```

### AUP Test Patterns

Create fixtures with known false positives and true violations for regression testing.

---

## Success Criteria

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] False positive rate reduced by 50%+ (measure with test fixtures)
- [ ] Claude-generated tests catch issues schema-based missed
- [ ] Annotation misalignments detected with >70% confidence
- [ ] Graceful degradation when Claude unavailable
- [ ] CLI flag works correctly
- [ ] Documentation updated

---

## Notes

- Tests should be runnable without Claude CLI (mocked)
- Integration tests with real Claude require CLI installed
- Consider CI/CD implications (Claude CLI availability)
- May need test fixtures for consistent Claude responses
