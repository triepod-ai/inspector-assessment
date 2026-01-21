# Assessment Test Suite

> **102 test files** organized by concern for selective execution.
>
> @since v1.43.0 (Issue #200 - V2 Refactoring)

## Quick Test Commands

```bash
# Run all assessment tests
npm test -- --testPathPattern="assessment"

# Run by category (see categories below)
npm test -- --testPathPattern="Security"        # Security tests
npm test -- --testPathPattern="FalsePositive"   # False positive prevention
npm test -- --testPathPattern="Protocol|Error"  # Protocol/Error handling
npm test -- --testPathPattern="Temporal"        # Temporal mutation tests
npm test -- --testPathPattern="TestData|TestScenario"  # Test infrastructure
```

---

## Test Categories

### Security Tests (26 files)

Core security detection and attack pattern testing.

| Pattern             | Files | Description                  |
| ------------------- | ----- | ---------------------------- |
| `SecurityAssessor-` | 12    | Main security assessor tests |
| `SecurityPayload`   | 3     | Payload generation/testing   |
| `SecurityPattern`   | 3     | Pattern library tests        |
| `SecurityResponse`  | 1     | Response analysis            |
| `Chain\|CrossTool`  | 2     | Multi-tool attack chains     |
| `Injection`         | 4     | Injection attack tests       |
| `Crypto`            | 1     | Cryptographic failure tests  |

**Run all security tests:**

```bash
npm test -- --testPathPattern="Security|Chain|CrossTool|Injection|Crypto|AuthBypass"
```

**File list:**

- `SecurityAssessor-APIWrapperFalsePositives.test.ts`
- `SecurityAssessor-AuthBypass.test.ts`
- `SecurityAssessor-BlacklistBypass.test.ts`
- `SecurityAssessor-ClaudeBridge.test.ts`
- `SecurityAssessor-ErrorReflection-Issue146.test.ts`
- `SecurityAssessor-ExcessivePermissions.test.ts`
- `SecurityAssessor-HTTP404FalsePositives.test.ts`
- `SecurityAssessor-OutputInjection.test.ts`
- `SecurityAssessor-ReflectionFalsePositives.test.ts`
- `SecurityAssessor-ValidationFalsePositives.test.ts`
- `SecurityAssessor-VulnerableTestbed.integration.test.ts`
- `SecurityPatternLibrary.test.ts`
- `SecurityPatternLibrary-Comprehensive-Issue146.test.ts`
- `SecurityPatterns-Issue103.test.ts`
- `SecurityPayloadGenerator-Auth.test.ts`
- `SecurityPayloadGenerator-AuthFailure.test.ts`
- `SecurityPayloadTester-Retry.test.ts`
- `SecurityResponseAnalyzer.test.ts`
- `ChainExploitation.test.ts`
- `CrossToolStateBypass.test.ts`
- `CrossCapabilitySecurityAssessor.test.ts`
- `CryptographicFailures.test.ts`
- `OutputInjectionAnalyzer.test.ts`
- `AppleScriptInjection-Issue174.test.ts`
- `AppleScriptInjection-FalseNegative-Issue177.test.ts`
- `AuthBypass-Testbed.test.ts`

---

### False Positive Prevention Tests (7 files)

Tests ensuring detection accuracy and reducing false positives.

**Run all false positive tests:**

```bash
npm test -- --testPathPattern="FalsePositive|AlignmentChecker|XXE"
```

**File list:**

- `SecurityAssessor-APIWrapperFalsePositives.test.ts`
- `SecurityAssessor-HTTP404FalsePositives.test.ts`
- `SecurityAssessor-ReflectionFalsePositives.test.ts`
- `SecurityAssessor-ValidationFalsePositives.test.ts`
- `XXEFalsePositive-AppleScript.test.ts`
- `AlignmentChecker-Issue150.test.ts`
- `AlignmentChecker-Issue155.test.ts`

---

### Protocol & Error Handling Tests (7 files)

Protocol compliance and error handling assessment.

**Run all protocol tests:**

```bash
npm test -- --testPathPattern="Protocol|ErrorHandling|Conformance|ErrorClassifier"
```

**File list:**

- `ProtocolConformanceAssessor.test.ts`
- `ProtocolConformance-CLI.integration.test.ts`
- `ConformanceAssessor.test.ts`
- `ErrorHandlingAssessor.test.ts`
- `ErrorHandlingAssessor-GracefulDegradation.test.ts`
- `ErrorHandlingAssessor-InvalidValues.test.ts`
- `ErrorClassifier.test.ts`

---

### Temporal Mutation Tests (7 files)

Tool definition mutation and temporal behavior tests.

**Run all temporal tests:**

```bash
npm test -- --testPathPattern="Temporal"
```

**File list:**

- `TemporalAssessor.test.ts`
- `TemporalAssessor-DefinitionMutation.test.ts`
- `TemporalAssessor-ExternalAPI.test.ts`
- `TemporalAssessor-ResponseNormalization.test.ts`
- `TemporalAssessor-SecondaryContent.test.ts`
- `TemporalAssessor-StatefulTools.test.ts`
- `TemporalAssessor-VarianceClassification.test.ts`

---

### Test Infrastructure Tests (13 files)

Test data generation and scenario engine tests.

**Run all infrastructure tests:**

```bash
npm test -- --testPathPattern="TestDataGenerator|TestScenarioEngine|TestValidity"
```

**File list:**

- `TestDataGenerator.test.ts`
- `TestDataGenerator.boundary.test.ts`
- `TestDataGenerator.dataPool.test.ts`
- `TestDataGenerator.numberFields.test.ts`
- `TestDataGenerator.scenarios.test.ts`
- `TestDataGenerator.stringFields.test.ts`
- `TestDataGenerator.typeHandlers.test.ts`
- `TestScenarioEngine.test.ts`
- `TestScenarioEngine.execution.test.ts`
- `TestScenarioEngine.integration.test.ts`
- `TestScenarioEngine.paramGeneration.test.ts`
- `TestScenarioEngine.reporting.test.ts`
- `TestScenarioEngine.status.test.ts`
- `TestValidityAnalyzer.test.ts`

---

### Orchestration Tests (6 files)

Assessment orchestration, registry, and enrichment tests.

**Run all orchestration tests:**

```bash
npm test -- --testPathPattern="Orchestrator|Registry|enrichment|emitModule"
```

**File list:**

- `AssessmentOrchestrator.test.ts`
- `AssessorRegistry.test.ts`
- `orchestratorHelpers.test.ts`
- `emitModuleProgress.test.ts`
- `moduleEnrichment.test.ts`
- `EnrichmentFields.test.ts`

---

### Module-Specific Tests (9 files)

Individual assessment module tests.

**Run by module:**

```bash
npm test -- --testPathPattern="ResourceAssessor"    # Resource tests
npm test -- --testPathPattern="PromptAssessor"      # Prompt tests
npm test -- --testPathPattern="ToolAnnotation"      # Annotation tests
npm test -- --testPathPattern="FileModularization"  # Modularization tests
npm test -- --testPathPattern="DeveloperExperience" # DX tests
```

**File list:**

- `ResourceAssessor.test.ts`
- `ResourceAssessor-BinaryResources.test.ts`
- `ResourceAssessor-Issue9.test.ts`
- `PromptAssessor.test.ts`
- `ToolAnnotationExtractor.test.ts`
- `ToolClassifier.test.ts`
- `FileModularizationAssessor.test.ts`
- `DeveloperExperienceAssessor-Quality.test.ts`
- `AnnotationAwareSeverity.test.ts`

---

### Analyzer Tests (10 files)

Individual analyzer component tests.

**Run all analyzer tests:**

```bash
npm test -- --testPathPattern="Analyzer|Detector|Scorer"
```

**File list:**

- `DescriptionAnalyzer.test.ts`
- `DescriptionPoisoningDetector.test.ts`
- `DescriptionPoisoning-DVMCP.test.ts`
- `AnnotationDeceptionDetector-Issue161.test.ts`
- `SchemaAnalyzer.test.ts`
- `MathAnalyzer.test.ts`
- `ArchitectureDetector.test.ts`
- `SafeResponseDetector.test.ts`
- `SanitizationDetector.test.ts`
- `ConfidenceScorer.test.ts`
- `ConfidenceScorer-ContextKeywords-Issue146.test.ts`

---

### Response Validation Tests (2 files)

Response validation and schema tests.

**Run all validation tests:**

```bash
npm test -- --testPathPattern="ResponseValidator|responseValidator"
```

**File list:**

- `ResponseValidator.test.ts`
- `responseValidatorSchemas.test.ts`

---

### Behavior Inference Tests (3 files)

Tool behavior inference and architecture integration.

**Run all behavior tests:**

```bash
npm test -- --testPathPattern="Behavior|Architecture"
```

**File list:**

- `BehaviorInference.test.ts`
- `BehaviorInference-Integration.test.ts`
- `ArchitectureBehaviorIntegration.test.ts`

---

### Integration & Real-World Tests (5 files)

End-to-end and real-world scenario tests.

**Run all integration tests:**

```bash
npm test -- --testPathPattern="integration|RealWorld|Firecrawl|Testbed"
```

**File list:**

- `RealWorldMCPScenarios.test.ts`
- `FirecrawlValidation.test.ts`
- `SecurityAssessor-VulnerableTestbed.integration.test.ts`
- `TestScenarioEngine.integration.test.ts`
- `ProtocolConformance-CLI.integration.test.ts`

---

### Utility Tests (7 files)

Utility functions and miscellaneous tests.

**File list:**

- `timeoutUtils.test.ts`
- `DualKeyOutput.test.ts`
- `SessionManagement.test.ts`
- `StdioTransportDetector.test.ts`
- `ExternalAPIDependencyDetector.test.ts`
- `ExecutionArtifactDetector.test.ts`
- `LanguageAwarePayloadGenerator.test.ts`

---

### Package & Export Tests (2 files)

Package structure and export validation.

**Run all package tests:**

```bash
npm test -- --testPathPattern="package-"
```

**File list:**

- `package-imports.test.ts`
- `package-structure.test.ts`

---

### Stage/Fix Validation Tests (2 files)

Stage-specific fix validation tests.

**Run all stage tests:**

```bash
npm test -- --testPathPattern="Stage3"
```

**File list:**

- `Stage3-Fixes-Validation.test.ts`
- `Stage3-TypeSafety-Fixes.test.ts`

---

### Barrel Export Tests (1 file)

Tests for barrel export correctness.

**File list:**

- `AnalyzersBarrelExport.test.ts`

---

## CI/CD Integration

### Run Tests by Concern in CI

```yaml
# GitHub Actions example
jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test -- --testPathPattern="Security|Chain|CrossTool"

  protocol-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test -- --testPathPattern="Protocol|ErrorHandling"

  false-positive-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test -- --testPathPattern="FalsePositive|AlignmentChecker"
```

### Performance-Sensitive Tests

Some tests are slow and gated by environment variables:

```bash
# Run slow reflection tests (security)
RUN_SLOW_TESTS=true npm test -- --testPathPattern="SecurityAssessor"

# Run performance benchmarks
RUN_PERF_TESTS=true npm test -- --testPathPattern="performance"
```

---

## Test Organization Rationale

**Why not physical subdirectories?**

All 102 test files use relative imports from parent directories (`from "../"`). Moving files to subdirectories would require updating 173+ import statements, risking breakage and complicating git history.

**Benefits of pattern-based organization:**

1. **Zero refactoring risk** - No imports to update
2. **Flexible categorization** - One test can match multiple patterns
3. **Easy CI/CD integration** - `--testPathPattern` works everywhere
4. **Self-documenting** - Test names indicate their concern
5. **Backwards compatible** - Existing workflows unchanged

---

## Adding New Tests

When adding new tests, follow these naming conventions:

| Concern         | Pattern                         | Example                                      |
| --------------- | ------------------------------- | -------------------------------------------- |
| Security        | `Security*.test.ts`             | `SecurityAssessor-NewAttack.test.ts`         |
| False Positives | `*FalsePositive*.test.ts`       | `SecurityAssessor-XYZFalsePositives.test.ts` |
| Protocol        | `Protocol*.test.ts`             | `ProtocolCompliance-NewCheck.test.ts`        |
| Temporal        | `Temporal*.test.ts`             | `TemporalAssessor-NewMutation.test.ts`       |
| Module          | `{ModuleName}Assessor*.test.ts` | `NewModuleAssessor.test.ts`                  |
| Integration     | `*.integration.test.ts`         | `NewFeature.integration.test.ts`             |

This ensures new tests are automatically included in the correct category patterns.
