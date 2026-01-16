# v2.0.0 Removal Checklist

**Status**: Ready for execution on release day
**Target**: v2.0.0 (Q2 2026)
**Prerequisite**: All deprecation warnings active since v1.25.2

This checklist tracks all items to be removed in v2.0.0. Use this as the execution guide on release day.

---

## Pre-Release Verification

Before starting removal, verify:

- [ ] All deprecation warnings active (since v1.25.2)
- [ ] Dual-key output working (#124)
- [ ] mcp-auditor#103 coordinated (downstream consumer)
- [ ] ~6 months since warnings started
- [ ] CHANGELOG.md entry drafted

---

## 1. Assessment Modules to Delete (4 modules)

### Files to Delete

```bash
# Module files
rm client/src/services/assessment/modules/DocumentationAssessor.ts
rm client/src/services/assessment/modules/UsabilityAssessor.ts
rm client/src/services/assessment/modules/MCPSpecComplianceAssessor.ts
rm client/src/services/assessment/modules/ProtocolConformanceAssessor.ts

# Test files
rm client/src/services/assessment/modules/DocumentationAssessor.test.ts
rm client/src/services/assessment/modules/UsabilityAssessor.test.ts
rm client/src/services/assessment/modules/MCPSpecComplianceAssessor.test.ts
# Note: ProtocolConformanceAssessor.test.ts may not exist - verify
```

### Checklist

- [ ] `DocumentationAssessor.ts` deleted
- [ ] `DocumentationAssessor.test.ts` deleted
- [ ] `UsabilityAssessor.ts` deleted
- [ ] `UsabilityAssessor.test.ts` deleted (if exists)
- [ ] `MCPSpecComplianceAssessor.ts` deleted
- [ ] `MCPSpecComplianceAssessor.test.ts` deleted
- [ ] `ProtocolConformanceAssessor.ts` deleted
- [ ] `ProtocolConformanceAssessor.test.ts` deleted (if exists)

---

## 2. Exports to Remove (modules/index.ts)

**File**: `client/src/services/assessment/modules/index.ts`

### Deprecated Exports Section (Lines ~100-134)

Remove entire section:

```typescript
// ============================================================================
// Deprecated Exports (backward compatibility - will be removed in v2.0.0)
// ============================================================================

/**
 * @deprecated Use DeveloperExperienceAssessor instead.
 */
export { DocumentationAssessor } from "./DocumentationAssessor";

/**
 * @deprecated Use DeveloperExperienceAssessor instead.
 */
export { UsabilityAssessor } from "./UsabilityAssessor";

/**
 * @deprecated Use ProtocolComplianceAssessor instead.
 */
export { MCPSpecComplianceAssessor } from "./MCPSpecComplianceAssessor";

/**
 * @deprecated Use ProtocolComplianceAssessor instead.
 */
export { ProtocolConformanceAssessor } from "./ProtocolConformanceAssessor";
```

### Type Exports to Update (Lines ~139-150)

Remove deprecated types from export block:

```typescript
// REMOVE these from type re-exports:
DocumentationAssessment,
UsabilityAssessment,
MCPSpecComplianceAssessment,
```

### Checklist

- [ ] `DocumentationAssessor` export removed
- [ ] `UsabilityAssessor` export removed
- [ ] `MCPSpecComplianceAssessor` export removed
- [ ] `ProtocolConformanceAssessor` export removed
- [ ] `DocumentationAssessment` type export removed
- [ ] `UsabilityAssessment` type export removed
- [ ] `MCPSpecComplianceAssessment` type export removed
- [ ] Entire "Deprecated Exports" section removed

---

## 3. Config Flags to Remove (configTypes.ts)

**File**: `client/src/lib/assessment/configTypes.ts`

### In assessmentCategories interface

Remove these properties:

```typescript
// REMOVE:
/** @deprecated Use protocolCompliance instead. Will be removed in v2.0.0. */
mcpSpecCompliance?: boolean;

/** @deprecated Use protocolCompliance instead. Will be removed in v2.0.0. */
protocolConformance?: boolean;
```

### Update behavior

- [ ] `documentation` flag behavior: Verify it maps to `developerExperience`
- [ ] `usability` flag: Consider removing or mapping to `developerExperience`

### In all preset configs

Update these files to remove deprecated flags:

- [ ] `DEFAULT_ASSESSMENT_CONFIG`
- [ ] `REVIEWER_MODE_CONFIG`
- [ ] `DEVELOPER_MODE_CONFIG`
- [ ] `AUDIT_MODE_CONFIG`
- [ ] `CLAUDE_ENHANCED_AUDIT_CONFIG`

### Checklist

- [ ] `mcpSpecCompliance` property removed from interface
- [ ] `protocolConformance` property removed from interface
- [ ] `maxToolsToTestForErrors` property removed (replaced by `selectedToolsForTesting`)
- [ ] All 5 preset configs updated

---

## 4. Config Parameters to Remove

**File**: `client/src/lib/assessment/configTypes.ts`

### Remove maxToolsToTestForErrors

```typescript
// REMOVE this line:
maxToolsToTestForErrors?: number; // @deprecated Use selectedToolsForTesting instead.
```

### Checklist

- [ ] `maxToolsToTestForErrors` removed from `AssessmentConfiguration` interface

---

## 5. BaseAssessor Methods to Remove

**File**: `client/src/services/assessment/modules/BaseAssessor.ts`

### Methods to delete

```typescript
// REMOVE: protected log() method (lines ~66-75)
protected log(message: string): void {
  // ... deprecation warning + forward to logger.info
}

// REMOVE: protected logError() method (lines ~84-93)
protected logError(message: string, error?: unknown): void {
  // ... deprecation warning + forward to logger.error
}

// REMOVE: deprecationWarningsEmitted tracking object (lines ~26-29)
private deprecationWarningsEmitted = {
  log: false,
  logError: false,
};
```

### Checklist

- [ ] `log()` method removed
- [ ] `logError()` method removed
- [ ] `deprecationWarningsEmitted` object removed
- [ ] Verify no internal usages remain

---

## 6. Method-Level APIs to Remove

### DocumentationAssessor.extractFunctionalExamples()

**File**: `client/src/services/assessment/modules/DocumentationAssessor.ts`

- [ ] Method removed (file is being deleted anyway)

### SecurityResponseAnalyzer.computeMathResult()

**File**: `client/src/services/assessment/modules/securityTests/SecurityResponseAnalyzer.ts`

- [ ] `computeMathResult()` method removed
- [ ] `analyzeComputedMathResult()` is the replacement (verify it exists)

### MathAnalyzer.computeMathResult()

**File**: `client/src/services/assessment/modules/securityTests/MathAnalyzer.ts`

- [ ] `computeMathResult()` method removed
- [ ] `analyzeComputedMathResult()` is the replacement (verify it exists)

### AssessmentOrchestrator.runFullAssessment()

**File**: `client/src/services/assessment/AssessmentOrchestrator.ts`

- [ ] `runFullAssessment()` method removed
- [ ] Verify `runAssessment()` covers the same functionality

---

## 7. Output Key Changes

**File**: `client/src/services/assessment/AssessmentOrchestrator.ts` (or output builder)

### Remove dual-key output

Currently outputs both old and new keys. In v2.0.0, only output new keys:

| Old Key               | New Key                             | Action         |
| --------------------- | ----------------------------------- | -------------- |
| `documentation`       | `developerExperience.documentation` | Remove old key |
| `usability`           | `developerExperience.usability`     | Remove old key |
| `mcpSpecCompliance`   | `protocolCompliance`                | Remove old key |
| `protocolConformance` | `protocolCompliance`                | Remove old key |

### Test file to update/remove

**File**: `client/src/services/assessment/__tests__/DualKeyOutput.test.ts`

- [ ] Either delete or update to verify only new keys exist

### Checklist

- [ ] `documentation` root key removed from output
- [ ] `usability` root key removed from output
- [ ] `mcpSpecCompliance` root key removed from output
- [ ] `protocolConformance` root key removed from output
- [ ] `DualKeyOutput.test.ts` updated/deleted

---

## 8. Type Interface Updates

**File**: `client/src/lib/assessment/types.ts` (or similar)

### Types to remove/update

- [ ] `DocumentationAssessment` interface - remove or mark internal
- [ ] `UsabilityAssessment` interface - remove or mark internal
- [ ] `MCPSpecComplianceAssessment` interface - remove or mark internal
- [ ] Verify `DeveloperExperienceAssessment` exists and is exported
- [ ] Verify `ProtocolComplianceAssessment` exists and is exported

---

## 9. Documentation Updates

### Files to update

- [ ] `docs/DEPRECATION_GUIDE.md` - Update status to "Removed in v2.0.0"
- [ ] `docs/DEPRECATION_INDEX.md` - Update status column
- [ ] `docs/ASSESSMENT_CATALOG.md` - Remove deprecated modules
- [ ] `README.md` - Update module count (22 → 18)
- [ ] `CLAUDE.md` - Update module references if any

### Files to potentially delete

- [ ] `docs/DEPRECATION_MIGRATION_EXAMPLES.md` - Consider archiving
- [ ] This checklist (`DEPRECATION_REMOVAL_CHECKLIST.md`) - Archive after completion

---

## 10. Post-Release Verification

### Build & Test

```bash
npm run build
npm test
npm run prettier-check
```

- [ ] `npm run build` succeeds
- [ ] `npm test` passes (expect some test deletions)
- [ ] No TypeScript errors
- [ ] No lint errors

### Functional Verification

```bash
# Test CLI still works
npm run assess -- --server test-server --config /tmp/test-config.json

# Verify new module names work
npm run assess -- --only-modules developerExperience,protocolCompliance
```

- [ ] CLI assessment runs successfully
- [ ] New module names work in `--only-modules`
- [ ] Old module names fail gracefully with clear error

### Publish

- [ ] `npm version major` (1.x.x → 2.0.0)
- [ ] `npm run publish-all`
- [ ] `bunx @bryan-thompson/inspector-assessment --help` works
- [ ] Git tag created and pushed

---

## Summary Counts

| Category             | Items to Remove |
| -------------------- | --------------- |
| Assessment Modules   | 4 files + tests |
| Module Exports       | 4 exports       |
| Type Exports         | 3 types         |
| Config Flags         | 2 flags         |
| Config Parameters    | 1 parameter     |
| BaseAssessor Methods | 2 methods       |
| Method-Level APIs    | 4 methods       |
| Output Keys          | 4 keys          |
| **Total**            | **~24 items**   |

---

## Related Issues

- **Issue #48**: v2.0.0 Roadmap (parent issue)
- **Issue #124**: Output key transition (dual-key)
- **Issue #176**: Remove deprecated assessment modules
- **mcp-auditor #103**: Downstream consumer coordination

---

**Created**: 2026-01-16
**Last Updated**: 2026-01-16
**Author**: Inspector Assessment Team
