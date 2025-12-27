# Upstream Sync Status

This document tracks the integration points between the upstream MCP Inspector and our assessment enhancements to facilitate future upstream syncs.

## Sync Information

| Field                   | Value                                             |
| ----------------------- | ------------------------------------------------- |
| **Upstream Repository** | https://github.com/modelcontextprotocol/inspector |
| **Last Sync Version**   | v0.18.0                                           |
| **Last Sync Date**      | 2025-12-23                                        |
| **Last Sync Commit**    | `fe393e514a2921fea58f16aa310563b5c5d0ee8e`        |

## Integration Points

### File: `client/src/App.tsx`

This is the **only upstream file** that requires modifications for assessment integration.

| Line      | Type   | Description                                                                |
| --------- | ------ | -------------------------------------------------------------------------- |
| 59        | Import | `ClipboardCheck` icon from lucide-react                                    |
| 75        | Import | `import AssessmentTab from "./components/AssessmentTab";`                  |
| 129       | State  | `const [isLoadingTools, setIsLoadingTools] = useState(false);`             |
| 372       | Array  | `...(serverCapabilities?.tools ? ["assessment"] : []),` in `availableTabs` |
| 1024-1036 | Logic  | Auto-load tools when assessment tab is selected                            |
| 1061-1067 | JSX    | `<TabsTrigger value="assessment">` with ClipboardCheck icon                |
| 1236-1249 | JSX    | `<AssessmentTab>` component rendering                                      |

### Detailed Changes

#### 1. Import Section (Lines 59, 75)

```typescript
// Line 59 - Add to lucide-react imports
  ClipboardCheck,

// Line 75 - Add component import
import AssessmentTab from "./components/AssessmentTab";
```

#### 2. State Declaration (Line 129)

```typescript
const [isLoadingTools, setIsLoadingTools] = useState(false);
```

#### 3. Available Tabs Array (Line 372)

```typescript
const availableTabs = [
  "resources",
  "prompts",
  "tools",
  ...(serverCapabilities?.tools ? ["assessment"] : []), // <-- ADD THIS
  // ... rest of tabs
];
```

#### 4. Tab Value Change Handler (Lines 1024-1036)

```typescript
// Auto-load tools when assessment tab is selected
if (value === "assessment" && tools.length === 0 && serverCapabilities?.tools) {
  try {
    clearError("tools");
    await listTools();
  } catch (error) {
    console.error("Failed to auto-load tools:", error);
  }
}
```

#### 5. Tab Trigger (Lines 1061-1067)

```typescript
<TabsTrigger
  value="assessment"
  disabled={!serverCapabilities?.tools}
>
  <ClipboardCheck className="w-4 h-4 mr-2" />
  Assessment
</TabsTrigger>
```

#### 6. Tab Content (Lines 1236-1249)

```typescript
<AssessmentTab
  tools={tools}
  isLoadingTools={isLoadingTools}
  listTools={() => {
    clearError("tools");
    listTools();
  }}
  callTool={async (name, params) => {
    const result = await callTool(name, params);
    return result;
  }}
  serverName={
    transportType === "stdio" ? command || "MCP Server" : ""
  }
/>
```

## Files Added (No Conflict Risk)

These files are entirely new and have no upstream equivalents:

### Assessment Core (`client/src/services/assessment/`)

- `AssessmentOrchestrator.ts`
- `TestScenarioEngine.ts`
- `ResponseValidator.ts`
- `TestDataGenerator.ts`
- `ToolClassifier.ts`
- `PolicyComplianceGenerator.ts`
- All files in `modules/`
- All files in `__tests__/`

### Assessment Libraries (`client/src/lib/`)

- `assessmentTypes.ts`
- `assessmentDiffer.ts`
- `aupPatterns.ts`
- `prohibitedLibraries.ts`
- `securityPatterns.ts`
- `policyMapping.ts`
- `moduleScoring.ts`
- `distributionDetection.ts`
- `reportFormatters/`

### Assessment Components (`client/src/components/`)

- `AssessmentTab.tsx`
- `ExtendedAssessmentCategories.tsx`
- `ReviewerAssessmentView.tsx`
- `UnifiedAssessmentHeader.tsx`
- `AssessmentCategoryFilter.tsx`
- `AssessmentSummary.tsx`
- `AssessmentChecklist.tsx`
- `ui/tool-selector.tsx`
- `ui/badge.tsx`
- `ui/progress.tsx`

### CLI Additions (`cli/src/`)

- `assess-full.ts`
- `assess-security.ts`
- `assessmentState.ts`
- `validate-testbed.ts`

### Scripts (`scripts/`)

- `run-full-assessment.ts`
- `run-security-assessment.ts`
- `lib/jsonl-events.ts`

### Documentation (`docs/`)

- All files in this directory

## Sync Procedure

### Automated Sync (Recommended)

Use the sync helper script for guided upstream syncing:

```bash
# Check status and view changes (safe, read-only)
npm run sync:upstream

# Or run individual commands:
./scripts/sync-upstream.sh status    # Show sync status
./scripts/sync-upstream.sh diff      # View upstream changes to App.tsx
./scripts/sync-upstream.sh merge     # Attempt merge with conflict guidance
./scripts/sync-upstream.sh validate  # Build and test after merge
```

The script automatically:

- Fetches upstream and shows divergence
- Highlights if integration lines are affected
- Provides merge conflict resolution guidance
- Prompts to update this document after successful merge

### Manual Sync

#### Before Syncing

1. **Check upstream changes to App.tsx**:

   ```bash
   git fetch upstream
   git diff upstream/main...HEAD -- client/src/App.tsx
   ```

2. **Identify conflicts in integration lines**:
   ```bash
   git diff fe393e514a..upstream/main -- client/src/App.tsx
   ```

#### During Sync

1. **Merge upstream**:

   ```bash
   git fetch upstream
   git merge upstream/main
   ```

2. **If App.tsx conflicts**, manually apply the 6 integration points listed above

3. **Verify integration**:
   ```bash
   npm run build
   npm test
   ```

#### After Sync

1. **Update this document** with:
   - New sync version
   - New sync date
   - New sync commit
   - Any line number changes

2. **Test assessment functionality**:
   ```bash
   npm run dev
   # Navigate to Assessment tab
   ```

## Risk Assessment

| Integration Point    | Risk   | Notes                                |
| -------------------- | ------ | ------------------------------------ |
| Icon import          | Low    | Stable lucide-react API              |
| Component import     | Low    | Additive, no conflicts expected      |
| State declaration    | Low    | Additive, no conflicts expected      |
| Available tabs array | Medium | May shift if upstream adds tabs      |
| Tab change handler   | Medium | Handler logic may be refactored      |
| TabsTrigger          | Low    | Standard pattern, unlikely to change |
| AssessmentTab render | Low    | Additive, no conflicts expected      |

## Future Improvements

To further reduce sync friction:

1. **Extract to integration layer**: Create `client/src/integrations/assessment.ts` to centralize all integration code
2. **Add feature flags**: Allow assessment to be disabled via environment variable
3. **Plugin architecture**: Enable assessment as optional npm package

---

_Last updated: 2025-12-27_
