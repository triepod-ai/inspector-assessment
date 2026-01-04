# Upstream Sync Workflow Guide

**Purpose**: Guide for maintaining the MCP Inspector fork while syncing with upstream changes.

**Scope**: Complete step-by-step workflow for syncing with `https://github.com/modelcontextprotocol/inspector`

**Last Updated**: 2026-01-04
**Current Upstream Version**: v0.18.0 (synced 2025-12-23)
**Current Local Version**: 1.23.1

> **📋 UPDATE (v1.23.0 - 2026-01-04): Assessment Tab UI Deprecated**
>
> The Assessment Tab UI integration points (`[ASSESSMENT-INTEGRATION]` markers) documented in this
> guide have been **removed** from `client/src/App.tsx`. Assessment functionality is now CLI-only.
>
> **What this means for upstream syncs:**
>
> - **No more UI integration conflicts** - App.tsx no longer has assessment-specific code
> - **Simpler merges** - No need to preserve 6 integration points during upstream syncs
> - **Historical reference** - The integration point documentation below is preserved for reference
>
> The assessment modules in `client/src/services/assessment/` remain untouched and are exported
> via the npm package for programmatic use.

---

## Table of Contents

1. [Pre-Sync Checklist](#pre-sync-checklist)
2. [Sync Command Sequence](#sync-command-sequence)
3. [Conflict Resolution Guide](#conflict-resolution-guide)
4. [Post-Sync Validation](#post-sync-validation)
5. [Integration Point Reference](#integration-point-reference)
6. [Rollback Procedure](#rollback-procedure)
7. [Version Tracking](#version-tracking)
8. [Troubleshooting](#troubleshooting)

---

## Pre-Sync Checklist

Complete these steps before attempting an upstream sync:

### 1. Verify Clean Working Directory

```bash
cd /home/bryan/inspector
git status
```

**Expected Output**:

```
On branch main
Your branch is up to date with 'origin/main'.

nothing to commit, working tree clean
```

**If Uncommitted Changes Exist**:

```bash
# Option 1: Commit your changes
git add .
git commit -m "feat: your changes"

# Option 2: Stash and restore later
git stash
# After sync: git stash pop
```

### 2. Verify All Tests Pass

```bash
npm test
```

**Expected**: ~1000 tests passing, build succeeds

**If Tests Fail**:

- Fix failures before syncing
- Syncing with failing tests makes conflict resolution harder
- If urgent, document which tests fail: `npm test 2>&1 | tee /tmp/test-baseline.log`

### 3. Document Current State

```bash
# Get current upstream status
./scripts/sync-upstream.sh status

# Document any local modifications to critical files
git diff HEAD -- client/src/App.tsx > /tmp/app-tsx-baseline.diff
git diff HEAD -- package.json > /tmp/package-json-baseline.diff
```

**Save the output** - you'll reference this during conflict resolution.

### 4. Verify Upstream Remote Exists

```bash
git remote -v | grep upstream
```

**Expected Output**:

```
upstream    https://github.com/modelcontextprotocol/inspector.git (fetch)
upstream    https://github.com/modelcontextprotocol/inspector.git (push)
```

**If Missing**:

```bash
git remote add upstream https://github.com/modelcontextprotocol/inspector.git
```

### 5. Create Sync Branch (Optional but Recommended)

```bash
# Create backup branch before attempting merge
git checkout -b sync-upstream-$(date +%Y%m%d)

# Return to main after creating backup
git checkout main
```

---

## Sync Command Sequence

Follow these commands in order. Each step builds on the previous one.

### Step 1: Check Sync Status

```bash
./scripts/sync-upstream.sh status
```

**Review**:

- Current branch (must be `main`)
- Last sync version and date
- How many commits behind/ahead
- Integration point line numbers

**Example Output**:

```
=== Sync Status ===

Current branch: main
Last sync: v0.18.0 (2025-12-23)
Sync commit: fe393e514a2921fea58f16aa310563b5c5d0ee8e

Upstream HEAD: a7b8c9d

⚠ Behind upstream by 12 commit(s)
ℹ Ahead of upstream by 342 commit(s) (our enhancements)

Integration Points in App.tsx:
  Lines 73-79: Import assessment integration layer
  Lines 134-135: isLoadingTools state declaration
  Lines 378-381: assessment tab in availableTabs array
  Lines 1034-1044: Auto-load tools when assessment tab selected
  Lines 1071-1077: TabsTrigger for assessment
  Lines 1252-1264: AssessmentTab component render
```

**Decision Point**:

- If behind upstream = sync needed
- If behind by >20 commits = higher risk of conflicts
- If integration lines changed upstream = manual review required

### Step 2: Fetch and Review Upstream Changes

```bash
./scripts/sync-upstream.sh diff
```

**Review**:

- What files changed in upstream
- Which lines in `App.tsx` were modified
- Whether integration points are affected

**Example Output**:

```
=== Upstream Changes to App.tsx ===

ℹ Fetching upstream...
Comparing: fe393e514a → upstream/main

✓ No changes to App.tsx since last sync

=== Integration Line Analysis ===

✓ Integration lines appear unaffected
```

**If Integration Lines ARE Affected**:

```
⚠ Lines 375-382 may be affected: assessment tab in availableTabs array
```

In this case, proceed to **Step 3a (Manual Merge)** instead of automated merge.

### Step 3: Merge Upstream (Automated Path)

If `./scripts/sync-upstream.sh diff` shows no conflicts:

```bash
./scripts/sync-upstream.sh merge
```

**Expected Output**:

```
=== Merge Upstream ===

ℹ Fetching upstream...
ℹ Attempting merge with upstream/main...
✓ Merge completed successfully!
```

**Proceed to**: Step 4 (Post-Sync Validation)

### Step 3a: Manual Merge (Conflict Path)

If conflicts are detected:

```bash
git fetch upstream
git merge upstream/main
```

**Expected Output** (with conflicts):

```
Auto-merging client/src/App.tsx
CONFLICT (content): Merge conflict in client/src/App.tsx
Automatic merge failed; fix conflicts and then commit the result.
```

**Proceed to**: [Conflict Resolution Guide](#conflict-resolution-guide)

### Step 4: Post-Sync Validation

After successful merge (automated or manual):

```bash
./scripts/sync-upstream.sh validate
```

**This runs**:

1. `npm run build` - Compile all packages
2. `npm test` - Run full test suite

**Expected Output**:

```
=== Build Validation ===

ℹ Running npm build...
✓ Build passed
ℹ Running tests...
✓ Tests passed
✓ Validation complete!

=== Update UPSTREAM_SYNC.md ===

Update UPSTREAM_SYNC.md with:
  Version: v0.19.0
  Date: 2026-01-05
  Commit: abc123def456...

Please update UPSTREAM_SYNC.md manually with these values
```

### Step 5: Update Documentation

Update `/home/bryan/inspector/UPSTREAM_SYNC.md` with new sync information:

```bash
# Get the upstream HEAD commit
git rev-parse upstream/main
# Example output: abc123def456789...

# Get upstream version from package.json
git show upstream/main:package.json | grep '"version"' | head -1
# Example output: "version": "0.19.0"

# Today's date
date +%Y-%m-%d
# Example output: 2026-01-05
```

**Edit UPSTREAM_SYNC.md**:

```markdown
| Field                   | Value                                             |
| ----------------------- | ------------------------------------------------- |
| **Upstream Repository** | https://github.com/modelcontextprotocol/inspector |
| **Last Sync Version**   | v0.19.0                                           |
| **Last Sync Date**      | 2026-01-05                                        |
| **Last Sync Commit**    | `abc123def456789...`                              |
```

### Step 6: Commit Sync Changes

```bash
# Review what changed
git status

# Stage changes
git add -A

# Commit with descriptive message
git commit -m "chore: sync upstream to v0.19.0

- Synced with modelcontextprotocol/inspector@v0.19.0
- Merged 12 upstream commits
- Assessment integration maintained (6 integration points preserved)
- All tests passing (1000+ tests)
- Build validated successfully"
```

### Step 7: Push to Origin

```bash
git push origin main
```

**Verify**:

```bash
git log --oneline -5
# Should show your sync commit at the top
```

---

## Conflict Resolution Guide

When `git merge upstream/main` fails, conflicts must be manually resolved.

### Conflict Detection

```bash
# Show all conflicted files
git status --short | grep '^UU\|^AA\|^DD\|^M[DU]\|^[DU]M'

# Focus on App.tsx (most likely file)
git diff --name-only --diff-filter=U | grep App.tsx
```

### Understanding Merge Markers

In a conflicted file, markers indicate:

```typescript
// <<<<<<< HEAD
// Your local changes (current branch - main)
// ||||||| MERGE_BASE
// Original code (before either branch changed it)
// =======
// Upstream changes (upstream/main)
// >>>>>>> upstream/main
```

### Integration Points - Preservation Strategy

The MCP Inspector has **6 integration points** in `App.tsx` that MUST be preserved during merge:

| Line Range | Integration Point       | Strategy                                         |
| ---------- | ----------------------- | ------------------------------------------------ |
| 73-79      | Import assessment layer | Keep all imports from `/integrations/assessment` |
| 134-135    | `isLoadingTools` state  | Preserve our state declaration                   |
| 378-381    | Assessment tab in array | Keep `getAssessmentTab()` call                   |
| 1034-1044  | Auto-load tools handler | Preserve assessment tab selection logic          |
| 1071-1077  | TabsTrigger component   | Keep assessment tab trigger                      |
| 1252-1264  | AssessmentTab render    | Keep assessment component rendering              |

### Conflict Resolution Process

#### Case 1: Conflict NOT in Integration Points

If conflict is elsewhere in `App.tsx`:

```bash
# View the conflict
grep -A 10 "^<<<<<<< HEAD" client/src/App.tsx | head -20

# Strategy: Usually accept upstream changes
# Keep: upstream code (the ">>>>>>>..." section)
# Remove: conflict markers and keep only upstream changes
```

**Resolution**:

```bash
# Use their (upstream) version for non-integration code
git checkout --theirs -- client/src/App.tsx

# Then manually add back our integration points
# (See integration point examples in section below)
```

#### Case 2: Conflict IN Integration Points

If conflict involves one of our integration points:

**Example Conflict** (in availableTabs array around line 378):

```typescript
const availableTabs = [
  "resources",
  "prompts",
  "tools",
<<<<<<< HEAD
  // [ASSESSMENT-INTEGRATION] Use integration layer with feature flag
  ...(FEATURES.ASSESSMENT_TAB
    ? getAssessmentTab(serverCapabilities)
    : []),
  // [/ASSESSMENT-INTEGRATION]
||||||| MERGE_BASE
  ...(serverCapabilities?.tools ? ["assessment"] : []),
=======
  "sampling",
  "ping",
>>>>>>> upstream/main
];
```

**Resolution Strategy**:

1. Keep upstream changes (sampling, ping sections)
2. Add back assessment integration code
3. Verify no duplicate entries

```typescript
const availableTabs = [
  "resources",
  "prompts",
  "tools",
  // [ASSESSMENT-INTEGRATION] Use integration layer with feature flag
  ...(FEATURES.ASSESSMENT_TAB ? getAssessmentTab(serverCapabilities) : []),
  // [/ASSESSMENT-INTEGRATION]
  "sampling",
  "ping",
  // ... rest of array
];
```

#### Case 3: Conflict in Handler Logic

If conflict in auto-load tools handler (around line 1034):

```typescript
const handleTabChange = async (value: string) => {
<<<<<<< HEAD
  // [ASSESSMENT-INTEGRATION] Auto-load tools when assessment tab is selected
  await handleAssessmentTabSelect(
    tools,
    serverCapabilities,
    listTools,
    clearError,
  );

  // ... rest of handler
||||||| MERGE_BASE
  // Original handler code
=======
  // Upstream's updated handler
  // ... different implementation
>>>>>>> upstream/main
};
```

**Resolution Strategy**:

1. Review upstream's handler changes
2. Apply assessment logic to new handler structure
3. Maintain assessment auto-load behavior

```typescript
const handleTabChange = async (value: string) => {
  // ... upstream code ...

  // [ASSESSMENT-INTEGRATION] Auto-load tools when assessment tab is selected
  if (value === "assessment") {
    await handleAssessmentTabSelect(
      tools,
      serverCapabilities,
      listTools,
      clearError,
    );
  }
};
```

### General Merge Resolution Flow

```bash
# 1. Open conflicted file
vim client/src/App.tsx

# 2. For each conflict marker:
#    - Decide: keep ours, theirs, or both
#    - Remove conflict markers
#    - Ensure syntax is valid

# 3. Verify no remaining conflict markers
grep -n "^<<<<<<< HEAD\|^=======\|^>>>>>>>" client/src/App.tsx
# Should return empty (no output)

# 4. Stage resolved file
git add client/src/App.tsx

# 5. Check for other conflicts
git diff --name-only --diff-filter=U
# Should show empty

# 6. Complete the merge
git commit --no-edit

# 7. Run validation
npm run build && npm test
```

### Conflict Resolution Checklist

> **Note (v1.23.0+)**: Assessment Tab UI has been deprecated. The checklist below applies to general App.tsx conflicts.

- [ ] All conflict markers removed (`<<<<<<<`, `=======`, `>>>>>>>`)
- [ ] File syntax valid (no mismatched braces)
- [ ] Imports are correct
- [ ] Build succeeds: `npm run build`
- [ ] Tests pass: `npm test`
- [ ] No console errors: `npm run dev` (check browser console)
- [ ] CLI assessment works: `npm run assess:full -- --help`

---

## Post-Sync Validation

After merging (success or manual resolution), validate the sync:

### 1. Build Validation

```bash
npm run build
```

**Expected Output**:

```
> @bryan-thompson/inspector-assessment build
> npm run build-server && npm run build-client && npm run build-cli

> build-server
(builds successfully...)

> build-client
(builds successfully...)

> build-cli
(builds successfully...)
```

**If Build Fails**:

```bash
# See detailed error
npm run build 2>&1 | tail -50

# Common issue: TypeScript compilation errors
# Check App.tsx syntax first:
npx tsc --noEmit client/src/App.tsx

# If ESLint errors, run prettier:
npm run prettier-fix
```

### 2. Test Suite Validation

```bash
npm test
```

**Expected Output**:

```
PASS  client/src/services/__tests__/...
PASS  client/src/components/__tests__/...
...

Test Suites: 52 passed, 52 total
Tests:       1000+ passed, 1000+ total
```

**If Tests Fail**:

```bash
# Run specific test file
npm test -- client/src/components/__tests__/AssessmentTab.test.ts

# Run assessment tests only
npm test -- assessment

# Update snapshots if expected
npm test -- --updateSnapshot
```

### 3. CLI Assessment Functionality Test

> **Note (v1.23.0+)**: Assessment is now CLI-only. The Assessment Tab UI has been deprecated.

```bash
# Test CLI help
npm run assess:full -- --help

# Run a quick assessment against a test server
npm run assess -- --server test-server --config /tmp/test-config.json

# Test CLI directly with npx (verifies npm package works)
npx @bryan-thompson/inspector-assessment mcp-assess-full --help
```

**Verification Checklist**:

1. CLI help displays correctly
2. Assessment runs against a test server
3. JSON output is valid: `cat /tmp/inspector-assessment-*.json | jq .overallStatus`
4. Exit codes work: `echo $?` (0 for PASS, 1 for FAIL)

### 4. Inspector UI Verification (Non-Assessment)

```bash
# Start dev server
npm run dev

# In browser: http://localhost:6274
# Verify core Inspector functionality works (tools, resources, prompts tabs)
```

> **Deprecated (v1.23.0)**: Integration Points Verification
>
> The 6 `[ASSESSMENT-INTEGRATION]` markers in App.tsx were removed in v1.23.0.
> Assessment functionality is now in `client/src/services/assessment/` and CLI tools.
> There are no longer any assessment-specific integration points to verify.

### 5. Upstream Compatibility Check

```bash
# Verify upstream imports still work
npm ls @modelcontextprotocol/sdk

# Check for any deprecation warnings
npm run build 2>&1 | grep -i deprecat || echo "No deprecations"
```

---

## Integration Point Reference

> **DEPRECATED (v1.23.0)**: This section is preserved for historical reference only.
> The Assessment Tab UI and its 6 integration points were removed in v1.23.0.
> Assessment functionality is now CLI-only via `mcp-assess-full` and `mcp-assess-security`.
>
> **For current documentation, see:**
>
> - [PROGRAMMATIC_API_GUIDE.md](PROGRAMMATIC_API_GUIDE.md) - Programmatic API usage
> - [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) - CLI usage guide

<details>
<summary>Historical Reference: 6 Integration Points (Click to expand)</summary>

This section documents all 6 integration points with code examples.

### Integration Point 1: Assessment Integration Layer Import

**Location**: Lines 73-79 in `client/src/App.tsx`

**Purpose**: Import assessment-related utilities and components

```typescript
// [ASSESSMENT-INTEGRATION] Assessment integration layer - see UPSTREAM_SYNC.md
import {
  AssessmentTab,
  ASSESSMENT_TAB_CONFIG,
  getAssessmentTab,
  handleAssessmentTabSelect,
} from "./integrations/assessment";
```

**Source File**: `/home/bryan/inspector/client/src/integrations/assessment.ts`

**What This Does**:

- Imports `AssessmentTab` component for rendering
- Imports `ASSESSMENT_TAB_CONFIG` with tab metadata
- Imports `getAssessmentTab()` helper for conditional tab inclusion
- Imports `handleAssessmentTabSelect()` for auto-loading tools

**Upstream Compatibility**:

- Low risk - imports from our new integration layer
- Only add these imports, don't modify upstream imports
- Integration layer file doesn't exist in upstream

---

### Integration Point 2: Tool Loading State

**Location**: Line 134-135 in `client/src/App.tsx`

**Purpose**: Track whether tools are being loaded for the assessment tab

```typescript
// [ASSESSMENT-INTEGRATION] Track tool loading state for AssessmentTab
const [isLoadingTools, setIsLoadingTools] = useState(false);
```

**What This Does**:

- Provides loading state to `AssessmentTab` component
- Enables UI feedback during tool loading
- Used by `handleAssessmentTabSelect()` to prevent duplicate loads

**Upstream Compatibility**:

- Low risk - additive state, doesn't conflict with other state
- Safe to add in any position among state declarations
- Unused by upstream code

---

### Integration Point 3: Assessment Tab in Available Tabs Array

**Location**: Lines 378-381 in `client/src/App.tsx`

**Purpose**: Conditionally include "assessment" tab when assessment feature is enabled

```typescript
// [ASSESSMENT-INTEGRATION] Use integration layer with feature flag
...(FEATURES.ASSESSMENT_TAB
  ? getAssessmentTab(serverCapabilities)
  : []),
// [/ASSESSMENT-INTEGRATION]
```

**What This Does**:

- Checks feature flag `FEATURES.ASSESSMENT_TAB` (from `lib/featureFlags.ts`)
- If enabled, calls `getAssessmentTab()` to get tab list conditionally
- `getAssessmentTab()` checks if server has `tools` capability
- Returns `["assessment"]` or `[]` depending on capabilities

**Context** (in `availableTabs` array):

```typescript
const availableTabs = [
  "resources",
  "prompts",
  "tools",
  // [ASSESSMENT-INTEGRATION] Use integration layer with feature flag
  ...(FEATURES.ASSESSMENT_TAB ? getAssessmentTab(serverCapabilities) : []),
  // [/ASSESSMENT-INTEGRATION]
  "ping",
  "sampling",
  "metadata",
  "elicitation",
];
```

**Upstream Compatibility**:

- Medium risk - position within array could shift
- Safe because we use spread operator (`...`)
- If upstream adds new tabs, just ensure this block stays after "tools"

---

### Integration Point 4: Auto-Load Tools on Assessment Tab Selection

**Location**: Lines 1034-1044 in `client/src/App.tsx`

**Purpose**: Automatically load tools when user clicks the Assessment tab

```typescript
// [ASSESSMENT-INTEGRATION] Auto-load tools when assessment tab is selected
if (value === "assessment" && tools.length === 0 && serverCapabilities?.tools) {
  try {
    clearError("tools");
    await handleAssessmentTabSelect(
      tools,
      serverCapabilities,
      listTools,
      clearError,
    );
  } catch (error) {
    console.error("Failed to auto-load tools for assessment:", error);
  }
}
```

**What This Does**:

- Checks if selected tab is "assessment"
- Checks if tools haven't been loaded yet (`tools.length === 0`)
- Checks if server has tools capability
- Calls assessment handler which loads tools via MCP
- Catches and logs errors

**Context** (in `handleTabChange` function):

```typescript
const handleTabChange = async (value: string) => {
  setActiveTab(value);

  // [ASSESSMENT-INTEGRATION] Auto-load tools when assessment tab is selected
  if (
    value === "assessment" &&
    tools.length === 0 &&
    serverCapabilities?.tools
  ) {
    try {
      clearError("tools");
      await handleAssessmentTabSelect(
        tools,
        serverCapabilities,
        listTools,
        clearError,
      );
    } catch (error) {
      console.error("Failed to auto-load tools for assessment:", error);
    }
  }
};
```

**Upstream Compatibility**:

- Medium/High risk - handler logic may be refactored upstream
- If upstream restructures `handleTabChange`, integrate assessment logic into new structure
- Key: Keep the condition (`value === "assessment"`) and handler call

---

### Integration Point 5: Assessment Tab Trigger Button

**Location**: Lines 1071-1077 in `client/src/App.tsx`

**Purpose**: Render the Assessment tab button in the tab bar

```typescript
{/* [ASSESSMENT-INTEGRATION] Assessment tab trigger */}
{FEATURES.ASSESSMENT_TAB && (
  <TabsTrigger
    value="assessment"
    disabled={!serverCapabilities?.tools}
  >
    <ClipboardCheck className="w-4 h-4 mr-2" />
    Assessment
  </TabsTrigger>
)}
```

**What This Does**:

- Checks feature flag before rendering
- Creates clickable tab button with Assessment label
- Shows ClipboardCheck icon (from `lucide-react`)
- Disabled when server lacks tools capability

**Context** (in Tabs component):

```typescript
<Tabs value={activeTab} onValueChange={handleTabChange}>
  <TabsList>
    <TabsTrigger value="resources">Resources</TabsTrigger>
    <TabsTrigger value="prompts">Prompts</TabsTrigger>
    <TabsTrigger value="tools">Tools</TabsTrigger>
    {/* [ASSESSMENT-INTEGRATION] Assessment tab trigger */}
    {FEATURES.ASSESSMENT_TAB && (
      <TabsTrigger
        value="assessment"
        disabled={!serverCapabilities?.tools}
      >
        <ClipboardCheck className="w-4 h-4 mr-2" />
        Assessment
      </TabsTrigger>
    )}
    {/* ... other tabs ... */}
  </TabsList>
```

**Upstream Compatibility**:

- Low risk - we add a new trigger, don't modify existing ones
- Safe to place after "tools" tab

---

### Integration Point 6: Assessment Tab Content

**Location**: Lines 1252-1264 in `client/src/App.tsx`

**Purpose**: Render the Assessment tab content panel

```typescript
{/* [ASSESSMENT-INTEGRATION] Assessment tab content */}
{FEATURES.ASSESSMENT_TAB && (
  <TabsContent value="assessment">
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
  </TabsContent>
)}
```

**What This Does**:

- Checks feature flag before rendering
- Creates tab content panel for assessment
- Passes required props to `AssessmentTab` component:
  - `tools` - list of MCP tools
  - `isLoadingTools` - loading state
  - `listTools()` - function to reload tools
  - `callTool()` - function to invoke MCP tools
  - `serverName` - display name for STDIO servers

**Context** (in Tabs component):

```typescript
<Tabs value={activeTab} onValueChange={handleTabChange}>
  {/* Tab list ... */}

  <TabsContent value="resources">
    {/* ... resources content ... */}
  </TabsContent>

  {/* ... other tab contents ... */}

  {/* [ASSESSMENT-INTEGRATION] Assessment tab content */}
  {FEATURES.ASSESSMENT_TAB && (
    <TabsContent value="assessment">
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
    </TabsContent>
  )}
</Tabs>
```

**Upstream Compatibility**:

- Low risk - we add a new content panel, don't modify existing ones
- Safe to place at end of TabsContent list

---

### Quick Integration Point Check Script

Use this to verify all integration points after sync:

```bash
#!/bin/bash
# Check all 6 integration points are preserved

echo "Checking integration points..."

check_point() {
  local pattern="$1"
  local name="$2"
  if grep -q "$pattern" client/src/App.tsx; then
    echo "✓ $name"
  else
    echo "✗ MISSING: $name"
  fi
}

check_point "from.*integrations/assessment" "Integration layer import"
check_point "isLoadingTools.*useState" "Tool loading state"
check_point "getAssessmentTab.*serverCapabilities" "Assessment tab in array"
check_point "value === \"assessment\".*handleAssessmentTabSelect" "Auto-load handler"
check_point "<ClipboardCheck.*Assessment" "Tab trigger button"
check_point "AssessmentTab.*tools=" "Tab content render"

echo "Done!"
```

</details>

---

## Rollback Procedure

If something goes wrong after merging, you can safely rollback.

### When to Rollback

- Build fails and can't be fixed quickly
- Tests fail with widespread issues
- Assessment functionality broken
- Major regression in upstream changes

### Rollback Methods

#### Method 1: Reset to Last Commit (Before Merge)

Use if merge commit was already pushed:

```bash
# View recent commits
git log --oneline -10

# Find the commit before merge (usually shows "Merge branch")
# Example: commit abc123 is merge commit
#         commit def456 is before merge

# Create new commit that reverts the merge
git revert -m 1 abc123

# Push the revert
git push origin main
```

**Advantages**:

- Preserves git history
- Other developers see what happened
- Safe for shared branches

#### Method 2: Hard Reset (Before Push)

Use if merge hasn't been pushed yet:

```bash
# View recent commits
git log --oneline -5

# Reset to state before merge
# Example: reset to commit def456 (before merge)
git reset --hard def456

# Verify the reset
git log --oneline -3
```

**Advantages**:

- Clean history
- No "revert" commits visible
- Only use if merge not yet pushed

#### Method 3: Merge Abort (During Merge)

Use if you're still in the middle of resolving conflicts:

```bash
# Abort the merge process
git merge --abort

# Verify you're back to main
git status

# Start over
./scripts/sync-upstream.sh
```

**Advantages**:

- Quick escape from ongoing merge
- No changes committed

### Recovery Checklist

After rollback:

```bash
# 1. Verify you're on main
git branch

# 2. Check current state
git log --oneline -3

# 3. Verify build works
npm run build

# 4. Verify tests pass
npm test

# 5. Document the issue
# - Why did you rollback?
# - What failed?
# - What will you do differently?
```

### Learning from Rollback

After rollback, analyze what went wrong:

```bash
# Compare reverted merge with the one that failed
git show abc123  # The reverted merge

# Document in PROJECT_STATUS.md
# Example:
# **2026-01-06 Upstream Sync Rollback**
# - Attempted sync to v0.19.0
# - Conflict in TestScenarioEngine.ts line 234
# - Resolution unclear, rolled back to investigate
# - Next attempt: Will check upstream changes to test modules first
```

---

## Version Tracking

Track upstream and local versions to understand divergence.

### Understanding Versions

The fork has **TWO version numbers**:

1. **Upstream Version** (MCP Inspector): v0.18.0
2. **Local Version** (Inspector Assessment): 1.21.4

**Example Timeline**:

```
Upstream:        v0.14.0 ─→ v0.15.0 ─→ v0.16.0 ─→ v0.17.0 ─→ v0.18.0
                  |        |         |         |        |
                  |        └─────────┴─────────┴────────┘
                  |         Last sync point (2025-12-23)
                  |
Local:  1.0.0 → 1.5.0 → 1.10.0 → 1.15.0 → 1.20.0 → 1.21.4
         |         |        |        |       |        |
         └─────────┴────────┴────────┴───────┴────────┘
         Assessment enhancements
```

### Sync Information File

Update `/home/bryan/inspector/UPSTREAM_SYNC.md` after each sync:

```markdown
| Field                   | Value                                             |
| ----------------------- | ------------------------------------------------- |
| **Upstream Repository** | https://github.com/modelcontextprotocol/inspector |
| **Last Sync Version**   | v0.18.0                                           |
| **Last Sync Date**      | 2025-12-23                                        |
| **Last Sync Commit**    | `fe393e514a2921fea58f16aa310563b5c5d0ee8e`        |
```

### Version Update Script

After successful sync, update versions:

```bash
# Check current versions
npm run check-version

# If minor upstream feature (not breaking), update patch:
npm version patch

# If major upstream feature, update minor:
npm version minor

# This syncs all workspace versions automatically
# Then update UPSTREAM_SYNC.md manually
```

### Version Commit Message Template

```
chore: sync upstream to v0.19.0

- Synced with modelcontextprotocol/inspector@v0.19.0 (12 commits)
- Assessment integration maintained across all 6 integration points
- No conflicts in core functionality
- All tests passing (1000+ tests)
- Build validated for all platforms

Integration Points:
- [x] Assessment tab import
- [x] Tool loading state
- [x] Tab availability array
- [x] Auto-load tools handler
- [x] Tab trigger button
- [x] Tab content renderer

Upstream Changes Included:
- Feature X description
- Fix Y description
- Performance Z improvement
```

### Changelog Updates

Update `CHANGELOG.md` after sync:

```markdown
## [1.21.5] - 2026-01-05

### Sync

- Synced with upstream v0.19.0
  - Added feature X from upstream
  - Fixed issue Y from upstream
  - Performance improvements from upstream

### Assessment

- (No changes to assessment modules in this sync)

### Integration

- Maintained all 6 integration points with upstream changes
- No conflicts in App.tsx merge
- Feature flags ensure backward compatibility
```

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Merge Conflicts with Line Number Confusion

**Symptom**: Line numbers in conflict messages don't match `UPSTREAM_SYNC.md`

**Cause**: Upstream has changed since last sync, line numbers shifted

**Solution**:

```bash
# Don't rely on line numbers, search for content instead
grep -n "availableTabs\s*=" client/src/App.tsx

# Use context to find the right section
grep -B 5 -A 5 "assessment.*getAssessmentTab" client/src/App.tsx
```

---

#### Issue 2: Build Fails with TypeScript Errors

**Symptom**: `npm run build` fails with type errors

**Cause**: Upstream changed type definitions, our code incompatible

**Solution**:

```bash
# See detailed error
npm run build 2>&1 | grep -A 5 "error TS"

# Check what changed in upstream types
git diff MERGE_HEAD...HEAD -- "*.d.ts"

# Update type annotations in our code
# Common: Tool interface changed, update props passing
```

---

#### Issue 3: Tests Fail After Merge

**Symptom**: `npm test` reports failures that weren't there before

**Cause**: Upstream changed test infrastructure or our tests are too strict

**Solution**:

```bash
# Run just assessment tests
npm test -- assessment

# Run specific test file
npm test -- client/src/components/__tests__/AssessmentTab.test.ts

# Check if it's a snapshot issue
npm test -- --updateSnapshot

# If test logic changed, update snapshots
git diff client/src/**/__snapshots__
```

---

#### Issue 4: Assessment Tab Doesn't Appear

**Symptom**: Assessment tab missing from UI after sync

**Cause**: Feature flag disabled or integration points lost

**Solution**:

```bash
# Check feature flag is enabled
grep -n "ASSESSMENT_TAB" client/src/lib/featureFlags.ts

# If disabled, enable it (should be true by default)

# Check integration point 3 (tab in array)
grep -n "getAssessmentTab" client/src/App.tsx

# Check integration point 5 (tab trigger)
grep -n "ClipboardCheck" client/src/App.tsx | grep Assessment

# If missing, re-apply integration points
git show MERGE_HEAD:client/src/App.tsx | grep -n "Assessment"
```

---

#### Issue 5: Upstream Remote Not Configured

**Symptom**: `error: 'upstream' does not appear to be a 'git' repository`

**Cause**: Upstream remote never added to local repo

**Solution**:

```bash
# Add upstream remote
git remote add upstream https://github.com/modelcontextprotocol/inspector.git

# Verify it's added
git remote -v

# Try sync again
./scripts/sync-upstream.sh
```

---

#### Issue 6: Can't Merge Due to Dirty Working Directory

**Symptom**: `error: Your local changes to the following files would be overwritten by merge`

**Cause**: Uncommitted changes exist in working directory

**Solution**:

```bash
# Option 1: Commit changes
git status
git add .
git commit -m "work in progress"

# Option 2: Stash and restore later
git stash
# After merge: git stash pop

# Option 3: Create sync on a fresh clone
git clone . /tmp/inspector-sync
cd /tmp/inspector-sync
./scripts/sync-upstream.sh merge
# Copy changes back if successful
```

---

#### Issue 7: Merge Conflicts in Non-App.tsx Files

**Symptom**: Conflicts in files like `package.json`, `README.md`, etc.

**Cause**: Upstream changed these files, we also changed them

**Solution**:

```bash
# Check what files have conflicts
git diff --name-only --diff-filter=U

# For each conflicted file:
# 1. Understand what upstream changed
git show MERGE_HEAD:package.json | head -20

# 2. Understand what we changed
git show HEAD:package.json | head -20

# 3. Merge them intelligently
# - Usually: keep both sets of changes
# - Example in package.json: merge dependencies, scripts, etc.

# 4. Resolve conflict and stage
vim package.json
git add package.json
```

---

#### Issue 8: CI/CD Fails After Merge

**Symptom**: GitHub Actions or CI pipeline fails after pushing sync

**Cause**: Upstream changes broke compatibility with CI configuration

**Solution**:

```bash
# View CI logs in GitHub

# Check if it's a Node version issue
node --version
# Should be >=22.7.5 per package.json

# Locally replicate CI
npm run build
npm test

# If passes locally but fails in CI:
# - Check environment variables in CI config
# - Check if CI has older Node version cached
# - Force CI rebuild (usually a GitHub button)

# If persistent, rollback
git revert -m 1 <merge-commit-hash>
git push origin main
```

---

### Getting Help

If you encounter issues not covered above:

1. **Check UPSTREAM_SYNC.md** - Most common issues documented
2. **Review git log** - See what changed in the merge
3. **Check GitHub Issues** - Upstream repo may have similar issues
4. **Create a rollback** - If urgent, rollback and debug in isolation
5. **Document for future** - Add solution to Troubleshooting section

---

## Quick Reference Cards

### Sync Status at a Glance

```bash
# One command to check everything
./scripts/sync-upstream.sh status
```

### Pre-Sync Health Check

```bash
git status                 # Clean working directory?
npm test                   # Tests passing?
npm run build             # Build successful?
git remote -v             # Upstream configured?
```

### Full Sync Sequence

```bash
./scripts/sync-upstream.sh          # Check status and changes
./scripts/sync-upstream.sh merge    # Attempt merge
./scripts/sync-upstream.sh validate # Build and test
# Then: Update UPSTREAM_SYNC.md and push
```

### Emergency Rollback

```bash
git revert -m 1 <merge-commit-hash>
# or
git reset --hard <previous-commit>
git push origin main
```

### Integration Point Quick Check

```bash
grep -n "\[ASSESSMENT-INTEGRATION\]" client/src/App.tsx
# Should show 6 matches with line numbers ~73, 134, 378, 1034, 1071, 1252
```

---

## Summary

**Sync Workflow in 3 Steps**:

1. **Check**: `./scripts/sync-upstream.sh` (status + diff)
2. **Merge**: `./scripts/sync-upstream.sh merge` (or manual if conflicts)
3. **Validate**: `./scripts/sync-upstream.sh validate` (build + test)

**Conflict Management**:

- Keep our 6 integration points
- Accept upstream changes elsewhere
- Re-test thoroughly
- Document in UPSTREAM_SYNC.md

**Risk Mitigation**:

- Always check status first (no surprises)
- Commit your work before syncing
- Create backup branch before merge
- Run tests after successful merge
- Roll back immediately if issues arise

---

**Last Updated**: 2026-01-03
**Upstream Version**: v0.18.0 (as of 2025-12-23)
**Maintained By**: Bryan Thompson (triepod-ai)
**Questions?**: See [UPSTREAM_SYNC.md](../UPSTREAM_SYNC.md) for integration point details
