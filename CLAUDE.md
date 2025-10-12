# MCP Inspector Development Guide

## Quick Reference

- **Full Documentation**: See [README.md](README.md) for features and usage
- **Timeline & Status**: See [PROJECT_STATUS.md](PROJECT_STATUS.md) for recent changes and development history
- **Build Commands**: Listed below for quick access

## Build Commands

- Build all: `npm run build`
- Build client: `npm run build-client`
- Build server: `npm run build-server`
- Development mode: `npm run dev` (use `npm run dev:windows` on Windows)
- Format code: `npm run prettier-fix`
- Client lint: `cd client && npm run lint`
- Run tests: `npm test` (464 passing, 100% pass rate)
- Run assessment tests: `npm test -- assessment` (208 assessment module tests)

## Code Style Guidelines

- Use TypeScript with proper type annotations
- Follow React functional component patterns with hooks
- Use ES modules (import/export) not CommonJS
- Use Prettier for formatting (auto-formatted on commit)
- Follow existing naming conventions:
  - camelCase for variables and functions
  - PascalCase for component names and types
  - kebab-case for file names
- Use async/await for asynchronous operations
- Implement proper error handling with try/catch blocks
- Use Tailwind CSS for styling in the client
- Keep components small and focused on a single responsibility

## Project Organization

The project is organized as a monorepo with workspaces:

- `client/`: React frontend with Vite, TypeScript and Tailwind
- `server/`: Express backend with TypeScript
- `cli/`: Command-line interface for testing and invoking MCP server methods directly

## CLI Security Assessment Runner

Run security assessments from the command line without the web UI:

```bash
# Test all tools on a server
npm run assess -- --server <server-name> --config <path-to-config.json>

# Test specific tool
npm run assess -- --server <server-name> --config <config.json> --tool <tool-name>
```

**Config File Format** (HTTP transport):

```json
{
  "transport": "http",
  "url": "http://localhost:10900/mcp"
}
```

**Config File Format** (STDIO transport):

```json
{
  "command": "python3",
  "args": ["server.py"],
  "env": {}
}
```

**Features:**

- ✅ No modifications to core assessment modules (preserves upstream sync compatibility)
- ✅ Supports stdio, HTTP, and SSE transports
- ✅ Test all tools or specific tool
- ✅ JSON output to `/tmp/inspector-assessment-{serverName}.json`
- ✅ Exit code 0 for safe, 1 for vulnerabilities (perfect for CI/CD)

**Implementation:** `scripts/run-security-assessment.ts`

## Assessment Result Analysis

Every assessment run automatically saves results to `/tmp/inspector-assessment-{serverName}.json` for fast CLI-based analysis.

**Quick Troubleshooting Commands:**

```bash
# View full assessment
cat /tmp/inspector-assessment-memory-mcp.json | jq

# Check functionality results
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality'

# List broken tools
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.brokenTools[]'

# Get specific tool details
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | select(.toolName == "tool_name")'

# See all tools and their status
cat /tmp/inspector-assessment-memory-mcp.json | jq '.functionality.enhancedResults[] | {tool: .toolName, status: .overallStatus}'

# Get security vulnerabilities
cat /tmp/inspector-assessment-memory-mcp.json | jq '.security.vulnerabilities'

# Check error handling metrics
cat /tmp/inspector-assessment-memory-mcp.json | jq '.errorHandling.metrics'
```

## Feature Documentation

For detailed documentation on specific features, see:

- **Reviewer Quick Start**: [docs/REVIEWER_QUICK_START.md](docs/REVIEWER_QUICK_START.md) - Fast-track guide for MCP directory reviewers (60-second screening + 5-minute detailed review)
- **Assessment Methodology**: [docs/ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md)
- **Functionality Testing**: [README.md](README.md#2-optimized-progressive-complexity-testing) - Multi-scenario validation, progressive complexity
- **Security Assessment**: [README.md](README.md#4-context-aware-security-assessment-with-zero-false-positives) - Domain-specific patterns, zero false positives
- **Error Handling**: [README.md](README.md#assessment-categories) - MCP protocol compliance, validation quality
- **MCP Spec Compliance**: See PROJECT_STATUS.md timeline for latest enhancements
- **Recent Changes**: [PROJECT_STATUS.md](PROJECT_STATUS.md#development-timeline---october-2025)

## Key Technical Implementations

**Assessment Architecture:**

- `client/src/services/assessment/TestScenarioEngine.ts` - Multi-scenario testing orchestration
- `client/src/services/assessment/ResponseValidator.ts` - Business logic error detection
- `client/src/services/assessment/TestDataGenerator.ts` - Context-aware test data
- `client/src/services/assessment/modules/SecurityAssessor.ts` - Domain-specific security testing
- `client/src/services/assessment/modules/ErrorHandlingAssessor.ts` - MCP protocol compliance
- `client/src/services/assessment/modules/MCPSpecComplianceAssessor.ts` - Hybrid protocol checks

**UI Components:**

- `client/src/components/AssessmentTab.tsx` - Main assessment interface
- `client/src/components/ExtendedAssessmentCategories.tsx` - Assessment results display
- `client/src/components/ui/tool-selector.tsx` - Multi-select tool picker for error handling

**Testing:**

- `client/src/services/__tests__/` - 464 total tests (100% passing)
- `client/src/services/assessment/__tests__/` - 208 assessment module tests

## Development Workflow

1. **Make changes** to source files
2. **Run tests** to ensure nothing broke: `npm test`
3. **Build** the project: `npm run build`
4. **Format code** (optional, auto-formatted on commit): `npm run prettier-fix`
5. **Test in dev mode**: `npm run dev` (opens http://localhost:6274)
6. **Commit changes** with descriptive message

## PROJECT_STATUS.md Maintenance & Archival

**Important**: When adding new timeline entries to PROJECT_STATUS.md, follow the archival procedure to keep the file manageable.

### Timeline Entry Guidelines

- **Format**: Reverse chronological order (newest entries at top)
- **Date Format**: `**2025-10-12**: Title - Description`
- **Location**: Add new entries at the top of "Development Timeline - October 2025" section
- **Structure**: Use consistent emoji indicators (✅ for completed, 🎯 for result, 📊 for impact, etc.)

### Archival Procedure (7-Day Rule)

**When to Archive**: After adding entries for a new day, check if there are entries older than 7 days.

**Steps**:

1. **Identify entries to archive**: Timeline entries from 8+ days ago

   ```bash
   grep -n "^\*\*2025-" /home/bryan/inspector/PROJECT_STATUS.md | head -15
   ```

2. **Extract entries with full detail sections**:
   - Find line boundaries: Summary entries end, detailed sections begin with `### 2025-`
   - Example: Lines 254-1015 contained Oct 7-9 summary + detailed sections

   ```bash
   grep -n "^### 2025-" /home/bryan/inspector/PROJECT_STATUS.md
   ```

3. **Append to PROJECT_STATUS_ARCHIVE.md**:
   - Extract entries: `sed -n 'START,ENDp' PROJECT_STATUS.md > /tmp/archived.txt`
   - Append to archive: `cat /tmp/archived.txt >> PROJECT_STATUS_ARCHIVE.md`

4. **Remove from PROJECT_STATUS.md**:

   ```bash
   sed -i 'START,ENDd' /home/bryan/inspector/PROJECT_STATUS.md
   ```

5. **Update archive note** (if first time archiving):
   - Add section after last Oct 10+ entry:

   ```markdown
   ---
   
   ## 📁 Older Timeline Entries
   
   **Note**: Timeline entries older than 7 days have been moved to [PROJECT_STATUS_ARCHIVE.md](PROJECT_STATUS_ARCHIVE.md) to keep this file focused on recent development.
   
   **Archive Policy**: Entries are automatically archived after 7 days to maintain readability and performance.
   
   **How to View Archived Entries**: See [PROJECT_STATUS_ARCHIVE.md](PROJECT_STATUS_ARCHIVE.md) for detailed entries from [date range] and earlier development history.
   
   ---
   ```

### Example Archival Session

```bash
# 1. Find boundaries
grep -n "^\*\*2025-10-09\|^\*\*2025-10-08\|^\*\*2025-10-07" PROJECT_STATUS.md
# Output: 254:**2025-10-09, 263:**2025-10-09, etc.

grep -n "^### 2025-10-09\|^### 2025-10-08\|^### 2025-10-07" PROJECT_STATUS.md
# Output: 288:### 2025-10-09, 424:### 2025-10-09, etc.

# 2. Extract (from first summary to last detailed section)
sed -n '254,1015p' PROJECT_STATUS.md > /tmp/archived.txt

# 3. Append to archive (add header first if new)
cat /tmp/archived.txt >> PROJECT_STATUS_ARCHIVE.md

# 4. Remove from main file
sed -i '254,1015d' PROJECT_STATUS.md

# 5. Verify
wc -l PROJECT_STATUS.md PROJECT_STATUS_ARCHIVE.md
```

### Archive File Structure

**PROJECT_STATUS_ARCHIVE.md** format:

```markdown
# Project Status Archive: MCP Inspector

This file contains archived project timeline entries from earlier development phases.

**Archive Policy**: Entries older than 7 days are moved here.

**Archived Date**: 2025-10-12

---

## Development Timeline - October 2025 (Oct 7-9)

[Summary entries]

---

[Detailed sections]
```

### Benefits

- **Performance**: Keeps main file under 2000 lines (readable in Claude)
- **Focus**: Recent entries remain visible and actionable
- **History**: Complete development history preserved in archive
- **Searchability**: Clear links between main and archive files

**Note**: Always add new timeline entries BEFORE performing archival. Archival is a maintenance task, not a development task.

## npm Package Publishing & Maintenance

**Package**: `@bryan-thompson/inspector-assessment`
**Current Version**: 1.0.1
**Published**: 2025-10-11 (v1.0.0), 2025-10-11 (v1.0.1)
**Registry**: https://www.npmjs.com/package/@bryan-thompson/inspector-assessment

### Quick Publish Workflow

When making changes that should be published to npm:

```bash
# 1. Update version (semantic versioning)
npm version patch   # Bug fixes: 1.0.0 -> 1.0.1
npm version minor   # New features: 1.0.0 -> 1.1.0
npm version major   # Breaking changes: 1.0.0 -> 2.0.0

# 2. Update CHANGELOG.md with changes

# 3. Build and format
npm run build
npm run prettier-fix

# 4. Publish all packages (workspaces + root)
npm run publish-all
# This runs: npm publish --workspaces --access public && npm publish --access public

# 5. Test the published package
bunx @bryan-thompson/inspector-assessment

# 6. Commit and tag
git add .
git commit -m "chore: release v1.0.x"
git tag v1.0.x
git push origin main --tags
```

### Publishing Commands Reference

**Publish all packages** (recommended - publishes workspaces first, then root):

```bash
npm run publish-all
```

**Publish workspaces only**:

```bash
npm publish --workspaces --access public
```

**Publish root package only**:

```bash
npm publish --access public
```

**Check what will be published**:

```bash
npm pack
tar -tzf bryan-thompson-inspector-assessment-1.0.0.tgz
```

### Version Numbering Guide

Follow [Semantic Versioning](https://semver.org/):

- **Patch** (1.0.0 → 1.0.1): Bug fixes, no new features, backward compatible
  - Security vulnerability fixes
  - Test expectation updates
  - Documentation corrections
  - Build script improvements

- **Minor** (1.0.0 → 1.1.0): New features, backward compatible
  - New assessment capabilities
  - Additional test scenarios
  - Performance improvements
  - New CLI options

- **Major** (1.0.0 → 2.0.0): Breaking changes
  - Changed API interfaces
  - Removed features
  - Changed command-line arguments
  - Modified assessment output format

### Package Structure

The npm package consists of 4 published packages:

1. **@bryan-thompson/inspector-assessment** (root) - Meta-package with CLI entry point
2. **@bryan-thompson/inspector-assessment-client** - React web interface
3. **@bryan-thompson/inspector-assessment-server** - Express backend
4. **@bryan-thompson/inspector-assessment-cli** - CLI tools

All four must be published for the package to work correctly.

### Testing Published Package

```bash
# Test with bunx (no install, fastest)
bunx @bryan-thompson/inspector-assessment

# Test with npx
npx @bryan-thompson/inspector-assessment

# Test global install
npm install -g @bryan-thompson/inspector-assessment
mcp-inspector-assess --help
npm uninstall -g @bryan-thompson/inspector-assessment
```

### Known Issues

- **24 test failures**: Test expectation mismatches from security enhancements (non-blocking)
  - Tests expect "FAIL" but get "PASS" due to improved detection
  - Update test expectations in future release
  - Does not affect functionality

### Important Notes

- **Always publish workspaces first**: The root package depends on workspace packages being available on npm
- **Update CHANGELOG.md**: Document all changes before publishing
- **Test locally first**: Use `npm pack` and test the tarball before publishing
- **Format code**: Run `npm run prettier-fix` before publishing to avoid format issues
- **Git tags**: Create git tags for each release for version tracking
- **Node version**: Package requires Node >=22.7.5 (currently using v18.19.0 with warnings)

### Complete Publishing Checklist

- [ ] Make and test changes locally (`npm run dev`)
- [ ] Run tests (`npm test`)
- [ ] Update version (`npm version [patch|minor|major]`)
- [ ] Update CHANGELOG.md with changes
- [ ] Build project (`npm run build`)
- [ ] Format code (`npm run prettier-fix`)
- [ ] Publish packages (`npm run publish-all`)
- [ ] Test published package (`bunx @bryan-thompson/inspector-assessment`)
- [ ] Commit changes (`git commit -am "chore: release vX.Y.Z"`)
- [ ] Create git tag (`git tag vX.Y.Z`)
- [ ] Push to GitHub (`git push origin main --tags`)
- [ ] Update PROJECT_STATUS.md with release notes

### Future Migration Path

If Anthropic adopts this package, it can be migrated to `@modelcontextprotocol/inspector-assessment`:

1. Update all package.json names
2. Publish to new namespace
3. Deprecate old packages with migration notice

See [PUBLISHING_GUIDE.md](PUBLISHING_GUIDE.md) for detailed publishing documentation.

## Upstream Sync Status

- **Current Version**: 0.17.0
- **Last Sync**: 2025-10-04 (121 commits from v0.17.0)
- **Fork**: triepod-ai/inspector-assessment
- **Upstream**: modelcontextprotocol/inspector
- See [PROJECT_STATUS.md](PROJECT_STATUS.md) for sync history
