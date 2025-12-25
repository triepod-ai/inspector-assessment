# Early Tool Discovery Output

## Purpose

The inspector CLI outputs individual tools to stderr immediately after the `listTools()` MCP call. This enables real-time UI updates in MCP Auditor and other consumers.

## Format

Tools are output to stderr with the following format:

```
TOOL_DISCOVERED:tool_name|tool_description
```

### Examples

```
TOOL_DISCOVERED:generate_chart|Generate a chart from data
TOOL_DISCOVERED:export_data|Export data to CSV or JSON format
TOOL_DISCOVERED:validate_input|Validate user input against schema
```

### Edge Cases

- Empty description: `TOOL_DISCOVERED:my_tool|`
- Description with special chars: Preserved as-is (no escaping)
- Tool names are not escaped (assumed valid identifiers)

## Location

**File**: `cli/src/assess-full.ts`
**After**: Line 346 (`client.listTools()`)

```typescript
// Output individual tools to stderr for early parsing by audit-worker
// Format: TOOL_DISCOVERED:name|description
// This enables MCP Auditor UI to show tools immediately after connection
for (const tool of tools) {
  const description = tool.description || "";
  console.error(`TOOL_DISCOVERED:${tool.name}|${description}`);
}
```

## Consumer: MCP Auditor

MCP Auditor's `audit-worker.js` parses these lines to:

1. **Display tools in UI immediately** - Tools appear in the sidebar within 2-5 seconds of audit start
2. **Save to database during running state** - Frontend polling can show tools before assessment completes
3. **Show progress to users** - "Discovering tools..." → actual tool list 60+ seconds earlier

### Parsing Pattern

```javascript
const toolPattern = /^TOOL_DISCOVERED:([^|]+)\|(.*)$/;
const toolMatch = line.match(toolPattern);
if (toolMatch) {
  const [, toolName, toolDescription] = toolMatch;
  // Save tool to progress...
}
```

## Timeline Comparison

### Before (without early output)

```
[0s]   Submit audit
[5s]   Clone repository
[20s]  Install dependencies
[30s]  Build server
[60s]  Inspector runs all 11 modules
[120s] Tools appear in UI (from final JSON results)
```

### After (with early output)

```
[0s]   Submit audit
[5s]   Clone repository
[20s]  Install dependencies
[30s]  Build server
[32s]  Inspector connects → TOOLS APPEAR IN UI
[60s]  Inspector continues with 11 modules
[120s] Assessment complete
```

**User benefit**: See tools 60-90 seconds earlier.

## Why stderr?

- `stdout` is reserved for JSON output (with `--json` flag)
- `stderr` is visible in terminal but parseable by audit-worker
- Structured format allows reliable regex parsing
- Does not interfere with JSON parsing of final results

## Maintenance Notes

- The `TOOL_DISCOVERED:` prefix must remain stable for backward compatibility
- If adding more early outputs, use similar prefix patterns (e.g., `RESOURCE_DISCOVERED:`)
- Changes here require corresponding updates in MCP Auditor's audit-worker.js
