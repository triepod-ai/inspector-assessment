# Early Tool Discovery Output (v1.9.0)

## Purpose

The inspector CLI outputs tool discovery events to stderr in JSONL format immediately after the `listTools()` MCP call. This enables real-time UI updates in MCP Auditor and other consumers, showing tools 60-90 seconds before the full assessment completes.

## Format

Tools are output to stderr as JSONL (JSON Lines), one event per line:

```jsonl
{"event":"server_connected","serverName":"my-server","transport":"http"}
{"event":"tool_discovered","name":"tool_name","description":"Tool description","params":[...]}
{"event":"tools_discovery_complete","count":N}
```

## Event Details

### `server_connected`

Emitted immediately after connecting to the MCP server:

```json
{ "event": "server_connected", "serverName": "memory-mcp", "transport": "http" }
```

### `tool_discovered`

Emitted for each tool found. Includes full parameter metadata extracted from the tool's `inputSchema`:

```json
{
  "event": "tool_discovered",
  "name": "add_memory",
  "description": "Store a memory in the database",
  "params": [
    {
      "name": "content",
      "type": "string",
      "required": true,
      "description": "The memory content to store"
    },
    {
      "name": "tags",
      "type": "array",
      "required": false
    }
  ]
}
```

**Fields:**

| Field         | Type           | Description                             |
| ------------- | -------------- | --------------------------------------- |
| `name`        | string         | Tool name                               |
| `description` | string \| null | Tool description (null if not provided) |
| `params`      | array          | Parameter definitions from inputSchema  |

**Param object fields:**

| Field         | Type              | Description                                            |
| ------------- | ----------------- | ------------------------------------------------------ |
| `name`        | string            | Parameter name                                         |
| `type`        | string            | Type from schema (string, number, object, array, etc.) |
| `required`    | boolean           | Whether parameter is required                          |
| `description` | string (optional) | Parameter description if provided                      |

### `tools_discovery_complete`

Emitted after all tools have been listed:

```json
{ "event": "tools_discovery_complete", "count": 17 }
```

## Example Output

```jsonl
{"event":"server_connected","serverName":"memory-mcp","transport":"http"}
{"event":"tool_discovered","name":"add_memory","description":"Store a memory","params":[{"name":"content","type":"string","required":true}]}
{"event":"tool_discovered","name":"search_memories","description":"Search stored memories","params":[{"name":"query","type":"string","required":true},{"name":"limit","type":"number","required":false}]}
{"event":"tool_discovered","name":"delete_memory","description":"Delete a memory by ID","params":[{"name":"id","type":"string","required":true}]}
{"event":"tools_discovery_complete","count":3}
```

## Implementation

**Files:**

- `scripts/run-full-assessment.ts` - Full assessment CLI
- `scripts/run-security-assessment.ts` - Security-only assessment CLI

**Key functions:**

```typescript
function emitToolDiscovered(tool: Tool): void {
  const params = extractToolParams(tool.inputSchema);
  emitJSONL({
    event: "tool_discovered",
    name: tool.name,
    description: tool.description || null,
    params,
  });
}

function extractToolParams(schema: unknown): Array<{
  name: string;
  type: string;
  required: boolean;
  description?: string;
}> {
  // Extracts parameter metadata from JSON Schema inputSchema
}
```

## Consumer Integration

### MCP Auditor

MCP Auditor parses these JSONL events to:

1. **Display tools immediately** - Tools appear in sidebar within 2-5 seconds of audit start
2. **Show parameter details** - Full parameter info available before assessment completes
3. **Update progress** - "Connecting..." → "Found 17 tools" as events arrive

### Parsing Example (JavaScript)

```javascript
proc.stderr.on("data", (data) => {
  const lines = data.toString().split("\n");
  for (const line of lines) {
    if (!line.startsWith("{")) continue;
    try {
      const event = JSON.parse(line);
      if (event.event === "tool_discovered") {
        console.log(`Tool: ${event.name}`);
        console.log(`  Description: ${event.description}`);
        console.log(`  Parameters: ${event.params.length}`);
        for (const p of event.params) {
          console.log(
            `    - ${p.name} (${p.type})${p.required ? " *required" : ""}`,
          );
        }
      }
    } catch (e) {
      // Not JSON, ignore
    }
  }
});
```

### Parsing Example (Shell)

```bash
# Get all tool names
npm run assess:full -- ... 2>&1 | grep '"event":"tool_discovered"' | jq -r '.name'

# Get tools with their parameter counts
npm run assess:full -- ... 2>&1 | grep '"event":"tool_discovered"' | jq '{name: .name, paramCount: (.params | length)}'

# Get required parameters for each tool
npm run assess:full -- ... 2>&1 | grep '"event":"tool_discovered"' | jq '{tool: .name, required: [.params[] | select(.required) | .name]}'
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

### After (with JSONL early output)

```
[0s]   Submit audit
[5s]   Clone repository
[20s]  Install dependencies
[30s]  Build server
[32s]  {"event":"server_connected",...}
[33s]  {"event":"tool_discovered",...} → TOOLS APPEAR IN UI
[34s]  {"event":"tools_discovery_complete",...}
[60s]  Inspector continues with 11 modules
[120s] Assessment complete
```

**User benefit**: See tools with full parameter details 60-90 seconds earlier.

## Why stderr?

- `stdout` is reserved for human-readable summary output
- `stderr` is parseable by audit workers and CI/CD pipelines
- JSONL format allows reliable parsing with `JSON.parse()`
- Does not interfere with piping stdout to files

## Migration from v1.8.x

The v1.8.x pipe-delimited format has been replaced:

**Old format (deprecated):**

```
TOOL_DISCOVERED:tool_name|tool_description
```

**New format (v1.9.0+):**

```json
{"event":"tool_discovered","name":"tool_name","description":"tool_description","params":[...]}
```

**Key improvements:**

- Full parameter metadata now included
- Proper JSON escaping for special characters
- Consistent format with all other progress events
- Easier parsing with standard JSON libraries

## Version History

- **v1.9.0**: Converted to JSONL format with full parameter metadata
  - Changed from pipe-delimited to JSON format
  - Added `params[]` array with type, required, and description
  - Added `server_connected` event
  - Added `tools_discovery_complete` event
- **v1.8.1**: Initial implementation with pipe-delimited format (deprecated)
