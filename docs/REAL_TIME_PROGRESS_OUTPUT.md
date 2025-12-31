# Real-Time JSONL Progress Output (v1.9.0)

## Overview

The MCP Inspector emits real-time progress events to stderr in JSONL (JSON Lines) format during assessment execution. This enables external tools (like the MCP Auditor) to parse and display live progress as each phase completes.

## Output Format

Each line is a valid JSON object with an `event` field indicating the event type:

```jsonl
{"event":"<event_type>", ...fields}
```

## Event Types

### 1. `server_connected`

Emitted immediately after connecting to the MCP server.

```json
{ "event": "server_connected", "serverName": "my-server", "transport": "http" }
```

| Field        | Type   | Description                                     |
| ------------ | ------ | ----------------------------------------------- |
| `serverName` | string | Name of the server being assessed               |
| `transport`  | string | Transport type: `"stdio"`, `"http"`, or `"sse"` |

### 2. `tool_discovered`

Emitted for each tool found during discovery.

```json
{
  "event": "tool_discovered",
  "name": "add_memory",
  "description": "Store a memory",
  "params": [{ "name": "content", "type": "string", "required": true }]
}
```

| Field         | Type           | Description                            |
| ------------- | -------------- | -------------------------------------- |
| `name`        | string         | Tool name                              |
| `description` | string \| null | Tool description                       |
| `params`      | array          | Parameter definitions from inputSchema |

**Param object fields:**

- `name` (string): Parameter name
- `type` (string): Parameter type (e.g., "string", "number", "object")
- `required` (boolean): Whether the parameter is required
- `description` (string, optional): Parameter description

### 3. `tools_discovery_complete`

Emitted after all tools have been discovered.

```json
{ "event": "tools_discovery_complete", "count": 17 }
```

| Field   | Type   | Description                      |
| ------- | ------ | -------------------------------- |
| `count` | number | Total number of tools discovered |

### 4. `module_complete`

Emitted after each assessment module completes.

```json
{
  "event": "module_complete",
  "module": "security",
  "status": "FAIL",
  "score": 70
}
```

| Field    | Type   | Description                               |
| -------- | ------ | ----------------------------------------- |
| `module` | string | Module name in snake_case                 |
| `status` | string | `"PASS"`, `"FAIL"`, or `"NEED_MORE_INFO"` |
| `score`  | number | Score from 0-100                          |

**Module names:**

Core modules (5):

- `functionality`
- `security`
- `documentation`
- `error_handling`
- `usability`

Extended modules (6):

- `mcp_spec`
- `aup`
- `annotations`
- `libraries`
- `manifest`
- `portability`

#### AUP Module Enrichment

When `module=aup`, the `module_complete` event includes additional fields for Claude analysis:

```json
{
  "event": "module_complete",
  "module": "aup",
  "status": "FAIL",
  "score": 70,
  "testsRun": 15,
  "duration": 250,
  "version": "1.19.5",
  "violationsSample": [
    {
      "category": "B",
      "categoryName": "Child Safety",
      "severity": "CRITICAL",
      "matchedText": "csam_generator",
      "location": "tool_name",
      "confidence": "high"
    }
  ],
  "samplingNote": "Sampled 5 of 12 violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).",
  "violationMetrics": {
    "total": 12,
    "critical": 2,
    "high": 5,
    "medium": 5,
    "byCategory": { "B": 2, "E": 5, "G": 5 }
  },
  "scannedLocations": {
    "toolNames": true,
    "toolDescriptions": true,
    "readme": true,
    "sourceCode": false
  },
  "highRiskDomains": ["weapons", "financial"]
}
```

| Field              | Type   | Description                                                                |
| ------------------ | ------ | -------------------------------------------------------------------------- |
| `violationsSample` | array  | Up to 10 sampled violations, prioritized by severity                       |
| `samplingNote`     | string | Describes sampling methodology                                             |
| `violationMetrics` | object | Quantitative summary: total, critical, high, medium counts, and byCategory |
| `scannedLocations` | object | Boolean flags indicating which locations were scanned                      |
| `highRiskDomains`  | array  | Up to 10 detected high-risk domains (e.g., weapons, financial, medical)    |

**Violation sample fields:**

| Field          | Type   | Description                                                           |
| -------------- | ------ | --------------------------------------------------------------------- |
| `category`     | string | AUP category code (A-N)                                               |
| `categoryName` | string | Human-readable category name                                          |
| `severity`     | string | `"CRITICAL"`, `"HIGH"`, or `"MEDIUM"`                                 |
| `matchedText`  | string | The text that triggered the violation                                 |
| `location`     | string | Where found: `tool_name`, `tool_description`, `readme`, `source_code` |
| `confidence`   | string | Detection confidence: `"high"`, `"medium"`, `"low"`                   |

### 5. `assessment_complete`

Emitted when the entire assessment finishes.

```json
{
  "event": "assessment_complete",
  "overallStatus": "FAIL",
  "totalTests": 728,
  "executionTime": 19287,
  "outputPath": "/tmp/inspector-full-assessment-my-server.json"
}
```

| Field           | Type   | Description                         |
| --------------- | ------ | ----------------------------------- |
| `overallStatus` | string | `"PASS"` or `"FAIL"`                |
| `totalTests`    | number | Total test count across all modules |
| `executionTime` | number | Execution time in milliseconds      |
| `outputPath`    | string | Path to full JSON results file      |

## Complete Example Output

```jsonl
{"event":"server_connected","serverName":"memory-mcp","transport":"http"}
{"event":"tool_discovered","name":"add_memory","description":"Store a memory in the database","params":[{"name":"content","type":"string","required":true,"description":"The memory content to store"}]}
{"event":"tool_discovered","name":"search_memories","description":"Search stored memories","params":[{"name":"query","type":"string","required":true}]}
{"event":"tools_discovery_complete","count":2}
{"event":"module_complete","module":"functionality","status":"PASS","score":100}
{"event":"module_complete","module":"security","status":"PASS","score":100}
{"event":"module_complete","module":"documentation","status":"FAIL","score":0}
{"event":"module_complete","module":"error_handling","status":"PASS","score":95}
{"event":"module_complete","module":"usability","status":"PASS","score":100}
{"event":"module_complete","module":"mcp_spec","status":"PASS","score":92}
{"event":"module_complete","module":"aup","status":"PASS","score":100}
{"event":"module_complete","module":"annotations","status":"FAIL","score":0}
{"event":"module_complete","module":"libraries","status":"PASS","score":100}
{"event":"module_complete","module":"manifest","status":"FAIL","score":0}
{"event":"module_complete","module":"portability","status":"PASS","score":100}
{"event":"assessment_complete","overallStatus":"FAIL","totalTests":234,"executionTime":5234,"outputPath":"/tmp/inspector-full-assessment-memory-mcp.json"}
```

## Score Calculation

Scores are calculated differently based on module type:

| Module Type         | Score Source                 | Calculation                          |
| ------------------- | ---------------------------- | ------------------------------------ |
| Functionality       | `workingPercentage`          | Direct percentage of working tools   |
| Error Handling      | `metrics.mcpComplianceScore` | MCP compliance percentage            |
| MCP Spec Compliance | `complianceScore`            | Direct compliance score              |
| Security            | `vulnerabilities[]`          | `100 - (vulnCount * 10)`, min 0      |
| AUP Compliance      | `violations[]`               | `100 - (violationCount * 10)`, min 0 |
| Others              | Status-based                 | PASS=100, FAIL=0, other=50           |

## Implementation Details

- **Orchestrator**: `client/src/services/assessment/AssessmentOrchestrator.ts`
- **CLI Scripts**: `scripts/run-full-assessment.ts`, `scripts/run-security-assessment.ts`
- **Output Stream**: stderr (doesn't interfere with JSON stdout)

## Usage

Progress output is automatic when running CLI assessments:

```bash
npm run assess:full -- --server <server-name> --config <config.json>
```

JSONL events go to stderr while human-readable summary goes to stdout:

```bash
# Capture JSONL events to file
npm run assess:full -- --server my-server --config config.json 2>events.jsonl

# Parse events with jq
npm run assess:full -- --server my-server --config config.json 2>&1 | \
  grep '^{"event":' | jq -s '.'

# Filter specific event types
npm run assess:full -- --server my-server --config config.json 2>&1 | \
  grep '"event":"module_complete"' | jq '.module, .status, .score'
```

## Consumer Integration

### Shell (jq)

```bash
# Count events by type
npm run assess:full -- ... 2>&1 | grep '^{"event":' | jq -s 'group_by(.event) | map({event: .[0].event, count: length})'

# Get all tool names
npm run assess:full -- ... 2>&1 | grep '"event":"tool_discovered"' | jq -r '.name'

# Get failing modules
npm run assess:full -- ... 2>&1 | grep '"event":"module_complete"' | jq -r 'select(.status == "FAIL") | .module'
```

### JavaScript/Node.js

```javascript
const { spawn } = require("child_process");

const proc = spawn("npm", [
  "run",
  "assess:full",
  "--",
  "--server",
  "my-server",
  "--config",
  "config.json",
]);

proc.stderr.on("data", (data) => {
  const lines = data
    .toString()
    .split("\n")
    .filter((l) => l.startsWith("{"));
  for (const line of lines) {
    try {
      const event = JSON.parse(line);
      switch (event.event) {
        case "server_connected":
          console.log(
            `Connected to ${event.serverName} via ${event.transport}`,
          );
          break;
        case "tool_discovered":
          console.log(
            `Found tool: ${event.name} (${event.params.length} params)`,
          );
          break;
        case "module_complete":
          console.log(`${event.module}: ${event.status} (${event.score}%)`);
          break;
        case "assessment_complete":
          console.log(
            `Done: ${event.overallStatus} - ${event.totalTests} tests in ${event.executionTime}ms`,
          );
          break;
      }
    } catch (e) {
      // Not a JSON line, ignore
    }
  }
});
```

### Python

```python
import subprocess
import json

proc = subprocess.Popen(
    ["npm", "run", "assess:full", "--", "--server", "my-server", "--config", "config.json"],
    stderr=subprocess.PIPE,
    text=True
)

for line in proc.stderr:
    line = line.strip()
    if line.startswith("{"):
        try:
            event = json.loads(line)
            if event["event"] == "module_complete":
                print(f"{event['module']}: {event['status']} ({event['score']}%)")
        except json.JSONDecodeError:
            pass
```

## Tests

Comprehensive tests ensure the JSONL output works correctly:

- **File**: `client/src/services/assessment/__tests__/emitModuleProgress.test.ts`
- **Coverage**:
  - Valid JSON output for all event types
  - Correct field structure
  - Status values (PASS/FAIL/NEED_MORE_INFO)
  - Score calculation from various module result types
  - Module names in snake_case format

## Version History

- **v1.9.0**: Converted to JSONL format for machine parsing
  - All events now emitted as JSON objects
  - Added `server_connected` event
  - Added `tool_discovered` event with full parameter metadata
  - Added `tools_discovery_complete` event
  - Added `assessment_complete` event
  - Module names changed to snake_case format
- **v1.8.1**: Initial implementation with emoji-based text format (deprecated)
