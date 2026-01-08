# Architecture Detection Guide

**Module**: `ArchitectureDetector`
**Location**: `client/src/services/assessment/modules/annotations/ArchitectureDetector.ts`
**Added in**: Issue #57

---

## Overview

The Architecture Detector analyzes MCP servers to identify their infrastructure characteristics:

- **Database backends** (Neo4j, MongoDB, PostgreSQL, etc.)
- **Transport modes** (stdio, HTTP, SSE)
- **Server type** (local, hybrid, remote)
- **Network requirements** and external dependencies

This information helps operators understand deployment requirements and security implications before integrating an MCP server.

---

## Use Cases

### 1. Deployment Planning

Determine what infrastructure an MCP server requires:

```typescript
const analysis = detectArchitecture(context);
if (analysis.databaseBackends.includes("neo4j")) {
  console.log("Server requires Neo4j database");
}
if (analysis.requiresNetworkAccess) {
  console.log("Server needs internet access - review firewall rules");
}
```

### 2. Security Assessment

Identify servers with external dependencies:

```typescript
if (analysis.serverType === "remote") {
  console.warn("Remote server - data leaves local network");
}
if (analysis.externalDependencies.length > 0) {
  console.log("External services:", analysis.externalDependencies);
}
```

### 3. Cloud Readiness Evaluation

Check if a server can run in restricted environments:

```typescript
const canRunOffline =
  analysis.serverType === "local" && !analysis.requiresNetworkAccess;
```

---

## Supported Databases

The detector identifies 12 database types:

| Database        | Detection Method                                  |
| --------------- | ------------------------------------------------- |
| `neo4j`         | Package deps, cypher queries, bolt:// connections |
| `mongodb`       | Package deps, MongoDB connection strings          |
| `postgresql`    | Package deps, pg:// connections, psql patterns    |
| `mysql`         | Package deps, mysql:// connections                |
| `sqlite`        | Package deps, .db/.sqlite file patterns           |
| `redis`         | Package deps, redis:// connections                |
| `dynamodb`      | AWS SDK deps, DynamoDB API patterns               |
| `firestore`     | Firebase deps, Firestore API patterns             |
| `supabase`      | Supabase client deps, connection patterns         |
| `cassandra`     | Driver deps, CQL patterns                         |
| `elasticsearch` | Client deps, Elasticsearch API patterns           |
| `unknown`       | Database-like operations but type not identified  |

### Detection Sources

Databases are detected from multiple sources (in order of confidence):

1. **Package dependencies** (highest confidence)
   - `package.json` dependencies/devDependencies
   - `requirements.txt` for Python servers
   - Manifest dependencies

2. **Tool patterns** (medium confidence)
   - Tool names containing query/select/insert
   - Tool descriptions mentioning database operations

3. **Source code patterns** (medium confidence)
   - Connection string patterns
   - Import statements
   - API call patterns

---

## Transport Modes

Three transport modes are detected:

| Mode    | Description                           | Detection Method                    |
| ------- | ------------------------------------- | ----------------------------------- |
| `stdio` | Standard input/output (local process) | Default, stdin/stdout patterns      |
| `http`  | HTTP-based transport                  | Express/Fastify deps, http patterns |
| `sse`   | Server-Sent Events                    | SSE endpoint patterns               |

### Transport from Connection

If you're already connected to the server, pass the transport type for highest confidence:

```typescript
const context: ArchitectureContext = {
  tools,
  transportType: "stdio", // Known from connection
};
```

---

## Server Classification

Servers are classified into three architecture types:

### `local`

- Uses stdio transport only
- No network requirements
- No external service dependencies
- Safest for air-gapped environments

**Example**: A local file system browser MCP server

### `hybrid`

- Uses stdio but requires network access
- Has some external dependencies
- Supports both local and remote transports

**Example**: An MCP server that uses stdio but calls the GitHub API

### `remote`

- Uses HTTP/SSE transport without stdio
- Multiple external service dependencies
- Data processing happens outside local machine

**Example**: A cloud-based MCP server running on a remote endpoint

### Classification Logic

```
IF (http OR sse) AND NOT stdio → remote
IF externalServices >= 3 → remote
IF stdio AND (http OR sse) → hybrid
IF stdio AND requiresNetwork → hybrid
IF externalServices > 0 → hybrid
ELSE → local
```

---

## API Reference

### `detectArchitecture(context: ArchitectureContext): ArchitectureAnalysis`

Main detection function.

**Parameters:**

```typescript
interface ArchitectureContext {
  /** Tools provided by the server */
  tools: Tool[];

  /** Transport type if known from connection */
  transportType?: string;

  /** Source code files (filename → content) */
  sourceCodeFiles?: Map<string, string>;

  /** Manifest JSON content */
  manifestJson?: {
    name?: string;
    description?: string;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  /** Package.json content */
  packageJson?: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };

  /** Requirements.txt content (Python) */
  requirementsTxt?: string;
}
```

**Returns:**

```typescript
interface ArchitectureAnalysis {
  /** Server classification: local | hybrid | remote */
  serverType: ServerArchitectureType;

  /** Primary database (first detected) */
  databaseBackend?: DatabaseBackend;

  /** All detected databases */
  databaseBackends: DatabaseBackend[];

  /** Supported transport modes */
  transportModes: TransportMode[];

  /** External services (GitHub, AWS, OpenAI, etc.) */
  externalDependencies: string[];

  /** Whether internet access is required */
  requiresNetworkAccess: boolean;

  /** Detection confidence: high | medium | low */
  confidence: "high" | "medium" | "low";

  /** Supporting evidence */
  evidence: {
    databaseIndicators: string[];
    transportIndicators: string[];
    networkIndicators: string[];
  };
}
```

### `hasDatabaseToolPatterns(tools: Tool[]): boolean`

Quick check if tools suggest database operations.

```typescript
if (hasDatabaseToolPatterns(serverTools)) {
  // Server likely works with a database
  const analysis = detectArchitecture({ tools: serverTools });
}
```

### `extractDatabasesFromDependencies(dependencies: Record<string, string>): DatabaseBackend[]`

Extract database types from package.json dependencies.

```typescript
const dbs = extractDatabasesFromDependencies({
  neo4j: "^5.0.0",
  pg: "^8.0.0",
});
// Returns: ["neo4j", "postgresql"]
```

---

## Type Definitions

### `DatabaseBackend`

```typescript
type DatabaseBackend =
  | "neo4j"
  | "mongodb"
  | "sqlite"
  | "postgresql"
  | "mysql"
  | "redis"
  | "dynamodb"
  | "firestore"
  | "supabase"
  | "cassandra"
  | "elasticsearch"
  | "unknown";
```

### `TransportMode`

```typescript
type TransportMode = "stdio" | "http" | "sse";
```

### `ServerArchitectureType`

```typescript
type ServerArchitectureType = "local" | "hybrid" | "remote";
```

---

## Confidence Scoring

Confidence is calculated based on available evidence:

| Evidence Source                    | Points |
| ---------------------------------- | ------ |
| High-confidence database match     | +30    |
| Low-confidence database match      | +15    |
| Known transport (from connection)  | +30    |
| Detected transport (from patterns) | +20    |
| Source code files available        | +20    |
| Package.json/requirements.txt      | +15    |
| 3+ tools with descriptions         | +15    |
| Some tools with descriptions       | +10    |

**Confidence Levels:**

- **High**: 60+ points
- **Medium**: 30-59 points
- **Low**: < 30 points

---

## Examples

### Example 1: Local File Browser

```typescript
const context: ArchitectureContext = {
  tools: [
    { name: "list_files", description: "List files in a directory" },
    { name: "read_file", description: "Read contents of a file" },
    { name: "write_file", description: "Write contents to a file" },
  ],
  transportType: "stdio",
};

const result = detectArchitecture(context);
// {
//   serverType: "local",
//   databaseBackend: undefined,
//   databaseBackends: [],
//   transportModes: ["stdio"],
//   externalDependencies: [],
//   requiresNetworkAccess: false,
//   confidence: "medium"
// }
```

### Example 2: Neo4j Graph Database Server

```typescript
const context: ArchitectureContext = {
  tools: [
    { name: "cypher_query", description: "Execute a Cypher query" },
    { name: "create_node", description: "Create a graph node" },
  ],
  packageJson: {
    dependencies: {
      "neo4j-driver": "^5.0.0",
    },
  },
};

const result = detectArchitecture(context);
// {
//   serverType: "hybrid",
//   databaseBackend: "neo4j",
//   databaseBackends: ["neo4j"],
//   transportModes: ["stdio"],
//   externalDependencies: [],
//   requiresNetworkAccess: true,  // Neo4j server connection
//   confidence: "high"
// }
```

### Example 3: Cloud API Gateway

```typescript
const context: ArchitectureContext = {
  tools: [
    { name: "call_openai", description: "Call OpenAI API" },
    { name: "store_to_s3", description: "Upload to AWS S3" },
    { name: "query_github", description: "Query GitHub API" },
  ],
  transportType: "http",
  packageJson: {
    dependencies: {
      openai: "^4.0.0",
      "@aws-sdk/client-s3": "^3.0.0",
      "@octokit/rest": "^20.0.0",
    },
  },
};

const result = detectArchitecture(context);
// {
//   serverType: "remote",
//   databaseBackend: undefined,
//   databaseBackends: [],
//   transportModes: ["http"],
//   externalDependencies: ["openai", "aws", "github"],
//   requiresNetworkAccess: true,
//   confidence: "high"
// }
```

---

## Troubleshooting

### Low Confidence Results

If detection confidence is low, provide more context:

1. **Add package.json** - Dependencies are high-confidence signals
2. **Include source code** - More patterns to analyze
3. **Specify transport type** - Known from your connection

### False Positives

Database detection may have false positives if tool names match database keywords accidentally. Check the `evidence.databaseIndicators` to see what triggered detection.

### Missing Database Types

If your database isn't detected:

1. Check if it's in the supported list
2. Ensure the dependency name matches expected patterns
3. Consider adding to `architecturePatterns.ts` (see Contributing)

---

## Related Documentation

- [Behavior Inference Guide](BEHAVIOR_INFERENCE_GUIDE.md) - Tool behavior classification
- [Assessment Catalog](ASSESSMENT_CATALOG.md) - All assessment modules
- [Tool Annotation Assessor](ASSESSMENT_CATALOG.md#toolannotationassessor) - How architecture detection integrates

---

## Import Paths

```typescript
// From published package
import {
  detectArchitecture,
  hasDatabaseToolPatterns,
  extractDatabasesFromDependencies,
} from "@bryan-thompson/inspector-assessment/annotations";

// Types
import type {
  ArchitectureContext,
  ArchitectureAnalysis,
  DatabaseBackend,
  TransportMode,
  ServerArchitectureType,
} from "@bryan-thompson/inspector-assessment/annotations";
```
