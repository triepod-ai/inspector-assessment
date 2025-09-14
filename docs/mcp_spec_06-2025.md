# Complete Model Context Protocol (MCP) Specification

## Executive Summary and Latest Version

The Model Context Protocol (MCP) is an **open protocol enabling seamless integration between LLM applications and external data sources/tools**, functioning as a standardized "USB-C port for AI applications." The **latest version 2025-06-18** introduces structured tool output, enhanced security with OAuth 2.1 Resource Server classification, elicitation support for user input requests, and removes JSON-RPC batching support. MCP eliminates the N×M integration problem by providing a single protocol that all AI applications can use to connect with any MCP-compliant server.

## Core Architecture and Protocol Foundation

MCP implements a **client-server architecture using JSON-RPC 2.0** messaging over two conceptual layers. The **transport layer** handles communication channels through stdio (recommended), Streamable HTTP, or custom implementations, while the **data layer** manages JSON-RPC message exchange, lifecycle management, and core primitives. Hosts (LLM applications) initiate connections to servers (services) through managed clients, establishing a clear separation of concerns where AI applications focus on intelligence while delegating data retrieval and tool execution to specialized servers.

### Protocol Specification and Message Formats

All MCP messages **must follow JSON-RPC 2.0 specification** with UTF-8 encoding. The protocol defines three message types: **requests** (bidirectional with unique IDs), **responses** (matching request IDs with either result or error), and **notifications** (one-way messages without IDs). Messages are structured as follows:

```json
// Request Example
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": "unique-request-id"
}

// Response Example
{
  "jsonrpc": "2.0",
  "result": {...},
  "id": "unique-request-id"
}
```

The protocol mandates **no ID reuse within sessions**, **no batching support** (removed in 2025-06-18), and requires the `MCP-Protocol-Version` header for HTTP transport. Standard error codes range from parse errors (-32700) to internal errors (-32603), with custom application-specific codes permitted.

## Transport Mechanisms

### stdio Transport (Primary Recommendation)

The **stdio transport** operates by launching the MCP server as a subprocess, with the server reading JSON-RPC messages from stdin and writing responses to stdout. Messages are **newline-delimited** without embedded newlines, while stderr remains available for logging. This transport provides process-level security through the execution context and represents the simplest, most secure implementation path.

### Streamable HTTP Transport

Replacing the legacy HTTP+SSE transport, **Streamable HTTP** provides a single endpoint supporting POST for client requests and optional GET for server-to-client streaming. Security requirements include **Origin header validation** to prevent DNS rebinding, localhost binding for local servers, and mandatory authentication implementation. Session management uses the `Mcp-Session-Id` header with backwards compatibility through fallback to SSE endpoints.

## Server and Client Implementation Requirements

### Initialization and Capability Negotiation

Servers and clients **must implement** the initialization handshake exchanging protocol versions and capabilities:

```typescript
interface InitializeRequest {
  protocolVersion: string; // e.g., "2025-06-18"
  capabilities: ClientCapabilities;
  clientInfo: Implementation;
}

interface ServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: {};
  experimental?: { [key: string]: any };
}
```

The **capabilities object** declares supported features enabling dynamic feature discovery. Servers may include optional **instructions** for LLM guidance during initialization.

## Resources, Tools, and Prompts

### Resource System

Resources provide **structured access to external data** through URIs with content negotiation:

```typescript
interface Resource {
  uri: string; // Unique resource identifier
  name: string; // Programmatic identifier
  title?: string; // Human-readable name
  mimeType?: string; // Content type
  size?: number; // Size in bytes
}
```

Resources support **listing** with pagination, **reading** with text or binary content, **subscriptions** for change monitoring, and **URI templates** (RFC 6570) for dynamic resource generation.

### Tool Definitions and Structured Output

Tools enable **server-side function execution** with JSON Schema validation:

```typescript
interface Tool {
  name: string; // URI-like identifier
  inputSchema: object; // JSON Schema for inputs
  outputSchema?: object; // NEW: Structured output schema
  annotations?: ToolAnnotations; // Behavioral hints
}
```

The **2025-06-18 version introduces structured output** through `outputSchema`, enabling type-safe tool results alongside traditional unstructured content. Tool annotations provide behavioral hints (readOnlyHint, destructiveHint, idempotentHint) but **must not be trusted** for security decisions.

### Prompt Templates

Prompts offer **reusable conversation templates** with variable substitution:

```typescript
interface Prompt {
  name: string; // Unique identifier
  arguments?: PromptArgument[]; // Template variables
}

interface PromptMessage {
  role: "user" | "assistant" | "system";
  content: TextContent | ImageContent | ResourceContent;
}
```

## Advanced Features

### Sampling (Server → Client LLM Access)

Servers can **request LLM generation** through the client using the sampling API:

```typescript
interface CreateMessageRequest {
  messages: SamplingMessage[];
  modelPreferences?: ModelPreferences; // Model selection hints
  temperature?: number;
  maxTokens: number;
  includeContext?: "none" | "thisServer" | "allServers";
}
```

Model preferences enable **intelligent model selection** based on cost, speed, and capability priorities with specific model hints.

### Elicitation (NEW in 2025-06-18)

The **elicitation feature** enables servers to request additional user input during interactions through structured data collection with JSON schemas, supporting dynamic workflows requiring human intervention.

### Completion Support

Argument completion provides **context-aware suggestions** for prompt and resource arguments:

```typescript
interface CompleteRequest {
  ref: { type: "ref/prompt" | "ref/resource"; name?: string };
  argument: { name: string; value: string };
  context?: { arguments?: { [key: string]: string } };
}
```

## Security Architecture

### OAuth 2.1 Resource Server Model

MCP servers are **classified as OAuth 2.1 Resource Servers** requiring:

- **PKCE implementation** for authorization code protection
- **Resource Indicators (RFC 8707)** preventing unauthorized token acquisition
- **Token audience validation** ensuring tokens are issued specifically for the server
- **No token passthrough** to upstream services
- **HTTPS mandatory** for all authorization endpoints

### Protected Resource Metadata (RFC 9728)

Servers expose authorization server discovery through:

```typescript
interface ProtectedResourceMetadata {
  authorization_servers: string[]; // Authorization server URLs
}
```

### Transport Security Requirements

**HTTP transports must validate Origin headers**, bind to localhost for local servers, implement proper authentication, and use Bearer tokens in Authorization headers (never in query strings). The protocol mandates **short-lived access tokens** with refresh token rotation for public clients.

## API Endpoints and Operations

### Core Protocol Endpoints

**Lifecycle Management:**

- `initialize` - Connection setup and capability exchange
- `ping` - Health check mechanism
- `notifications/initialized` - Client ready signal

**Resource Operations:**

- `resources/list` - Enumerate available resources
- `resources/read` - Retrieve resource content
- `resources/subscribe` - Monitor resource changes
- `resources/templates/list` - Get URI templates

**Tool Operations:**

- `tools/list` - Discover available tools
- `tools/call` - Execute tool with arguments

**Prompt Operations:**

- `prompts/list` - Get available prompts
- `prompts/get` - Retrieve prompt with substitution

**Client Features:**

- `sampling/createMessage` - Request LLM generation
- `elicitation/create` - Request user input
- `roots/list` - Request client root directories

## Implementation Patterns and Code Examples

### Basic Server Implementation (TypeScript)

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new Server({
  name: "example-server",
  version: "1.0.0",
});

server.registerTool(
  {
    name: "get_weather",
    description: "Get weather for a city",
    inputSchema: {
      type: "object",
      properties: { city: { type: "string" } },
      required: ["city"],
    },
  },
  async (args) => ({
    content: [{ type: "text", text: `Weather for ${args.city}` }],
  }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
```

### Client Implementation Pattern

```typescript
const client = new Client({ name: "example-client", version: "1.0.0" });
const transport = new StdioClientTransport({
  command: "node",
  args: ["server.js"],
});

await client.connect(transport);
const tools = await client.request({ method: "tools/list" });
```

## SDK Ecosystem and Language Support

**Official SDKs** are available for **TypeScript** (@modelcontextprotocol/sdk), **Python** (mcp with FastMCP framework), **C#** (Microsoft collaboration), **Go** (Google collaboration), **Ruby** (Shopify collaboration), and **Kotlin** (JetBrains collaboration). Each SDK provides full specification support with type safety, multiple transport implementations, and comprehensive error handling patterns.

## Registry and Industry Adoption

The **MCP Registry** (registry.modelcontextprotocol.io) launched in preview September 2025, providing official server discovery and distribution with OpenAPI specifications and sub-registry support. Major adopters include **Anthropic** (Claude Desktop), **OpenAI** (ChatGPT desktop, March 2025), **Microsoft** (Copilot integration), and development tools including Zed, Replit, Codeium, and Sourcegraph.

## Latest Changes and Migration Guide

### Breaking Changes in 2025-06-18

The latest version **removes JSON-RPC batching support** (PR #416), **requires Protocol Version headers** for HTTP transport (PR #548), and changes lifecycle operations from SHOULD to MUST requirements. Migration requires updating batched requests to individual calls, adding version headers to HTTP implementations, and ensuring lifecycle operation compliance.

### New Capabilities

**Structured tool output** enables type-safe results through outputSchema definitions. **OAuth Resource Server classification** strengthens security with protected resource metadata. **Resource Indicators requirement** prevents malicious token acquisition. **Elicitation support** enables dynamic user input requests. **Enhanced security documentation** provides comprehensive implementation guidance.

## Conclusion and Technical Assessment

The Model Context Protocol represents a **mature, production-ready specification** for AI-tool integration with robust security, flexible transport options, and comprehensive type safety. The protocol's **modular design** allows selective implementation while maintaining interoperability. With **industry-wide adoption** from major AI providers and development platforms, MCP establishes itself as the de facto standard for LLM-external system communication. The **active development cycle** with regular updates and growing SDK ecosystem ensures continued evolution aligned with emerging AI application requirements.
