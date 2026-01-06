# Base Inspector Guide

> **Note**: This document covers the underlying MCP Inspector UI and operational features. For assessment-specific documentation (CLI commands, security testing, policy compliance), see the [main README](../README.md) or [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md).

---

## Overview

The MCP Inspector Assessment is built on top of [Anthropic's MCP Inspector](https://github.com/modelcontextprotocol/inspector), an interactive debugging tool for MCP servers. This guide covers the base inspector's operational features that are still available for debugging and development workflows.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Running the Inspector UI](#running-the-inspector-ui)
3. [Docker Container](#docker-container)
4. [From an MCP Server Repository](#from-an-mcp-server-repository)
5. [Servers File Export](#servers-file-export)
6. [Authentication](#authentication)
7. [Security Considerations](#security-considerations)
8. [Configuration](#configuration)
9. [Development Mode](#development-mode)
10. [UI Mode vs CLI Mode](#ui-mode-vs-cli-mode)
11. [Tool Input Validation Guidelines](#tool-input-validation-guidelines)

---

## Architecture Overview

The MCP Inspector consists of two main components that work together:

- **MCP Inspector Client (MCPI)**: A React-based web UI that provides an interactive interface for testing and debugging MCP servers
- **MCP Proxy (MCPP)**: A Node.js server that acts as a protocol bridge, connecting the web UI to MCP servers via various transport methods (stdio, SSE, streamable-http)

Note that the proxy is not a network proxy for intercepting traffic. Instead, it functions as both an MCP client (connecting to your MCP server) and an HTTP server (serving the web UI), enabling browser-based interaction with MCP servers that use different transport protocols.

---

## Running the Inspector UI

### Requirements

- Node.js: ^22.7.5

### Quick Start (UI mode)

To get up and running right away with the UI, just execute the following:

```bash
bunx @bryan-thompson/inspector-assessment
# or with npx
npx @bryan-thompson/inspector-assessment
```

The server will start up and the UI will be accessible at `http://localhost:6274`.

---

## Docker Container

**Note**: Docker container is not yet available for `@bryan-thompson/inspector-assessment`. The Docker image below is for the upstream inspector only (without assessment features):

```bash
docker run --rm \
  -p 127.0.0.1:6274:6274 \
  -p 127.0.0.1:6277:6277 \
  -e HOST=0.0.0.0 \
  -e MCP_AUTO_OPEN_ENABLED=false \
  ghcr.io/modelcontextprotocol/inspector:latest
```

---

## From an MCP Server Repository

To inspect an MCP server implementation, there's no need to clone this repo. Instead, use `bunx` or `npx`. For example, if your server is built at `build/index.js`:

```bash
bunx @bryan-thompson/inspector-assessment node build/index.js
# or with npx
npx @bryan-thompson/inspector-assessment node build/index.js
```

You can pass both arguments and environment variables to your MCP server. Arguments are passed directly to your server, while environment variables can be set using the `-e` flag:

```bash
# Pass arguments only
bunx @bryan-thompson/inspector-assessment node build/index.js arg1 arg2

# Pass environment variables only
bunx @bryan-thompson/inspector-assessment -e key=value -e key2=$VALUE2 node build/index.js

# Pass both environment variables and arguments
bunx @bryan-thompson/inspector-assessment -e key=value -e key2=$VALUE2 node build/index.js arg1 arg2

# Use -- to separate inspector flags from server arguments
bunx @bryan-thompson/inspector-assessment -e key=$VALUE -- node build/index.js -e server-flag
```

The inspector runs both an MCP Inspector (MCPI) client UI (default port 6274) and an MCP Proxy (MCPP) server (default port 6277). Open the MCPI client UI in your browser to use the inspector. (These ports are derived from the T9 dialpad mapping of MCPI and MCPP respectively, as a mnemonic). You can customize the ports if needed:

```bash
CLIENT_PORT=8080 SERVER_PORT=9000 bunx @bryan-thompson/inspector-assessment node build/index.js
```

For more details on ways to use the inspector, see the [Inspector section of the MCP docs site](https://modelcontextprotocol.io/docs/tools/inspector). For help with debugging, see the [Debugging guide](https://modelcontextprotocol.io/docs/tools/debugging).

---

## Servers File Export

The MCP Inspector provides convenient buttons to export server launch configurations for use in clients such as Cursor, Claude Code, or the Inspector's CLI. The file is usually called `mcp.json`.

### Server Entry Button

Copies a single server configuration entry to your clipboard. This can be added to your `mcp.json` file inside the `mcpServers` object with your preferred server name.

**STDIO transport example:**

```json
{
  "command": "node",
  "args": ["build/index.js", "--debug"],
  "env": {
    "API_KEY": "your-api-key",
    "DEBUG": "true"
  }
}
```

**SSE transport example:**

```json
{
  "type": "sse",
  "url": "http://localhost:3000/events",
  "note": "For SSE connections, add this URL directly in Client"
}
```

**Streamable HTTP transport example:**

```json
{
  "type": "streamable-http",
  "url": "http://localhost:3000/mcp",
  "note": "For Streamable HTTP connections, add this URL directly in your MCP Client"
}
```

### Servers File Button

Copies a complete MCP configuration file structure to your clipboard, with your current server configuration added as `default-server`. This can be saved directly as `mcp.json`.

**STDIO transport example:**

```json
{
  "mcpServers": {
    "default-server": {
      "command": "node",
      "args": ["build/index.js", "--debug"],
      "env": {
        "API_KEY": "your-api-key",
        "DEBUG": "true"
      }
    }
  }
}
```

**SSE transport example:**

```json
{
  "mcpServers": {
    "default-server": {
      "type": "sse",
      "url": "http://localhost:3000/events",
      "note": "For SSE connections, add this URL directly in Client"
    }
  }
}
```

**Streamable HTTP transport example:**

```json
{
  "mcpServers": {
    "default-server": {
      "type": "streamable-http",
      "url": "http://localhost:3000/mcp",
      "note": "For Streamable HTTP connections, add this URL directly in your MCP Client"
    }
  }
}
```

These buttons appear in the Inspector UI after you've configured your server settings, making it easy to save and reuse your configurations.

For SSE and Streamable HTTP transport connections, the Inspector provides similar functionality for both buttons. The "Server Entry" button copies the configuration that can be added to your existing configuration file, while the "Servers File" button creates a complete configuration file containing the URL for direct use in clients.

You can paste the Server Entry into your existing `mcp.json` file under your chosen server name, or use the complete Servers File payload to create a new configuration file.

---

## Authentication

The inspector supports bearer token authentication for SSE connections. Enter your token in the UI when connecting to an MCP server, and it will be sent in the Authorization header. You can override the header name using the input field in the sidebar.

---

## Security Considerations

The MCP Inspector includes a proxy server that can run and communicate with local MCP processes. The proxy server should not be exposed to untrusted networks as it has permissions to spawn local processes and can connect to any specified MCP server.

### Proxy Authentication

The MCP Inspector proxy server requires authentication by default. When starting the server, a random session token is generated and printed to the console:

```
Session token: 3a1c267fad21f7150b7d624c160b7f09b0b8c4f623c7107bbf13378f051538d4

Open inspector with token pre-filled:
   http://localhost:6274/?MCP_PROXY_AUTH_TOKEN=3a1c267fad21f7150b7d624c160b7f09b0b8c4f623c7107bbf13378f051538d4
```

This token must be included as a Bearer token in the Authorization header for all requests to the server. The inspector will automatically open your browser with the token pre-filled in the URL.

**Automatic browser opening** - The inspector now automatically opens your browser with the token pre-filled in the URL when authentication is enabled.

**Alternative: Manual configuration** - If you already have the inspector open:

1. Click the "Configuration" button in the sidebar
2. Find "Proxy Session Token" and enter the token displayed in the proxy console
3. Click "Save" to apply the configuration

The token will be saved in your browser's local storage for future use.

If you need to disable authentication (NOT RECOMMENDED), you can set the `DANGEROUSLY_OMIT_AUTH` environment variable:

```bash
DANGEROUSLY_OMIT_AUTH=true npm start
```

---

**WARNING**

Disabling authentication with `DANGEROUSLY_OMIT_AUTH` is incredibly dangerous! Disabling auth leaves your machine open to attack not just when exposed to the public internet, but also **via your web browser**. Meaning, visiting a malicious website OR viewing a malicious advertizement could allow an attacker to remotely compromise your computer. Do not disable this feature unless you truly understand the risks.

Read more about the risks of this vulnerability on Oligo's blog: [Critical RCE Vulnerability in Anthropic MCP Inspector - CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)

---

You can also set the token via the `MCP_PROXY_AUTH_TOKEN` environment variable when starting the server:

```bash
MCP_PROXY_AUTH_TOKEN=$(openssl rand -hex 32) npm start
```

### Local-only Binding

By default, both the MCP Inspector proxy server and client bind only to `localhost` to prevent network access. This ensures they are not accessible from other devices on the network. If you need to bind to all interfaces for development purposes, you can override this with the `HOST` environment variable:

```bash
HOST=0.0.0.0 npm start
```

**Warning:** Only bind to all interfaces in trusted network environments, as this exposes the proxy server's ability to execute local processes and both services to network access.

### DNS Rebinding Protection

To prevent DNS rebinding attacks, the MCP Inspector validates the `Origin` header on incoming requests. By default, only requests from the client origin are allowed (respects `CLIENT_PORT` if set, defaulting to port 6274). You can configure additional allowed origins by setting the `ALLOWED_ORIGINS` environment variable (comma-separated list):

```bash
ALLOWED_ORIGINS=http://localhost:6274,http://localhost:8000 npm start
```

---

## Configuration

The MCP Inspector supports the following configuration settings. To change them, click on the `Configuration` button in the MCP Inspector UI:

| Setting                                 | Description                                                                                                                                         | Default |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `MCP_SERVER_REQUEST_TIMEOUT`            | Client-side timeout (ms) - Inspector will cancel the request if no response is received within this time. Note: servers may have their own timeouts | 300000  |
| `MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS` | Reset timeout on progress notifications                                                                                                             | true    |
| `MCP_REQUEST_MAX_TOTAL_TIMEOUT`         | Maximum total timeout for requests sent to the MCP server (ms) (Use with progress notifications)                                                    | 60000   |
| `MCP_PROXY_FULL_ADDRESS`                | Set this if you are running the MCP Inspector Proxy on a non-default address. Example: http://10.1.1.22:5577                                        | ""      |
| `MCP_AUTO_OPEN_ENABLED`                 | Enable automatic browser opening when inspector starts (works with authentication enabled). Only as environment var, not configurable in browser.   | true    |

**Note on Timeouts:** The timeout settings above control when the Inspector (as an MCP client) will cancel requests. These are independent of any server-side timeouts. For example, if a server tool has a 10-minute timeout but the Inspector's timeout is set to 30 seconds, the Inspector will cancel the request after 30 seconds. Conversely, if the Inspector's timeout is 10 minutes but the server times out after 30 seconds, you'll receive the server's timeout error. For tools that require user interaction (like elicitation) or long-running operations, ensure the Inspector's timeout is set appropriately.

These settings can be adjusted in real-time through the UI and will persist across sessions.

### Configuration Files

The inspector also supports configuration files to store settings for different MCP servers. This is useful when working with multiple servers or complex configurations:

```bash
bunx @bryan-thompson/inspector-assessment --config path/to/config.json --server everything
```

Example server configuration file:

```json
{
  "mcpServers": {
    "everything": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-everything"],
      "env": {
        "hello": "Hello MCP!"
      }
    },
    "my-server": {
      "command": "node",
      "args": ["build/index.js", "arg1", "arg2"],
      "env": {
        "key": "value",
        "key2": "value2"
      }
    }
  }
}
```

### Transport Types in Config Files

The inspector automatically detects the transport type from your config file. You can specify different transport types:

**STDIO (default):**

```json
{
  "mcpServers": {
    "my-stdio-server": {
      "type": "stdio",
      "command": "npx",
      "args": ["@modelcontextprotocol/server-everything"]
    }
  }
}
```

**SSE (Server-Sent Events):**

```json
{
  "mcpServers": {
    "my-sse-server": {
      "type": "sse",
      "url": "http://localhost:3000/sse"
    }
  }
}
```

**Streamable HTTP:**

```json
{
  "mcpServers": {
    "my-http-server": {
      "type": "streamable-http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

### Default Server Selection

You can launch the inspector without specifying a server name if your config has:

1. **A single server** - automatically selected:

```bash
# Automatically uses "my-server" if it's the only one
bunx @bryan-thompson/inspector-assessment --config mcp.json
```

2. **A server named "default-server"** - automatically selected:

```json
{
  "mcpServers": {
    "default-server": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-everything"]
    },
    "other-server": {
      "command": "node",
      "args": ["other.js"]
    }
  }
}
```

> **Tip:** You can easily generate this configuration format using the **Server Entry** and **Servers File** buttons in the Inspector UI, as described in the Servers File Export section above.

### URL Query Parameters

You can set the initial `transport` type, `serverUrl`, `serverCommand`, and `serverArgs` via query params:

```
http://localhost:6274/?transport=sse&serverUrl=http://localhost:8787/sse
http://localhost:6274/?transport=streamable-http&serverUrl=http://localhost:8787/mcp
http://localhost:6274/?transport=stdio&serverCommand=npx&serverArgs=arg1%20arg2
```

You can also set initial config settings via query params:

```
http://localhost:6274/?MCP_SERVER_REQUEST_TIMEOUT=60000&MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS=false&MCP_PROXY_FULL_ADDRESS=http://10.1.1.22:5577
```

Note that if both the query param and the corresponding localStorage item are set, the query param will take precedence.

---

## Development Mode

If you're working on the inspector itself:

**Development mode:**

```bash
npm run dev

# To co-develop with the typescript-sdk package (assuming it's cloned in ../typescript-sdk; set MCP_SDK otherwise):
npm run dev:sdk "cd sdk && npm run examples:simple-server:w"
# then open http://localhost:3000/mcp as SHTTP in the inspector.
# To go back to the deployed SDK version:
#   npm run unlink:sdk && npm i
```

> **Note for Windows users:**
> On Windows, use the following command instead:
>
> ```bash
> npm run dev:windows
> ```

**Production mode:**

```bash
npm run build
npm start
```

---

## UI Mode vs CLI Mode

| Use Case                 | UI Mode                                                                   | CLI Mode                                                                                                                                             |
| ------------------------ | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Server Development**   | Visual interface for interactive testing and debugging during development | Scriptable commands for quick testing and continuous integration; creates feedback loops with AI coding assistants like Cursor for rapid development |
| **Resource Exploration** | Interactive browser with hierarchical navigation and JSON visualization   | Programmatic listing and reading for automation and scripting                                                                                        |
| **Tool Testing**         | Form-based parameter input with real-time response visualization          | Command-line tool execution with JSON output for scripting                                                                                           |
| **Prompt Engineering**   | Interactive sampling with streaming responses and visual comparison       | Batch processing of prompts with machine-readable output                                                                                             |
| **Debugging**            | Request history, visualized errors, and real-time notifications           | Direct JSON output for log analysis and integration with other tools                                                                                 |
| **Automation**           | N/A                                                                       | Ideal for CI/CD pipelines, batch processing, and integration with coding assistants                                                                  |
| **Learning MCP**         | Rich visual interface helps new users understand server capabilities      | Simplified commands for focused learning of specific endpoints                                                                                       |

---

## Tool Input Validation Guidelines

When implementing or modifying tool input parameter handling in the Inspector:

- **Omit optional fields with empty values** - When processing form inputs, omit empty strings or null values for optional parameters, UNLESS the field has an explicit default value in the schema that matches the current value
- **Preserve explicit default values** - If a field schema contains an explicit default (e.g., `default: null`), and the current value matches that default, include it in the request. This is a meaningful value the tool expects
- **Always include required fields** - Preserve required field values even when empty, allowing the MCP server to validate and return appropriate error messages
- **Defer deep validation to the server** - Implement basic field presence checking in the Inspector client, but rely on the MCP server for parameter validation according to its schema

These guidelines maintain clean parameter passing and proper separation of concerns between the Inspector client and MCP servers.

---

## Related Documentation

- **Assessment CLI Guide**: [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) - CLI commands and workflows
- **Main README**: [../README.md](../README.md) - Assessment capabilities overview
- **Fork History**: [FORK_HISTORY.md](FORK_HISTORY.md) - Upstream relationship and sync status
- **Upstream MCP Docs**: https://modelcontextprotocol.io/docs/tools/inspector
