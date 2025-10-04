# MCP Inspector

The MCP inspector is a developer tool for testing and debugging MCP servers with comprehensive assessment capabilities for validating server functionality, security, documentation, and compliance.

![MCP Inspector Screenshot](https://raw.githubusercontent.com/modelcontextprotocol/inspector/main/mcp-inspector.png)

## About This Fork

This is an enhanced fork of [Anthropic's MCP Inspector](https://github.com/modelcontextprotocol/inspector) with significantly expanded assessment capabilities for MCP server validation and testing.

**Original Repository**: https://github.com/modelcontextprotocol/inspector
**Our Enhanced Fork**: https://github.com/triepod-ai/inspector-assessment

### What We Added

We've built a comprehensive assessment framework on top of the original inspector that transforms it from a debugging tool into a full validation suite for MCP servers. Our enhancements focus on accuracy, depth, and actionable insights for MCP server developers.

## Key Features

- **Interactive Testing**: Visual interface for testing MCP server tools, resources, and prompts
- **Comprehensive Assessment**: Automated validation of server functionality, error handling, documentation, security, and usability
- **Enhanced Testing Modes**: Multi-scenario validation with progressive complexity testing
- **Business Logic Validation**: Distinguishes between proper error handling and unintended failures
- **Detailed Test Reports**: Confidence scoring, test scenario details, and actionable recommendations
- **Multiple Transport Support**: STDIO, SSE, and Streamable HTTP transports

## Our Enhancements to the MCP Inspector

We've significantly expanded the original MCP Inspector's capabilities with advanced assessment features that go far beyond basic debugging. Here's what makes our fork unique:

### 1. Enhanced Business Logic Error Detection

**Problem**: The original inspector couldn't distinguish between broken tools and tools that correctly validate input. A tool returning "user not found" would be marked as broken.

**Our Solution**: Confidence-based validation system (ResponseValidator.ts:client/src/services/assessment/ResponseValidator.ts)

- **MCP Standard Error Code Recognition**: Properly identifies error codes like `-32602` (Invalid params) as successful validation
- **Confidence Scoring**: Multi-factor analysis determines if errors represent proper business logic
- **Tool Type Awareness**: Different validation thresholds for CRUD vs utility tools
- **Impact**: Estimated 80% reduction in false positives for resource-based tools (based on analysis in [FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md](docs/FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md#key-problems-addressed))

### 2. Progressive Complexity Testing

**Problem**: Testing tools with only complex inputs makes it hard to identify where functionality breaks down.

**Our Solution**: Four-level progressive testing (TestScenarioEngine.ts:client/src/services/assessment/TestScenarioEngine.ts)

1. **Minimal**: Only required fields with simplest values
2. **Simple**: Required fields with realistic simple values
3. **Typical**: Common usage patterns with realistic data
4. **Complex**: All parameters with nested structures

**Benefits**:

- Identifies exact complexity level where tools fail
- Provides specific, actionable recommendations
- Helps developers understand tool limitations and requirements

### 3. Realistic Test Data Generation

**Problem**: Generic test data like "test_value" and fake IDs trigger validation errors, causing false failures.

**Our Solution**: Context-aware test data generation (TestDataGenerator.ts:client/src/services/assessment/TestDataGenerator.ts)

- **Publicly Accessible URLs**: `https://www.google.com`, `https://api.github.com/users/octocat`
- **Real API Endpoints**: Uses actual test APIs like jsonplaceholder.typicode.com
- **Valid UUIDs**: Properly formatted identifiers that won't trigger format validation
- **Context Awareness**: Generates appropriate data based on field names (email, url, id, etc.)

### 4. Comprehensive Assessment Methodology

**Based on Real-World Testing**: Our methodology has been validated through systematic testing using the taskmanager MCP server as a case study (11 tools tested with 8 security injection patterns, detailed in [ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md)).

**Five Core Assessment Areas** (detailed in docs/ASSESSMENT_METHODOLOGY.md:docs/ASSESSMENT_METHODOLOGY.md):

1. **Functionality Testing** (35% weight)
   - Multi-scenario validation with progressive complexity
   - Coverage tracking and reliability scoring
   - Performance measurement

2. **Security Assessment** (25% weight)
   - 8 distinct injection attack patterns
   - Direct command injection, role override, data exfiltration detection
   - Vulnerability analysis with risk levels (HIGH/MEDIUM/LOW)

3. **Documentation Analysis** (20% weight)
   - README structure and completeness
   - Code example extraction and validation
   - API reference quality assessment

4. **Error Handling** (25% weight)
   - MCP protocol compliance scoring
   - Error response quality analysis
   - Invalid input resilience testing

5. **Usability Evaluation** (10% weight)
   - Naming convention consistency
   - Parameter clarity assessment
   - Best practices compliance

### 5. Advanced Assessment Components

We've built a complete assessment architecture with specialized modules:

- **AssessmentOrchestrator.ts**: Coordinates multi-phase testing across all assessment dimensions
- **ResponseValidator.ts**: Advanced response validation with confidence scoring
- **TestScenarioEngine.ts**: Generates and executes progressive complexity tests
- **TestDataGenerator.ts**: Context-aware realistic test data generation
- **Assessment UI Components**: Rich visualization of test results and recommendations

### Documentation

Our enhancements include comprehensive documentation:

- **ASSESSMENT_METHODOLOGY.md**: Complete methodology with examples and best practices
- **FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md**: Implementation details and impact analysis
- **Test Coverage Reports**: Detailed validation of our assessment accuracy

## Architecture Overview

The MCP Inspector consists of two main components that work together:

- **MCP Inspector Client (MCPI)**: A React-based web UI that provides an interactive interface for testing and debugging MCP servers
- **MCP Proxy (MCPP)**: A Node.js server that acts as a protocol bridge, connecting the web UI to MCP servers via various transport methods (stdio, SSE, streamable-http)

Note that the proxy is not a network proxy for intercepting traffic. Instead, it functions as both an MCP client (connecting to your MCP server) and an HTTP server (serving the web UI), enabling browser-based interaction with MCP servers that use different transport protocols.

## Assessment Capabilities

Our enhanced MCP Inspector includes a comprehensive assessment system that validates MCP servers against Anthropic's directory submission requirements and MCP protocol standards:

### Assessment Categories

1. **Functionality Testing** (35% weight)
   - Multi-scenario validation with happy path, edge cases, and boundary testing
   - Progressive complexity testing from simple to complex inputs
   - Business logic validation to distinguish proper error handling from failures
   - Confidence scoring based on test coverage and consistency

2. **Error Handling** (25% weight)
   - Invalid input resilience testing
   - Comprehensive error message analysis
   - Resource validation vs. unintended failures
   - Quality scoring for descriptive error messages

3. **Documentation** (20% weight)
   - Tool description completeness and clarity
   - Parameter documentation validation
   - README structure and examples evaluation
   - API documentation quality assessment

4. **Security** (10% weight)
   - Input validation and sanitization checks
   - Authentication/authorization testing
   - Sensitive data exposure detection
   - Security best practices compliance

5. **Usability** (10% weight)
   - Tool naming consistency analysis
   - Description quality assessment
   - Schema completeness validation
   - Parameter clarity evaluation

### Enhanced Testing Features

**Note**: The features below are our enhancements to the original MCP Inspector. See the "Our Enhancements" section above for detailed technical descriptions.

#### Multi-Scenario Validation

The inspector tests each tool with multiple scenarios:

- **Happy Path**: Valid inputs with expected success cases
- **Edge Cases**: Boundary values and unusual but valid inputs
- **Error Cases**: Invalid inputs to test error handling
- **Boundary Testing**: Maximum/minimum values and limits

#### Progressive Complexity Testing

Tools are tested with progressively complex inputs:

1. **Simple**: Basic, minimal valid inputs
2. **Moderate**: Typical real-world usage patterns
3. **Complex**: Advanced scenarios with multiple parameters
4. **Extreme**: Stress testing with maximum complexity

#### Business Logic Validation

The assessment distinguishes between:

- **Proper Validation**: Expected errors for invalid business logic (e.g., "User not found")
- **Tool Failures**: Unexpected errors indicating implementation issues
- **Resource Validation**: Proper handling of non-existent resources
- **Input Validation**: Appropriate rejection of malformed inputs

### Assessment Configuration

Configure assessment behavior through the UI:

| Setting                   | Description                                   | Default  |
| ------------------------- | --------------------------------------------- | -------- |
| Enhanced Testing          | Enable multi-scenario validation              | Enabled  |
| Max Tools to Test         | Number of tools to test (-1 for all)          | 10       |
| Error Handling Test Limit | Tools to test for error handling (-1 for all) | 5        |
| Test Complexity           | Simple, Moderate, or Complex scenarios        | Moderate |

### Viewing Assessment Results

The Assessment tab provides:

- **Overall Score**: Weighted aggregate score with letter grade (A-F)
- **Category Breakdown**: Individual scores for each assessment category
- **Tool Details**: Click any tool name to see detailed test results including:
  - Test scenarios executed
  - Input parameters used
  - Actual responses received
  - Pass/fail status with confidence scores
  - Specific issues identified
- **Recommendations**: Actionable suggestions for improvement
- **Test Coverage**: Visual indicators of testing completeness

### Assessment API

Programmatically run assessments using the CLI:

```bash
# Run full assessment
npx @modelcontextprotocol/inspector --cli node build/index.js --assess

# Run specific category
npx @modelcontextprotocol/inspector --cli node build/index.js --assess functionality

# Export assessment results
npx @modelcontextprotocol/inspector --cli node build/index.js --assess --output assessment-report.json
```

## Running the Inspector

### Requirements

- Node.js: ^22.7.5

### Quick Start (UI mode)

To get up and running right away with the UI, just execute the following:

```bash
npx @modelcontextprotocol/inspector
```

The server will start up and the UI will be accessible at `http://localhost:6274`.

### Docker Container

You can also start it in a Docker container with the following command:

```bash
docker run --rm --network host -p 6274:6274 -p 6277:6277 ghcr.io/modelcontextprotocol/inspector:latest
```

### From an MCP server repository

To inspect an MCP server implementation, there's no need to clone this repo. Instead, use `npx`. For example, if your server is built at `build/index.js`:

```bash
npx @modelcontextprotocol/inspector node build/index.js
```

You can pass both arguments and environment variables to your MCP server. Arguments are passed directly to your server, while environment variables can be set using the `-e` flag:

```bash
# Pass arguments only
npx @modelcontextprotocol/inspector node build/index.js arg1 arg2

# Pass environment variables only
npx @modelcontextprotocol/inspector -e key=value -e key2=$VALUE2 node build/index.js

# Pass both environment variables and arguments
npx @modelcontextprotocol/inspector -e key=value -e key2=$VALUE2 node build/index.js arg1 arg2

# Use -- to separate inspector flags from server arguments
npx @modelcontextprotocol/inspector -e key=$VALUE -- node build/index.js -e server-flag
```

The inspector runs both an MCP Inspector (MCPI) client UI (default port 6274) and an MCP Proxy (MCPP) server (default port 6277). Open the MCPI client UI in your browser to use the inspector. (These ports are derived from the T9 dialpad mapping of MCPI and MCPP respectively, as a mnemonic). You can customize the ports if needed:

```bash
CLIENT_PORT=8080 SERVER_PORT=9000 npx @modelcontextprotocol/inspector node build/index.js
```

For more details on ways to use the inspector, see the [Inspector section of the MCP docs site](https://modelcontextprotocol.io/docs/tools/inspector). For help with debugging, see the [Debugging guide](https://modelcontextprotocol.io/docs/tools/debugging).

### Servers File Export

The MCP Inspector provides convenient buttons to export server launch configurations for use in clients such as Cursor, Claude Code, or the Inspector's CLI. The file is usually called `mcp.json`.

- **Server Entry** - Copies a single server configuration entry to your clipboard. This can be added to your `mcp.json` file inside the `mcpServers` object with your preferred server name.

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

- **Servers File** - Copies a complete MCP configuration file structure to your clipboard, with your current server configuration added as `default-server`. This can be saved directly as `mcp.json`.

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

These buttons appear in the Inspector UI after you've configured your server settings, making it easy to save and reuse your configurations.

For SSE transport connections, the Inspector provides similar functionality for both buttons. The "Server Entry" button copies the SSE URL configuration that can be added to your existing configuration file, while the "Servers File" button creates a complete configuration file containing the SSE URL for direct use in clients.

You can paste the Server Entry into your existing `mcp.json` file under your chosen server name, or use the complete Servers File payload to create a new configuration file.

### Authentication

The inspector supports bearer token authentication for SSE connections. Enter your token in the UI when connecting to an MCP server, and it will be sent in the Authorization header. You can override the header name using the input field in the sidebar.

### Security Considerations

The MCP Inspector includes a proxy server that can run and communicate with local MCP processes. The proxy server should not be exposed to untrusted networks as it has permissions to spawn local processes and can connect to any specified MCP server.

#### Authentication

The MCP Inspector proxy server requires authentication by default. When starting the server, a random session token is generated and printed to the console:

```
🔑 Session token: 3a1c267fad21f7150b7d624c160b7f09b0b8c4f623c7107bbf13378f051538d4

🔗 Open inspector with token pre-filled:
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

**🚨 WARNING 🚨**

Disabling authentication with `DANGEROUSLY_OMIT_AUTH` is incredibly dangerous! Disabling auth leaves your machine open to attack not just when exposed to the public internet, but also **via your web browser**. Meaning, visiting a malicious website OR viewing a malicious advertizement could allow an attacker to remotely compromise your computer. Do not disable this feature unless you truly understand the risks.

Read more about the risks of this vulnerability on Oligo's blog: [Critical RCE Vulnerability in Anthropic MCP Inspector - CVE-2025-49596](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)

---

You can also set the token via the `MCP_PROXY_AUTH_TOKEN` environment variable when starting the server:

```bash
MCP_PROXY_AUTH_TOKEN=$(openssl rand -hex 32) npm start
```

#### Local-only Binding

By default, both the MCP Inspector proxy server and client bind only to `localhost` to prevent network access. This ensures they are not accessible from other devices on the network. If you need to bind to all interfaces for development purposes, you can override this with the `HOST` environment variable:

```bash
HOST=0.0.0.0 npm start
```

**Warning:** Only bind to all interfaces in trusted network environments, as this exposes the proxy server's ability to execute local processes and both services to network access.

#### DNS Rebinding Protection

To prevent DNS rebinding attacks, the MCP Inspector validates the `Origin` header on incoming requests. By default, only requests from the client origin are allowed (respects `CLIENT_PORT` if set, defaulting to port 6274). You can configure additional allowed origins by setting the `ALLOWED_ORIGINS` environment variable (comma-separated list):

```bash
ALLOWED_ORIGINS=http://localhost:6274,http://localhost:8000 npm start
```

### Configuration

The MCP Inspector supports the following configuration settings. To change them, click on the `Configuration` button in the MCP Inspector UI:

| Setting                                 | Description                                                                                                                                       | Default |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------- |
| `MCP_SERVER_REQUEST_TIMEOUT`            | Timeout for requests to the MCP server (ms)                                                                                                       | 10000   |
| `MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS` | Reset timeout on progress notifications                                                                                                           | true    |
| `MCP_REQUEST_MAX_TOTAL_TIMEOUT`         | Maximum total timeout for requests sent to the MCP server (ms) (Use with progress notifications)                                                  | 60000   |
| `MCP_PROXY_FULL_ADDRESS`                | Set this if you are running the MCP Inspector Proxy on a non-default address. Example: http://10.1.1.22:5577                                      | ""      |
| `MCP_AUTO_OPEN_ENABLED`                 | Enable automatic browser opening when inspector starts (works with authentication enabled). Only as environment var, not configurable in browser. | true    |

These settings can be adjusted in real-time through the UI and will persist across sessions.

The inspector also supports configuration files to store settings for different MCP servers. This is useful when working with multiple servers or complex configurations:

```bash
npx @modelcontextprotocol/inspector --config path/to/config.json --server everything
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

#### Transport Types in Config Files

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

#### Default Server Selection

You can launch the inspector without specifying a server name if your config has:

1. **A single server** - automatically selected:

```bash
# Automatically uses "my-server" if it's the only one
npx @modelcontextprotocol/inspector --config mcp.json
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

You can also set the initial `transport` type, `serverUrl`, `serverCommand`, and `serverArgs` via query params, for example:

```
http://localhost:6274/?transport=sse&serverUrl=http://localhost:8787/sse
http://localhost:6274/?transport=streamable-http&serverUrl=http://localhost:8787/mcp
http://localhost:6274/?transport=stdio&serverCommand=npx&serverArgs=arg1%20arg2
```

You can also set initial config settings via query params, for example:

```
http://localhost:6274/?MCP_SERVER_REQUEST_TIMEOUT=10000&MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS=false&MCP_PROXY_FULL_ADDRESS=http://10.1.1.22:5577
```

Note that if both the query param and the corresponding localStorage item are set, the query param will take precedence.

### From this repository

If you're working on the inspector itself:

Development mode:

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

Production mode:

```bash
npm run build
npm start
```

### CLI Mode

CLI mode enables programmatic interaction with MCP servers from the command line, ideal for scripting, automation, and integration with coding assistants. This creates an efficient feedback loop for MCP server development.

```bash
npx @modelcontextprotocol/inspector --cli node build/index.js
```

The CLI mode supports most operations across tools, resources, and prompts. A few examples:

```bash
# Basic usage
npx @modelcontextprotocol/inspector --cli node build/index.js

# With config file
npx @modelcontextprotocol/inspector --cli --config path/to/config.json --server myserver

# List available tools
npx @modelcontextprotocol/inspector --cli node build/index.js --method tools/list

# Call a specific tool
npx @modelcontextprotocol/inspector --cli node build/index.js --method tools/call --tool-name mytool --tool-arg key=value --tool-arg another=value2

# Call a tool with JSON arguments
npx @modelcontextprotocol/inspector --cli node build/index.js --method tools/call --tool-name mytool --tool-arg 'options={"format": "json", "max_tokens": 100}'

# List available resources
npx @modelcontextprotocol/inspector --cli node build/index.js --method resources/list

# List available prompts
npx @modelcontextprotocol/inspector --cli node build/index.js --method prompts/list

# Connect to a remote MCP server (default is SSE transport)
npx @modelcontextprotocol/inspector --cli https://my-mcp-server.example.com

# Connect to a remote MCP server (with Streamable HTTP transport)
npx @modelcontextprotocol/inspector --cli https://my-mcp-server.example.com --transport http --method tools/list

# Connect to a remote MCP server (with custom headers)
npx @modelcontextprotocol/inspector --cli https://my-mcp-server.example.com --transport http --method tools/list --header "X-API-Key: your-api-key"

# Call a tool on a remote server
npx @modelcontextprotocol/inspector --cli https://my-mcp-server.example.com --method tools/call --tool-name remotetool --tool-arg param=value

# List resources from a remote server
npx @modelcontextprotocol/inspector --cli https://my-mcp-server.example.com --method resources/list
```

### UI Mode vs CLI Mode: When to Use Each

| Use Case                 | UI Mode                                                                   | CLI Mode                                                                                                                                             |
| ------------------------ | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Server Development**   | Visual interface for interactive testing and debugging during development | Scriptable commands for quick testing and continuous integration; creates feedback loops with AI coding assistants like Cursor for rapid development |
| **Resource Exploration** | Interactive browser with hierarchical navigation and JSON visualization   | Programmatic listing and reading for automation and scripting                                                                                        |
| **Tool Testing**         | Form-based parameter input with real-time response visualization          | Command-line tool execution with JSON output for scripting                                                                                           |
| **Prompt Engineering**   | Interactive sampling with streaming responses and visual comparison       | Batch processing of prompts with machine-readable output                                                                                             |
| **Debugging**            | Request history, visualized errors, and real-time notifications           | Direct JSON output for log analysis and integration with other tools                                                                                 |
| **Automation**           | N/A                                                                       | Ideal for CI/CD pipelines, batch processing, and integration with coding assistants                                                                  |
| **Learning MCP**         | Rich visual interface helps new users understand server capabilities      | Simplified commands for focused learning of specific endpoints                                                                                       |

## Evidence & Validation

All performance claims in this README are backed by implementation analysis and documented methodology. We maintain transparency about what has been measured versus estimated.

**📋 Complete Validation Report**: See [CLAIMS_VALIDATION.md](CLAIMS_VALIDATION.md) for detailed evidence supporting every claim made in this README.

### Validated Claims

| Claim                                     | Evidence                                                                                                                                 | Type       |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------- |
| Progressive complexity testing (4 levels) | Implementation in [TestScenarioEngine.ts](client/src/services/assessment/TestScenarioEngine.ts)                                          | Measured   |
| 8 security injection patterns             | Implementation in [ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md#eight-security-test-patterns)                               | Measured   |
| Context-aware test data generation        | Implementation in [TestDataGenerator.ts](client/src/services/assessment/TestDataGenerator.ts)                                            | Measured   |
| MCP error code recognition                | Implementation in [ResponseValidator.ts](client/src/services/assessment/ResponseValidator.ts)                                            | Measured   |
| 80% reduction in false positives          | Analysis in [FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md](docs/FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md#key-problems-addressed) | Estimated  |
| Taskmanager case study results            | Methodology validation in [ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md)                                                    | Case Study |

### Supporting Documentation

- **Implementation Details**: [FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md](docs/FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md)
- **Assessment Methodology**: [ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md)
- **Testing Comparison**: [TESTING_COMPARISON_EXAMPLE.md](docs/TESTING_COMPARISON_EXAMPLE.md)
- **Error Handling Validation**: [ERROR_HANDLING_VALIDATION_SUMMARY.md](ERROR_HANDLING_VALIDATION_SUMMARY.md)

### Reproducibility

All enhancements can be verified by:

1. Examining the source code in `client/src/services/assessment/`
2. Running the test suites in `client/src/services/__tests__/`
3. Reviewing the methodology documentation in `docs/`
4. Testing against your own MCP servers using the assessment features

## Contributing & Citing This Work

### For Researchers and Developers

If you use our enhanced MCP Inspector in your research, testing, or MCP server development, please cite this work:

```
MCP Inspector - Enhanced Assessment Fork
https://github.com/triepod-ai/inspector-assessment
Enhancements: Advanced assessment methodology, progressive complexity testing,
business logic error detection, and comprehensive security validation.
Based on Anthropic's MCP Inspector: https://github.com/modelcontextprotocol/inspector
```

### Documentation

- **Comprehensive Assessment Methodology**: [docs/ASSESSMENT_METHODOLOGY.md](docs/ASSESSMENT_METHODOLOGY.md)
- **Functionality Test Enhancements**: [docs/FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md](docs/FUNCTIONALITY_TEST_ENHANCEMENTS_IMPLEMENTED.md)
- **Original MCP Inspector Documentation**: https://modelcontextprotocol.io/docs/tools/inspector

### Contributing

We welcome contributions to our enhanced assessment capabilities! Areas of particular interest:

- Additional security injection patterns
- More sophisticated business logic detection
- Performance profiling enhancements
- Integration with CI/CD pipelines
- Additional assessment visualizations

Please submit issues and pull requests to our repository: https://github.com/triepod-ai/inspector-assessment

### Acknowledgments

This project builds upon the excellent foundation provided by Anthropic's MCP Inspector team. We're grateful for their work on the original inspector and the MCP protocol specification.

## License

This project is licensed under the MIT License—see the [LICENSE](LICENSE) file for details.
