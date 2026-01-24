# DVMCP (Damn Vulnerable MCP) Usage Guide

## Overview

**Damn Vulnerable MCP (DVMCP)** is an educational project that contains 10 intentionally vulnerable MCP servers designed to demonstrate security challenges in MCP implementations. It serves as a third-party validation testbed for the MCP Inspector, complementing the existing A/B comparison testing with the vulnerable-mcp and hardened-mcp servers.

DVMCP is useful for:

- **Security Training**: Learn about MCP vulnerabilities in a controlled environment
- **Pattern Validation**: Test Inspector security patterns against real-world vulnerability implementations
- **CI/CD Integration**: Automated validation in security testing pipelines
- **Research**: Understand attack vectors and defensive techniques

**Repository**: https://github.com/harishsg993010/damn-vulnerable-MCP-server
**Fork**: https://github.com/triepod-ai/damn-vulnerable-MCP-server
**Local Path**: `/home/bryan/mcp-servers/damn-vulnerable-mcp-server/`

---

## Challenge Overview

DVMCP contains 10 challenges across three difficulty tiers. Each challenge runs on a separate port (9001-9010) and demonstrates a specific vulnerability class.

### Easy Challenges (Ports 9001-9003)

| Port | Challenge | Vulnerability Class                            | Description                                                                                        |
| ---- | --------- | ---------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| 9001 | CH1       | Prompt Injection via Resources                 | Injecting malicious instructions through resource descriptions and content                         |
| 9002 | CH2       | Tool Description Poisoning + Command Injection | Embedding hidden instructions in tool descriptions to manipulate LLM behavior and execute commands |
| 9003 | CH3       | Path Traversal / Excessive Permissions         | Exploiting overly permissive file access to read sensitive files outside intended scope            |

### Medium Challenges (Ports 9004-9007)

| Port | Challenge | Vulnerability Class             | Description                                                              |
| ---- | --------- | ------------------------------- | ------------------------------------------------------------------------ |
| 9004 | CH4       | Rug Pull (Temporal Mutation)    | Changing tool definitions at runtime to perform unexpected actions       |
| 9005 | CH5       | Tool Shadowing                  | Creating fake tools with legitimate-sounding names to intercept requests |
| 9006 | CH6       | Indirect Prompt Injection       | Injecting malicious instructions through data returned by tools          |
| 9007 | CH7       | Token Theft via Info Disclosure | Leaking authentication tokens and credentials through tool responses     |

### Hard Challenges (Ports 9008-9010)

| Port | Challenge | Vulnerability Class       | Description                                                                   |
| ---- | --------- | ------------------------- | ----------------------------------------------------------------------------- |
| 9008 | CH8       | Arbitrary Code Execution  | Executing arbitrary code on the system through vulnerable operations          |
| 9009 | CH9       | Command Injection (RCE)   | Exploiting command execution vulnerabilities to achieve remote code execution |
| 9010 | CH10      | Multi-Vector Attack Chain | Combining multiple vulnerabilities to achieve complex attack objectives       |

---

## Setup Instructions

### 1. Clone and Install DVMCP

```bash
# Clone the repository
cd /home/bryan/mcp-servers
git clone https://github.com/harishsg993010/damn-vulnerable-mcp-server.git

# Navigate to the directory
cd damn-vulnerable-mcp-server

# Create Python virtual environment
uv venv .venv
source .venv/bin/activate

# Install dependencies
uv pip install -e .
```

### 2. Verify Installation

```bash
# Check that the package installed correctly
python3 -c "import challenges; print('DVMCP installed successfully')"
```

### 3. Start DVMCP Servers

DVMCP servers can be run in two ways:

#### Option A: Docker (Recommended)

```bash
# Build Docker image
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server
docker build -t dvmcp .

# Run container (exposes ports 9001-9010)
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp

# Verify all challenges are running
for port in {9001..9010}; do
  echo "Testing port $port..."
  curl -s http://localhost:$port/sse | head -c 100 && echo " OK" || echo " FAILED"
done
```

#### Option B: Direct Python (For Testing Individual Challenges)

```bash
# For SSE transport (default for testing)
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server/challenges/easy/challenge2
python3 sse_server.py  # Runs on port 9002

# For STDIO transport (useful for accessing poisoned descriptions in server.py)
# See "Advanced Configuration" section below
```

---

## Configuration

### SSE Transport (Most Common)

SSE (Server-Sent Events) transport is ideal for testing locally running servers.

**Create config file** (`/tmp/dvmcp-ch2-sse.json`):

```json
{
  "transport": "sse",
  "url": "http://localhost:9002/sse"
}
```

**Create configs for all challenges:**

```bash
for i in {1..10}; do
  echo "{\"transport\": \"sse\", \"url\": \"http://localhost:900$i/sse\"}" > /tmp/dvmcp-ch$i-sse.json
done
```

### STDIO Transport (For Testing Poisoned Descriptions)

STDIO transport is required to test tool description poisoning because some DVMCP challenges have poisoned descriptions only in `server.py`, not in the SSE server.

**Create wrapper script** (`/tmp/run-ch2-stdio.py`):

```python
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/bryan/mcp-servers/damn-vulnerable-mcp-server/challenges/easy/challenge2')
from server import mcp
mcp.run(transport='stdio')
```

**Make it executable:**

```bash
chmod +x /tmp/run-ch2-stdio.py
```

**Create config file** (`/tmp/dvmcp-ch2-stdio.json`):

```json
{
  "command": "/home/bryan/mcp-servers/damn-vulnerable-mcp-server/.venv/bin/python3",
  "args": ["/tmp/run-ch2-stdio.py"]
}
```

**Create wrapper scripts for other challenges:**

```bash
for i in {1..10}; do
  difficulty="easy"
  if [ $i -gt 3 ] && [ $i -le 7 ]; then
    difficulty="medium"
  elif [ $i -gt 7 ]; then
    difficulty="hard"
  fi

  cat > /tmp/run-ch$i-stdio.py << EOF
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/bryan/mcp-servers/damn-vulnerable-mcp-server/challenges/$difficulty/challenge$i')
from server import mcp
mcp.run(transport='stdio')
EOF
  chmod +x /tmp/run-ch$i-stdio.py
done
```

---

## Running Assessments

### Quick Start: Single Challenge

**Test Challenge 2 (Tool Description Poisoning) with STDIO transport:**

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-stdio.json \
  --output /tmp/dvmcp-ch2-results.json
```

**Test Challenge 2 with SSE transport (if docker running):**

```bash
# Start docker first
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp

# Run assessment
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-sse.json \
  --output /tmp/dvmcp-ch2-results.json
```

### Test All Challenges

**Via SSE (Docker):**

```bash
# Start docker container
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp

# Create all SSE configs
for i in {1..10}; do
  echo "{\"transport\": \"sse\", \"url\": \"http://localhost:900$i/sse\"}" > /tmp/dvmcp-ch$i-sse.json
done

# Run all assessments
for i in {1..10}; do
  echo "Testing Challenge $i..."
  npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch$i \
    --config /tmp/dvmcp-ch$i-sse.json \
    --output /tmp/dvmcp-ch$i-sse-results.json
done
```

**Via STDIO (local testing):**

```bash
# Create all STDIO wrapper scripts and configs (see Configuration section)

# Run all assessments
for i in {1..10}; do
  echo "Testing Challenge $i..."
  npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch$i \
    --config /tmp/dvmcp-ch$i-stdio.json \
    --output /tmp/dvmcp-ch$i-stdio-results.json
done
```

### Using Local npm Binary (During Development)

If developing locally without publishing to npm:

```bash
# Build the project first
npm run build

# Full assessment (primary workflow)
npm run assess:full -- --server dvmcp-ch2 --config /tmp/dvmcp-ch2-sse.json

# Or security assessment only
npm run assess -- --server dvmcp-ch2 --config /tmp/dvmcp-ch2-sse.json

# Legacy script (deprecated, will be removed in v2.0.0)
npm run assess:full:legacy -- --server dvmcp-ch2 --config /tmp/dvmcp-ch2-sse.json
```

---

## Understanding Results

Each assessment run saves results to `/tmp/inspector-assessment-dvmcp-ch{N}.json`.

### View Full Results

```bash
cat /tmp/dvmcp-ch2-results.json | jq '.'
```

### Check Detected Vulnerabilities

```bash
# Count vulnerabilities
cat /tmp/dvmcp-ch2-results.json | jq '.modules.security.vulnerabilities | length'

# List vulnerability names
cat /tmp/dvmcp-ch2-results.json | jq '.modules.security.vulnerabilities[].name'

# View detailed vulnerability info
cat /tmp/dvmcp-ch2-results.json | jq '.modules.security.vulnerabilities[] | {name, toolName, pattern}'
```

### Check Tool Annotation Results

```bash
# View tool poisoning detections
cat /tmp/dvmcp-ch2-results.json | jq '.toolAnnotations.toolResults[] | select(.descriptionPoisoning.detected == true) | {toolName, patterns: [.descriptionPoisoning.patterns[].name]}'

# Count poisoned tools
cat /tmp/dvmcp-ch2-results.json | jq '.toolAnnotations.poisonedDescriptionsDetected'
```

### View Functionality Status

```bash
# List broken tools
cat /tmp/dvmcp-ch2-results.json | jq '.modules.functionality.brokenTools[]'

# Check tool-by-tool status
cat /tmp/dvmcp-ch2-results.json | jq '.modules.functionality.enhancedResults[] | {tool: .toolName, status: .overallStatus}'
```

---

## Challenge Details

### CH1: Prompt Injection via Resources

**Vulnerability**: Malicious instructions embedded in resource descriptions can manipulate LLM behavior.

**Detection Status**: GAP (resources not tested by Inspector)

**Expected Behavior**:

- Returns MCP resources with poisoned descriptions
- Should detect prompt injection via resource content

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch1 \
  --config /tmp/dvmcp-ch1-sse.json \
  --output /tmp/dvmcp-ch1-results.json
```

**Note**: Current Inspector version focuses on tool testing. Resource-based injection requires enhancement.

### CH2: Tool Description Poisoning + Command Injection

**Vulnerability**: Tool descriptions contain hidden instructions that manipulate LLM behavior, combined with command injection in parameters.

**Detection Status**: ✅ DETECTED (7+ patterns)

**Expected Behavior**:

- `get_company_data` tool has 3 poisoned patterns
- `search_company_database` tool has 7 poisoned patterns
- Command injection possible through search parameters

**Poisoned Patterns Detected**:

- `important_tag`: `<IMPORTANT>...</IMPORTANT>` tags
- `hidden_tag`: `<HIDDEN>...</HIDDEN>` tags
- `override_auth_protocol`: Auth bypass instructions
- `internal_resource_uri`: References to internal systems
- `access_confidential`: Confidential data access instructions
- `hidden_trigger_phrase`: Conditional execution triggers
- `do_not_mention`: Concealment instructions

**Test with Inspector**:

```bash
# STDIO transport is recommended for description poisoning
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-stdio.json \
  --output /tmp/dvmcp-ch2-results.json

# Check detected patterns
cat /tmp/dvmcp-ch2-results.json | jq '.toolAnnotations.toolResults[] | select(.descriptionPoisoning.detected == true) | {toolName, patterns: [.descriptionPoisoning.patterns[].name]}'
```

**Expected Output**:

- `get_company_data`: 3 patterns detected
- `search_company_database`: 7 patterns detected

### CH3: Path Traversal / Excessive Permissions

**Vulnerability**: File system access without proper path validation allows reading files outside intended scope.

**Detection Status**: ✅ DETECTED

**Expected Behavior**:

- Tools allow file operations (read, write, list)
- No validation on file paths
- Can access `/etc/passwd`, parent directories, etc.

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch3 \
  --config /tmp/dvmcp-ch3-sse.json \
  --output /tmp/dvmcp-ch3-results.json

# Check for permission/traversal vulnerabilities
cat /tmp/dvmcp-ch3-results.json | jq '.modules.security.vulnerabilities[] | select(.name | test("traversal|permission"; "i"))'
```

### CH4: Rug Pull (Temporal Mutation)

**Vulnerability**: Tool definitions can change at runtime, allowing benign-looking tools to perform malicious actions after verification.

**Detection Status**: GAP (stateful tool pattern exemption)

**Current Limitation**: Inspector's TemporalAssessor uses schema-only comparison for stateful tools and exempts them from detailed behavior checking. The `get_weather` tool matches the "get" pattern in `STATEFUL_TOOL_PATTERNS`, preventing full temporal mutation detection.

**Expected Behavior**:

- Tools define themselves as returning weather data
- Actually perform unauthorized actions
- Behavior inconsistent with schema/description

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch4 \
  --config /tmp/dvmcp-ch4-sse.json \
  --output /tmp/dvmcp-ch4-results.json
```

**Note**: This is a known limitation. Future versions may enhance stateful tool assessment.

### CH5: Tool Shadowing

**Vulnerability**: Legitimate-sounding tool names are created to intercept and redirect requests.

**Detection Status**: GAP (FastMCP compatibility issue)

**Current Limitation**: The DVMCP implementation uses `listed=False` parameter in tool definitions, which is not supported by the newer `mcp` package version used by Inspector.

**Expected Behavior**:

- Fake tools with legitimate names (e.g., `get_weather`, `fetch_data`)
- Hidden from normal tool listings
- Intercept requests intended for legitimate tools

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch5 \
  --config /tmp/dvmcp-ch5-sse.json \
  --output /tmp/dvmcp-ch5-results.json
```

**Note**: Tool shadowing detection requires MCP spec compliance work to support the `listed` parameter.

### CH6: Indirect Prompt Injection

**Vulnerability**: Malicious instructions are injected through data returned by tools, which the LLM then executes.

**Detection Status**: GAP (requires enhanced data source analysis)

**Expected Behavior**:

- Data sources return poisoned content
- Hidden instructions in returned data
- LLM follows embedded commands in results

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch6 \
  --config /tmp/dvmcp-ch6-sse.json \
  --output /tmp/dvmcp-ch6-results.json
```

### CH7: Token Theft via Info Disclosure

**Vulnerability**: Authentication tokens and credentials are leaked through tool responses.

**Detection Status**: ✅ DETECTED

**Expected Behavior**:

- Tools return sensitive information in responses
- JWT tokens, API keys, session tokens exposed
- Credential storage accessible

**Detection Patterns**:

- JWT format: `eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+`
- Token keywords: `bearer`, `jwt`, `auth`, `session`, `oauth`

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch7 \
  --config /tmp/dvmcp-ch7-sse.json \
  --output /tmp/dvmcp-ch7-results.json

# Check for token theft vulnerabilities
cat /tmp/dvmcp-ch7-results.json | jq '.modules.security.vulnerabilities[] | select(.name | test("token|credential|jwt"; "i"))'
```

**Expected Output**:

- Token exposure vulnerabilities detected
- Multiple attack vectors revealed

### CH8: Arbitrary Code Execution

**Vulnerability**: System allows arbitrary code execution through reflection or deserialization.

**Detection Status**: SAFE (Inspector treats reflection as safe by design)

**Expected Behavior**:

- Code execution capability present
- Reflection-based attacks possible
- Deserialization vulnerabilities

**Note**: Inspector deliberately treats reflection as safe because many legitimate tools use introspection. CH8 demonstrates this design decision.

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch8 \
  --config /tmp/dvmcp-ch8-sse.json \
  --output /tmp/dvmcp-ch8-results.json
```

### CH9: Command Injection (RCE)

**Vulnerability**: System commands can be injected through tool parameters to achieve remote code execution.

**Detection Status**: ✅ DETECTED

**Expected Behavior**:

- Tools accept system commands in parameters
- No input sanitization
- Full shell command execution possible

**Detection Patterns**:

- Command delimiters: `; | & && || $ < > ( ) { }`
- Shell metacharacters in payloads
- Command chaining attempts

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch9 \
  --config /tmp/dvmcp-ch9-sse.json \
  --output /tmp/dvmcp-ch9-results.json

# View detected command injection vulnerabilities
cat /tmp/dvmcp-ch9-results.json | jq '.modules.security.vulnerabilities[] | select(.name | test("command|rce|injection"; "i"))'
```

**Expected Output**:

- Command injection detected
- Multiple attack vectors confirmed

### CH10: Multi-Vector Attack Chain

**Vulnerability**: Combines multiple vulnerabilities to demonstrate complex attack chains.

**Detection Status**: ✅ DETECTED (3+ patterns, 12+ vulnerabilities)

**Expected Tools**:

- `get_user_profile`: Command injection + data exfiltration
- `malicious_check_system_status`: Status check with hidden behaviors
- Multiple other tools with various vulnerabilities

**Expected Detections**:

- `get_user_profile`: 2 poisoning patterns (`important_tag`, `internal_resource_uri`)
- `malicious_check_system_status`: 1 pattern (`hidden_tag`)
- Plus 12+ security vulnerabilities across the attack chain

**Test with Inspector**:

```bash
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch10 \
  --config /tmp/dvmcp-ch10-sse.json \
  --output /tmp/dvmcp-ch10-results.json

# View all detected vulnerabilities
cat /tmp/dvmcp-ch10-results.json | jq '.modules.security.vulnerabilities | length'

# List them by type
cat /tmp/dvmcp-ch10-results.json | jq '[.modules.security.vulnerabilities[] | .name] | unique'
```

**Expected Output**:

- 12+ vulnerabilities detected
- Multiple attack patterns represented
- Demonstrates Inspector's ability to identify complex chains

---

## Results Comparison: Expected vs Actual

### Complete Results Table

| Challenge | Port | Detection Status | Expected Vulnerabilities          | Notes                          |
| --------- | ---- | ---------------- | --------------------------------- | ------------------------------ |
| CH1       | 9001 | GAP              | Prompt Injection via Resources    | Resources not currently tested |
| CH2       | 9002 | ✅ DETECTED      | 7+ description poisoning patterns | Use STDIO for full detection   |
| CH3       | 9003 | ✅ DETECTED      | Path traversal, permission scope  | File access vulnerabilities    |
| CH4       | 9004 | GAP              | Temporal mutation, rug pull       | Stateful tool exemption        |
| CH5       | 9005 | GAP              | Tool shadowing, hidden tools      | FastMCP compatibility issue    |
| CH6       | 9006 | GAP              | Indirect prompt injection         | Requires enhanced analysis     |
| CH7       | 9007 | ✅ DETECTED      | Token theft, credential exposure  | JWT and auth token detection   |
| CH8       | 9008 | SAFE             | Code execution via reflection     | Reflection treated as safe     |
| CH9       | 9009 | ✅ DETECTED      | Command injection, RCE            | Shell metacharacter detection  |
| CH10      | 9010 | ✅ DETECTED      | 12+ multi-vector vulnerabilities  | Combined attack patterns       |

---

## Advanced Configuration

### Custom Port Mapping

If running DVMCP on non-standard ports:

```json
{
  "transport": "sse",
  "url": "http://custom-host:9001/sse"
}
```

### Remote Testing

For testing against remote DVMCP instances:

```json
{
  "transport": "sse",
  "url": "https://your-dvmcp-server.com:9002/sse"
}
```

### Batch Processing

Create a shell script to test all challenges:

```bash
#!/bin/bash
# /tmp/test-all-dvmcp.sh

DVMCP_PORT_START=9001
DVMCP_PORT_END=9010
OUTPUT_DIR="/tmp/dvmcp-results"

mkdir -p $OUTPUT_DIR

for port in $(seq $DVMCP_PORT_START $DVMCP_PORT_END); do
  challenge=$((port - 9000))
  config="/tmp/dvmcp-ch$challenge-sse.json"
  output="$OUTPUT_DIR/dvmcp-ch$challenge-results.json"

  echo "Testing Challenge $challenge (port $port)..."

  npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch$challenge \
    --config "$config" \
    --output "$output"

  # Extract summary
  vulnerabilities=$(jq '.modules.security.vulnerabilities | length' "$output" 2>/dev/null || echo "0")
  echo "  Vulnerabilities found: $vulnerabilities"
done

echo "All tests complete. Results in $OUTPUT_DIR"
```

Make it executable and run:

```bash
chmod +x /tmp/test-all-dvmcp.sh
/tmp/test-all-dvmcp.sh
```

---

## Docker Management

### Check Status

```bash
# List running DVMCP container
docker ps | grep dvmcp

# View all DVMCP containers (including stopped)
docker ps -a | grep dvmcp
```

### View Logs

```bash
# Real-time logs
docker logs -f dvmcp

# Last 50 lines
docker logs --tail 50 dvmcp

# Search for errors
docker logs dvmcp 2>&1 | grep -i error
```

### Restart

```bash
# Soft restart
docker restart dvmcp

# Hard restart (remove and recreate)
docker stop dvmcp && docker rm dvmcp
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp
```

### Cleanup

```bash
# Stop container
docker stop dvmcp

# Remove container
docker rm dvmcp

# Remove image
docker rmi dvmcp

# Complete cleanup (remove all traces)
docker stop dvmcp && docker rm dvmcp && docker rmi dvmcp
```

### Update DVMCP

```bash
# Pull latest changes
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server
git pull origin main

# Rebuild image
docker build -t dvmcp .

# Stop and remove old container
docker stop dvmcp && docker rm dvmcp

# Run new version
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp
```

---

## Troubleshooting

### Connection Issues

**Error: Unable to connect to localhost:9001**

```bash
# Check if container is running
docker ps | grep dvmcp

# Check if port is open
nc -zv localhost 9001

# If not running, start it
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp
```

**Error: Connection refused**

```bash
# Check container logs
docker logs dvmcp

# Verify port mapping
docker inspect dvmcp | grep -A 5 PortBindings

# Try different port or restart container
docker restart dvmcp && sleep 2
curl -v http://localhost:9001/sse
```

### Assessment Failures

**Error: Config file not found**

```bash
# Verify config file exists
ls -la /tmp/dvmcp-ch2-sse.json

# Verify JSON is valid
jq . /tmp/dvmcp-ch2-sse.json

# Create if missing
echo '{"transport": "sse", "url": "http://localhost:9002/sse"}' > /tmp/dvmcp-ch2-sse.json
```

**Error: No results in output file**

```bash
# Check if output file was created
ls -la /tmp/dvmcp-ch2-results.json

# Check for errors in the output
jq '.error' /tmp/dvmcp-ch2-results.json 2>/dev/null || echo "No error field"

# Try again with verbose output
npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch2 \
  --config /tmp/dvmcp-ch2-sse.json \
  --output /tmp/dvmcp-ch2-results.json \
  2>&1 | tail -50
```

### Tool Definition Issues

**Error: Tools are not loading properly**

```bash
# For SSE transport, verify the server is responding with tools
curl -s http://localhost:9002/sse -N | jq . | head -100

# Check if tool list is empty
curl -s http://localhost:9002/sse -N | jq '.tools | length'
```

**Error: STDIO wrapper script fails**

```bash
# Test wrapper script directly
python3 /tmp/run-ch2-stdio.py 2>&1 | head -50

# Check Python path
which python3
echo $PYTHONPATH

# Verify challenge module exists
python3 -c "import sys; sys.path.insert(0, '/home/bryan/mcp-servers/damn-vulnerable-mcp-server/challenges/easy/challenge2'); from server import mcp; print('Module loaded')"
```

### Version Compatibility

**Error: Python version mismatch**

```bash
# Check Python version
python3 --version

# Ensure virtual environment is using correct version
source /home/bryan/mcp-servers/damn-vulnerable-mcp-server/.venv/bin/activate
python3 --version

# Rebuild virtual environment if needed
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server
rm -rf .venv
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: DVMCP Security Assessment

on: [push, pull_request]

jobs:
  dvmcp-assessment:
    runs-on: ubuntu-latest

    services:
      dvmcp:
        image: dvmcp:latest
        ports:
          - 9001-9010:9001-9010

    steps:
      - uses: actions/checkout@v3

      - uses: actions/setup-node@v3
        with:
          node-version: "18"

      - name: Wait for DVMCP to be ready
        run: |
          for i in {1..30}; do
            curl -s http://localhost:9001/sse && break
            sleep 1
          done

      - name: Run assessments
        run: |
          for i in {1..10}; do
            echo "{\"transport\": \"sse\", \"url\": \"http://localhost:900$i/sse\"}" > /tmp/dvmcp-ch$i.json
            npx -p @bryan-thompson/inspector-assessment mcp-assess-full dvmcp-ch$i \
              --config /tmp/dvmcp-ch$i.json \
              --output /tmp/dvmcp-ch$i-results.json
          done

      - name: Check results
        run: |
          for i in {1..10}; do
            vulns=$(jq '.modules.security.vulnerabilities | length' /tmp/dvmcp-ch$i-results.json)
            echo "Challenge $i: $vulns vulnerabilities"
          done
```

---

## Security Considerations

### Important Warning

DVMCP is **intentionally vulnerable** for educational purposes. It should only be run in:

- Local development environments
- Isolated testing systems
- Dedicated security training labs
- CI/CD pipelines in secure infrastructure

**Never expose DVMCP ports to untrusted networks.**

### Safe Practices

1. Run DVMCP in Docker containers for isolation
2. Use network policies to restrict access
3. Run in dedicated security test subnets
4. Never use production credentials with DVMCP
5. Clean up DVMCP resources after testing
6. Monitor for unexpected network access

---

## Known Limitations and Future Work

### Current Gaps

| Gap                | Challenge | Reason                     | Future Fix                             |
| ------------------ | --------- | -------------------------- | -------------------------------------- |
| Resource Injection | CH1       | Inspector focused on tools | Expand to test resources               |
| Tool Shadowing     | CH5       | FastMCP compatibility      | Support `listed` parameter in MCP spec |
| Temporal Mutation  | CH4       | Stateful tool exemption    | Enhance temporal mutation detection    |
| Indirect Injection | CH6       | Requires enhanced analysis | Implement data source analysis         |

### Enhancement Opportunities

1. **Resource Testing**: Extend assessor to test MCP resources for injection
2. **Listed Parameter Support**: Implement MCP spec support for hidden tools
3. **Stateful Tool Analysis**: Enhanced behavior verification for tools with state
4. **Data Source Analysis**: Test returned data for embedded instructions
5. **Attack Chain Detection**: Multi-step vulnerability correlation

---

## References

- **DVMCP GitHub**: https://github.com/harishsg93010/damn-vulnerable-MCP-server
- **MCP Specification**: https://modelcontextprotocol.io/
- **Inspector Assessment Guide**: See `/home/bryan/inspector/docs/ASSESSMENT_CATALOG.md`
- **Description Poisoning Tests**: `client/src/services/assessment/__tests__/DescriptionPoisoning-DVMCP.test.ts`

---

## Support and Contributions

For issues with DVMCP:

- Check the [DVMCP GitHub Issues](https://github.com/harishsg993010/damn-vulnerable-MCP-server/issues)
- Review the [DVMCP README](https://github.com/harishsg993010/damn-vulnerable-MCP-server/blob/main/README.md)

For Inspector-specific questions:

- See `/home/bryan/inspector/CLAUDE.md` - Project development guide
- Check `/home/bryan/inspector/docs/ASSESSMENT_CATALOG.md` - Assessment reference
- Review test cases: `client/src/services/assessment/__tests__/`
