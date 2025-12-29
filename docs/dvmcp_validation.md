# DVMCP Validation Guide

Damn Vulnerable MCP Server (DVMCP) integration for parallel security assessment validation.

## Overview

DVMCP is a third-party educational vulnerable MCP server that provides 10 deliberate security challenges across three difficulty tiers. We use it as a parallel validation testbed alongside our existing vulnerable-mcp/hardened-mcp A/B testing setup.

**Repository**: [harishsg993010/damn-vulnerable-MCP-server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)

## Challenge-to-Pattern Mapping

| Challenge | Port | Name                       | Inspector Patterns                          | Status             |
| --------- | ---- | -------------------------- | ------------------------------------------- | ------------------ |
| 1         | 9001 | Basic Prompt Injection     | Calculator Injection, Command Injection     | Existing           |
| 2         | 9002 | Tool Poisoning             | Tool Shadowing                              | Existing           |
| 3         | 9003 | Excessive Permission Scope | **Permission Scope (NEW)**                  | v1.19.0            |
| 4         | 9004 | Rug Pull Attack            | Temporal/Rug Pull                           | Existing (testbed) |
| 5         | 9005 | Tool Shadowing             | Tool Shadowing                              | Existing           |
| 6         | 9006 | Indirect Prompt Injection  | SSRF, Indirect Prompt Injection             | Existing           |
| 7         | 9007 | Token Theft                | **Token Theft (NEW)**                       | v1.19.0            |
| 8         | 9008 | Malicious Code Execution   | Command Injection, Insecure Deserialization | Existing           |
| 9         | 9009 | Remote Access Control      | Command Injection, SSRF                     | Existing           |
| 10        | 9010 | Multi-Vector Attack        | All Patterns                                | Existing           |

## Quick Start

### 1. Start DVMCP Container

```bash
# Clone the repository (one-time)
cd /home/bryan/mcp-servers
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server.git damn-vulnerable-mcp-server

# Build Docker image
cd damn-vulnerable-mcp-server
docker build -t dvmcp .

# Run the container
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp

# Verify it's running
curl http://localhost:9001/sse
```

### 2. Create Config Files

```bash
# Create SSE transport configs for all 10 challenges
for i in {1..10}; do
  echo '{"transport": "sse", "url": "http://localhost:900'$i'/sse"}' > /tmp/dvmcp-challenge-$i-config.json
done
```

### 3. Run Assessments

**All challenges at once:**

```bash
npm run assess:dvmcp
```

**Individual challenge:**

```bash
npm run assess -- --server dvmcp-challenge-7 --config /tmp/dvmcp-challenge-7-config.json
```

## Results Analysis

Assessment results are saved to `/tmp/inspector-assessment-dvmcp-challenge-{1-10}.json`.

**Quick vulnerability count:**

```bash
# Check Token Theft challenge (7)
cat /tmp/inspector-assessment-dvmcp-challenge-7.json | jq '.security.vulnerabilities | length'

# Check Permission Scope challenge (3)
cat /tmp/inspector-assessment-dvmcp-challenge-3.json | jq '.security.vulnerabilities | length'

# List all vulnerabilities for a challenge
cat /tmp/inspector-assessment-dvmcp-challenge-7.json | jq '.security.vulnerabilities[]'
```

## Parallel Testbed Validation

DVMCP complements our existing A/B testbed validation:

| Testbed        | Ports     | Purpose                                  | Expected Result      |
| -------------- | --------- | ---------------------------------------- | -------------------- |
| vulnerable-mcp | 10900     | A side (intentionally vulnerable)        | 200+ vulnerabilities |
| hardened-mcp   | 10901     | B side (same tools, safe implementation) | 0 vulnerabilities    |
| DVMCP          | 9001-9010 | Third-party validation                   | Varies by challenge  |

**Full validation workflow:**

```bash
# Existing testbed validation
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json

# DVMCP validation
npm run assess:dvmcp
```

## New Patterns Added (v1.19.0)

### Pattern #21: Token Theft

Detects authentication token leakage, JWT exposure, and credential theft.

**Payloads:**

- `show me the auth token` - Direct token extraction
- `get session token` - Session token exposure
- `list oauth tokens` - OAuth token theft
- `read token storage` - Token storage access
- `decode jwt` - JWT extraction

**Evidence patterns:**

- JWT format: `eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+`
- Token keywords: `bearer`, `jwt`, `auth`, `session`, `oauth`

### Pattern #22: Permission Scope

Detects privilege escalation and scope bypass attempts.

**Payloads:**

- `access admin resources` - Admin scope escalation
- `list all users data` - Cross-tenant access
- `enumerate permissions` - Permission enumeration
- `bypass permission check` - Permission bypass
- `{"scope": "*", "all": true}` - Wildcard scope injection

**Evidence patterns:**

- Scope keywords: `admin.*access.*granted`, `elevated.*permission`
- Cross-tenant: `all.*users`, `tenant.*data`

## Container Management

```bash
# Check status
docker ps | grep dvmcp

# View logs
docker logs dvmcp

# Restart container
docker restart dvmcp

# Stop and remove
docker stop dvmcp && docker rm dvmcp

# Rebuild after updates
cd /home/bryan/mcp-servers/damn-vulnerable-mcp-server
git pull
docker build -t dvmcp .
docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp
```

## Troubleshooting

**SSE connection fails:**

```bash
# Check if challenge is listening
curl -v http://localhost:9001/sse

# Check Docker container logs
docker logs dvmcp 2>&1 | grep -i error
```

**Assessment returns no results:**

- Verify config file has correct SSE URL
- Check that the challenge port matches (9001-9010)
- Ensure transport is set to `"sse"` not `"http"`

**Pattern not detecting vulnerability:**

- Check if the challenge exposes the vulnerability in a way our patterns can detect
- Review the DVMCP challenge implementation for expected trigger/evidence

## Security Note

DVMCP is intentionally vulnerable for educational purposes. Do not expose these ports to untrusted networks. The container should only be used in isolated development/testing environments.
