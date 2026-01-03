# MCP Manifest Requirements Guide

## Overview

The MCP Inspector validates `manifest.json` files for MCPB (MCP Bundle) bundles. The manifest is a critical configuration file that defines how an MCP server should be invoked and provides metadata about the bundle.

**Manifest Format**: JSON
**Current Version**: 0.3
**Specification**: MCPB (Model Context Protocol Bundle)

This guide explains all validation rules the Inspector checks, required vs. optional fields, common anti-patterns, and how manifest issues affect your assessment score.

---

## Quick Reference: Required Fields

| Field                | Type   | Purpose                              | Example           |
| -------------------- | ------ | ------------------------------------ | ----------------- |
| `manifest_version`   | string | Protocol version (must be "0.3")     | `"0.3"`           |
| `name`               | string | Bundle identifier (npm-style naming) | `"my-mcp-server"` |
| `version`            | string | Semantic versioning (X.Y.Z format)   | `"1.0.0"`         |
| `mcp_config`         | object | Server invocation configuration      | See below         |
| `mcp_config.command` | string | Command to run (node, python3, etc.) | `"node"`          |

**Note**: Failing to provide any of these required fields will result in a FAIL status.

---

## Detailed Field Reference

### manifest_version (Required)

**Purpose**: Specifies the manifest protocol version.

**Validation Rules**:

- Must be present and non-empty
- Must equal `"0.3"` (current version)
- Failure severity: **ERROR** (if missing) or **WARNING** (if not 0.3)

**Valid Example**:

```json
{
  "manifest_version": "0.3"
}
```

**Invalid Examples**:

```json
{
  "manifest_version": "0.2"  // Warning: old version
}

{
  // Missing entirely: ERROR
}
```

**Impact**: Mismatched versions may indicate incompatibility with the current MCP specification. Always use `"0.3"`.

---

### name (Required)

**Purpose**: Identifies the bundle by name, used in package managers and directories.

**Validation Rules**:

- Must be present and non-empty
- Should be lowercase
- Should contain only alphanumeric characters, hyphens, underscores, and dots
- Pattern: `^[a-z0-9][a-z0-9._-]*$`
- Failure severity: **ERROR** (if missing) or **WARNING** (if format invalid)

**Valid Examples**:

```json
{
  "name": "my-mcp-server"
}

{
  "name": "weather.api"
}

{
  "name": "calculator_v1"
}
```

**Invalid Examples**:

```json
{
  "name": "My MCP Server"  // Warning: contains spaces and capitals
}

{
  "name": "My-MCP-Server!"  // Warning: contains special characters
}

{
  // Missing entirely: ERROR
}
```

**Impact**: Invalid names may prevent distribution through package managers or directories.

---

### version (Required)

**Purpose**: Indicates the bundle version for updating and compatibility tracking.

**Validation Rules**:

- Must be present and non-empty
- Must follow semantic versioning (semver): `X.Y.Z` where X, Y, Z are integers
- May include pre-release or build metadata: `X.Y.Z-pre.1+build.123`
- Failure severity: **ERROR** (if missing) or **WARNING** (if not semver format)

**Valid Examples**:

```json
{
  "version": "1.0.0"
}

{
  "version": "0.1.0"
}

{
  "version": "2.3.4-beta.1"  // Pre-release
}

{
  "version": "1.0.0+build.123"  // Build metadata
}
```

**Invalid Examples**:

```json
{
  "version": "v1.0.0"  // Warning: prefix 'v' is not semver
}

{
  "version": "1.0"  // Warning: missing patch version
}

{
  "version": "latest"  // Warning: not a version number
}

{
  // Missing entirely: ERROR
}
```

**Impact**: Non-semver versions make it difficult to track updates and dependencies. Package managers expect strict semver compliance.

---

### mcp_config (Required)

**Purpose**: Defines how the MCP server should be started.

**Structure**:

```json
{
  "mcp_config": {
    "command": "node",
    "args": ["${__dirname}/dist/index.js"],
    "env": {
      "KEY": "value"
    }
  }
}
```

#### mcp_config.command (Required)

**Validation Rules**:

- Must be present in `mcp_config`
- Must be a relative command (e.g., `node`, `python3`, `./bin/server`)
- Must NOT be an absolute path (e.g., `/usr/local/bin/node`)
- Must NOT use `${BUNDLE_ROOT}` (legacy/unsupported placeholder)
- Failure severity: **ERROR**

**Valid Examples**:

```json
{
  "mcp_config": {
    "command": "node"
  }
}

{
  "mcp_config": {
    "command": "python3"
  }
}

{
  "mcp_config": {
    "command": "./bin/start.sh"
  }
}
```

**Invalid Examples**:

```json
{
  "mcp_config": {
    "command": "/usr/local/bin/node"  // ERROR: absolute path
  }
}

{
  "mcp_config": {
    "command": "C:\\Program Files\\Node\\node.exe"  // ERROR: Windows absolute path
  }
}

{
  "mcp_config": {
    "args": ["${BUNDLE_ROOT}/dist/index.js"]  // ERROR: ${BUNDLE_ROOT} not supported
  }
}

{
  "mcp_config": {
    // Missing command: ERROR
  }
}
```

**Anti-Patterns to Avoid**:

1. **Absolute Paths**: Break portability across systems

   ```json
   // BAD
   { "command": "/home/user/project/bin/server" }

   // GOOD
   { "command": "./bin/server" }
   ```

2. **${BUNDLE_ROOT} Placeholder**: Not supported by MCP

   ```json
   // BAD
   { "args": ["${BUNDLE_ROOT}/dist/index.js"] }

   // GOOD
   { "args": ["${__dirname}/dist/index.js"] }
   ```

3. **Hardcoded User Paths**: Creates environment-specific failures

   ```json
   // BAD
   { "args": ["/Users/john/projects/mcp/index.js"] }

   // GOOD
   { "args": ["/dist/index.js"] }  // Relative to bundle
   ```

#### mcp_config.args (Optional)

**Purpose**: Command-line arguments passed to the server command.

**Best Practices**:

- Use `${__dirname}` for paths relative to the manifest
- Keep arguments minimal and configuration-free
- Support environment variables for runtime configuration

**Valid Examples**:

```json
{
  "mcp_config": {
    "command": "node",
    "args": ["${__dirname}/dist/index.js"]
  }
}

{
  "mcp_config": {
    "command": "python3",
    "args": [
      "${__dirname}/server.py",
      "--debug"
    ]
  }
}
```

#### mcp_config.env (Optional)

**Purpose**: Environment variables to pass to the server process.

**Valid Examples**:

```json
{
  "mcp_config": {
    "command": "node",
    "args": ["index.js"],
    "env": {
      "DEBUG": "true",
      "LOG_LEVEL": "info"
    }
  }
}
```

**Best Practices**:

- Use only for essential configuration
- Don't include secrets (API keys, tokens)
- Document expected environment variables in README

---

### description (Recommended)

**Purpose**: Human-readable description of what the bundle does.

**Validation Rules**:

- Optional but highly recommended
- If present, should be non-empty
- Failure severity: **WARNING** (if missing or empty)

**Valid Examples**:

```json
{
  "description": "An MCP server that provides access to the weather API"
}

{
  "description": "Calculator tool for mathematical operations"
}
```

**Invalid Examples**:

```json
{
  "description": ""  // Warning: empty
}

{
  // No description key: warning
}
```

**Impact**: Descriptions help users understand the bundle's purpose in directories and package managers. Missing descriptions reduce discoverability.

---

### author (Recommended)

**Purpose**: Credits the bundle creator or organization.

**Validation Rules**:

- Optional but highly recommended
- If present, should be non-empty
- Can be a name or email format
- Failure severity: **WARNING** (if missing or empty)

**Valid Examples**:

```json
{
  "author": "John Doe"
}

{
  "author": "john@example.com"
}

{
  "author": "Acme Corp <contact@acme.com>"
}
```

**Invalid Examples**:

```json
{
  "author": ""  // Warning: empty
}

{
  // No author key: warning
}
```

**Impact**: Missing author information reduces accountability and trust.

---

### repository (Recommended)

**Purpose**: Links to the source code repository for transparency.

**Validation Rules**:

- Optional but highly recommended
- Should be a valid URL or repository identifier
- Failure severity: **WARNING** (if missing)

**Valid Examples**:

```json
{
  "repository": "https://github.com/user/mcp-server"
}

{
  "repository": "github:user/mcp-server"
}

{
  "repository": "git@github.com:user/mcp-server.git"
}
```

**Impact**: Repository links improve transparency and enable users to review source code, report issues, and contribute.

---

### icon (Recommended)

**Purpose**: Visual representation of the bundle in package managers and directories.

**Validation Rules**:

- Optional but highly recommended
- Should reference a PNG or SVG file
- File should exist in the bundle
- Failure severity: **WARNING** (if missing)

**Valid Examples**:

```json
{
  "icon": "icon.png"
}

{
  "icon": "assets/logo.svg"
}
```

**Invalid Examples**:

```json
{
  "icon": "/absolute/path/icon.png"  // Use relative paths
}

{
  "icon": "https://example.com/icon.png"  // Use local files
}

{
  // No icon: warning (but icon.png will still be discovered)
}
```

**Best Practices**:

- Size: 256x256 pixels or larger
- Format: PNG or SVG (PNG recommended)
- Location: Root of bundle or `assets/` directory
- Even if icon field is missing, Inspector will discover `icon.png` or `icon.svg` files

---

### privacy_policies (Optional)

**Purpose**: Links to privacy policy documents explaining data handling practices.

**Validation Rules**:

- Optional
- Should be an array of valid HTTPS URLs
- URLs are fetched and verified to be accessible
- Failure severity: **WARNING** (if any URL is inaccessible)

**Valid Examples**:

```json
{
  "privacy_policies": [
    "https://example.com/privacy"
  ]
}

{
  "privacy_policies": [
    "https://example.com/privacy",
    "https://example.com/data-practices"
  ]
}
```

**Invalid Examples**:

```json
{
  "privacy_policies": [
    "example.com/privacy"  // Warning: not HTTPS or valid URL
  ]
}

{
  "privacy_policies": [
    "https://dead-link.example.com/privacy"  // Warning: URL inaccessible
  ]
}
```

**Validation Details**:

- Inspector makes HEAD requests with 5-second timeout
- Falls back to GET if HEAD fails
- Checks for HTTP 200-299 status codes
- Validates URL format before network requests

**Impact**: Privacy policies demonstrate transparency and may be required by directories or regulations.

---

## Assessment Status Determination

The manifest validation module produces one of three statuses:

### PASS

- All required fields present and valid
- No ERROR severity violations
- May have optional fields with values

### NEED_MORE_INFO

- All required fields present and valid
- One or more WARNING severity issues (missing recommended fields, deprecated version, etc.)
- Can be improved by addressing warnings

### FAIL

- Missing one or more required fields, OR
- One or more ERROR severity violations (invalid JSON, bad command, etc.)
- Cannot proceed without fixing errors

---

## Common Anti-Patterns to Avoid

### 1. Using ${BUNDLE_ROOT}

**Problem**: `${BUNDLE_ROOT}` is not a supported placeholder in MCP.

```json
// WRONG
{
  "mcp_config": {
    "args": ["${BUNDLE_ROOT}/dist/index.js"]  // ERROR
  }
}

// CORRECT
{
  "mcp_config": {
    "args": ["${__dirname}/dist/index.js"]  // Use __dirname
  }
}
```

**Why**: The MCP specification uses Node.js-style `${__dirname}` for relative paths. Use this instead.

---

### 2. Hardcoded Absolute Paths

**Problem**: Absolute paths break portability across different systems.

```json
// WRONG
{
  "mcp_config": {
    "command": "/usr/local/bin/node",
    "args": ["/home/user/mcp-servers/index.js"]
  }
}

// CORRECT
{
  "mcp_config": {
    "command": "node",
    "args": ["${__dirname}/dist/index.js"]
  }
}
```

**Why**: Different systems have different installations. Use relative paths and let the system PATH find the command.

---

### 3. Windows-Specific Paths

**Problem**: Windows absolute paths prevent Linux/Mac compatibility.

```json
// WRONG
{
  "mcp_config": {
    "command": "C:\\Program Files\\Node\\node.exe",
    "args": ["C:\\Users\\user\\mcp\\index.js"]
  }
}

// CORRECT
{
  "mcp_config": {
    "command": "node",
    "args": ["dist/index.js"]  // Or ${__dirname}/dist/index.js
  }
}
```

**Why**: Use platform-agnostic commands and relative paths.

---

### 4. Non-Semver Version Numbers

**Problem**: Version numbers that don't follow semver make dependency management impossible.

```json
// WRONG
{
  "version": "v1"       // ERROR
}

{
  "version": "latest"   // ERROR
}

{
  "version": "1.0"      // ERROR: missing patch
}

// CORRECT
{
  "version": "1.0.0"
}

{
  "version": "2.3.4-beta.1"
}
```

**Why**: Semver is the standard for version management. Tools expect X.Y.Z format.

---

### 5. Invalid Name Format

**Problem**: Names with spaces or capitals may break package managers.

```json
// WRONG
{
  "name": "My MCP Server"      // WARNING: spaces and capitals
}

{
  "name": "MCP-Server-2!"      // WARNING: special characters
}

// CORRECT
{
  "name": "my-mcp-server"
}

{
  "name": "mcp_server_2"
}
```

**Why**: Package managers expect lowercase, alphanumeric names with hyphens/underscores.

---

## Complete Valid Example

```json
{
  "manifest_version": "0.3",
  "name": "weather-mcp",
  "version": "1.0.0",
  "description": "An MCP server providing access to weather data and forecasts",
  "author": "Weather Team <team@weather.example.com>",
  "repository": "https://github.com/example/weather-mcp",
  "license": "MIT",
  "homepage": "https://weather.example.com",
  "keywords": ["weather", "forecast", "mcp"],
  "mcp_config": {
    "command": "node",
    "args": ["${__dirname}/dist/index.js"],
    "env": {
      "LOG_LEVEL": "info",
      "NODE_ENV": "production"
    }
  },
  "icon": "icon.png",
  "privacy_policies": ["https://weather.example.com/privacy"]
}
```

**Validation Result**: PASS

---

## Complete Invalid Example with Explanations

```json
{
  "manifest_version": "0.2", // WARNING: Expected 0.3
  "name": "My Weather MCP!", // WARNING: Contains spaces and special chars
  "version": "1", // WARNING: Not semver (missing .0.0)
  "description": "", // WARNING: Empty description (recommended field)
  // Missing: author (recommended field) - WARNING
  // Missing: mcp_config (REQUIRED) - ERROR
  "icon": "/absolute/path/icon.png" // WARNING: Use relative paths
}
```

**Validation Result**: FAIL (missing required `mcp_config`)

---

## Scoring Impact

Manifest validation issues affect your overall Inspector assessment:

| Category                      | Impact                           | Severity |
| ----------------------------- | -------------------------------- | -------- |
| **Missing mcp_config**        | FAIL (cannot assess)             | ERROR    |
| **Invalid JSON**              | FAIL (cannot parse)              | ERROR    |
| **Missing required fields**   | FAIL                             | ERROR    |
| **Hardcoded absolute paths**  | FAIL (portability broken)        | ERROR    |
| **Invalid manifest_version**  | WARNING                          | WARNING  |
| **Invalid name format**       | WARNING                          | WARNING  |
| **Non-semver version**        | WARNING                          | WARNING  |
| **Missing description**       | WARNING (info incomplete)        | WARNING  |
| **Missing author**            | WARNING (accountability unclear) | WARNING  |
| **Missing icon**              | WARNING (poor UX)                | WARNING  |
| **Inaccessible privacy URLs** | WARNING (transparency concern)   | WARNING  |

---

## Testing with Inspector

### From Web UI

1. Navigate to the Inspector web interface
2. Connect to your MCPB bundle
3. Run assessment
4. Check the "Manifest Validation" tab in results

### From CLI

```bash
npm run assess -- --server my-bundle --config config.json
```

Check results:

```bash
cat /tmp/inspector-assessment-my-bundle.json | jq '.manifestValidation'
```

---

## Debugging Manifest Issues

### Common Issues and Solutions

**Error: "No manifest.json found"**

- Solution: Ensure `manifest.json` exists in the bundle root
- Check: File path, file permissions, bundle structure

**Error: "Invalid JSON"**

- Solution: Validate JSON syntax using a linter
- Tools: `jq`, VS Code JSON validation, jsonlint.com
- Check: Missing quotes, trailing commas, unclosed braces

**Error: "Missing required field: mcp_config"**

- Solution: Add `mcp_config` object with `command` field
- Example: `"mcp_config": { "command": "node", "args": ["index.js"] }`

**Warning: "Uses ${BUNDLE_ROOT} which is not supported"**

- Solution: Replace `${BUNDLE_ROOT}` with `${__dirname}`
- Example: `"${__dirname}/dist/index.js"`

**Warning: "Command uses hardcoded absolute path"**

- Solution: Use relative paths or commands from system PATH
- Example: Change `/usr/local/bin/node` to `node`

**Warning: "Version should follow semver format"**

- Solution: Use X.Y.Z format (e.g., "1.0.0")
- Reference: https://semver.org/

---

## Manifest Best Practices

1. **Validate JSON**: Always validate manifest.json before deployment

   ```bash
   jq empty manifest.json
   ```

2. **Test Portability**: Ensure your manifest works across platforms
   - Use relative paths
   - Don't hardcode user directories
   - Test on Windows, macOS, and Linux

3. **Keep Privacy Policies Updated**: Ensure all privacy policy URLs are current
   - Test links regularly
   - Update manifests when policies move
   - Consider using canonical URLs

4. **Document Configuration**: Explain any environment variables in README

   ```json
   "env": {
     "DEBUG": "Set to 'true' for verbose logging"
   }
   ```

5. **Use Semantic Versioning**: Follow semver rules for releases
   - Patch (1.0.1): Bug fixes
   - Minor (1.1.0): New features
   - Major (2.0.0): Breaking changes

6. **Provide All Recommended Fields**: Complete metadata improves user experience
   - `description`: What does it do?
   - `author`: Who created it?
   - `repository`: Where's the source?
   - `icon`: What's it called in the directory?

---

## References

- **MCP Specification**: https://modelcontextprotocol.io/
- **MCPB Bundle Spec**: Latest version in MCP documentation
- **Semantic Versioning**: https://semver.org/
- **JSON Schema Validation**: https://json-schema.org/
- **npm Package.json Format**: https://docs.npmjs.com/cli/v10/configuring-npm/package-json (for naming conventions)

---

## Questions?

For issues with manifest validation:

1. Check this guide for your specific error
2. Validate JSON syntax first
3. Review the manifest against the "Complete Valid Example"
4. Run the Inspector to get detailed validation results
5. Open an issue on GitHub with your manifest and error details
