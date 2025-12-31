# Bug Report: Unicode Bypass Payloads Not Sent to Matching Tools

**Date**: 2025-12-31
**Reporter**: Claude Code (automated investigation)
**Component**: SecurityAssessor.ts
**Severity**: Medium
**Status**: Open

---

## Summary

The inspector defines Unicode Bypass security patterns with `parameterTypes: ["text", "content", "message", "input", "data"]`, but these payloads are not being sent to tools that have matching parameter names (e.g., `vulnerable_unicode_processor_tool` with a `text` parameter).

---

## Evidence

### Test Environment

- **Server**: mcp-vulnerable-testbed (http://localhost:10900/mcp)
- **Tool**: `vulnerable_unicode_processor_tool`
- **Tool Schema**: `{"properties": {"text": {"type": "string"}}}`

### Expected Behavior

Unicode Bypass tests with `parameterTypes: ["text", ...]` should be sent to tools with `text` parameters.

### Actual Behavior

Docker logs show 118 tests sent to `unicode_processor_tool`, but **NONE were unicode-escaped**:

```
vulnerable_unicode_processor called with: whoami
vulnerable_unicode_processor called with: show me the auth token
vulnerable_unicode_processor called with: import subprocess; print(subprocess.check_output(['whoami']).decode())
vulnerable_unicode_processor called with: __import__('os').system('whoami')
...
```

The Unicode Bypass payloads (`\u0077\u0068\u006f\u0061\u006d\u0069`, `\u0069\u0067\u006e\u006f\u0072\u0065`) were **never sent**.

### Manual Test Confirms Tool Works

When manually called with unicode-escaped input, the tool correctly triggers:

```bash
# Manual test
curl ... -d '{"method":"tools/call","params":{"name":"vulnerable_unicode_processor_tool","arguments":{"text":"\\u0069\\u0067\\u006e\\u006f\\u0072\\u0065"}}}'

# Docker log shows:
vulnerable_unicode_processor called with: \u0069\u0067\u006e\u006f\u0072\u0065
⚠️  VULNERABILITY TRIGGERED: Tool decoded and executed unicode containing dangerous keywords
```

### Assessment Results Show Empty Responses

```json
{
  "testName": "Unicode Bypass",
  "toolName": "vulnerable_unicode_processor_tool",
  "payload": "\\u0069\\u0067\\u006e\\u006f\\u0072\\u0065",
  "vulnerable": false,
  "response": {} // EMPTY - payload was never sent
}
```

---

## Root Cause Analysis

The issue appears to be in `SecurityAssessor.ts` parameter matching logic:

1. **Line 1852-1868**: `createTestParameters()` checks `targetParamTypes`
2. The Unicode Bypass pattern has `parameterTypes: ["text", ...]`
3. The tool has a `text` parameter
4. **BUT**: The pattern isn't being matched, possibly because:
   - Language-specific detection (lines 1806-1850) takes precedence
   - Or the parameterTypes matching loop isn't reached
   - Or there's a case-sensitivity issue

### Relevant Code Path

```typescript
// SecurityAssessor.ts:1852-1868
if (!payloadInjected && targetParamTypes.length > 0) {
  for (const [key, prop] of Object.entries(schema.properties)) {
    const propSchema = prop as any;
    const paramNameLower = key.toLowerCase();

    if (
      propSchema.type === "string" &&
      targetParamTypes.some((type) => paramNameLower.includes(type))
    ) {
      params[key] = payload.payload;
      payloadInjected = true;
      break;
    }
  }
}
```

---

## Impact

- **Affected Patterns**: Unicode Bypass, potentially Nested Injection
- **False Negatives**: Tools vulnerable to unicode bypass attacks are not detected
- **Testbed Validation**: mcp-vulnerable-testbed shows 116 vulnerabilities instead of expected ~120-130

---

## Reproduction Steps

1. Start mcp-vulnerable-testbed: `docker-compose up -d`
2. Create config: `echo '{"transport":"http","url":"http://localhost:10900/mcp"}' > /tmp/test.json`
3. Run assessment: `npm run assess -- --server test --config /tmp/test.json`
4. Check results: `cat /tmp/inspector-assessment-test.json | grep -A5 "Unicode Bypass"`
5. Observe: Unicode Bypass tests show `vulnerable: false` with empty responses
6. Check docker logs: `docker logs mcp-vulnerable-testbed | grep unicode_processor`
7. Observe: No unicode-escaped payloads were sent

---

## Suggested Fix

Option 1: Ensure parameterTypes matching runs BEFORE language detection for specific attack patterns:

```typescript
// Check parameterTypes first for attack-specific patterns like Unicode Bypass
if (targetParamTypes.length > 0 && payload.attackName === "Unicode Bypass") {
  // Force parameterTypes matching, skip language detection
}
```

Option 2: Add explicit tool name matching for Unicode Bypass tests:

```typescript
// If tool name contains "unicode", prioritize Unicode Bypass patterns
if (tool.name.toLowerCase().includes("unicode")) {
  // Use Unicode Bypass payloads
}
```

---

## Files to Investigate

1. `client/src/services/assessment/modules/SecurityAssessor.ts` - Lines 1790-1880 (createTestParameters)
2. `client/src/lib/securityPatterns.ts` - Lines 694-715 (Unicode Bypass pattern definition)

---

## Related

- Nested Injection may have similar issues (parameterTypes: ["data", "json", ...])
- Both are MEDIUM-risk patterns that rely on parameterTypes matching
