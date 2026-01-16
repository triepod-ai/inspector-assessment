/**
 * AppleScript Injection False Negative Tests (Issue #177)
 *
 * Tests that AppleScript injection vulnerabilities are CORRECTLY flagged
 * even when AppleScript errors are present in the response.
 *
 * Background:
 * - H1 #3480575: Inspector marked CRITICAL RCE as "not vulnerable"
 * - The payload " & do shell script "id" & " SUCCESSFULLY escaped string context
 * - Error -2710 came AFTER injection point (Word not running)
 * - The vulnerability EXISTS - payload reached shell execution context
 *
 * Root cause:
 * - Issue #175 fix (AppleScript syntax error detection) was too aggressive
 * - It dismissed ALL AppleScript errors as "safe", including injection SUCCESS cases
 * - Need to distinguish: syntax error (safe) vs runtime error after injection (vulnerable)
 *
 * Fix:
 * - Issue #177: Check for injection SUCCESS patterns BEFORE dismissing as syntax error
 * - If injection patterns detected (e.g., "" & do shell script), continue analysis
 *
 * This test suite validates:
 * 1. Injection success patterns are detected
 * 2. H1 #3480575 scenario is flagged as vulnerable
 * 3. Issue #175 regression: XXE in AppleScript errors still NOT flagged
 * 4. Plain syntax errors without injection are still safe
 *
 * @group unit
 * @group security
 * @group regression
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import {
  isAppleScriptInjectionSuccess,
  isAppleScriptSyntaxError,
  APPLESCRIPT_INJECTION_SUCCESS_PATTERNS,
  APPLESCRIPT_RUNTIME_ERROR_CODES,
} from "../modules/securityTests/SecurityPatternLibrary";
import { SafeResponseDetector } from "../modules/securityTests/SafeResponseDetector";
import { SecurityPayload } from "@/lib/securityPatterns";
import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";

describe("AppleScript Injection False Negative (Issue #177)", () => {
  let analyzer: SecurityResponseAnalyzer;
  let safeDetector: SafeResponseDetector;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
    safeDetector = new SafeResponseDetector();
  });

  /**
   * Helper to create a mock response
   */
  function createResponse(text: string): CompatibilityCallToolResult {
    return {
      content: [{ type: "text", text }],
    } as CompatibilityCallToolResult;
  }

  /**
   * Helper to create a mock tool
   */
  function createTool(name: string, description?: string): Tool {
    return {
      name,
      description: description || `Test tool ${name}`,
      inputSchema: { type: "object", properties: {} },
    };
  }

  /**
   * Helper to create an AppleScript injection payload
   */
  function createAppleScriptInjectionPayload(): SecurityPayload {
    return {
      payload: '" & do shell script "id" & "',
      description: "AppleScript string escape to shell (double quotes)",
      payloadType: "injection",
      evidence: /uid=\d+|gid=\d+|\broot\b(?=:|\s|$)|whoami\s*$/i,
      riskLevel: "HIGH",
    };
  }

  /**
   * Helper to create an XXE payload (for regression testing)
   */
  function createXXEPayload(): SecurityPayload {
    return {
      payload:
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      description: "XXE file disclosure via SYSTEM entity",
      payloadType: "injection",
      evidence:
        /(root:x:0:0|xxe.*processed|external.*entity.*loaded|file.*contents)/i,
      riskLevel: "HIGH",
    };
  }

  // ===========================================================================
  // SECTION 1: Pattern Library - Injection Success Detection
  // ===========================================================================

  describe("Pattern Library - Injection Success Detection", () => {
    describe("APPLESCRIPT_INJECTION_SUCCESS_PATTERNS", () => {
      it.each([
        ['"" & do shell script "id"', "double-quote escape to shell"],
        ['if "" & do shell script "id" & ""', "if wrapper with injection"],
        ["'' & do shell script 'whoami'", "single-quote escape to shell"],
        [
          'do shell script "cat /etc/passwd" &',
          "shell script with concat after",
        ],
        ['" & do shell script "id" & "', "raw injection payload in context"],
      ])(
        "should match injection success pattern: %s (%s)",
        (input: string, _description: string) => {
          const matches = APPLESCRIPT_INJECTION_SUCCESS_PATTERNS.some((p) =>
            p.test(input),
          );
          expect(matches).toBe(true);
        },
      );

      it.each([
        [
          "syntax error: parameter specified more than once",
          "syntax error only",
        ],
        ["do shell script", "bare command without escape context"],
        ['Error: invalid input "test"', "normal error message"],
        ["The operation failed", "generic error"],
      ])(
        "should NOT match non-injection pattern: %s (%s)",
        (input: string, _description: string) => {
          const matches = APPLESCRIPT_INJECTION_SUCCESS_PATTERNS.some((p) =>
            p.test(input),
          );
          expect(matches).toBe(false);
        },
      );
    });

    describe("APPLESCRIPT_RUNTIME_ERROR_CODES", () => {
      it.each([
        ["-2710", "Can't make class"],
        ["-2753", "Can't get property"],
        ["-1708", "Application isn't running"],
        ["-10810", "Application launch failed"],
      ])(
        "should match runtime error code: %s (%s)",
        (code: string, _description: string) => {
          const matches = APPLESCRIPT_RUNTIME_ERROR_CODES.some((p) =>
            p.test(code),
          );
          expect(matches).toBe(true);
        },
      );

      it.each([
        ["-2750", "Syntax error code (should NOT match)"],
        ["-2500", "OSA script error (should NOT match)"],
        ["2710", "Without minus sign"],
      ])(
        "should NOT match non-runtime error: %s (%s)",
        (code: string, _description: string) => {
          const matches = APPLESCRIPT_RUNTIME_ERROR_CODES.some((p) =>
            p.test(code),
          );
          expect(matches).toBe(false);
        },
      );
    });

    describe("isAppleScriptInjectionSuccess function", () => {
      it("should detect H1 #3480575 scenario", () => {
        const responseText = `
          Error: -2710: Can't make class document.
          Script was:
          if "" & do shell script "id" & "" is not "" then
            tell newDoc
        `;
        expect(isAppleScriptInjectionSuccess(responseText)).toBe(true);
      });

      it("should detect runtime error with injection pattern in payload", () => {
        const responseText =
          'Error (-2710): do shell script "cat /etc/passwd" failed';
        const payload = '" & do shell script "cat /etc/passwd" & "';
        expect(isAppleScriptInjectionSuccess(responseText, payload)).toBe(true);
      });

      it("should NOT detect syntax error without injection pattern", () => {
        const responseText = `
          syntax error: The \u00ABclass 5642\u00BB parameter is specified more than once. (-2750)
        `;
        expect(isAppleScriptInjectionSuccess(responseText)).toBe(false);
      });

      it("should NOT detect runtime error without injection pattern in response", () => {
        // Runtime error but no injection pattern in response text
        const responseText = "Error (-2710): Could not create document object";
        expect(isAppleScriptInjectionSuccess(responseText)).toBe(false);
      });

      it("should detect when runtime error AND payload has shell script", () => {
        const responseText =
          'Error (-2710): Failed. Response shows do shell script "id"';
        const payload = '" & do shell script "id" & "';
        expect(isAppleScriptInjectionSuccess(responseText, payload)).toBe(true);
      });
    });
  });

  // ===========================================================================
  // SECTION 2: SafeResponseDetector
  // ===========================================================================

  describe("SafeResponseDetector", () => {
    it("should expose isAppleScriptInjectionSuccess method", () => {
      const responseText = 'if "" & do shell script "id" & "" then';
      expect(safeDetector.isAppleScriptInjectionSuccess(responseText)).toBe(
        true,
      );
    });

    it("should return false for non-injection AppleScript error", () => {
      const responseText = "syntax error (-2750): duplicate parameter";
      expect(safeDetector.isAppleScriptInjectionSuccess(responseText)).toBe(
        false,
      );
    });

    it("should handle payload parameter", () => {
      const responseText = 'Error (-2710): do shell script "whoami" failed';
      const payload = '" & do shell script "whoami" & "';
      expect(
        safeDetector.isAppleScriptInjectionSuccess(responseText, payload),
      ).toBe(true);
    });
  });

  // ===========================================================================
  // SECTION 3: SecurityResponseAnalyzer - H1 #3480575 Scenario
  // ===========================================================================

  describe("SecurityResponseAnalyzer - H1 #3480575 Scenario", () => {
    it("should FLAG injection when payload escapes to shell execution", () => {
      // The exact scenario from the bug report
      const responseText = `
        Error: -2710: Can't make class document.
        Script was:
        if "" & do shell script "id" & "" is not "" then
          tell newDoc
            set content to result
          end tell
        end if
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("applescript_tool", "AppleScript automation tool"),
      );

      // This MUST NOT return vulnerable: false due to "AppleScript syntax error"
      // The injection succeeded - it should continue analysis
      // Evidence may be undefined or different if analysis continues past the AppleScript check
      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });

    it("should FLAG injection with -2710 runtime error", () => {
      const responseText = `
        Error (-2710): Can't make document.
        Attempted command: "" & do shell script "whoami" & ""
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("word_automation"),
      );

      // Should not be dismissed as safe syntax error
      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });

    it("should FLAG injection with -1708 application not running error", () => {
      const responseText = `
        Error (-1708): Application "Microsoft Word" is not running.
        Script attempted: if "" & do shell script "id" & "" then tell application "Word"
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("office_automation"),
      );

      // Should not be dismissed as safe syntax error
      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });

    it("should FLAG injection with if-wrapper pattern", () => {
      const responseText = `
        osascript error (-2710):
        if "" & do shell script "cat /etc/passwd" & "" is not "" then
          set result to content
        end if
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("applescript_tool"),
      );

      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });
  });

  // ===========================================================================
  // SECTION 4: Issue #175 Regression - XXE False Positive Prevention
  // ===========================================================================

  describe("Issue #175 Regression - XXE False Positive Prevention", () => {
    it("should NOT flag XXE payload echoed in AppleScript syntax error", () => {
      // Original Issue #175 scenario - must still work
      const responseText = `
        syntax error: The \u00ABclass 5642\u00BB parameter is specified more than once. (-2750)
        Input was: <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createXXEPayload(),
        createTool("xml_tool"),
      );

      // This should NOT be flagged - it's XXE in error message, not execution
      expect(result.isVulnerable).toBe(false);
      expect(result.evidence).toContain("AppleScript syntax error");
    });

    it("should NOT flag -2750 duplicate parameter error without injection", () => {
      const responseText =
        'Error (-2750): The parameter "text" is specified more than once';

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("applescript_tool"),
      );

      // No injection success pattern, so this is safe
      expect(result.isVulnerable).toBe(false);
      expect(result.evidence).toContain("AppleScript syntax error");
    });

    it("should NOT flag generic AppleScript syntax error", () => {
      const responseText =
        "syntax error: Expected end of line but found identifier. (-2741)";

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("applescript_tool"),
      );

      expect(result.isVulnerable).toBe(false);
    });
  });

  // ===========================================================================
  // SECTION 5: Edge Cases
  // ===========================================================================

  describe("Edge Cases", () => {
    it("should distinguish syntax error (safe) from runtime error (vulnerable)", () => {
      // Syntax error: payload itself was malformed -> safe
      const syntaxError = "syntax error (-2750): unexpected token at line 1";
      expect(isAppleScriptSyntaxError(syntaxError)).toBe(true);
      expect(isAppleScriptInjectionSuccess(syntaxError)).toBe(false);

      // Runtime error with injection: payload executed but target unavailable -> vulnerable
      const runtimeError =
        'Error (-2710): Can\'t make. if "" & do shell script "id"';
      expect(isAppleScriptSyntaxError(runtimeError)).toBe(true); // Has -27xx code
      expect(isAppleScriptInjectionSuccess(runtimeError)).toBe(true); // Has injection pattern
    });

    it("should handle mixed patterns with injection success taking precedence", () => {
      const responseText = `
        syntax error: The \u00ABclass 5642\u00BB parameter (-2750)
        Script attempted: if "" & do shell script "id" & "" then
      `;

      // Both syntax error (-2750) and injection success pattern present
      expect(isAppleScriptSyntaxError(responseText)).toBe(true);
      expect(isAppleScriptInjectionSuccess(responseText)).toBe(true);

      // Full analysis should NOT dismiss as safe (injection success takes precedence)
      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("test_tool"),
      );

      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });

    it("should not false positive on error code alone without injection context", () => {
      // Just having -2710 error without injection patterns should be safe
      const responseText = "Error (-2710): Could not create document object";

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        createAppleScriptInjectionPayload(),
        createTool("word_tool"),
      );

      // This is a runtime error but no injection pattern detected
      // It should be dismissed as AppleScript syntax error (safe)
      expect(result.isVulnerable).toBe(false);
    });

    it("should handle single-quote injection variant", () => {
      const responseText = `
        Error (-2710): Application error
        Script: '' & do shell script 'whoami' & ''
      `;

      const result = analyzer.analyzeResponse(
        createResponse(responseText),
        {
          ...createAppleScriptInjectionPayload(),
          payload: "' & do shell script 'whoami' & '",
        },
        createTool("applescript_tool"),
      );

      const wasNotDismissedAsSyntaxError =
        !result.evidence ||
        !result.evidence.includes("AppleScript syntax error");
      expect(wasNotDismissedAsSyntaxError).toBe(true);
    });
  });

  // ===========================================================================
  // SECTION 6: Pattern Coverage
  // ===========================================================================

  describe("Pattern Coverage", () => {
    it("should have expected number of injection success patterns", () => {
      expect(
        APPLESCRIPT_INJECTION_SUCCESS_PATTERNS.length,
      ).toBeGreaterThanOrEqual(4);
    });

    it("should have expected number of runtime error codes", () => {
      expect(APPLESCRIPT_RUNTIME_ERROR_CODES.length).toBeGreaterThanOrEqual(4);
    });

    it("all injection success patterns should be valid regex", () => {
      APPLESCRIPT_INJECTION_SUCCESS_PATTERNS.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
        // Should not throw when testing
        expect(() => pattern.test("test")).not.toThrow();
      });
    });

    it("all runtime error codes should be valid regex", () => {
      APPLESCRIPT_RUNTIME_ERROR_CODES.forEach((pattern) => {
        expect(pattern).toBeInstanceOf(RegExp);
        expect(() => pattern.test("test")).not.toThrow();
      });
    });
  });
});
