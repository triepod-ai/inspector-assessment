/**
 * AppleScript Command Injection Evidence Regex Tests (Issue #174)
 *
 * Tests for the refined evidence pattern that reduces false positives while
 * maintaining true positive detection of command injection.
 *
 * Background:
 * - Issue #174: False positives from generic words like "User", "username", "rooted"
 * - FIX-001: Updated evidence regex to require specific patterns:
 *   - uid=\d+ or gid=\d+ (id command output)
 *   - \broot\b(?=:|\s|$) (root with colon, space, or end of string)
 *   - whoami\s*$ (whoami at end of string with optional trailing whitespace)
 *
 * This test suite validates both:
 * 1. True positives: Actual command injection evidence should still match
 * 2. False positives: Generic text containing "user", "root", etc. should NOT match
 */

import { SECURITY_ATTACK_PATTERNS } from "../../../lib/securityPatterns";

describe("AppleScript Command Injection (Issue #174)", () => {
  const appleScriptPattern = SECURITY_ATTACK_PATTERNS.find(
    (p) => p.attackName === "AppleScript Command Injection",
  );

  if (!appleScriptPattern) {
    throw new Error("AppleScript Command Injection pattern not found");
  }

  // Get the evidence regex from the first payload (shell escape patterns)
  const shellEscapePayload = appleScriptPattern.payloads.find(
    (p) =>
      p.description === "AppleScript string escape to shell (double quotes)",
  );

  if (!shellEscapePayload) {
    throw new Error("Shell escape payload not found");
  }

  const shellEscapeEvidence = shellEscapePayload.evidence;

  describe("Pattern Configuration Validation", () => {
    it("should have two shell escape payloads (double and single quote)", () => {
      const shellEscapePayloads = appleScriptPattern.payloads.filter((p) =>
        p.description.includes("AppleScript string escape to shell"),
      );
      expect(shellEscapePayloads).toHaveLength(2);
    });

    it("should have double-quote escape payload", () => {
      const doubleQuotePayload = appleScriptPattern.payloads.find(
        (p) =>
          p.description ===
          "AppleScript string escape to shell (double quotes)",
      );
      expect(doubleQuotePayload).toBeDefined();
      expect(doubleQuotePayload!.payload).toBe('" & do shell script "id" & "');
      expect(doubleQuotePayload!.riskLevel).toBe("HIGH");
    });

    it("should have single-quote escape payload", () => {
      const singleQuotePayload = appleScriptPattern.payloads.find(
        (p) =>
          p.description ===
          "AppleScript string escape to shell (single quotes)",
      );
      expect(singleQuotePayload).toBeDefined();
      expect(singleQuotePayload!.payload).toBe(
        "' & do shell script 'whoami' & '",
      );
      expect(singleQuotePayload!.riskLevel).toBe("HIGH");
    });

    it("should use identical evidence regex for both shell escape payloads", () => {
      const doubleQuotePayload = appleScriptPattern.payloads.find(
        (p) =>
          p.description ===
          "AppleScript string escape to shell (double quotes)",
      );
      const singleQuotePayload = appleScriptPattern.payloads.find(
        (p) =>
          p.description ===
          "AppleScript string escape to shell (single quotes)",
      );

      expect(doubleQuotePayload!.evidence.source).toBe(
        singleQuotePayload!.evidence.source,
      );
      expect(doubleQuotePayload!.evidence.flags).toBe(
        singleQuotePayload!.evidence.flags,
      );
    });

    it("should have case-insensitive flag", () => {
      expect(shellEscapeEvidence.flags).toContain("i");
    });
  });

  describe("Evidence Regex True Positives (Command Injection Detection)", () => {
    describe("uid/gid patterns (id command output)", () => {
      it.each([
        ["uid=501", "id command uid output"],
        ["gid=20", "id command gid output"],
        ["uid=0(root)", "root user uid output"],
        ["uid=501(user) gid=20(staff)", "full id command output"],
        ["uid=1000 gid=1000", "uid and gid together"],
        [
          "uid=0(root) gid=0(root) groups=0(root)",
          "full root id output with groups",
        ],
        ["Output: uid=502", "uid in context"],
        ["Command result: gid=100", "gid in context"],
      ])(
        "should match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(true);
        },
      );
    });

    describe("root patterns (passwd file / user context)", () => {
      it.each([
        ["root:x:0:0:root:/root:/bin/bash", "passwd file root entry"],
        ["root:*:0:0:System Administrator:/var/root:/bin/sh", "macOS root"],
        ["Output: root", "root at end of string"],
        ["Current user: root", "root followed by space"],
        ["User is root now", "root in middle followed by space"],
        ["root:", "root with colon"],
        ["root user authenticated", "root with trailing space"],
      ])(
        "should match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(true);
        },
      );
    });

    describe("whoami patterns (end of string)", () => {
      it.each([
        ["Output: whoami", "whoami at end of string"],
        ["whoami", "whoami alone"],
        ["Command output: whoami", "whoami with context at end"],
        ["whoami  ", "whoami with trailing whitespace"],
        ["whoami\n", "whoami with trailing newline"],
        ["whoami\t", "whoami with trailing tab"],
      ])(
        "should match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(true);
        },
      );
    });

    describe("Complex realistic scenarios", () => {
      it("should match full macOS id command output", () => {
        const output =
          "uid=501(john) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts)";
        expect(shellEscapeEvidence.test(output)).toBe(true);
      });

      it("should match Linux id command output", () => {
        const output =
          "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),27(sudo)";
        expect(shellEscapeEvidence.test(output)).toBe(true);
      });

      it("should match passwd file root entry", () => {
        const output = "root:x:0:0:root:/root:/bin/bash";
        expect(shellEscapeEvidence.test(output)).toBe(true);
      });

      it("should match root from whoami command", () => {
        const output = "root";
        expect(shellEscapeEvidence.test(output)).toBe(true);
      });

      it("should match whoami output from regular user", () => {
        const output = "whoami";
        expect(shellEscapeEvidence.test(output)).toBe(true);
      });
    });
  });

  describe("Evidence Regex False Positives (Issue #174 Fix)", () => {
    describe("Generic text with 'user' keyword (should NOT match)", () => {
      it.each([
        ["User logged in", "generic user text"],
        ["username is valid", "username text"],
        ["user data retrieved", "user data text"],
        ["The user requested access", "user in sentence"],
        ["User profile updated", "user profile text"],
        ["Invalid username provided", "username validation"],
        ["User ID: 12345", "user ID without unix format"],
        ["Authenticating user john", "user authentication"],
      ])(
        "should NOT match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(false);
        },
      );
    });

    describe("Generic text with 'root' keyword (should NOT match)", () => {
      it.each([
        ["the device was rooted", "rooted past tense"],
        ["rooted in tradition", "rooted phrase"],
        ["rootkit detection", "rootkit compound word"],
        ["Rooted phone detected", "rooted phone"],
      ])(
        "should NOT match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(false);
        },
      );
    });

    describe("Known edge cases with 'root' (acceptable tradeoff)", () => {
      // These cases still match but are rare in practice and represent
      // an acceptable tradeoff vs. the original false positives
      it.each([
        ["Find root cause", "root cause phrase"],
        ["Square root of 16", "math root"],
        ["Root directory access", "root directory"],
      ])(
        "DOES match %s (%s) - edge case",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(true);
        },
      );
    });

    describe("whoami in middle of text (should NOT match)", () => {
      it.each([
        ["whoami command is common", "whoami followed by text"],
        ["Run whoami to check", "whoami in sentence"],
        ["The whoami utility", "whoami utility"],
        ["whoami-like behavior", "whoami with hyphen"],
      ])(
        "should NOT match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(false);
        },
      );
    });

    describe("Generic system messages (should NOT match)", () => {
      it.each([
        ["Error: Invalid user input", "error message"],
        ["Warning: User session expired", "warning message"],
        ["System user defaults loaded", "system message"],
        ["User preferences saved", "preferences message"],
        ["Access denied for user", "access control message"],
      ])(
        "should NOT match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(false);
        },
      );
    });

    describe("uid/gid without numeric format (should NOT match)", () => {
      it.each([
        ["uid information", "uid without equals"],
        ["Check gid field", "gid without equals"],
        ["User ID (uid) is required", "uid in parentheses"],
        ["Group ID (gid) validation", "gid in parentheses"],
        ["uid", "uid alone"],
        ["gid", "gid alone"],
      ])(
        "should NOT match %s (%s)",
        (input: string, _description: string): void => {
          expect(shellEscapeEvidence.test(input)).toBe(false);
        },
      );
    });
  });

  describe("Edge Cases", () => {
    it("should match uid with leading text", () => {
      const output = "Current user identity: uid=501(john) gid=20(staff)";
      expect(shellEscapeEvidence.test(output)).toBe(true);
    });

    it("should match root at absolute end (no trailing characters)", () => {
      const output = "Current user is root";
      expect(shellEscapeEvidence.test(output)).toBe(true);
    });

    it("should match whoami with only whitespace after", () => {
      const output = "whoami   \n\t  ";
      expect(shellEscapeEvidence.test(output)).toBe(true);
    });

    it("should NOT match 'root' in middle of word", () => {
      const output = "grootfs filesystem";
      expect(shellEscapeEvidence.test(output)).toBe(false);
    });

    it("should NOT match 'root' without word boundary before", () => {
      const output = "newroot:x:1000:1000";
      expect(shellEscapeEvidence.test(output)).toBe(false);
    });

    it("should match case-insensitive variants", () => {
      expect(shellEscapeEvidence.test("UID=501")).toBe(true);
      expect(shellEscapeEvidence.test("GID=20")).toBe(true);
      expect(shellEscapeEvidence.test("Root:x:0:0")).toBe(true);
      expect(shellEscapeEvidence.test("WHOAMI")).toBe(true);
    });
  });

  describe("Payload Attack Vectors", () => {
    it("should have double-quote escape injection vector", () => {
      const payload = appleScriptPattern.payloads.find(
        (p) => p.payload === '" & do shell script "id" & "',
      );
      expect(payload).toBeDefined();
      expect(payload!.description).toContain("double quotes");
      expect(payload!.riskLevel).toBe("HIGH");
    });

    it("should have single-quote escape injection vector", () => {
      const payload = appleScriptPattern.payloads.find(
        (p) => p.payload === "' & do shell script 'whoami' & '",
      );
      expect(payload).toBeDefined();
      expect(payload!.description).toContain("single quotes");
      expect(payload!.riskLevel).toBe("HIGH");
    });

    it("should have system info extraction vector", () => {
      const payload = appleScriptPattern.payloads.find((p) =>
        p.description.includes("system info extraction"),
      );
      expect(payload).toBeDefined();
      expect(payload!.payload).toBe("osascript -e 'return (system info)'");
      expect(payload!.riskLevel).toBe("MEDIUM");
    });

    it("should have file read vector", () => {
      const payload = appleScriptPattern.payloads.find((p) =>
        p.description.includes("file read"),
      );
      expect(payload).toBeDefined();
      expect(payload!.payload).toBe(
        '" & do shell script "cat /etc/passwd" & "',
      );
      expect(payload!.riskLevel).toBe("HIGH");
    });
  });

  describe("Pattern Integration", () => {
    it("should be included in SECURITY_ATTACK_PATTERNS", () => {
      const pattern = SECURITY_ATTACK_PATTERNS.find(
        (p) => p.attackName === "AppleScript Command Injection",
      );
      expect(pattern).toBeDefined();
    });

    it("should have injection payload type", () => {
      appleScriptPattern.payloads.forEach((payload) => {
        expect(payload.payloadType).toBe("injection");
      });
    });

    it("should have at least 4 payloads", () => {
      expect(appleScriptPattern.payloads.length).toBeGreaterThanOrEqual(4);
    });

    it("should have HIGH risk level for shell escape payloads", () => {
      const shellEscapePayloads = appleScriptPattern.payloads.filter((p) =>
        p.description.includes("shell escape"),
      );
      shellEscapePayloads.forEach((payload) => {
        expect(payload.riskLevel).toBe("HIGH");
      });
    });
  });
});
