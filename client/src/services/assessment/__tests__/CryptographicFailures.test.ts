/**
 * Cryptographic Failures Detection Tests (Issue #112, Challenge #13)
 * Tests for OWASP A02:2021 cryptographic failure detection:
 * - CWE-328: Weak Hash (MD5/SHA1 for password hashing)
 * - CWE-916: Static Salt / Weak KDF
 * - CWE-330: Predictable RNG (random.random() with timestamp seed)
 * - CWE-208: Timing Attack (non-constant-time comparison)
 * - CWE-327: Broken Cipher (ECB mode, XOR)
 * - CWE-321: Hardcoded Key (key_source: "hardcoded")
 * - CWE-326: Weak Key Length (key_length < 16)
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";

describe("Cryptographic Failures Detection (Issue #112, Challenge #13)", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("CWE-328: Weak Hash Algorithm Detection", () => {
    it("should detect algorithm: MD5 as weak hash", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Password hashed successfully",
              hash: "5f4dcc3b5aa765d61d8327deb882cf99",
              algorithm: "MD5",
              algorithm_secure: false,
              vulnerable: true,
              cwe_ids: ["CWE-328"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.vulnerabilityType).toBe("WEAK_HASH");
      expect(result.cweIds).toContain("CWE-328");
      expect(result.evidence).toContain("MD5");
    });

    it("should detect algorithm: SHA1 as weak hash", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Password hashed",
              hash: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
              algorithm: "SHA1",
              algorithm_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.vulnerabilityType).toBe("WEAK_HASH");
      expect(result.cweIds).toContain("CWE-328");
    });

    it("should detect algorithm_secure: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              hash: "somehash",
              algorithm_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-328");
    });
  });

  describe("CWE-916: Static Salt Detection", () => {
    it("should detect salt_type: static", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Password hashed with salt",
              hash: "abc123hash",
              algorithm: "SHA1",
              salt: "static_salt_123",
              salt_type: "static",
              salt_secure: false,
              vulnerable: true,
              cwe_ids: ["CWE-916", "CWE-327"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });

    it("should detect hardcoded static_salt_123", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              salt: "static_salt_123",
              hash: "somehash",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });

    it("should detect salt_secure: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              hash: "somehash",
              salt_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });
  });

  describe("CWE-330: Predictable RNG Detection", () => {
    it("should detect rng_type: random.random()", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Generated token",
              token: "a1b2c3d4e5f67890",
              rng_type: "random.random()",
              seed: "timestamp",
              cryptographically_secure: false,
              vulnerable: true,
              cwe_ids: ["CWE-330"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-330");
    });

    it("should detect seed: timestamp", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              token: "predictable_token",
              seed: "timestamp",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-330");
    });

    it("should detect cryptographically_secure: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              token: "weak_token",
              cryptographically_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-330");
    });
  });

  describe("CWE-208: Timing Attack Detection", () => {
    it("should detect timing_safe: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Password verified",
              match: true,
              comparison_type: "direct_equality",
              timing_safe: false,
              vulnerable: true,
              cwe_ids: ["CWE-208", "CWE-328"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-208");
    });

    it("should detect comparison_type: direct_equality", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              match: false,
              comparison_type: "direct_equality",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-208");
    });
  });

  describe("CWE-327: Broken Cipher Mode Detection", () => {
    it("should detect mode: ECB", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data encrypted",
              ciphertext: "YWJjMTIz",
              algorithm: "AES",
              mode: "ECB",
              key_source: "hardcoded",
              vulnerable: true,
              cwe_ids: ["CWE-327", "CWE-321"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-327");
    });

    it("should detect algorithm: XOR as weak cipher", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data encrypted (XOR fallback)",
              algorithm: "XOR",
              mode: "stream",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-327");
    });
  });

  describe("CWE-321: Hardcoded Key Detection", () => {
    it("should detect key_source: hardcoded", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data encrypted",
              ciphertext: "encrypted_data",
              key_source: "hardcoded",
              key_preview: "hardcode...",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-321");
    });

    it("should detect key_preview showing hardcoded key", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              ciphertext: "encrypted",
              key_preview: "hardcoded_key_123",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-321");
    });
  });

  describe("CWE-916: Weak KDF Detection", () => {
    it("should detect derivation_function: MD5", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Key derived from password",
              derived_key: "abc123",
              derivation_function: "MD5",
              iterations: 1,
              salt_used: false,
              kdf_secure: false,
              vulnerable: true,
              cwe_ids: ["CWE-916", "CWE-328"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });

    it("should detect iterations: 1 (no key stretching)", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              derived_key: "weak_key",
              iterations: 1,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });

    it("should detect kdf_secure: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              derived_key: "key",
              kdf_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-916");
    });
  });

  describe("CWE-326: Weak Key Length Detection", () => {
    it("should detect single digit key_length (< 16 bytes)", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data signed",
              signature: "abcdef",
              algorithm: "HMAC-SHA256",
              key_length: 3,
              key_secure: false,
              vulnerable: true,
              cwe_ids: ["CWE-326"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-326");
    });

    it("should detect key_secure: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              signature: "sig",
              key_secure: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds).toContain("CWE-326");
    });

    it("should detect key_length 10-15 bytes as weak (Issue #115)", () => {
      // Test boundary cases: 10, 12, and 15 bytes are all weak
      const testCases = [10, 12, 15];

      for (const keyLength of testCases) {
        const response = {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                result: "Data signed",
                algorithm: "HMAC-SHA256",
                key_length: keyLength,
              }),
            },
          ],
        };

        const result = analyzer.analyzeCryptographicFailures(response);

        expect(result.detected).toBe(true);
        expect(result.cweIds).toContain("CWE-326");
        expect(result.evidence).toContain("< 16 bytes");
      }
    });

    it("should NOT flag key_length 16+ as weak", () => {
      // 16 bytes (128 bits) is the minimum secure key length
      const testCases = [16, 32, 64, 256];

      for (const keyLength of testCases) {
        const response = {
          content: [
            {
              type: "text" as const,
              text: JSON.stringify({
                result: "Data signed",
                algorithm: "HMAC-SHA256",
                key_length: keyLength,
                key_secure: true,
              }),
            },
          ],
        };

        const result = analyzer.analyzeCryptographicFailures(response);

        // Should NOT detect CWE-326 for adequate key lengths
        expect(result.cweIds).not.toContain("CWE-326");
      }
    });
  });

  describe("Multiple Vulnerability Detection", () => {
    it("should detect multiple CWEs in vulnerable crypto response", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data encrypted",
              ciphertext: "YWJjMTIz",
              algorithm: "AES",
              mode: "ECB",
              key_source: "hardcoded",
              key_preview: "hardcode...",
              vulnerable: true,
              cwe_ids: ["CWE-327", "CWE-321"],
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(true);
      expect(result.cweIds.length).toBeGreaterThanOrEqual(2);
      expect(result.cweIds).toContain("CWE-327"); // ECB mode
      expect(result.cweIds).toContain("CWE-321"); // Hardcoded key
    });
  });

  describe("Safe Pattern Detection (Hardened Server)", () => {
    it("should NOT detect vulnerability when status: stored", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Crypto request stored: action=hash",
              note: "Weak crypto operations blocked - request logged for admin review using secure alternatives",
              action: "hash",
              status: "stored",
              recommendation: "Use bcrypt/scrypt/Argon2 for hashing",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(false);
      expect(result.cweIds.length).toBe(0);
      expect(result.evidence).toContain("Secure crypto handling");
    });

    it("should NOT detect vulnerability when note mentions blocked", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Request processed",
              note: "Weak crypto blocked - using secure alternative",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability when vulnerable: false", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Operation complete",
              vulnerable: false,
              algorithm: "AES-256-GCM",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability when secure recommendation present", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Request stored",
              recommendation: "Use AES-GCM for encryption",
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      expect(result.detected).toBe(false);
    });

    it("should NOT detect vulnerability for completely safe crypto response", () => {
      const response = {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              result: "Data encrypted",
              algorithm: "AES-256-GCM",
              mode: "GCM",
              key_derived_from: "PBKDF2",
              iterations: 100000,
            }),
          },
        ],
      };

      const result = analyzer.analyzeCryptographicFailures(response);

      // No vulnerable patterns detected
      expect(result.detected).toBe(false);
    });
  });
});
