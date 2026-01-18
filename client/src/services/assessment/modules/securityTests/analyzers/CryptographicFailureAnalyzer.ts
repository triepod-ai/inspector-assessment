/**
 * Cryptographic Failure Analyzer (Issue #112, Challenge #13)
 * Detects OWASP A02:2021 Cryptographic Failures
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of cryptographic failure analysis (Issue #112, Challenge #13)
 * Detects OWASP A02:2021 Cryptographic Failures:
 * - CWE-328: Weak Hash (MD5/SHA1 for passwords)
 * - CWE-916: Static Salt / Weak KDF (static_salt_123, MD5 derivation)
 * - CWE-330: Predictable RNG (random.random() with timestamp seed)
 * - CWE-208: Timing Attack (non-constant-time comparison)
 * - CWE-327: Broken Cipher (ECB mode, XOR cipher)
 * - CWE-321: Hardcoded Key (key_source: "hardcoded")
 * - CWE-326: Weak Key Length (key_length < 16)
 */
export interface CryptoFailureResult {
  detected: boolean;
  vulnerabilityType:
    | "WEAK_HASH"
    | "STATIC_SALT"
    | "PREDICTABLE_RNG"
    | "TIMING_ATTACK"
    | "ECB_MODE"
    | "HARDCODED_KEY"
    | "WEAK_KDF"
    | "WEAK_KEY_LENGTH"
    | "UNKNOWN";
  cweIds: string[];
  evidence?: string;
}

/**
 * Analyzes responses for cryptographic failures
 *
 * Detects OWASP A02:2021 Cryptographic Failures from mcp-vulnerable-testbed:
 * - CWE-328: Weak Hash (MD5/SHA1 for password hashing)
 * - CWE-916: Static Salt / Weak KDF
 * - CWE-330: Predictable RNG (random.random() with timestamp seed)
 * - CWE-208: Timing Attack (non-constant-time comparison)
 * - CWE-327: Broken Cipher (ECB mode, XOR)
 * - CWE-321: Hardcoded Key (key_source: "hardcoded")
 * - CWE-326: Weak Key Length (key_length < 16)
 */
export class CryptographicFailureAnalyzer {
  private safeDetector: SafeResponseDetector;

  /**
   * Safe patterns (hardened server)
   */
  private static readonly SAFE_PATTERNS = [
    {
      pattern: /"status"\s*:\s*"stored"/i,
      name: "request stored (not executed)",
    },
    {
      pattern: /"note"\s*:\s*".*blocked.*secure/i,
      name: "weak crypto blocked",
    },
    {
      pattern:
        /"recommendation"\s*:\s*"Use\s+(?:bcrypt|scrypt|Argon2|AES-GCM)/i,
      name: "secure alternative recommended",
    },
    {
      pattern: /"vulnerable"\s*:\s*false/i,
      name: "vulnerable: false",
    },
  ];

  /**
   * CWE-328: Weak Hash Algorithm patterns
   */
  private static readonly WEAK_HASH_PATTERNS = [
    {
      pattern: /"algorithm"\s*:\s*"MD5"/i,
      evidence: 'algorithm: "MD5" (weak hash for passwords)',
    },
    {
      pattern: /"algorithm"\s*:\s*"SHA1"/i,
      evidence: 'algorithm: "SHA1" (weak hash for passwords)',
    },
    {
      pattern: /"algorithm_secure"\s*:\s*false/i,
      evidence: "algorithm_secure: false",
    },
  ];

  /**
   * CWE-916: Static Salt patterns
   */
  private static readonly STATIC_SALT_PATTERNS = [
    {
      pattern: /"salt_type"\s*:\s*"static"/i,
      evidence: 'salt_type: "static" (same salt for all passwords)',
    },
    {
      pattern: /"salt"\s*:\s*"static_salt_123"/i,
      evidence: 'salt: "static_salt_123" (hardcoded static salt)',
    },
    {
      pattern: /"salt_secure"\s*:\s*false/i,
      evidence: "salt_secure: false",
    },
  ];

  /**
   * CWE-330: Predictable RNG patterns
   */
  private static readonly PREDICTABLE_RNG_PATTERNS = [
    {
      pattern: /"rng_type"\s*:\s*"random\.random\(\)"/i,
      evidence: 'rng_type: "random.random()" (non-cryptographic RNG)',
    },
    {
      pattern: /"seed"\s*:\s*"timestamp"/i,
      evidence: 'seed: "timestamp" (predictable seed)',
    },
    {
      pattern: /"cryptographically_secure"\s*:\s*false/i,
      evidence: "cryptographically_secure: false",
    },
  ];

  /**
   * CWE-208: Timing Attack patterns
   */
  private static readonly TIMING_PATTERNS = [
    {
      pattern: /"timing_safe"\s*:\s*false/i,
      evidence: "timing_safe: false (vulnerable to timing attacks)",
    },
    {
      pattern: /"comparison_type"\s*:\s*"direct_equality"/i,
      evidence: 'comparison_type: "direct_equality" (non-constant-time)',
    },
  ];

  /**
   * CWE-327: Broken Cipher patterns
   */
  private static readonly BROKEN_CIPHER_PATTERNS = [
    {
      pattern: /"mode"\s*:\s*"ECB"/i,
      evidence: 'mode: "ECB" (pattern leakage in ciphertext)',
    },
    {
      pattern: /"algorithm"\s*:\s*"XOR"/i,
      evidence: 'algorithm: "XOR" (weak cipher)',
    },
  ];

  /**
   * CWE-321: Hardcoded Key patterns
   */
  private static readonly HARDCODED_KEY_PATTERNS = [
    {
      pattern: /"key_source"\s*:\s*"hardcoded"/i,
      evidence: 'key_source: "hardcoded" (key in source code)',
    },
    {
      pattern: /"key_preview"\s*:\s*"hardcode/i,
      evidence: "key_preview shows hardcoded key",
    },
  ];

  /**
   * CWE-916: Weak KDF patterns
   */
  private static readonly WEAK_KDF_PATTERNS = [
    {
      pattern: /"derivation_function"\s*:\s*"MD5"/i,
      evidence: 'derivation_function: "MD5" (weak KDF)',
    },
    {
      pattern: /"iterations"\s*:\s*1\b/i,
      evidence: "iterations: 1 (no key stretching)",
    },
    {
      pattern: /"kdf_secure"\s*:\s*false/i,
      evidence: "kdf_secure: false",
    },
  ];

  /**
   * CWE-326: Weak Key Length patterns
   */
  private static readonly WEAK_KEY_PATTERNS = [
    {
      // Match key_length 1-15 bytes (< 16 bytes = weak for AES-128/HMAC)
      pattern: /"key_length"\s*:\s*(?:[1-9]|1[0-5])(?!\d)/i,
      evidence: "key_length < 16 bytes (weak key)",
    },
    {
      pattern: /"key_secure"\s*:\s*false/i,
      evidence: "key_secure: false (weak key)",
    },
  ];

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Analyze response for cryptographic failures (Issue #112, Challenge #13)
   *
   * @param response The tool response to analyze
   * @returns Analysis result with cryptographic failure detection status
   */
  analyze(response: CompatibilityCallToolResult): CryptoFailureResult {
    const responseText = this.safeDetector.extractResponseContent(response);
    const cweIds: string[] = [];
    let vulnerabilityType: CryptoFailureResult["vulnerabilityType"] = "UNKNOWN";
    let evidence: string | undefined;

    // Check for safe patterns first (hardened server)
    for (const {
      pattern,
      name,
    } of CryptographicFailureAnalyzer.SAFE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          detected: false,
          vulnerabilityType: "UNKNOWN",
          cweIds: [],
          evidence: `Secure crypto handling: ${name}`,
        };
      }
    }

    // CWE-328: Weak Hash Algorithm (MD5/SHA1)
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.WEAK_HASH_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-328")) cweIds.push("CWE-328");
        vulnerabilityType = "WEAK_HASH";
        evidence = evidenceText;
        break;
      }
    }

    // CWE-916: Static Salt
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.STATIC_SALT_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-916")) cweIds.push("CWE-916");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "STATIC_SALT";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-330: Predictable RNG
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.PREDICTABLE_RNG_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-330")) cweIds.push("CWE-330");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "PREDICTABLE_RNG";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-208: Timing Attack
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.TIMING_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-208")) cweIds.push("CWE-208");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "TIMING_ATTACK";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-327: Broken Cipher Mode (ECB/XOR)
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.BROKEN_CIPHER_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-327")) cweIds.push("CWE-327");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "ECB_MODE";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-321: Hardcoded Key
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.HARDCODED_KEY_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-321")) cweIds.push("CWE-321");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "HARDCODED_KEY";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-916: Weak KDF (MD5 for key derivation)
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.WEAK_KDF_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-916")) cweIds.push("CWE-916");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "WEAK_KDF";
          evidence = evidenceText;
        }
        break;
      }
    }

    // CWE-326: Weak Key Length
    for (const {
      pattern,
      evidence: evidenceText,
    } of CryptographicFailureAnalyzer.WEAK_KEY_PATTERNS) {
      if (pattern.test(responseText)) {
        if (!cweIds.includes("CWE-326")) cweIds.push("CWE-326");
        if (vulnerabilityType === "UNKNOWN") {
          vulnerabilityType = "WEAK_KEY_LENGTH";
          evidence = evidenceText;
        }
        break;
      }
    }

    return {
      detected: cweIds.length > 0,
      vulnerabilityType,
      cweIds: [...new Set(cweIds)], // Dedupe
      evidence,
    };
  }
}
