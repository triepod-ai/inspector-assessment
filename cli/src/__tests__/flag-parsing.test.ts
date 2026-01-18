/**
 * CLI Flag Parsing Unit Tests
 *
 * Tests for validation functions used in CLI argument parsing:
 * - parseKeyValuePair() - KEY=VALUE parsing for env vars
 * - parseHeaderPair() - "HeaderName: Value" parsing
 * - validateEnvVars() - Env var name/value validation and sensitive var blocking
 * - validateServerUrl() - SSRF protection and URL validation
 * - validateCommand() - Command injection prevention
 * - validateModuleNames() - Module name validation
 * - Profile/format validation - CLI option validation
 * - Mutual exclusivity - Flag conflict detection
 */

import { describe, it, expect, jest } from "@jest/globals";
import { parseArgs, printVersion } from "../lib/cli-parser.js";
import packageJson from "../../package.json" with { type: "json" };

describe("Key-Value Pair Parsing", () => {
  /**
   * Recreates parseKeyValuePair logic from cli.ts
   */
  function parseKeyValuePair(
    value: string,
    previous: Record<string, string> = {},
  ): Record<string, string> {
    const parts = value.split("=");
    const key = parts[0];
    const val = parts.slice(1).join("=");

    if (val === undefined || val === "") {
      throw new Error(
        `Invalid parameter format: ${value}. Use key=value format.`,
      );
    }

    return { ...previous, [key as string]: val };
  }

  describe("Valid key-value pairs", () => {
    it("should parse simple KEY=VALUE format", () => {
      expect(parseKeyValuePair("MY_VAR=hello")).toEqual({ MY_VAR: "hello" });
    });

    it("should handle multiple equals signs in value", () => {
      expect(parseKeyValuePair("KEY=val=ue=test")).toEqual({
        KEY: "val=ue=test",
      });
      expect(parseKeyValuePair("URL=https://example.com?a=1&b=2")).toEqual({
        URL: "https://example.com?a=1&b=2",
      });
    });

    it("should accumulate multiple pairs", () => {
      let result = parseKeyValuePair("VAR1=value1");
      result = parseKeyValuePair("VAR2=value2", result);
      expect(result).toEqual({ VAR1: "value1", VAR2: "value2" });
    });

    it("should handle special characters in value", () => {
      expect(parseKeyValuePair("PATH=/usr/bin:/usr/local/bin")).toEqual({
        PATH: "/usr/bin:/usr/local/bin",
      });
      expect(parseKeyValuePair('JSON={"key":"value"}')).toEqual({
        JSON: '{"key":"value"}',
      });
    });
  });

  describe("Invalid key-value pairs", () => {
    it("should throw on missing equals sign", () => {
      expect(() => parseKeyValuePair("NOEQUALS")).toThrow(
        "Invalid parameter format",
      );
    });

    it("should throw on empty value", () => {
      expect(() => parseKeyValuePair("KEY=")).toThrow(
        "Invalid parameter format",
      );
    });

    it("should throw on key without equals", () => {
      expect(() => parseKeyValuePair("KEY")).toThrow(
        "Invalid parameter format",
      );
    });
  });
});

describe("Header Pair Parsing", () => {
  /**
   * Recreates parseHeaderPair logic from cli.ts
   */
  function parseHeaderPair(
    value: string,
    previous: Record<string, string> = {},
  ): Record<string, string> {
    const colonIndex = value.indexOf(":");

    if (colonIndex === -1) {
      throw new Error(
        `Invalid header format: ${value}. Use "HeaderName: Value" format.`,
      );
    }

    const key = value.slice(0, colonIndex).trim();
    const val = value.slice(colonIndex + 1).trim();

    if (key === "" || val === "") {
      throw new Error(
        `Invalid header format: ${value}. Use "HeaderName: Value" format.`,
      );
    }

    return { ...previous, [key]: val };
  }

  describe("Valid header pairs", () => {
    it("should parse simple HeaderName: Value format", () => {
      expect(parseHeaderPair("Authorization: Bearer token123")).toEqual({
        Authorization: "Bearer token123",
      });
    });

    it("should handle colons in value", () => {
      expect(parseHeaderPair("X-Custom: https://example.com:8080")).toEqual({
        "X-Custom": "https://example.com:8080",
      });
      expect(parseHeaderPair("Time: 12:30:45")).toEqual({ Time: "12:30:45" });
    });

    it("should trim whitespace", () => {
      expect(parseHeaderPair("  Content-Type  :  application/json  ")).toEqual({
        "Content-Type": "application/json",
      });
    });

    it("should accumulate multiple headers", () => {
      let result = parseHeaderPair("Accept: application/json");
      result = parseHeaderPair("User-Agent: inspector-cli/1.0", result);
      expect(result).toEqual({
        Accept: "application/json",
        "User-Agent": "inspector-cli/1.0",
      });
    });
  });

  describe("Invalid header pairs", () => {
    it("should throw on missing colon", () => {
      expect(() => parseHeaderPair("Authorization Bearer token")).toThrow(
        "Invalid header format",
      );
    });

    it("should throw on empty header name", () => {
      expect(() => parseHeaderPair(": value")).toThrow("Invalid header format");
    });

    it("should throw on empty header value", () => {
      expect(() => parseHeaderPair("Header:")).toThrow("Invalid header format");
      expect(() => parseHeaderPair("Header:   ")).toThrow(
        "Invalid header format",
      );
    });
  });
});

describe("Environment Variable Validation", () => {
  /**
   * Recreates validation logic from cli.ts
   */
  function isValidEnvVarName(name: string): boolean {
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name);
  }

  function isValidEnvVarValue(value: string): boolean {
    return !value.includes("\0");
  }

  const BLOCKED_ENV_VAR_PATTERNS = [
    /^(AWS|AZURE|GCP|GOOGLE)_/i,
    /^(API|AUTH|SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)_/i,
    /^(PRIVATE|SSH|PGP|GPG)_/i,
    /_(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)$/i,
  ];

  function isSensitiveEnvVar(name: string): boolean {
    return BLOCKED_ENV_VAR_PATTERNS.some((pattern) => pattern.test(name));
  }

  describe("Valid environment variable names", () => {
    it("should accept valid names", () => {
      expect(isValidEnvVarName("MY_VAR")).toBe(true);
      expect(isValidEnvVarName("PATH")).toBe(true);
      expect(isValidEnvVarName("_INTERNAL")).toBe(true);
      expect(isValidEnvVarName("VAR_123")).toBe(true);
    });

    it("should reject names starting with numbers", () => {
      expect(isValidEnvVarName("123VAR")).toBe(false);
    });

    it("should reject names with special characters", () => {
      expect(isValidEnvVarName("MY-VAR")).toBe(false);
      expect(isValidEnvVarName("MY.VAR")).toBe(false);
      expect(isValidEnvVarName("MY VAR")).toBe(false);
      expect(isValidEnvVarName("MY@VAR")).toBe(false);
    });

    it("should reject empty names", () => {
      expect(isValidEnvVarName("")).toBe(false);
    });
  });

  describe("Valid environment variable values", () => {
    it("should accept normal values", () => {
      expect(isValidEnvVarValue("hello world")).toBe(true);
      expect(isValidEnvVarValue("/path/to/file")).toBe(true);
      expect(isValidEnvVarValue("")).toBe(true);
    });

    it("should reject values with null bytes", () => {
      expect(isValidEnvVarValue("hello\0world")).toBe(false);
    });
  });

  describe("Sensitive environment variable detection", () => {
    it("should block AWS credentials", () => {
      expect(isSensitiveEnvVar("AWS_ACCESS_KEY_ID")).toBe(true);
      expect(isSensitiveEnvVar("AWS_SECRET_ACCESS_KEY")).toBe(true);
      expect(isSensitiveEnvVar("aws_session_token")).toBe(true);
    });

    it("should block Azure credentials", () => {
      expect(isSensitiveEnvVar("AZURE_CLIENT_SECRET")).toBe(true);
      expect(isSensitiveEnvVar("AZURE_SUBSCRIPTION_ID")).toBe(true);
    });

    it("should block GCP credentials", () => {
      expect(isSensitiveEnvVar("GOOGLE_APPLICATION_CREDENTIALS")).toBe(true);
      expect(isSensitiveEnvVar("GCP_SERVICE_ACCOUNT_KEY")).toBe(true);
    });

    it("should block generic secrets", () => {
      expect(isSensitiveEnvVar("API_KEY")).toBe(true);
      expect(isSensitiveEnvVar("AUTH_TOKEN")).toBe(true);
      expect(isSensitiveEnvVar("SECRET_KEY")).toBe(true);
      expect(isSensitiveEnvVar("PASSWORD_HASH")).toBe(true);
    });

    it("should block suffix patterns", () => {
      expect(isSensitiveEnvVar("GITHUB_API_KEY")).toBe(true);
      expect(isSensitiveEnvVar("DATABASE_PASSWORD")).toBe(true);
      expect(isSensitiveEnvVar("OAUTH_TOKEN")).toBe(true);
    });

    it("should block private keys", () => {
      expect(isSensitiveEnvVar("PRIVATE_KEY")).toBe(true);
      expect(isSensitiveEnvVar("SSH_KEY_PATH")).toBe(true);
      expect(isSensitiveEnvVar("GPG_PASSPHRASE")).toBe(true);
    });

    it("should allow safe environment variables", () => {
      expect(isSensitiveEnvVar("NODE_ENV")).toBe(false);
      expect(isSensitiveEnvVar("PATH")).toBe(false);
      expect(isSensitiveEnvVar("HOME")).toBe(false);
      expect(isSensitiveEnvVar("LOG_LEVEL")).toBe(false);
    });
  });
});

describe("URL Validation (SSRF Protection)", () => {
  /**
   * Recreates SSRF validation logic from cli.ts
   */
  const PRIVATE_HOSTNAME_PATTERNS = [
    /^localhost$/,
    /^localhost\./,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^0\./,
    /^\[::1\]$/,
    /^\[::ffff:127\./,
    /^\[fe80:/i,
    /^\[fc/i,
    /^\[fd/i,
    /^169\.254\.169\.254$/,
    /^metadata\./,
  ];

  function isPrivateHostname(hostname: string): boolean {
    const normalizedHostname = hostname.toLowerCase();
    return PRIVATE_HOSTNAME_PATTERNS.some((pattern) =>
      pattern.test(normalizedHostname),
    );
  }

  function validateServerUrl(url: string): { valid: boolean; error?: string } {
    try {
      const parsed = new URL(url);

      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return {
          valid: false,
          error: `Invalid URL protocol: ${parsed.protocol}. Must be http or https.`,
        };
      }

      // In production, private hostnames only warn (don't error)
      // For testing purposes, we'll track if it's private
      const isPrivate = isPrivateHostname(parsed.hostname);

      return { valid: true, error: isPrivate ? "PRIVATE_WARNING" : undefined };
    } catch (error) {
      return { valid: false, error: "Invalid URL format" };
    }
  }

  describe("Valid HTTP/HTTPS URLs", () => {
    it("should accept HTTP URLs", () => {
      expect(validateServerUrl("http://example.com")).toEqual({ valid: true });
      expect(validateServerUrl("http://api.example.com:8080/mcp")).toEqual({
        valid: true,
      });
    });

    it("should accept HTTPS URLs", () => {
      expect(validateServerUrl("https://example.com")).toEqual({ valid: true });
      expect(validateServerUrl("https://secure.example.com/api")).toEqual({
        valid: true,
      });
    });

    it("should accept localhost URLs (with warning)", () => {
      const result = validateServerUrl("http://localhost:3000");
      expect(result.valid).toBe(true);
      expect(result.error).toBe("PRIVATE_WARNING");
    });
  });

  describe("Invalid URL protocols", () => {
    it("should reject file URLs", () => {
      expect(validateServerUrl("file:///etc/passwd").valid).toBe(false);
    });

    it("should reject FTP URLs", () => {
      expect(validateServerUrl("ftp://example.com").valid).toBe(false);
    });

    it("should reject custom protocols", () => {
      expect(validateServerUrl("gopher://example.com").valid).toBe(false);
    });
  });

  describe("Private IP detection (SSRF prevention)", () => {
    it("should detect localhost variants", () => {
      expect(isPrivateHostname("localhost")).toBe(true);
      expect(isPrivateHostname("localhost.localdomain")).toBe(true);
    });

    it("should detect IPv4 loopback", () => {
      expect(isPrivateHostname("127.0.0.1")).toBe(true);
      expect(isPrivateHostname("127.1.1.1")).toBe(true);
    });

    it("should detect IPv4 private ranges", () => {
      expect(isPrivateHostname("10.0.0.1")).toBe(true);
      expect(isPrivateHostname("172.16.0.1")).toBe(true);
      expect(isPrivateHostname("192.168.1.1")).toBe(true);
    });

    it("should detect link-local addresses", () => {
      expect(isPrivateHostname("169.254.1.1")).toBe(true);
    });

    it("should detect cloud metadata endpoints", () => {
      expect(isPrivateHostname("169.254.169.254")).toBe(true);
      expect(isPrivateHostname("metadata.google.internal")).toBe(true);
    });

    it("should detect IPv6 private ranges", () => {
      expect(isPrivateHostname("[::1]")).toBe(true);
      expect(isPrivateHostname("[fe80::1]")).toBe(true);
      expect(isPrivateHostname("[fc00::1]")).toBe(true);
      expect(isPrivateHostname("[fd00::1]")).toBe(true);
    });

    it("should allow public addresses", () => {
      expect(isPrivateHostname("example.com")).toBe(false);
      expect(isPrivateHostname("8.8.8.8")).toBe(false);
      expect(isPrivateHostname("1.1.1.1")).toBe(false);
    });
  });

  describe("Malformed URLs", () => {
    it("should reject invalid URL formats", () => {
      expect(validateServerUrl("not-a-url").valid).toBe(false);
      expect(validateServerUrl("://missing-protocol").valid).toBe(false);
      expect(validateServerUrl("").valid).toBe(false);
    });
  });
});

describe("Command Validation (Injection Prevention)", () => {
  /**
   * Recreates validateCommand logic from cli.ts
   */
  function validateCommand(command: string): {
    valid: boolean;
    error?: string;
  } {
    const dangerousChars = /[;&|`$(){}[\]<>!]/;
    if (dangerousChars.test(command)) {
      return {
        valid: false,
        error: `Invalid command: contains shell metacharacters: ${command}`,
      };
    }
    return { valid: true };
  }

  describe("Valid commands", () => {
    it("should accept simple commands", () => {
      expect(validateCommand("node")).toEqual({ valid: true });
      expect(validateCommand("python3")).toEqual({ valid: true });
      expect(validateCommand("/usr/bin/node")).toEqual({ valid: true });
    });

    it("should accept commands with safe characters", () => {
      expect(validateCommand("my-command")).toEqual({ valid: true });
      expect(validateCommand("command_name")).toEqual({ valid: true });
      expect(validateCommand("command.exe")).toEqual({ valid: true });
    });
  });

  describe("Commands with shell metacharacters", () => {
    it("should reject commands with semicolons", () => {
      expect(validateCommand("cmd; rm -rf /").valid).toBe(false);
    });

    it("should reject commands with pipes", () => {
      expect(validateCommand("cat file | bash").valid).toBe(false);
    });

    it("should reject commands with ampersands", () => {
      expect(validateCommand("cmd && malicious").valid).toBe(false);
      expect(validateCommand("cmd & background").valid).toBe(false);
    });

    it("should reject commands with backticks", () => {
      expect(validateCommand("cmd `whoami`").valid).toBe(false);
    });

    it("should reject commands with dollar signs", () => {
      expect(validateCommand("cmd $(whoami)").valid).toBe(false);
      expect(validateCommand("cmd $VAR").valid).toBe(false);
    });

    it("should reject commands with redirects", () => {
      expect(validateCommand("cmd > output").valid).toBe(false);
      expect(validateCommand("cmd < input").valid).toBe(false);
    });

    it("should reject commands with brackets", () => {
      expect(validateCommand("cmd [arg]").valid).toBe(false);
      expect(validateCommand("cmd {arg}").valid).toBe(false);
    });

    it("should reject commands with parentheses", () => {
      expect(validateCommand("(cmd)").valid).toBe(false);
    });

    it("should reject commands with exclamation marks", () => {
      expect(validateCommand("cmd !arg").valid).toBe(false);
    });
  });
});

describe("Module Name Validation", () => {
  /**
   * Recreates validateModuleNames logic from assess-full.ts
   */
  const VALID_MODULE_NAMES = [
    "functionality",
    "security",
    "documentation",
    "errorHandling",
    "usability",
    "mcpSpecCompliance", // deprecated, use protocolCompliance
    "protocolCompliance",
    "aupCompliance",
    "toolAnnotations",
    "prohibitedLibraries",
    "manifestValidation",
    "authentication",
    "temporal",
    "resources",
    "prompts",
    "crossCapability",
    "protocolConformance", // deprecated, use protocolCompliance
    "developerExperience",
    "portability",
    "externalAPIScanner",
    "fileModularization",
    "conformance",
  ];

  function validateModuleNames(input: string): {
    valid: boolean;
    names?: string[];
    invalid?: string[];
  } {
    const names = input
      .split(",")
      .map((n) => n.trim())
      .filter(Boolean);
    const invalid = names.filter((n) => !VALID_MODULE_NAMES.includes(n));

    if (invalid.length > 0) {
      return { valid: false, invalid };
    }
    return { valid: true, names };
  }

  describe("Valid module names", () => {
    it("should accept single valid module", () => {
      expect(validateModuleNames("security")).toEqual({
        valid: true,
        names: ["security"],
      });
    });

    it("should accept comma-separated modules", () => {
      expect(validateModuleNames("security,functionality,temporal")).toEqual({
        valid: true,
        names: ["security", "functionality", "temporal"],
      });
    });

    it("should trim whitespace", () => {
      expect(
        validateModuleNames(" security , functionality , temporal "),
      ).toEqual({
        valid: true,
        names: ["security", "functionality", "temporal"],
      });
    });

    it("should filter empty values", () => {
      expect(validateModuleNames("security,,functionality")).toEqual({
        valid: true,
        names: ["security", "functionality"],
      });
    });
  });

  describe("Invalid module names", () => {
    it("should reject invalid module names", () => {
      const result = validateModuleNames("invalid,security");
      expect(result.valid).toBe(false);
      expect(result.invalid).toEqual(["invalid"]);
    });

    it("should reject all invalid if multiple", () => {
      const result = validateModuleNames("invalid1,invalid2,security");
      expect(result.valid).toBe(false);
      expect(result.invalid).toEqual(["invalid1", "invalid2"]);
    });

    it("should reject case-sensitive mismatches", () => {
      const result = validateModuleNames("SECURITY");
      expect(result.valid).toBe(false);
      expect(result.invalid).toEqual(["SECURITY"]);
    });
  });
});

describe("Profile Validation", () => {
  /**
   * Profile validation logic from assess-full.ts
   */
  const VALID_PROFILES = ["quick", "security", "compliance", "full", "dev"];

  function isValidProfileName(name: string): boolean {
    return VALID_PROFILES.includes(name);
  }

  describe("Valid profiles", () => {
    it("should accept valid profile names", () => {
      expect(isValidProfileName("quick")).toBe(true);
      expect(isValidProfileName("security")).toBe(true);
      expect(isValidProfileName("compliance")).toBe(true);
      expect(isValidProfileName("full")).toBe(true);
      expect(isValidProfileName("dev")).toBe(true);
    });
  });

  describe("Invalid profiles", () => {
    it("should reject invalid profile names", () => {
      expect(isValidProfileName("invalid")).toBe(false);
      expect(isValidProfileName("QUICK")).toBe(false);
      expect(isValidProfileName("")).toBe(false);
      expect(isValidProfileName("custom")).toBe(false);
    });
  });
});

describe("Format Validation", () => {
  /**
   * Format validation from assess-full.ts
   */
  type ReportFormat = "json" | "markdown";

  function isValidFormat(format: string): format is ReportFormat {
    return format === "json" || format === "markdown";
  }

  describe("Valid formats", () => {
    it("should accept json format", () => {
      expect(isValidFormat("json")).toBe(true);
    });

    it("should accept markdown format", () => {
      expect(isValidFormat("markdown")).toBe(true);
    });
  });

  describe("Invalid formats", () => {
    it("should reject invalid formats", () => {
      expect(isValidFormat("html")).toBe(false);
      expect(isValidFormat("xml")).toBe(false);
      expect(isValidFormat("JSON")).toBe(false);
      expect(isValidFormat("")).toBe(false);
    });
  });
});

describe("Mutual Exclusivity Validation", () => {
  /**
   * Flag conflict detection from assess-full.ts
   */
  interface FlagOptions {
    profile?: string;
    skipModules?: string[];
    onlyModules?: string[];
  }

  function validateMutualExclusivity(options: FlagOptions): {
    valid: boolean;
    error?: string;
  } {
    if (
      options.profile &&
      (options.skipModules?.length || options.onlyModules?.length)
    ) {
      return {
        valid: false,
        error: "--profile cannot be used with --skip-modules or --only-modules",
      };
    }

    if (options.skipModules?.length && options.onlyModules?.length) {
      return {
        valid: false,
        error: "--skip-modules and --only-modules are mutually exclusive",
      };
    }

    return { valid: true };
  }

  describe("Valid flag combinations", () => {
    it("should allow profile alone", () => {
      expect(validateMutualExclusivity({ profile: "quick" })).toEqual({
        valid: true,
      });
    });

    it("should allow skip-modules alone", () => {
      expect(validateMutualExclusivity({ skipModules: ["temporal"] })).toEqual({
        valid: true,
      });
    });

    it("should allow only-modules alone", () => {
      expect(validateMutualExclusivity({ onlyModules: ["security"] })).toEqual({
        valid: true,
      });
    });

    it("should allow no module selection flags", () => {
      expect(validateMutualExclusivity({})).toEqual({ valid: true });
    });
  });

  describe("Invalid flag combinations", () => {
    it("should reject profile + skip-modules", () => {
      const result = validateMutualExclusivity({
        profile: "quick",
        skipModules: ["temporal"],
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("--profile cannot be used");
    });

    it("should reject profile + only-modules", () => {
      const result = validateMutualExclusivity({
        profile: "quick",
        onlyModules: ["security"],
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("--profile cannot be used");
    });

    it("should reject skip-modules + only-modules", () => {
      const result = validateMutualExclusivity({
        skipModules: ["temporal"],
        onlyModules: ["security"],
      });
      expect(result.valid).toBe(false);
      expect(result.error).toContain("mutually exclusive");
    });

    it("should reject all three flags together", () => {
      const result = validateMutualExclusivity({
        profile: "quick",
        skipModules: ["temporal"],
        onlyModules: ["security"],
      });
      expect(result.valid).toBe(false);
    });
  });
});

describe("Log Level Validation", () => {
  /**
   * Log level validation from assess-full.ts
   */
  type LogLevel = "silent" | "error" | "warn" | "info" | "debug";

  function isValidLogLevel(level: string): level is LogLevel {
    const validLevels: LogLevel[] = [
      "silent",
      "error",
      "warn",
      "info",
      "debug",
    ];
    return validLevels.includes(level as LogLevel);
  }

  describe("Valid log levels", () => {
    it("should accept all valid log levels", () => {
      expect(isValidLogLevel("silent")).toBe(true);
      expect(isValidLogLevel("error")).toBe(true);
      expect(isValidLogLevel("warn")).toBe(true);
      expect(isValidLogLevel("info")).toBe(true);
      expect(isValidLogLevel("debug")).toBe(true);
    });
  });

  describe("Invalid log levels", () => {
    it("should reject invalid log levels", () => {
      expect(isValidLogLevel("verbose")).toBe(false);
      expect(isValidLogLevel("trace")).toBe(false);
      expect(isValidLogLevel("INFO")).toBe(false);
      expect(isValidLogLevel("")).toBe(false);
    });
  });
});

describe("Version Flag Parsing", () => {
  describe("parseArgs with version flags", () => {
    it("should set versionRequested flag for --version", () => {
      const options = parseArgs(["test-server", "--version"]);
      expect(options.versionRequested).toBe(true);
    });

    it("should set versionRequested flag for -V", () => {
      const options = parseArgs(["test-server", "-V"]);
      expect(options.versionRequested).toBe(true);
    });

    it("should return early when version flag is present", () => {
      const options = parseArgs(["--version"]);
      expect(options.versionRequested).toBe(true);
      expect(options.serverName).toBeUndefined();
    });

    it("should handle version flag at any position", () => {
      const options = parseArgs(["--version", "--verbose"]);
      expect(options.versionRequested).toBe(true);
    });
  });

  describe("printVersion function", () => {
    it("should output version in correct format", () => {
      const consoleSpy = jest
        .spyOn(console, "log")
        .mockImplementation(() => {});
      printVersion();
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringMatching(/^mcp-assess-full \d+\.\d+\.\d+$/),
      );
      consoleSpy.mockRestore();
    });

    it("should match package.json version", () => {
      const consoleSpy = jest
        .spyOn(console, "log")
        .mockImplementation(() => {});
      printVersion();
      expect(consoleSpy).toHaveBeenCalledWith(
        `mcp-assess-full ${packageJson.version}`,
      );
      consoleSpy.mockRestore();
    });
  });
});

/**
 * Issue #118: Zod Schema Integration Tests
 *
 * Tests the integration between parseArgs() and Zod schema validation.
 * Verifies that CLI arguments are validated through Zod schemas before
 * being accepted into the options object.
 */
describe("parseArgs Zod Schema Integration", () => {
  // Store original process.exit to mock it
  let processExitSpy: jest.SpiedFunction<typeof process.exit>;
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    // Use fake timers to handle setTimeout in cli-parser error paths
    jest.useFakeTimers();
    // Mock process.exit to prevent actual exit
    processExitSpy = jest
      .spyOn(process, "exit")
      .mockImplementation((() => {}) as never);
    // Mock console.error to capture error messages
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    // Run any pending timers and restore
    jest.runAllTimers();
    jest.useRealTimers();
    // Use optional chaining in case spies weren't created (prevents memory leaks)
    processExitSpy?.mockRestore();
    consoleErrorSpy?.mockRestore();
  });

  describe("LogLevelSchema integration", () => {
    it("parseArgs validates log level with LogLevelSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--log-level",
        "debug",
      ]);
      expect(result.logLevel).toBe("debug");
    });

    it("parseArgs rejects invalid log level via LogLevelSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--log-level",
        "invalid-level",
      ]);

      // Should set helpRequested and exit
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid log level"),
      );
    });

    it("accepts all valid log levels: silent, error, warn, info, debug", () => {
      const validLevels = ["silent", "error", "warn", "info", "debug"];

      for (const level of validLevels) {
        consoleErrorSpy.mockClear();
        const result = parseArgs([
          "test-server",
          "--config",
          "config.json",
          "--log-level",
          level,
        ]);
        expect(result.logLevel).toBe(level);
        expect(result.helpRequested).toBeFalsy();
      }
    });
  });

  describe("ReportFormatSchema integration", () => {
    it("parseArgs validates report format with ReportFormatSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--format",
        "markdown",
      ]);
      expect(result.format).toBe("markdown");
    });

    it("parseArgs accepts json format", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--format",
        "json",
      ]);
      expect(result.format).toBe("json");
    });

    it("parseArgs rejects invalid format via ReportFormatSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--format",
        "xml",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid format"),
      );
    });

    it("accepts short flag -f for format", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "-f",
        "json",
      ]);
      expect(result.format).toBe("json");
    });
  });

  describe("AssessmentProfileNameSchema integration", () => {
    it("parseArgs validates profile name with AssessmentProfileNameSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--profile",
        "security",
      ]);
      expect(result.profile).toBe("security");
    });

    it("parseArgs rejects invalid profile via AssessmentProfileNameSchema", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--profile",
        "invalid-profile",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid profile name"),
      );
    });

    it("accepts all valid profiles: quick, security, compliance, full", () => {
      const validProfiles = ["quick", "security", "compliance", "full"];

      for (const profile of validProfiles) {
        consoleErrorSpy.mockClear();
        const result = parseArgs([
          "test-server",
          "--config",
          "config.json",
          "--profile",
          profile,
        ]);
        expect(result.profile).toBe(profile);
        expect(result.helpRequested).toBeFalsy();
      }
    });
  });

  describe("Module names validation via safeParseModuleNames", () => {
    it("parseArgs validates --skip-modules with valid module names", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--skip-modules",
        "temporal,security",
      ]);
      expect(result.skipModules).toContain("temporal");
      expect(result.skipModules).toContain("security");
    });

    it("parseArgs validates --only-modules with valid module names", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--only-modules",
        "functionality,errorHandling",
      ]);
      expect(result.onlyModules).toContain("functionality");
      expect(result.onlyModules).toContain("errorHandling");
    });

    it("parseArgs rejects invalid module names with helpful error", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--skip-modules",
        "invalid-module",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });

    it("parseArgs rejects mix of valid and invalid module names", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--only-modules",
        "security,not-a-real-module",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });
  });
});

/**
 * Transport Flag Tests (--http, --sse)
 *
 * Tests for the convenience transport flags that allow quick testing
 * without creating a config file.
 */
describe("Transport Flags (--http, --sse)", () => {
  let processExitSpy: jest.SpiedFunction<typeof process.exit>;
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    jest.useFakeTimers();
    processExitSpy = jest
      .spyOn(process, "exit")
      .mockImplementation((() => {}) as never);
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    jest.runAllTimers();
    jest.useRealTimers();
    processExitSpy?.mockRestore();
    consoleErrorSpy?.mockRestore();
  });

  describe("--http flag", () => {
    it("should accept valid HTTP URL", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should accept valid HTTPS URL", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "https://api.example.com/mcp",
      ]);
      expect(result.httpUrl).toBe("https://api.example.com/mcp");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should reject invalid URL", () => {
      const result = parseArgs(["test-server", "--http", "not-a-valid-url"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid URL for --http"),
      );
    });

    it("should reject missing URL argument", () => {
      const result = parseArgs(["test-server", "--http"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http requires a URL argument"),
      );
    });

    it("should reject when next argument is another flag", () => {
      const result = parseArgs(["test-server", "--http", "--verbose"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http requires a URL argument"),
      );
    });

    it("should reject non-HTTP protocol (file://)", () => {
      const result = parseArgs(["test-server", "--http", "file:///etc/passwd"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "--http requires HTTP or HTTPS URL, got: file:",
        ),
      );
    });

    it("should reject non-HTTP protocol (ftp://)", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "ftp://example.com/file",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http requires HTTP or HTTPS URL, got: ftp:"),
      );
    });
  });

  describe("--sse flag", () => {
    it("should accept valid SSE URL", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
      ]);
      expect(result.sseUrl).toBe("http://localhost:9002/sse");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should accept valid HTTPS SSE URL", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "https://api.example.com/sse",
      ]);
      expect(result.sseUrl).toBe("https://api.example.com/sse");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should reject invalid URL", () => {
      const result = parseArgs(["test-server", "--sse", "invalid-url"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid URL for --sse"),
      );
    });

    it("should reject missing URL argument", () => {
      const result = parseArgs(["test-server", "--sse"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--sse requires a URL argument"),
      );
    });

    it("should reject non-HTTP protocol (file://)", () => {
      const result = parseArgs(["test-server", "--sse", "file:///etc/passwd"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--sse requires HTTP or HTTPS URL, got: file:"),
      );
    });
  });

  describe("mutual exclusivity", () => {
    it("should reject --http with --config", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--config",
        "config.json",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http/--sse cannot be used with --config"),
      );
    });

    it("should reject --sse with --config", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
        "--config",
        "config.json",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http/--sse cannot be used with --config"),
      );
    });

    it("should reject --http with --sse", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--sse",
        "http://localhost:9002/sse",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--http and --sse are mutually exclusive"),
      );
    });

    it("should allow --http without --config or --sse", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.sseUrl).toBeUndefined();
      expect(result.serverConfigPath).toBeUndefined();
      expect(result.helpRequested).toBeFalsy();
    });

    it("should allow --sse without --config or --http", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
      ]);
      expect(result.sseUrl).toBe("http://localhost:9002/sse");
      expect(result.httpUrl).toBeUndefined();
      expect(result.serverConfigPath).toBeUndefined();
      expect(result.helpRequested).toBeFalsy();
    });
  });

  describe("combined with other options", () => {
    it("should work with --http and --temporal-invocations", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--temporal-invocations",
        "5",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.temporalInvocations).toBe(5);
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --sse and --profile", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
        "--profile",
        "quick",
      ]);
      expect(result.sseUrl).toBe("http://localhost:9002/sse");
      expect(result.profile).toBe("quick");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --http and --output", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--output",
        "/tmp/results.json",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.outputPath).toBe("/tmp/results.json");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --http and --conformance", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--conformance",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.conformanceEnabled).toBe(true);
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --sse and --conformance", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
        "--conformance",
      ]);
      expect(result.sseUrl).toBe("http://localhost:9002/sse");
      expect(result.conformanceEnabled).toBe(true);
      expect(result.helpRequested).toBeFalsy();
    });
  });
});

/**
 * Module Flag Tests (--module, -m)
 *
 * Tests for the single module execution flag that bypasses orchestrator.
 * Issue #184: Single module runner for focused testing without orchestration overhead.
 */
describe("Module Flag (--module, -m)", () => {
  let processExitSpy: jest.SpiedFunction<typeof process.exit>;
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    jest.useFakeTimers();
    processExitSpy = jest
      .spyOn(process, "exit")
      .mockImplementation((() => {}) as never);
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    jest.runAllTimers();
    jest.useRealTimers();
    processExitSpy?.mockRestore();
    consoleErrorSpy?.mockRestore();
  });

  describe("valid module names", () => {
    it("should accept valid module name with long flag", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "toolAnnotations",
      ]);
      expect(result.singleModule).toBe("toolAnnotations");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should accept valid module name with short flag", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "-m",
        "security",
      ]);
      expect(result.singleModule).toBe("security");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should accept all valid core module names", () => {
      const coreModules = [
        "functionality",
        "security",
        "documentation",
        "errorHandling",
        "usability",
        "mcpSpecCompliance",
        "aupCompliance",
        "toolAnnotations",
        "prohibitedLibraries",
        "externalAPIScanner",
        "authentication",
        "temporal",
        "resources",
        "prompts",
        "crossCapability",
        "protocolConformance",
      ];

      for (const moduleName of coreModules) {
        consoleErrorSpy.mockClear();
        const result = parseArgs([
          "test-server",
          "--config",
          "config.json",
          "--module",
          moduleName,
        ]);
        expect(result.singleModule).toBe(moduleName);
        expect(result.helpRequested).toBeFalsy();
      }
    });

    it("should accept optional module names", () => {
      const optionalModules = ["manifestValidation", "portability"];

      for (const moduleName of optionalModules) {
        consoleErrorSpy.mockClear();
        const result = parseArgs([
          "test-server",
          "--config",
          "config.json",
          "--module",
          moduleName,
        ]);
        expect(result.singleModule).toBe(moduleName);
        expect(result.helpRequested).toBeFalsy();
      }
    });
  });

  describe("invalid module names", () => {
    it("should reject invalid module name", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "invalidModule",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });

    it("should reject missing module argument", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module requires a module name"),
      );
    });

    it("should reject when next argument is another flag", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "--verbose",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module requires a module name"),
      );
    });

    it("should reject case-sensitive mismatch", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "SECURITY",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });

    it("should reject module name with typo", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "functionalaty",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });
  });

  describe("mutual exclusivity with orchestrator flags", () => {
    it("should reject --module with --profile", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "security",
        "--profile",
        "quick",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "--module cannot be used with --skip-modules, --only-modules, or --profile",
        ),
      );
    });

    it("should reject --module with --skip-modules", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "security",
        "--skip-modules",
        "temporal",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module cannot be used with"),
      );
    });

    it("should reject --module with --only-modules", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "security",
        "--only-modules",
        "functionality",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module cannot be used with"),
      );
    });

    it("should reject --profile with --module (order reversed)", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--profile",
        "quick",
        "--module",
        "security",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module cannot be used with"),
      );
    });
  });

  describe("combined with transport flags", () => {
    it("should work with --http", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--module",
        "security",
      ]);
      expect(result.httpUrl).toBe("http://localhost:10900/mcp");
      expect(result.singleModule).toBe("security");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --sse", () => {
      const result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
        "--module",
        "functionality",
      ]);
      expect(result.sseUrl).toBe("http://localhost:9002/sse");
      expect(result.singleModule).toBe("functionality");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --config", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "temporal",
      ]);
      expect(result.serverConfigPath).toBe("config.json");
      expect(result.singleModule).toBe("temporal");
      expect(result.helpRequested).toBeFalsy();
    });
  });

  describe("combined with other compatible flags", () => {
    it("should work with --output", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "security",
        "--output",
        "/tmp/results.json",
      ]);
      expect(result.singleModule).toBe("security");
      expect(result.outputPath).toBe("/tmp/results.json");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --verbose", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "toolAnnotations",
        "--verbose",
      ]);
      expect(result.singleModule).toBe("toolAnnotations");
      expect(result.verbose).toBe(true);
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --log-level", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "errorHandling",
        "--log-level",
        "debug",
      ]);
      expect(result.singleModule).toBe("errorHandling");
      expect(result.logLevel).toBe("debug");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --temporal-invocations", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "temporal",
        "--temporal-invocations",
        "10",
      ]);
      expect(result.singleModule).toBe("temporal");
      expect(result.temporalInvocations).toBe(10);
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --conformance", () => {
      const result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "--module",
        "protocolConformance",
        "--conformance",
      ]);
      expect(result.singleModule).toBe("protocolConformance");
      expect(result.conformanceEnabled).toBe(true);
      expect(result.helpRequested).toBeFalsy();
    });

    it("should work with --format", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "--module",
        "security",
        "--format",
        "markdown",
      ]);
      expect(result.singleModule).toBe("security");
      expect(result.format).toBe("markdown");
      expect(result.helpRequested).toBeFalsy();
    });
  });

  describe("short flag behavior", () => {
    it("should accept -m with all transport types", () => {
      // Test with --http
      let result = parseArgs([
        "test-server",
        "--http",
        "http://localhost:10900/mcp",
        "-m",
        "security",
      ]);
      expect(result.singleModule).toBe("security");
      expect(result.helpRequested).toBeFalsy();

      // Test with --sse
      consoleErrorSpy.mockClear();
      result = parseArgs([
        "test-server",
        "--sse",
        "http://localhost:9002/sse",
        "-m",
        "functionality",
      ]);
      expect(result.singleModule).toBe("functionality");
      expect(result.helpRequested).toBeFalsy();

      // Test with --config
      consoleErrorSpy.mockClear();
      result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "-m",
        "temporal",
      ]);
      expect(result.singleModule).toBe("temporal");
      expect(result.helpRequested).toBeFalsy();
    });

    it("should reject -m with missing argument", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "-m",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--module requires a module name"),
      );
    });

    it("should reject -m with invalid module", () => {
      const result = parseArgs([
        "test-server",
        "--config",
        "config.json",
        "-m",
        "notAModule",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("Invalid module name"),
      );
    });
  });
});
