/**
 * CLI E2E Integration Tests (Issue #97)
 *
 * End-to-end tests that verify the mcp-assess-full CLI works correctly
 * as a black-box system, including:
 * - Command-line argument handling (--help, --version, --config, etc.)
 * - JSONL event stream output format
 * - Exit codes (0 for PASS, 1 for FAIL/error)
 * - Graceful error handling
 *
 * Tests that require testbed servers (vulnerable-mcp, hardened-mcp) skip
 * gracefully when servers are unavailable, allowing CI to pass without
 * external dependencies.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/97
 */

import { describe, it, expect, beforeAll, afterAll } from "@jest/globals";
import { spawn, ChildProcess } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { fileURLToPath } from "url";

// ============================================================================
// Constants
// ============================================================================

/** Get __dirname equivalent for ES modules */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** Path to the built CLI entry point */
const CLI_PATH = path.resolve(__dirname, "../../build/assess-full.js");

/** Testbed server URLs */
const VULNERABLE_URL = "http://localhost:10900/mcp";
const HARDENED_URL = "http://localhost:10901/mcp";

/** Default headers for MCP HTTP servers */
const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

/** Temp directory for test config files */
const TEMP_DIR = path.join(os.tmpdir(), "assess-full-e2e-tests");

// ============================================================================
// Types
// ============================================================================

/** Result from spawning CLI process */
interface CLIResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  jsonlEvents: JSONLEvent[];
  duration: number;
}

/** JSONL event structure */
interface JSONLEvent {
  event: string;
  version?: string;
  [key: string]: unknown;
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Spawn the CLI process and capture output
 *
 * @param args - CLI arguments
 * @param timeout - Timeout in milliseconds (default: 60000)
 * @returns CLI result with stdout, stderr, exit code, and parsed JSONL events
 */
async function spawnCLI(
  args: string[],
  timeout: number = 60000,
): Promise<CLIResult> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    let stdout = "";
    let stderr = "";
    let exitCode: number | null = null;
    let proc: ChildProcess | null = null;

    // Spawn the CLI process
    proc = spawn("node", [CLI_PATH, ...args], {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        // Ensure consistent output
        NO_COLOR: "1",
        FORCE_COLOR: "0",
      },
    });

    // Capture stdout
    proc.stdout?.on("data", (data: Buffer) => {
      stdout += data.toString();
    });

    // Capture stderr
    proc.stderr?.on("data", (data: Buffer) => {
      stderr += data.toString();
    });

    // Set timeout
    const timer = setTimeout(() => {
      if (proc && !proc.killed) {
        proc.kill("SIGTERM");
        exitCode = -1; // Indicate timeout
      }
    }, timeout);

    // Handle process exit
    proc.on("close", (code) => {
      clearTimeout(timer);
      exitCode = code;

      const duration = Date.now() - startTime;
      const jsonlEvents = parseJSONLEvents(stderr);

      resolve({
        stdout,
        stderr,
        exitCode,
        jsonlEvents,
        duration,
      });
    });

    // Handle errors
    proc.on("error", (err) => {
      clearTimeout(timer);
      stderr += `\nProcess error: ${err.message}`;
      resolve({
        stdout,
        stderr,
        exitCode: -1,
        jsonlEvents: [],
        duration: Date.now() - startTime,
      });
    });
  });
}

/**
 * Parse JSONL events from stderr output
 *
 * JSONL events are emitted one per line to stderr.
 * Non-JSON lines are ignored (they may be console warnings or errors).
 *
 * @param stderr - Raw stderr output
 * @returns Array of parsed JSONL events
 */
function parseJSONLEvents(stderr: string): JSONLEvent[] {
  const events: JSONLEvent[] = [];
  const lines = stderr.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const parsed = JSON.parse(trimmed);
      // Check if it looks like a JSONL event (has 'event' field)
      if (parsed && typeof parsed === "object" && "event" in parsed) {
        events.push(parsed as JSONLEvent);
      }
    } catch {
      // Not a JSON line, skip
    }
  }

  return events;
}

/**
 * Check if a server is available by sending an initialize request
 *
 * @param url - Server URL to check
 * @returns True if server responds, false otherwise
 */
async function checkServerAvailable(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    const response = await fetch(url, {
      method: "POST",
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "e2e-test", version: "1.0.0" },
        },
        id: 1,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    return response.status < 500;
  } catch {
    return false;
  }
}

/**
 * Create a temporary config file for testing
 *
 * @param config - Configuration object
 * @param filename - Optional filename (default: auto-generated)
 * @returns Path to the created config file
 */
function createTempConfig(
  config: Record<string, unknown>,
  filename?: string,
): string {
  const name = filename || `config-${Date.now()}.json`;
  const configPath = path.join(TEMP_DIR, name);
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  return configPath;
}

/**
 * Create an invalid (malformed) JSON config file
 *
 * @param content - Raw content to write
 * @param filename - Optional filename
 * @returns Path to the created file
 */
function createInvalidConfig(content: string, filename?: string): string {
  const name = filename || `invalid-${Date.now()}.json`;
  const configPath = path.join(TEMP_DIR, name);
  fs.writeFileSync(configPath, content);
  return configPath;
}

// ============================================================================
// Test Setup
// ============================================================================

describe("CLI E2E Integration Tests", () => {
  let vulnerableAvailable = false;
  let hardenedAvailable = false;

  beforeAll(async () => {
    // Create temp directory
    if (!fs.existsSync(TEMP_DIR)) {
      fs.mkdirSync(TEMP_DIR, { recursive: true });
    }

    // Check server availability for integration tests
    const [v, h] = await Promise.all([
      checkServerAvailable(VULNERABLE_URL),
      checkServerAvailable(HARDENED_URL),
    ]);
    vulnerableAvailable = v;
    hardenedAvailable = h;

    if (!v && !h) {
      console.log(
        "\n⚠️  Testbed servers unavailable - integration tests will skip gracefully",
      );
      console.log("   To run full tests, start:");
      console.log("   - vulnerable-mcp: http://localhost:10900/mcp");
      console.log("   - hardened-mcp: http://localhost:10901/mcp\n");
    }
  }, 30000); // 30 second timeout for server availability checks

  afterAll(() => {
    // Clean up temp directory
    if (fs.existsSync(TEMP_DIR)) {
      const files = fs.readdirSync(TEMP_DIR);
      for (const file of files) {
        fs.unlinkSync(path.join(TEMP_DIR, file));
      }
      fs.rmdirSync(TEMP_DIR);
    }
  });

  // ==========================================================================
  // Group 1: Help and Version Display (No Server Required)
  // ==========================================================================

  describe("Help and Version Display", () => {
    it("should display help with --help flag", async () => {
      const result = await spawnCLI(["--help"], 10000);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Usage: mcp-assess-full");
      expect(result.stdout).toContain("--server");
      expect(result.stdout).toContain("--config");
      expect(result.stdout).toContain("--profile");
    });

    it("should display help with -h flag", async () => {
      const result = await spawnCLI(["-h"], 10000);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain("Usage: mcp-assess-full");
    });

    it("should display version with --version flag", async () => {
      const result = await spawnCLI(["--version"], 10000);

      expect(result.exitCode).toBe(0);
      // Version should match semver pattern (e.g., 1.26.7)
      expect(result.stdout).toMatch(/mcp-assess-full \d+\.\d+\.\d+/);
    });

    it("should display version with -V flag", async () => {
      const result = await spawnCLI(["-V"], 10000);

      expect(result.exitCode).toBe(0);
      expect(result.stdout).toMatch(/\d+\.\d+\.\d+/);
    });
  });

  // ==========================================================================
  // Group 2: Configuration Validation (No Server Required)
  // ==========================================================================

  describe("Configuration Validation", () => {
    it("should fail gracefully when config file is missing", async () => {
      const result = await spawnCLI(
        [
          "--server",
          "test-server",
          "--config",
          "/nonexistent/path/config.json",
        ],
        10000,
      );

      expect(result.exitCode).toBe(1);
      // Error message should mention the issue
      expect(result.stderr.toLowerCase()).toMatch(/error|not found|enoent/i);
    });

    it("should fail gracefully for malformed JSON config", async () => {
      const configPath = createInvalidConfig("{ invalid json }");

      const result = await spawnCLI(
        ["--server", "test-server", "--config", configPath],
        10000,
      );

      expect(result.exitCode).toBe(1);
      expect(result.stderr.toLowerCase()).toMatch(/error|parse|json|syntax/i);
    });

    it("should fail gracefully with missing --server flag", async () => {
      const configPath = createTempConfig({
        transport: "http",
        url: "http://localhost:9999/mcp",
      });

      const result = await spawnCLI(["--config", configPath], 10000);

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain("--server is required");
    });
  });

  // ==========================================================================
  // Group 3: Profile Selection (No Server Required)
  // ==========================================================================

  describe("Profile Selection", () => {
    it("should list available profiles in help text", async () => {
      const result = await spawnCLI(["--help"], 10000);

      expect(result.stdout).toContain("quick");
      expect(result.stdout).toContain("security");
      expect(result.stdout).toContain("compliance");
      expect(result.stdout).toContain("full");
    });

    it("should reject invalid profile names", async () => {
      const result = await spawnCLI(
        ["--server", "test", "--profile", "invalid-profile-name"],
        10000,
      );

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toMatch(/invalid profile/i);
    });
  });

  // ==========================================================================
  // Group 4: Error Handling (No Server Required)
  // ==========================================================================

  describe("Error Handling", () => {
    it("should fail gracefully when server is unreachable", async () => {
      const configPath = createTempConfig({
        transport: "http",
        url: "http://localhost:19999/mcp", // Non-existent port
      });

      const result = await spawnCLI(
        ["--server", "unreachable", "--config", configPath],
        30000,
      );

      expect(result.exitCode).toBe(1);
      // Should have some error indication
      expect(result.stderr.toLowerCase()).toMatch(
        /error|connect|fail|econnrefused/i,
      );
    });

    it("should reject unknown arguments", async () => {
      const result = await spawnCLI(
        ["--server", "test", "--unknown-flag-xyz"],
        10000,
      );

      expect(result.exitCode).toBe(1);
      expect(result.stderr).toMatch(/unknown argument/i);
    });
  });

  // ==========================================================================
  // Group 5: Server Assessment (Integration - Requires Testbed Servers)
  // ==========================================================================

  describe("Server Assessment (Integration)", () => {
    it("should complete assessment against vulnerable-mcp", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const configPath = createTempConfig({
        transport: "http",
        url: VULNERABLE_URL,
      });

      const result = await spawnCLI(
        [
          "--server",
          "vulnerable-mcp",
          "--config",
          configPath,
          "--profile",
          "quick",
        ],
        120000,
      );

      // Should complete (may PASS or FAIL based on vulnerabilities)
      expect([0, 1]).toContain(result.exitCode);

      // Should emit assessment_complete event
      const completeEvent = result.jsonlEvents.find(
        (e) => e.event === "assessment_complete",
      );
      expect(completeEvent).toBeDefined();
    }, 180000); // 3 minute timeout for full assessment

    it("should emit valid JSONL events to stderr", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const configPath = createTempConfig({
        transport: "http",
        url: VULNERABLE_URL,
      });

      const result = await spawnCLI(
        [
          "--server",
          "vulnerable-mcp",
          "--config",
          configPath,
          "--profile",
          "quick",
        ],
        120000,
      );

      // Validate event sequence
      const eventTypes = result.jsonlEvents.map((e) => e.event);

      expect(eventTypes).toContain("server_connected");
      expect(eventTypes).toContain("tools_discovery_complete");
      expect(eventTypes).toContain("assessment_complete");

      // Validate server_connected event structure
      const serverConnected = result.jsonlEvents.find(
        (e) => e.event === "server_connected",
      );
      expect(serverConnected).toHaveProperty("serverName");
      expect(serverConnected).toHaveProperty("transport");
      expect(serverConnected).toHaveProperty("version");

      // Validate assessment_complete event structure
      const assessmentComplete = result.jsonlEvents.find(
        (e) => e.event === "assessment_complete",
      );
      expect(assessmentComplete).toHaveProperty("overallStatus");
      expect(assessmentComplete).toHaveProperty("totalTests");
      expect(assessmentComplete).toHaveProperty("outputPath");
    }, 180000); // 3 minute timeout for full assessment

    it("should return exit code 1 for FAIL status on vulnerable server", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const configPath = createTempConfig({
        transport: "http",
        url: VULNERABLE_URL,
      });

      const result = await spawnCLI(
        [
          "--server",
          "vulnerable-mcp",
          "--config",
          configPath,
          "--profile",
          "security",
        ],
        180000,
      );

      // Vulnerable server should have vulnerabilities -> FAIL status
      const assessmentComplete = result.jsonlEvents.find(
        (e) => e.event === "assessment_complete",
      );

      if (assessmentComplete?.overallStatus === "FAIL") {
        expect(result.exitCode).toBe(1);
      }
    }, 240000); // 4 minute timeout for security profile

    it("should return exit code 0 for PASS status on hardened server", async () => {
      if (!hardenedAvailable) {
        console.log("⏩ Skipping: hardened-mcp not available");
        return;
      }

      const configPath = createTempConfig({
        transport: "http",
        url: HARDENED_URL,
      });

      const result = await spawnCLI(
        [
          "--server",
          "hardened-mcp",
          "--config",
          configPath,
          "--profile",
          "quick",
        ],
        120000,
      );

      // Hardened server should pass -> exit 0
      const assessmentComplete = result.jsonlEvents.find(
        (e) => e.event === "assessment_complete",
      );

      if (assessmentComplete?.overallStatus === "PASS") {
        expect(result.exitCode).toBe(0);
      }
    }, 180000); // 3 minute timeout for full assessment
  });

  // ==========================================================================
  // Group 6: Preflight Mode (Integration - Requires Testbed Servers)
  // ==========================================================================

  describe("Preflight Mode", () => {
    it("should run preflight validation quickly", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: testbed server not available");
        return;
      }

      const configPath = createTempConfig({
        transport: "http",
        url: VULNERABLE_URL,
      });

      const result = await spawnCLI(
        ["--server", "vulnerable-mcp", "--config", configPath, "--preflight"],
        30000,
      );

      // Preflight should complete faster than full assessment
      expect(result.duration).toBeLessThan(20000);

      // Should indicate success or provide validation info
      expect([0, 1]).toContain(result.exitCode);
    }, 60000); // 1 minute timeout for preflight
  });
});
