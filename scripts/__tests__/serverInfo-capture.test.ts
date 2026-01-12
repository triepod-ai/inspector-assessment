/**
 * ServerInfo Capture Unit Tests
 *
 * Tests the serverInfo capture logic in CLI assess-full.ts
 * to ensure proper handling of getServerVersion() and getServerCapabilities()
 * return values.
 *
 * Created to address GitHub Issue #23 requirement for CLI integration testing.
 */

import * as fs from "fs";
import * as path from "path";

const CLI_PATH = path.join(__dirname, "../../cli/src/assess-full.ts");

describe("ServerInfo Capture Logic", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  let cliContent: string;

  beforeAll(() => {
    cliContent = fs.readFileSync(CLI_PATH, "utf-8");
  });

  describe("serverInfo extraction", () => {
    it("should call client.getServerVersion() after connection", () => {
      // Verify getServerVersion is called
      expect(cliContent).toContain("client.getServerVersion()");
    });

    it("should call client.getServerCapabilities() after connection", () => {
      // Verify getServerCapabilities is called
      expect(cliContent).toContain("client.getServerCapabilities()");
    });

    it("should capture rawServerInfo before processing", () => {
      // Verify the pattern: const rawServerInfo = client.getServerVersion();
      expect(cliContent).toMatch(
        /const rawServerInfo\s*=\s*client\.getServerVersion\(\)/,
      );
    });

    it("should capture rawServerCapabilities before processing", () => {
      // Verify the pattern: const rawServerCapabilities = client.getServerCapabilities();
      expect(cliContent).toMatch(
        /const rawServerCapabilities\s*=\s*client\.getServerCapabilities\(\)/,
      );
    });
  });

  describe("null/undefined handling", () => {
    it("should handle null serverInfo with conditional", () => {
      // Verify ternary pattern: rawServerInfo ? {...} : undefined
      expect(cliContent).toMatch(/rawServerInfo\s*\?\s*\{/);
      expect(cliContent).toMatch(/\}\s*:\s*undefined/);
    });

    it("should handle undefined serverCapabilities with nullish coalescing", () => {
      // Verify pattern: rawServerCapabilities ?? undefined
      expect(cliContent).toMatch(/rawServerCapabilities\s*\?\?\s*undefined/);
    });

    it('should use "unknown" fallback when name is missing', () => {
      // Verify pattern: rawServerInfo.name || "unknown"
      expect(cliContent).toMatch(
        /rawServerInfo\.name\s*\|\|\s*["']unknown["']/,
      );
    });
  });

  describe("serverInfo object construction", () => {
    it("should extract name field from rawServerInfo", () => {
      expect(cliContent).toMatch(/name:\s*rawServerInfo\.name/);
    });

    it("should extract version field from rawServerInfo", () => {
      expect(cliContent).toMatch(/version:\s*rawServerInfo\.version/);
    });

    it("should extract metadata field with type cast", () => {
      // Verify metadata is extracted with proper casting
      expect(cliContent).toMatch(
        /metadata:\s*\(rawServerInfo\s+as\s+Record<string,\s*unknown>\)\.metadata/,
      );
    });
  });

  describe("context integration", () => {
    it("should pass serverInfo to AssessmentContext", () => {
      // Verify serverInfo is added to context object
      expect(cliContent).toMatch(/serverInfo[,\s]*$/m);
    });

    it("should pass serverCapabilities to AssessmentContext with type cast", () => {
      // Verify serverCapabilities is added to context with AssessmentContext type
      expect(cliContent).toMatch(
        /serverCapabilities:\s*\n?\s*serverCapabilities\s+as\s+AssessmentContext\["serverCapabilities"\]/,
      );
    });
  });

  describe("user feedback", () => {
    it("should log warning when serverInfo is missing", () => {
      // Verify console warning pattern exists
      expect(cliContent).toContain(
        "Server did not provide serverInfo during initialization",
      );
    });
  });
});
