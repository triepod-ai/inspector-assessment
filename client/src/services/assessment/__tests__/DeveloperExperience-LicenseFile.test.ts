/**
 * Issue #208: LICENSE File Existence Check Tests
 *
 * Tests that inspector properly distinguishes between:
 * - Actual LICENSE file presence (PASS) - 10 points
 * - Only license declaration in package.json/manifest (WARNING) - 5 points
 * - No license file AND no declaration (FAIL) - 0 points
 *
 * This fixes false positives where README "## License" sections
 * caused PASS when no actual LICENSE file existed (MeetGeek audit evidence).
 */

import { DeveloperExperienceAssessor } from "../modules/DeveloperExperienceAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: true,
    errorHandling: false,
    usability: false,
  },
  ...overrides,
});

// Helper to create a mock tool
const createTool = (name: string, description?: string) => ({
  name,
  description: description || `Tool ${name} for testing`,
  inputSchema: { type: "object", properties: {} },
});

// Helper to create assessment context with optional package.json/manifestJson
const createContext = (
  readmeContent: string,
  tools: ReturnType<typeof createTool>[] = [],
  sourceCodeFiles?: Map<string, string>,
  packageJson?: Record<string, unknown>,
  manifestJson?: Record<string, unknown>,
): AssessmentContext =>
  ({
    serverName: "test-server",
    tools,
    readmeContent,
    sourceCodeFiles,
    packageJson,
    manifestJson,
    callTool: jest.fn(),
    config: createConfig(),
  }) as unknown as AssessmentContext;

describe("Issue #208: LICENSE File Existence Check", () => {
  let assessor: DeveloperExperienceAssessor;

  beforeEach(() => {
    assessor = new DeveloperExperienceAssessor(createConfig());
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("LICENSE File Detection (PASS scenarios)", () => {
    it("should set hasLicenseFile=true when LICENSE exists", async () => {
      const sourceCodeFiles = new Map([["LICENSE", "MIT License"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.hasLicense).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe("LICENSE");
      expect(result.documentation.qualityScore?.breakdown.license).toBe(10);
    });

    it("should set hasLicenseFile=true when LICENSE.md exists", async () => {
      const sourceCodeFiles = new Map([["LICENSE.md", "Apache License 2.0"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe(
        "LICENSE.md",
      );
      expect(result.documentation.qualityScore?.breakdown.license).toBe(10);
    });

    it("should set hasLicenseFile=true when LICENSE.txt exists", async () => {
      const sourceCodeFiles = new Map([["LICENSE.txt", "GPL v3"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe(
        "LICENSE.txt",
      );
    });

    it("should set hasLicenseFile=true when COPYING exists", async () => {
      const sourceCodeFiles = new Map([["COPYING", "GNU License"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe("COPYING");
    });

    it("should set hasLicenseFile=true when lowercase license exists", async () => {
      const sourceCodeFiles = new Map([["license", "MIT"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe("license");
    });
  });

  describe("License Declaration Only (WARNING scenarios)", () => {
    it("should set hasLicenseDeclaration=true when only package.json has license field", async () => {
      const packageJson = { name: "test-server", license: "MIT" };
      const result = await assessor.assess(
        createContext("# README", [], undefined, packageJson),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        true,
      );
      expect(result.documentation.qualityChecks?.hasLicense).toBe(true); // Legacy field
      expect(result.documentation.qualityChecks?.licenseFile).toBeUndefined();
      expect(result.documentation.qualityScore?.breakdown.license).toBe(5); // Partial points
    });

    it("should set hasLicenseDeclaration=true when only manifest.json has license field", async () => {
      const manifest = { name: "test-mcp", license: "Apache-2.0" };
      const result = await assessor.assess(
        createContext("# README", [], undefined, undefined, manifest),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        true,
      );
      expect(result.documentation.qualityScore?.breakdown.license).toBe(5);
    });

    it("should give partial credit (5 points) for declaration only", async () => {
      const packageJson = { name: "test-server", license: "ISC" };
      const result = await assessor.assess(
        createContext("# README", [], undefined, packageJson),
      );

      expect(result.documentation.qualityScore?.breakdown.license).toBe(5);
    });
  });

  describe("No License (FAIL scenarios)", () => {
    it("should set both hasLicenseFile and hasLicenseDeclaration to false when neither exists", async () => {
      const result = await assessor.assess(createContext("# README"));

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
      expect(result.documentation.qualityScore?.breakdown.license).toBe(0);
    });

    it("should NOT count README license section as license (Issue #208 fix)", async () => {
      // This was the false positive case - README had "## License" but no actual file
      const readme = "# README\n\n## License\n\nMIT";
      const result = await assessor.assess(createContext(readme));

      // Issue #208 FIX: README sections should NOT count
      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
      expect(result.documentation.qualityScore?.breakdown.license).toBe(0);
    });

    it("should give 0 points when only README mentions license", async () => {
      const readme =
        "# My Server\n\n## License\n\nThis project is MIT licensed.";
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityScore?.breakdown.license).toBe(0);
    });
  });

  describe("Both File and Declaration (PASS)", () => {
    it("should prefer file over declaration", async () => {
      const sourceCodeFiles = new Map([["LICENSE", "MIT License"]]);
      const packageJson = { name: "test-server", license: "MIT" };
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles, packageJson),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        true,
      );
      expect(result.documentation.qualityChecks?.licenseFile).toBe("LICENSE");
      expect(result.documentation.qualityScore?.breakdown.license).toBe(10); // Full points for file
    });

    it("should detect license type when file exists", async () => {
      const sourceCodeFiles = new Map([
        [
          "LICENSE",
          "MIT License\n\nPermission is hereby granted, free of charge...",
        ],
      ]);
      const packageJson = { name: "test-server", license: "MIT" };
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles, packageJson),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe("MIT");
    });

    it("should NOT detect license type when only declaration exists", async () => {
      const packageJson = { name: "test-server", license: "MIT" };
      const result = await assessor.assess(
        createContext("# README", [], undefined, packageJson),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBeUndefined();
    });
  });

  describe("Scoring Impact", () => {
    it("should calculate max score with license file", async () => {
      // README (10) + comprehensive (20) + install (20) + config (20) + examples (20) + license file (10) = 100
      const readme = Array(16 * 1024)
        .fill("x")
        .join(""); // 16KB = comprehensive
      const readmeWithSections = `# Installation\nnpm install\n\n# Configuration\nSet API_KEY\n\n# Usage\n\`\`\`\nstart()\`\`\`\n\n${readme}`;
      const sourceCodeFiles = new Map([["LICENSE", "MIT License"]]);

      const result = await assessor.assess(
        createContext(readmeWithSections, [], sourceCodeFiles),
      );

      expect(result.documentation.qualityScore?.total).toBe(100);
    });

    it("should calculate 95 max score with declaration only", async () => {
      // README (10) + comprehensive (20) + install (20) + config (20) + examples (20) + declaration only (5) = 95
      const readme = Array(16 * 1024)
        .fill("x")
        .join("");
      const readmeWithSections = `# Installation\nnpm install\n\n# Configuration\nSet API_KEY\n\n# Usage\n\`\`\`\nstart()\`\`\`\n\n${readme}`;
      const packageJson = { name: "test", license: "MIT" };

      const result = await assessor.assess(
        createContext(readmeWithSections, [], undefined, packageJson),
      );

      expect(result.documentation.qualityScore?.total).toBe(95);
    });

    it("should calculate 90 max score with no license", async () => {
      // README (10) + comprehensive (20) + install (20) + config (20) + examples (20) + no license (0) = 90
      const readme = Array(16 * 1024)
        .fill("x")
        .join("");
      const readmeWithSections = `# Installation\nnpm install\n\n# Configuration\nSet API_KEY\n\n# Usage\n\`\`\`\nstart()\`\`\`\n\n${readme}`;

      const result = await assessor.assess(
        createContext(readmeWithSections, [], undefined),
      );

      expect(result.documentation.qualityScore?.total).toBe(90);
    });
  });

  describe("Edge Cases", () => {
    it("should handle British spelling (LICENCE)", async () => {
      const sourceCodeFiles = new Map([["LICENCE", "BSD License"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe("LICENCE");
    });

    it("should handle empty sourceCodeFiles map", async () => {
      const sourceCodeFiles = new Map<string, string>();
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
    });

    it("should handle package.json without license field", async () => {
      const packageJson = { name: "test-server", version: "1.0.0" };
      const result = await assessor.assess(
        createContext("# README", [], undefined, packageJson),
      );

      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
    });

    it("should handle undefined sourceCodeFiles and packageJson", async () => {
      const result = await assessor.assess(
        createContext("# README", [], undefined, undefined, undefined),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
    });
  });

  describe("MeetGeek False Positive Scenario (Issue #208 Evidence)", () => {
    /**
     * Evidence from MeetGeek audit:
     * - Manual review: LICENSE file missing → FAIL
     * - Inspector result: D6 License Declaration → PASS (false positive)
     *
     * This test replicates the exact scenario that caused the false positive.
     */
    it("should return hasLicenseFile=false when only README mentions MIT license", async () => {
      // Simulate MeetGeek scenario: README mentions license but no actual file
      const readme = `# MeetGeek MCP Server

A tool for meeting management.

## Features
- Schedule meetings
- Get meeting notes

## License

MIT License - see LICENSE file for details.
`;

      const result = await assessor.assess(createContext(readme));

      // The bug was: this returned hasLicense=true (false positive)
      // The fix: hasLicenseFile should be false
      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
    });

    it("should correctly identify when actual LICENSE file exists", async () => {
      const readme = `# MeetGeek MCP Server

## License

MIT License - see LICENSE file for details.
`;
      const sourceCodeFiles = new Map([
        [
          "LICENSE",
          "MIT License\n\nCopyright (c) 2025 MeetGeek\n\nPermission is hereby granted...",
        ],
      ]);

      const result = await assessor.assess(
        createContext(readme, [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(true);
      expect(result.documentation.qualityChecks?.licenseFile).toBe("LICENSE");
      expect(result.documentation.qualityChecks?.licenseType).toBe("MIT");
    });
  });
});
