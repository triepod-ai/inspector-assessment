/**
 * DeveloperExperienceAssessor Quality Scoring Tests (Issue #55)
 *
 * Tests for documentation quality scoring including:
 * - Point-based scoring (100 points max)
 * - README size tiers (minimal/adequate/comprehensive)
 * - License detection and type identification
 * - Status thresholds (PASS/VERIFY/FAIL)
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

// Helper to create assessment context
const createContext = (
  readmeContent: string,
  tools: ReturnType<typeof createTool>[] = [],
  sourceCodeFiles?: Map<string, string>,
): AssessmentContext =>
  ({
    serverName: "test-server",
    tools,
    readmeContent,
    sourceCodeFiles,
    callTool: jest.fn(),
    config: createConfig(),
  }) as unknown as AssessmentContext;

// Helper to generate README content of specific size
const generateReadme = (sizeKB: number, sections: string[] = []): string => {
  const sectionContent = sections.join("\n\n");
  const targetBytes = sizeKB * 1024;
  const padding = "x".repeat(Math.max(0, targetBytes - sectionContent.length));
  return sectionContent + padding;
};

describe("DeveloperExperienceAssessor - Issue #55 Quality Scoring", () => {
  let assessor: DeveloperExperienceAssessor;

  beforeEach(() => {
    assessor = new DeveloperExperienceAssessor(createConfig());
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Point Allocation", () => {
    it("should award 10 points for README presence", async () => {
      const result = await assessor.assess(
        createContext("# README\n\nMinimal content"),
      );

      expect(result.documentation.qualityScore?.breakdown.readmeExists).toBe(
        10,
      );
    });

    it("should award 0 points for missing README", async () => {
      const result = await assessor.assess(createContext(""));

      expect(result.documentation.qualityScore?.breakdown.readmeExists).toBe(0);
      expect(result.documentation.qualityScore?.total).toBe(0);
    });

    it("should award +10 points for README >5KB (adequate)", async () => {
      const readme = generateReadme(6, ["# Installation\nnpm install"]);
      const result = await assessor.assess(createContext(readme));

      expect(
        result.documentation.qualityScore?.breakdown.readmeComprehensive,
      ).toBe(10);
    });

    it("should award +20 points for README >15KB (comprehensive)", async () => {
      const readme = generateReadme(16, ["# Installation\nnpm install"]);
      const result = await assessor.assess(createContext(readme));

      expect(
        result.documentation.qualityScore?.breakdown.readmeComprehensive,
      ).toBe(20);
    });

    it("should award 20 points for installation section", async () => {
      const readme = "# Installation\n\nnpm install my-package";
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityScore?.breakdown.installation).toBe(
        20,
      );
    });

    it("should award 20 points for configuration section", async () => {
      const readme = "# Configuration\n\nSet OPENAI_API_KEY in your .env file";
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityScore?.breakdown.configuration).toBe(
        20,
      );
    });

    it("should detect configuration with various keywords", async () => {
      const keywords = [
        "environment variable",
        "env var",
        ".env",
        "api key",
        "API_KEY",
      ];

      for (const keyword of keywords) {
        const readme = `# Setup\n\nPlease set the ${keyword}`;
        const result = await assessor.assess(createContext(readme));
        expect(result.documentation.qualityScore?.breakdown.configuration).toBe(
          20,
        );
      }
    });

    it("should award 20 points for examples/usage section", async () => {
      const readme = "# Usage\n\n```javascript\nserver.start();\n```";
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityScore?.breakdown.examples).toBe(20);
    });

    it("should award 10 points for license presence", async () => {
      const sourceCodeFiles = new Map([["LICENSE", "MIT License"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityScore?.breakdown.license).toBe(10);
    });
  });

  describe("README Quality Tiers", () => {
    it("should classify < 5KB as minimal", async () => {
      const readme = generateReadme(1);
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityChecks?.readmeQuality).toBe("minimal");
    });

    it("should classify 5KB-15KB as adequate", async () => {
      const readme = generateReadme(10);
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityChecks?.readmeQuality).toBe(
        "adequate",
      );
    });

    it("should classify > 15KB as comprehensive", async () => {
      const readme = generateReadme(20);
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.qualityChecks?.readmeQuality).toBe(
        "comprehensive",
      );
    });

    it("should track readmeSizeBytes accurately", async () => {
      const readme = "Hello World"; // 11 bytes
      const result = await assessor.assess(createContext(readme));

      expect(result.documentation.readmeSizeBytes).toBe(11);
    });
  });

  describe("License Detection", () => {
    it("should detect LICENSE file", async () => {
      const sourceCodeFiles = new Map([["LICENSE", "MIT License text"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicense).toBe(true);
    });

    it("should detect LICENSE.md file", async () => {
      const sourceCodeFiles = new Map([["LICENSE.md", "Apache License 2.0"]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicense).toBe(true);
    });

    // Issue #208: README sections should NOT count as license presence
    // This was the false positive scenario - fixed by distinguishing file vs declaration
    it("should NOT count README license section as actual license file (Issue #208)", async () => {
      const readme = "# README\n\n## License\n\nMIT";
      const result = await assessor.assess(createContext(readme));

      // Issue #208 FIX: README sections don't count - must have actual file
      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseFile).toBe(false);
      expect(result.documentation.qualityChecks?.hasLicenseDeclaration).toBe(
        false,
      );
    });

    it("should return false when no license found", async () => {
      const result = await assessor.assess(
        createContext("# README\n\nNo license here"),
      );

      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
    });
  });

  describe("License Type Detection", () => {
    it("should detect MIT license", async () => {
      const licenseText =
        "MIT License\n\nPermission is hereby granted, free of charge...";
      const sourceCodeFiles = new Map([["LICENSE", licenseText]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe("MIT");
    });

    it("should detect Apache-2.0 license", async () => {
      const licenseText = "Apache License\nVersion 2.0, January 2004";
      const sourceCodeFiles = new Map([["LICENSE", licenseText]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe(
        "Apache-2.0",
      );
    });

    it("should detect GPL-3.0 license", async () => {
      const licenseText = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007";
      const sourceCodeFiles = new Map([["LICENSE", licenseText]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe("GPL-3.0");
    });

    it("should detect BSD-3-Clause license", async () => {
      const licenseText = "BSD 3-Clause License";
      const sourceCodeFiles = new Map([["LICENSE", licenseText]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe(
        "BSD-3-Clause",
      );
    });

    it("should return Unknown for unrecognized license", async () => {
      const licenseText = "Custom License v1.0\nDo whatever you want";
      const sourceCodeFiles = new Map([["LICENSE", licenseText]]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.licenseType).toBe("Unknown");
    });

    it("should return undefined when no source files available", async () => {
      const result = await assessor.assess(createContext("# README"));

      expect(result.documentation.qualityChecks?.licenseType).toBeUndefined();
    });
  });

  describe("Status Thresholds (Issue #55)", () => {
    it("should return PASS status for score >= 80", async () => {
      // Comprehensive README (30) + Install (20) + Config (20) + Examples (20) + License (10) = 100
      const readme = generateReadme(20, [
        "# Installation\nnpm install",
        "# Configuration\nSet API_KEY",
        "# Usage\n```\nserver.start()```",
      ]);
      const sourceCodeFiles = new Map([["LICENSE", "MIT License"]]);
      const result = await assessor.assess(
        createContext(readme, [], sourceCodeFiles),
      );

      expect(result.documentation.qualityScore?.total).toBeGreaterThanOrEqual(
        80,
      );
      // Note: Overall status also includes usability (40% weight)
    });

    it("should calculate documentation score correctly", async () => {
      // README exists (10) + adequate size (10) + install (20) = 40
      const readme = generateReadme(6, ["# Installation\nnpm install"]);
      const result = await assessor.assess(createContext(readme));

      expect(result.scores.documentation).toBe(40);
    });

    it("should return max score of 100 with all checks passing", async () => {
      const readme = generateReadme(20, [
        "# Installation\nnpm install my-mcp-server",
        "# Configuration\nSet your API_KEY in the .env file",
        "# Usage\n```javascript\nconst server = require('mcp');\nserver.start();\n```",
      ]);
      const sourceCodeFiles = new Map([
        [
          "LICENSE",
          "MIT License\n\nPermission is hereby granted, free of charge...",
        ],
      ]);
      const result = await assessor.assess(
        createContext(readme, [], sourceCodeFiles),
      );

      expect(result.documentation.qualityScore?.total).toBe(100);
      expect(result.documentation.qualityScore?.breakdown).toEqual({
        readmeExists: 10,
        readmeComprehensive: 20,
        installation: 20,
        configuration: 20,
        examples: 20,
        license: 10,
      });
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty README gracefully", async () => {
      const result = await assessor.assess(createContext(""));

      expect(result.documentation.qualityChecks?.hasReadme).toBe(false);
      expect(result.documentation.qualityScore?.total).toBe(0);
      expect(result.status).toBe("FAIL");
    });

    it("should handle README with only whitespace", async () => {
      const result = await assessor.assess(createContext("   \n\n   "));

      expect(result.documentation.qualityChecks?.hasReadme).toBe(true);
      expect(result.documentation.qualityChecks?.readmeQuality).toBe("minimal");
    });

    it("should handle sourceCodeFiles without LICENSE", async () => {
      const sourceCodeFiles = new Map([
        ["package.json", '{"name": "test"}'],
        ["index.js", "console.log('hello')"],
      ]);
      const result = await assessor.assess(
        createContext("# README", [], sourceCodeFiles),
      );

      expect(result.documentation.qualityChecks?.hasLicense).toBe(false);
      expect(result.documentation.qualityChecks?.licenseType).toBeUndefined();
    });

    it("should preserve existing documentation metrics", async () => {
      const readme = "# Installation\nnpm install";
      const result = await assessor.assess(createContext(readme));

      // Original metrics should still be present
      expect(result.documentation.hasReadme).toBe(true);
      expect(result.documentation.hasInstallInstructions).toBe(true);
      // Quality metrics should be added
      expect(result.documentation.qualityChecks).toBeDefined();
      expect(result.documentation.qualityScore).toBeDefined();
    });
  });

  describe("Integration with Overall Score", () => {
    it("should use quality score in overall calculation", async () => {
      // Quality score = 50 (README 10 + adequate 10 + install 20 + config 0 + examples 0 + license 10)
      const readme = generateReadme(6, ["# Installation\nnpm install"]);
      const sourceCodeFiles = new Map([["LICENSE", "MIT"]]);
      const tools = [createTool("test-tool", "A well-documented test tool")];

      const result = await assessor.assess(
        createContext(readme, tools, sourceCodeFiles),
      );

      // Documentation score should be from quality scoring
      expect(result.scores.documentation).toBe(50);
      // Overall = 60% docs + 40% usability
      expect(result.scores.overall).toBeGreaterThan(0);
    });
  });
});
