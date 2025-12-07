import { PortabilityAssessor } from "./PortabilityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
  createMockManifestJson,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("PortabilityAssessor", () => {
  let assessor: PortabilityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      enableSourceCodeAnalysis: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        portability: true,
      },
    });
    assessor = new PortabilityAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should pass with no portability issues", async () => {
      // Arrange
      mockContext.manifestRaw = JSON.stringify(
        createMockManifestJson({
          mcp_config: {
            command: "node",
            args: ["${__dirname}/dist/index.js"],
          },
        }),
      );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.issues.length).toBe(0);
      expect(result.usesDirname).toBe(true);
    });

    it("should fail when ${BUNDLE_ROOT} is used", async () => {
      // Arrange
      mockContext.manifestRaw = JSON.stringify({
        ...createMockManifestJson(),
        mcp_config: {
          command: "node",
          args: ["${BUNDLE_ROOT}/dist/index.js"],
        },
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.usesBundleRoot).toBe(true);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: "bundle_root_antipattern",
          severity: "HIGH",
        }),
      );
    });

    it("should detect hardcoded Unix absolute paths", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/config.ts": `
          const configPath = "/usr/local/etc/myapp/config.json";
          const dataDir = "/var/data/myapp";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hardcodedPathCount).toBeGreaterThan(0);
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: "absolute_path",
          severity: "HIGH",
        }),
      );
    });

    it("should detect hardcoded Windows absolute paths", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/config.ts": `
          const configPath = "C:\\Program Files\\MyApp\\config.json";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: "absolute_path",
          severity: "HIGH",
        }),
      );
    });

    it("should detect user home directory references", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/config.ts": `
          const homeConfig = "~/.myapp/config.json";
          const userPath = "/Users/developer/projects/data";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.issues).toContainEqual(
        expect.objectContaining({
          type: "user_home_path",
          severity: "MEDIUM",
        }),
      );
    });

    it("should detect platform-specific code without fallbacks", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/platform.ts": `
          if (process.platform === "darwin") {
            // macOS specific code
            console.log("Running on macOS");
          }
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.platformSpecificCount).toBeGreaterThan(0);
    });

    it("should not flag platform code with fallbacks", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/platform.ts": `
          if (process.platform === "darwin") {
            console.log("macOS");
          } else {
            console.log("Other platform");
          }
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should not flag as issue because there's an else clause
      const platformIssues = result.issues.filter(
        (i) => i.type === "platform_specific",
      );
      expect(platformIssues.length).toBe(0);
    });

    it("should skip test files", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.test.ts": `
          const testPath = "/usr/local/test/data";
        `,
        "src/__tests__/config.test.ts": `
          const configPath = "/var/test/config";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - test files should be skipped
      expect(result.issues.length).toBe(0);
    });

    it("should skip node_modules paths", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "node_modules/some-package/index.js": `
          const path = "/usr/local/lib";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.issues.length).toBe(0);
    });

    it("should not flag URLs as hardcoded paths", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/api.ts": `
          const apiUrl = "https://api.example.com/users";
          const docsUrl = "http://docs.example.com/guide";
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - URLs should not be flagged
      expect(result.issues.length).toBe(0);
    });

    it("should not flag comments with paths", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/config.ts": `
          // Configuration file located at /etc/myapp/config
          // Users should copy to /home/user/.config/myapp
          const config = loadConfig();
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - comments should be ignored
      expect(result.issues.length).toBe(0);
    });

    it("should check package.json scripts for hardcoded paths", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "test",
        version: "1.0.0",
        scripts: {
          start: "node /usr/local/bin/server.js",
          build: "tsc && cp -r /var/data ./dist",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.issues.length).toBeGreaterThan(0);
    });

    it("should generate recommendations for BUNDLE_ROOT usage", async () => {
      // Arrange
      mockContext.manifestRaw = JSON.stringify({
        ...createMockManifestJson(),
        mcp_config: {
          command: "node",
          args: ["${BUNDLE_ROOT}/index.js"],
        },
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("${__dirname}"),
      );
    });

    it("should report correct count of scanned files", async () => {
      // Arrange
      mockContext.manifestRaw = JSON.stringify(createMockManifestJson());
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": "const x = 1;",
        "src/utils.ts": "const y = 2;",
        "src/config.ts": "const z = 3;",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.scannedFiles).toBeGreaterThanOrEqual(3);
    });

    it("should detect ${__dirname} as correct usage", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/paths.ts": `
          const dataPath = \`\${__dirname}/data\`;
          const configPath = path.join(__dirname, 'config.json');
        `,
      });
      mockContext.manifestRaw = JSON.stringify(
        createMockManifestJson({
          mcp_config: {
            command: "node",
            args: ["${__dirname}/dist/index.js"],
          },
        }),
      );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usesDirname).toBe(true);
    });
  });
});
