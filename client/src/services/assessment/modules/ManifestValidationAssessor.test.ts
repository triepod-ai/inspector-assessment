import { ManifestValidationAssessor } from "./ManifestValidationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockManifestJson,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ManifestValidationAssessor", () => {
  let assessor: ManifestValidationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        manifestValidation: true,
      },
    });
    assessor = new ManifestValidationAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should pass with valid manifest.json", async () => {
      // Arrange - include icon for complete manifest
      mockContext.manifestJson = createMockManifestJson({
        icon: "icon.png",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.hasManifest).toBe(true);
      expect(result.hasRequiredFields).toBe(true);
      expect(result.manifestVersion).toBe("0.3");
    });

    it("should fail when manifest.json is missing", async () => {
      // Arrange - no manifest provided

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.hasManifest).toBe(false);
      expect(result.explanation).toContain("No manifest.json found");
    });

    it("should fail with invalid JSON in manifestRaw", async () => {
      // Arrange
      mockContext.manifestRaw = "{ invalid json }";

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "manifest.json",
          valid: false,
          severity: "ERROR",
        }),
      );
    });

    it("should fail when manifest_version is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        manifest_version: undefined as any,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "manifest_version",
          valid: false,
          severity: "ERROR",
        }),
      );
    });

    it("should warn when manifest_version is not 0.3", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        manifest_version: "0.2",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "manifest_version",
          valid: false,
          issue: expect.stringContaining("0.3"),
        }),
      );
    });

    it("should fail when name is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        name: undefined as any,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasRequiredFields).toBe(false);
      expect(result.missingFields).toContain("name");
    });

    it("should fail when version is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        version: undefined as any,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasRequiredFields).toBe(false);
      expect(result.missingFields).toContain("version");
    });

    it("should fail when mcp_config is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        mcp_config: undefined as any,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasRequiredFields).toBe(false);
      expect(result.missingFields).toContain("mcp_config");
    });

    it("should warn when description is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        description: undefined,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "description",
          severity: "WARNING",
        }),
      );
    });

    it("should fail when mcp_config.command is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        mcp_config: { args: ["index.js"] } as any,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "mcp_config.command",
          valid: false,
          severity: "ERROR",
        }),
      );
    });

    it("should fail when mcp_config uses ${BUNDLE_ROOT}", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        mcp_config: {
          command: "node",
          args: ["${BUNDLE_ROOT}/dist/index.js"],
        },
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "mcp_config",
          valid: false,
          issue: expect.stringContaining("BUNDLE_ROOT"),
        }),
      );
    });

    it("should fail when command uses hardcoded absolute path", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        mcp_config: {
          command: "/usr/local/bin/node",
          args: ["index.js"],
        },
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "mcp_config.command",
          valid: false,
          issue: expect.stringContaining("hardcoded"),
        }),
      );
    });

    it("should pass icon check when icon field is present", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        icon: "icon.png",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasIcon).toBe(true);
    });

    it("should warn when icon is missing", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson();

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasIcon).toBe(false);
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "icon",
          severity: "WARNING",
        }),
      );
    });

    it("should warn when name format is invalid", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        name: "My MCP Server!", // Invalid: contains space and special char
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "name (format)",
          severity: "WARNING",
        }),
      );
    });

    it("should warn when version is not semver format", async () => {
      // Arrange
      mockContext.manifestJson = createMockManifestJson({
        version: "v1", // Invalid semver
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "version (format)",
          severity: "WARNING",
        }),
      );
    });

    it("should accept valid semver versions", async () => {
      const validVersions = [
        "1.0.0",
        "0.1.0",
        "2.3.4-beta.1",
        "1.0.0+build.123",
      ];

      for (const version of validVersions) {
        mockContext.manifestJson = createMockManifestJson({ version });
        const result = await assessor.assess(mockContext);

        expect(result.validationResults).toContainEqual(
          expect.objectContaining({
            field: "version (format)",
            valid: true,
          }),
        );
      }
    });

    it("should parse manifestRaw when manifestJson not provided", async () => {
      // Arrange - include icon for complete manifest
      mockContext.manifestRaw = JSON.stringify(
        createMockManifestJson({
          icon: "icon.png",
        }),
      );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.hasManifest).toBe(true);
    });
  });

  describe("mcp_config nested path support (Issue #138)", () => {
    it("should accept mcp_config at root level (legacy format)", async () => {
      // Arrange - root-level mcp_config (existing behavior)
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "test-server",
        version: "1.0.0",
        mcp_config: {
          command: "node",
          args: ["index.js"],
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.hasRequiredFields).toBe(true);
      expect(result.missingFields).not.toContain("mcp_config");
    });

    it("should accept mcp_config nested under server object (v0.3 format)", async () => {
      // Arrange - nested mcp_config under server (Issue #138)
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "clarity-mcp-server",
        version: "2.0.0",
        server: {
          type: "node",
          entry_point: "dist/index.js",
          mcp_config: {
            command: "node",
            args: ["${__dirname}/dist/index.js"],
            env: { CLARITY_API_TOKEN: "${user_config.api_token}" },
          },
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.hasRequiredFields).toBe(true);
      expect(result.missingFields).not.toContain("mcp_config");

      // Verify mcp_config validation passed
      const mcpConfigResult = result.validationResults.find(
        (r) => r.field === "mcp_config" && r.severity === "INFO",
      );
      expect(mcpConfigResult).toBeDefined();
      expect(mcpConfigResult?.valid).toBe(true);
    });

    it("should prefer root-level mcp_config when both are present", async () => {
      // Arrange - both root and nested mcp_config
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "test-server",
        version: "1.0.0",
        mcp_config: {
          command: "node",
          args: ["root-index.js"],
        },
        server: {
          type: "node",
          mcp_config: {
            command: "python",
            args: ["nested-index.py"],
          },
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.hasRequiredFields).toBe(true);

      // Verify root mcp_config was used (node, not python)
      const mcpConfigResult = result.validationResults.find(
        (r) => r.field === "mcp_config" && r.severity === "INFO",
      );
      expect(mcpConfigResult).toBeDefined();
      expect((mcpConfigResult?.value as { command: string })?.command).toBe(
        "node",
      );
    });

    it("should fail when mcp_config missing from both root and server.mcp_config", async () => {
      // Arrange - no mcp_config anywhere
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "test-server",
        version: "1.0.0",
        server: {
          type: "node",
          entry_point: "dist/index.js",
          // Note: no mcp_config here
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.hasRequiredFields).toBe(false);
      expect(result.missingFields).toContain("mcp_config");

      // Verify error message mentions both paths checked
      const mcpConfigError = result.validationResults.find(
        (r) => r.field === "mcp_config" && r.valid === false,
      );
      expect(mcpConfigError).toBeDefined();
      expect(mcpConfigError?.issue).toContain("root");
      expect(mcpConfigError?.issue).toContain("server.mcp_config");
    });

    it("should validate nested mcp_config structure correctly", async () => {
      // Arrange - nested mcp_config with ${BUNDLE_ROOT} anti-pattern
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "test-server",
        version: "1.0.0",
        server: {
          type: "node",
          mcp_config: {
            command: "node",
            args: ["${BUNDLE_ROOT}/dist/index.js"], // Anti-pattern
          },
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should detect BUNDLE_ROOT anti-pattern even in nested config
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "mcp_config",
          valid: false,
          issue: expect.stringContaining("BUNDLE_ROOT"),
        }),
      );
    });

    it("should validate nested mcp_config.command is required", async () => {
      // Arrange - nested mcp_config missing command
      mockContext.manifestJson = {
        manifest_version: "0.3",
        name: "test-server",
        version: "1.0.0",
        server: {
          type: "node",
          mcp_config: {
            args: ["index.js"],
            // Note: no command
          } as any,
        },
        icon: "icon.png",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.validationResults).toContainEqual(
        expect.objectContaining({
          field: "mcp_config.command",
          valid: false,
          severity: "ERROR",
        }),
      );
    });
  });

  describe("tool name validation (Issue #140)", () => {
    it("should pass when manifest tools match server tools", async () => {
      mockContext.manifestJson = createMockManifestJson({
        tools: [{ name: "tool_a" }, { name: "tool_b" }],
        icon: "icon.png",
      });
      mockContext.tools = [
        { name: "tool_a", inputSchema: { type: "object" } },
        { name: "tool_b", inputSchema: { type: "object" } },
      ];

      const result = await assessor.assess(mockContext);

      const toolResult = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)",
      );
      expect(toolResult?.valid).toBe(true);
      expect(toolResult?.severity).toBe("INFO");
    });

    it("should warn when manifest declares tools not on server", async () => {
      mockContext.manifestJson = createMockManifestJson({
        tools: [{ name: "missing_tool" }],
        icon: "icon.png",
      });
      mockContext.tools = [
        { name: "other_tool", inputSchema: { type: "object" } },
      ];

      const result = await assessor.assess(mockContext);

      const toolResult = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)",
      );
      expect(toolResult?.valid).toBe(false);
      expect(toolResult?.severity).toBe("WARNING");
      expect(toolResult?.issue).toContain("Manifest declares tools not found");
    });

    it("should report undeclared server tools as INFO", async () => {
      mockContext.manifestJson = createMockManifestJson({
        tools: [{ name: "tool_a" }],
        icon: "icon.png",
      });
      mockContext.tools = [
        { name: "tool_a", inputSchema: { type: "object" } },
        { name: "tool_b", inputSchema: { type: "object" } },
      ];

      const result = await assessor.assess(mockContext);

      const undeclaredResult = result.validationResults.find(
        (r) => r.field === "tools (undeclared)",
      );
      expect(undeclaredResult?.valid).toBe(false);
      expect(undeclaredResult?.severity).toBe("INFO");
      expect(undeclaredResult?.issue).toContain(
        "Server has tools not declared",
      );
    });

    it("should skip validation when manifest has no tools field", async () => {
      mockContext.manifestJson = createMockManifestJson({
        icon: "icon.png",
      });
      mockContext.tools = [
        { name: "some_tool", inputSchema: { type: "object" } },
      ];

      const result = await assessor.assess(mockContext);

      const toolResult = result.validationResults.find((r) =>
        r.field.includes("tools"),
      );
      expect(toolResult).toBeUndefined();
    });

    it("should suggest closest match for mismatched tool names", async () => {
      mockContext.manifestJson = createMockManifestJson({
        tools: [{ name: "query-documentation-data" }],
        icon: "icon.png",
      });
      mockContext.tools = [
        {
          name: "query-documentation-resources",
          inputSchema: { type: "object" },
        },
      ];

      const result = await assessor.assess(mockContext);

      const toolResult = result.validationResults.find(
        (r) => r.field === "tools (manifest vs server)",
      );
      expect(toolResult?.issue).toContain("did you mean");
      expect(toolResult?.issue).toContain("query-documentation-resources");
    });

    it("should skip validation when server has no tools", async () => {
      mockContext.manifestJson = createMockManifestJson({
        tools: [{ name: "tool_a" }],
        icon: "icon.png",
      });
      mockContext.tools = [];

      const result = await assessor.assess(mockContext);

      const toolResult = result.validationResults.find((r) =>
        r.field.includes("tools"),
      );
      expect(toolResult).toBeUndefined();
    });
  });
});
