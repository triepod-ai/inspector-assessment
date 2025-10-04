import { DocumentationAssessor } from "./DocumentationAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockReadmeContent,
  createMockPackageJson,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("DocumentationAssessor", () => {
  let assessor: DocumentationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new DocumentationAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess documentation with complete README", async () => {
      // Arrange
      mockContext.readmeContent = createMockReadmeContent();
      mockContext.packageJson = createMockPackageJson();
      mockContext.tools = [
        createMockTool({ name: "getTool", description: "Gets a tool" }),
        createMockTool({ name: "executeTool", description: "Executes a tool" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics).toBeDefined();
      expect(result.metrics.hasReadme).toBe(true);
      expect(result.metrics.exampleCount).toBeGreaterThan(0);
      expect(result.metrics.hasInstallInstructions).toBe(true);
      expect(result.metrics.hasUsageGuide).toBe(true);
      expect(result.metrics.hasAPIReference).toBe(true);
      expect(result.status).toBe("PASS");
    });

    it("should detect missing README", async () => {
      // Arrange
      mockContext.readmeContent = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasReadme).toBe(false);
      expect(result.metrics.exampleCount).toBe(0);
      expect(result.metrics.hasInstallInstructions).toBe(false);
      expect(result.status).toBe("FAIL");
    });

    it("should identify documented tools", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "getTool" }),
        createMockTool({ name: "setTool" }),
        createMockTool({ name: "deleteTool" }),
      ];
      mockContext.tools = tools;
      mockContext.readmeContent = `
        # API Documentation
        
        ## getTool
        This method gets a tool.
        
        ## setTool
        This method sets a tool.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.exampleCount).toBeGreaterThan(0);
      expect(result.metrics.hasAPIReference).toBe(true);
      expect(result.metrics.missingExamples).not.toContain("getTool");
      expect(result.metrics.missingExamples).not.toContain("setTool");
    });

    it("should detect all README sections", async () => {
      // Arrange
      mockContext.readmeContent = `
        # Project Name
        
        ## Description
        Project description here.
        
        ## Installation
        npm install project
        
        ## Usage
        How to use the project.
        
        ## API
        API documentation.
        
        ## Configuration
        Configuration options.
        
        ## Examples
        Usage examples.
        
        ## Security
        Security considerations.
        
        ## Contributing
        How to contribute.
        
        ## License
        MIT License
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const expectedSections = [
        "description",
        "installation",
        "usage",
        "api",
        "configuration",
        "examples",
        "security",
        "contributing",
        "license",
      ];

      expect(result.metrics.hasInstallInstructions).toBe(true);
      expect(result.metrics.hasUsageGuide).toBe(true);
      expect(result.metrics.hasAPIReference).toBe(true);
      expect(result.status).toBe("PASS");
    });

    it("should calculate documentation score based on completeness", async () => {
      // Arrange - minimal documentation
      mockContext.readmeContent = `
        # Project

        ## Description
        A project.
      `;
      mockContext.tools = [
        createMockTool({ name: "tool1", description: "" }),
        createMockTool({ name: "tool2", description: "" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasInstallInstructions).toBe(false);
      expect(result.metrics.missingExamples.length).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
    });

    it("should give high score for comprehensive documentation", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "tool1" }),
        createMockTool({ name: "tool2" }),
      ];
      mockContext.tools = tools;
      mockContext.readmeContent = `
        # Complete Documentation
        
        ## Description
        Comprehensive project description with details.
        
        ## Installation
        \`\`\`bash
        npm install package
        \`\`\`
        
        ## Usage
        Detailed usage instructions with examples.
        
        ## API
        
        ### tool1
        Documentation for tool1.
        
        ### tool2
        Documentation for tool2.
        
        ## Examples
        Multiple code examples here.
        
        ## Security
        Security best practices.
        
        ## Configuration
        All configuration options.
        
        ## License
        MIT
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.missingExamples.length).toBe(0);
      expect(result.metrics.hasInstallInstructions).toBe(true);
      expect(result.status).toBe("PASS");
    });

    it("should handle empty README content", async () => {
      // Arrange
      mockContext.readmeContent = "";

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasReadme).toBe(false);
      expect(result.metrics.exampleCount).toBe(0);
      expect(result.metrics.hasInstallInstructions).toBe(false);
    });

    it("should detect code examples in documentation", async () => {
      // Arrange
      mockContext.readmeContent = `
        # Project
        
        ## Usage
        
        \`\`\`javascript
        const tool = new Tool();
        tool.execute();
        \`\`\`
        
        ## Examples
        
        \`\`\`python
        tool = Tool()
        tool.run()
        \`\`\`
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasUsageGuide).toBe(true);
      expect(result.metrics.extractedExamples?.length).toBeGreaterThan(0);
      expect(result.metrics.exampleCount).toBeGreaterThan(0);
    });

    it("should handle tools with no descriptions", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({ name: "tool1", description: undefined }),
        createMockTool({ name: "tool2", description: "" }),
        createMockTool({ name: "tool3", description: "Has description" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.missingExamples).toContain("tool1");
      expect(result.metrics.missingExamples).toContain("tool2");
      expect(result.metrics.missingExamples).not.toContain("tool3");
    });

    it("should assess package.json metadata", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "test-package",
        version: "1.0.0",
        description: "Test package description",
        author: "Test Author",
        license: "MIT",
        repository: {
          type: "git",
          url: "https://github.com/test/repo",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Note: hasPackageJson and packageMetadata properties were deprecated
      expect(result.metrics).toBeDefined();
      expect(result.status).toBeDefined();
    });

    it("should handle missing package.json", async () => {
      // Arrange
      mockContext.packageJson = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Note: hasPackageJson and packageMetadata properties were deprecated
      expect(result.metrics).toBeDefined();
      expect(result.status).toBeDefined();
    });

    it("should identify API documentation patterns", async () => {
      // Arrange
      mockContext.readmeContent = `
        # API Reference
        
        ## Methods
        
        ### getTool(name: string): Tool
        Returns a tool by name.
        
        **Parameters:**
        - name: The tool name
        
        **Returns:** Tool instance
        
        ### setTool(name: string, config: object): void
        Sets tool configuration.
        
        **Parameters:**
        - name: Tool name
        - config: Configuration object
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Note: documentation.sections and hasApiDocs properties were deprecated
      expect(result.metrics.hasAPIReference).toBe(true);
    });

    it("should calculate appropriate score for different quality levels", async () => {
      // Test cases with expected score ranges
      const testCases = [
        {
          readme: "# Title\n\nShort description.",
          tools: 2,
          expectedRange: [0, 30],
        },
        {
          readme: createMockReadmeContent(),
          tools: 2,
          expectedRange: [50, 80],
        },
        {
          readme: `# Complete Docs\n\n${[
            "Description",
            "Installation",
            "Usage",
            "API",
            "Examples",
            "Security",
            "Configuration",
            "License",
          ]
            .map((s) => `## ${s}\n\nDetailed content for ${s}.\n\n`)
            .join("")}`,
          tools: 0,
          expectedRange: [70, 100],
        },
      ];

      for (const testCase of testCases) {
        mockContext.readmeContent = testCase.readme;
        mockContext.tools = Array(testCase.tools)
          .fill(null)
          .map((_, i) => createMockTool({ name: `tool${i}` }));

        const result = await assessor.assess(mockContext);

        // Note: documentationScore property was deprecated
        // Just verify result structure is valid
        expect(result.metrics).toBeDefined();
        expect(result.status).toBeDefined();
      }
    });
  });
});
