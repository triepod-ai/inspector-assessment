import { SupplyChainAssessor } from "./SupplyChainAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("SupplyChainAssessor", () => {
  let assessor: SupplyChainAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new SupplyChainAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess supply chain with clean dependencies", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "test-package",
        version: "1.0.0",
        dependencies: {
          express: "^4.18.0",
          lodash: "^4.17.21",
          uuid: "^9.0.0",
        },
        devDependencies: {
          jest: "^29.0.0",
          typescript: "^5.0.0",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.category).toBe("supplyChain");
      expect(result.totalDependencies).toBe(5);
      expect(result.vulnerableDependencies).toBe(0);
      expect(result.status).toBe("PASS");
      expect(result.score).toBeGreaterThan(80);
    });

    it("should detect vulnerable dependencies", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "vulnerable-package",
        version: "1.0.0",
        dependencies: {
          "vulnerable-pkg": "1.0.0", // Simulated vulnerable package
          "outdated-pkg": "0.1.0", // Simulated outdated package
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.vulnerableDependencies).toBeGreaterThan(0);
      expect(result.criticalFindings).toContain(
        "Vulnerable dependencies detected",
      );
      expect(result.status).toBe("FAIL");
      expect(result.score).toBeLessThan(60);
    });

    it("should assess license compliance", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "license-test",
        version: "1.0.0",
        dependencies: {
          "mit-licensed": "1.0.0",
          "apache-licensed": "2.0.0",
          "gpl-licensed": "3.0.0", // Potentially problematic
          "unknown-license": "1.0.0",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.licenseCompliance.compliant).toBeGreaterThan(0);
      expect(result.licenseCompliance.nonCompliant).toBeGreaterThan(0);
      expect(result.licenseCompliance.unknown).toBeGreaterThan(0);
      expect(result.criticalFindings).toContain("License compliance issues");
    });

    it("should detect typosquatting risks", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "typo-test",
        version: "1.0.0",
        dependencies: {
          expres: "1.0.0", // Typosquatting attempt of 'express'
          loadsh: "1.0.0", // Typosquatting attempt of 'lodash'
          reactt: "1.0.0", // Typosquatting attempt of 'react'
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.typosquattingRisks.length).toBeGreaterThan(0);
      expect(result.typosquattingRisks).toContain(
        "expres (similar to express)",
      );
      expect(result.typosquattingRisks).toContain("loadsh (similar to lodash)");
      expect(result.criticalFindings).toContain(
        "Potential typosquatting detected",
      );
      expect(result.status).toBe("FAIL");
    });

    it("should verify package integrity", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "integrity-test",
        version: "1.0.0",
        dependencies: {
          "secure-pkg": "1.0.0",
          "insecure-pkg": "1.0.0",
          "unknown-pkg": "1.0.0",
        },
      };

      // Mock integrity check results
      mockContext.packageLock = {
        dependencies: {
          "secure-pkg": {
            version: "1.0.0",
            integrity: "sha512-valid-hash...",
          },
          "insecure-pkg": {
            version: "1.0.0",
            // Missing integrity hash
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.integrityChecks.passed).toBeGreaterThan(0);
      expect(result.integrityChecks.failed).toBeGreaterThan(0);
      expect(result.criticalFindings).toContain("Package integrity failures");
    });

    it("should generate SBOM (Software Bill of Materials)", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "sbom-test",
        version: "1.0.0",
        dependencies: {
          dep1: "1.0.0",
          dep2: "2.0.0",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.sbomGenerated).toBe(true);
      expect(result.recommendations).toContain("SBOM generated successfully");
    });

    it("should handle missing package.json", async () => {
      // Arrange
      mockContext.packageJson = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.totalDependencies).toBe(0);
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.criticalFindings).toContain("No package.json found");
      expect(result.score).toBe(0);
    });

    it("should assess transitive dependencies", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "transitive-test",
        version: "1.0.0",
        dependencies: {
          "main-dep": "1.0.0",
        },
      };

      mockContext.packageLock = {
        dependencies: {
          "main-dep": {
            version: "1.0.0",
            dependencies: {
              "transitive-dep1": "1.0.0",
              "transitive-dep2": "2.0.0",
            },
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.totalDependencies).toBe(3); // 1 direct + 2 transitive
      expect(result.explanation).toContain("transitive dependencies");
    });

    it("should detect dependency confusion risks", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "confusion-test",
        version: "1.0.0",
        dependencies: {
          "@internal/package": "1.0.0", // Private package that might exist publicly
          "common-name": "1.0.0", // Very generic name
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain("Dependency confusion risks");
      expect(result.recommendations).toContain("Review package naming");
    });

    it("should assess supply chain attack vectors", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "attack-vector-test",
        version: "1.0.0",
        dependencies: {
          "suspicious-pkg": "1.0.0",
        },
      };

      // Mock suspicious package characteristics
      const mockSuspiciousPackage = {
        name: "suspicious-pkg",
        recentlyPublished: true,
        fewDownloads: true,
        obfuscatedCode: true,
        networkActivity: true,
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain("Supply chain attack vectors");
      expect(result.status).toBe("FAIL");
      expect(result.recommendations).toContain("Review suspicious packages");
    });

    it("should calculate comprehensive security score", async () => {
      // Arrange - mixed security profile
      mockContext.packageJson = {
        name: "mixed-security",
        version: "1.0.0",
        dependencies: {
          "secure-pkg": "1.0.0", // Good
          "vulnerable-pkg": "1.0.0", // Bad - has vulnerabilities
          "outdated-pkg": "0.1.0", // Bad - very outdated
          "unknown-pkg": "1.0.0", // Neutral - unknown license
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should be mixed score
      expect(result.score).toBeGreaterThan(30);
      expect(result.score).toBeLessThan(70);
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.vulnerableDependencies).toBe(2); // vulnerable + outdated
    });

    it("should provide actionable recommendations", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "recommendations-test",
        version: "1.0.0",
        dependencies: {
          "vulnerable-pkg": "1.0.0",
          "outdated-pkg": "0.1.0",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContain(
        "Update vulnerable dependencies",
      );
      expect(result.recommendations).toContain("Implement dependency scanning");
      expect(result.recommendations).toContain("Use lock files");
      expect(result.recommendations).toContain("Regular security audits");
      expect(result.recommendations.length).toBeGreaterThan(3);
    });

    it("should handle large dependency trees efficiently", async () => {
      // Arrange - simulate large dependency tree
      const largeDependencies: Record<string, string> = {};
      for (let i = 0; i < 100; i++) {
        largeDependencies[`dep-${i}`] = "1.0.0";
      }

      mockContext.packageJson = {
        name: "large-deps-test",
        version: "1.0.0",
        dependencies: largeDependencies,
      };

      const startTime = Date.now();

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const executionTime = Date.now() - startTime;
      expect(executionTime).toBeLessThan(5000); // Should complete within 5 seconds
      expect(result.totalDependencies).toBe(100);
      expect(result.explanation).toContain("100 dependencies analyzed");
    });
  });

  describe("edge cases", () => {
    it("should handle malformed package.json", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "malformed-test",
        // Missing version, malformed structure
      } as any;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.criticalFindings).toContain("Malformed package.json");
    });

    it("should handle circular dependencies", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "circular-test",
        version: "1.0.0",
        dependencies: {
          "pkg-a": "1.0.0",
        },
      };

      mockContext.packageLock = {
        dependencies: {
          "pkg-a": {
            version: "1.0.0",
            dependencies: {
              "pkg-b": "1.0.0",
            },
          },
          "pkg-b": {
            version: "1.0.0",
            dependencies: {
              "pkg-a": "1.0.0", // Circular reference
            },
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain(
        "Circular dependencies detected",
      );
    });

    it("should handle network timeouts gracefully", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "timeout-test",
        version: "1.0.0",
        dependencies: {
          "slow-pkg": "1.0.0",
        },
      };

      // Mock network timeout scenario
      jest
        .spyOn(global, "fetch")
        .mockImplementation(
          () =>
            new Promise((resolve) =>
              setTimeout(
                () =>
                  resolve(new Response(JSON.stringify({}), { status: 408 })),
                10000,
              ),
            ),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.criticalFindings).toContain(
        "Network timeout during assessment",
      );
    });
  });
});
