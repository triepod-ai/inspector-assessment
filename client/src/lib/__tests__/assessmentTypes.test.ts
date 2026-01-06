import {
  AssessmentCategoryTier,
  AssessmentCategoryMetadata,
  AssessmentModuleName,
  ASSESSMENT_CATEGORY_METADATA,
  getAllModulesConfig,
} from "../assessmentTypes";

describe("Assessment Types", () => {
  describe("AssessmentCategoryTier type", () => {
    it("should accept 'core' as a valid tier", () => {
      const tier: AssessmentCategoryTier = "core";
      expect(tier).toBe("core");
    });

    it("should accept 'optional' as a valid tier", () => {
      const tier: AssessmentCategoryTier = "optional";
      expect(tier).toBe("optional");
    });
  });

  describe("AssessmentCategoryMetadata interface", () => {
    it("should allow metadata with required fields only", () => {
      const metadata: AssessmentCategoryMetadata = {
        tier: "core",
        description: "Test description",
      };
      expect(metadata.tier).toBe("core");
      expect(metadata.description).toBe("Test description");
      expect(metadata.applicableTo).toBeUndefined();
    });

    it("should allow metadata with optional applicableTo field", () => {
      const metadata: AssessmentCategoryMetadata = {
        tier: "optional",
        description: "Test description",
        applicableTo: "MCPB bundles",
      };
      expect(metadata.tier).toBe("optional");
      expect(metadata.description).toBe("Test description");
      expect(metadata.applicableTo).toBe("MCPB bundles");
    });
  });

  describe("ASSESSMENT_CATEGORY_METADATA constant", () => {
    describe("category count", () => {
      it("should have exactly 18 assessment categories", () => {
        const categoryKeys = Object.keys(ASSESSMENT_CATEGORY_METADATA);
        expect(categoryKeys).toHaveLength(18);
      });
    });

    describe("tier classification", () => {
      it("should mark manifestValidation as optional tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.manifestValidation.tier).toBe(
          "optional",
        );
      });

      it("should mark portability as optional tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.portability.tier).toBe("optional");
      });

      it("should mark functionality as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.functionality.tier).toBe("core");
      });

      it("should mark security as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.security.tier).toBe("core");
      });

      it("should mark documentation as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.documentation.tier).toBe("core");
      });

      it("should mark errorHandling as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.errorHandling.tier).toBe("core");
      });

      it("should mark usability as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.usability.tier).toBe("core");
      });

      it("should mark mcpSpecCompliance as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.mcpSpecCompliance.tier).toBe(
          "core",
        );
      });

      it("should mark aupCompliance as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.aupCompliance.tier).toBe("core");
      });

      it("should mark toolAnnotations as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.toolAnnotations.tier).toBe("core");
      });

      it("should mark prohibitedLibraries as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.prohibitedLibraries.tier).toBe(
          "core",
        );
      });

      it("should mark externalAPIScanner as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.externalAPIScanner.tier).toBe(
          "core",
        );
      });

      it("should mark authentication as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.authentication.tier).toBe("core");
      });

      it("should mark temporal as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.temporal.tier).toBe("core");
      });

      it("should mark resources as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.resources.tier).toBe("core");
      });

      it("should mark prompts as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.prompts.tier).toBe("core");
      });

      it("should mark crossCapability as core tier", () => {
        expect(ASSESSMENT_CATEGORY_METADATA.crossCapability.tier).toBe("core");
      });

      it("should have exactly 2 optional tier categories", () => {
        const optionalCategories = Object.values(
          ASSESSMENT_CATEGORY_METADATA,
        ).filter((metadata) => metadata.tier === "optional");
        expect(optionalCategories).toHaveLength(2);
      });

      it("should have exactly 16 core tier categories", () => {
        const coreCategories = Object.values(
          ASSESSMENT_CATEGORY_METADATA,
        ).filter((metadata) => metadata.tier === "core");
        expect(coreCategories).toHaveLength(16);
      });
    });

    describe("required fields", () => {
      it("should have tier field for all categories", () => {
        Object.entries(ASSESSMENT_CATEGORY_METADATA).forEach(
          ([_categoryName, metadata]) => {
            expect(metadata.tier).toBeDefined();
            expect(["core", "optional"]).toContain(metadata.tier);
          },
        );
      });

      it("should have description field for all categories", () => {
        Object.entries(ASSESSMENT_CATEGORY_METADATA).forEach(
          ([_categoryName, metadata]) => {
            expect(metadata.description).toBeDefined();
            expect(typeof metadata.description).toBe("string");
            expect(metadata.description.length).toBeGreaterThan(0);
          },
        );
      });
    });

    describe("applicableTo field", () => {
      it("should have applicableTo field for all optional tier categories", () => {
        const optionalCategories = Object.entries(
          ASSESSMENT_CATEGORY_METADATA,
        ).filter(([_, metadata]) => metadata.tier === "optional");

        optionalCategories.forEach(([_categoryName, metadata]) => {
          expect(metadata.applicableTo).toBeDefined();
          expect(typeof metadata.applicableTo).toBe("string");
          expect(metadata.applicableTo?.length).toBeGreaterThan(0);
        });
      });

      it("should not require applicableTo field for core tier categories", () => {
        const coreCategories = Object.entries(
          ASSESSMENT_CATEGORY_METADATA,
        ).filter(([_, metadata]) => metadata.tier === "core");

        coreCategories.forEach(([_categoryName, metadata]) => {
          // applicableTo is optional for core categories - may or may not be present
          if (metadata.applicableTo !== undefined) {
            expect(typeof metadata.applicableTo).toBe("string");
          }
        });
      });

      it("should have consistent applicableTo value for optional categories", () => {
        expect(
          ASSESSMENT_CATEGORY_METADATA.manifestValidation.applicableTo,
        ).toBe("MCPB bundles");
        expect(ASSESSMENT_CATEGORY_METADATA.portability.applicableTo).toBe(
          "MCPB bundles",
        );
      });
    });

    describe("category keys", () => {
      it("should have no duplicate category keys", () => {
        const categoryKeys = Object.keys(ASSESSMENT_CATEGORY_METADATA);
        const uniqueKeys = new Set(categoryKeys);
        expect(uniqueKeys.size).toBe(categoryKeys.length);
      });

      it("should contain all expected core category keys", () => {
        const expectedCoreKeys = [
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

        expectedCoreKeys.forEach((key) => {
          expect(ASSESSMENT_CATEGORY_METADATA).toHaveProperty(key);
        });
      });

      it("should contain all expected optional category keys", () => {
        const expectedOptionalKeys = ["manifestValidation", "portability"];

        expectedOptionalKeys.forEach((key) => {
          expect(ASSESSMENT_CATEGORY_METADATA).toHaveProperty(key);
        });
      });
    });

    describe("description quality", () => {
      it("should have meaningful descriptions for all categories", () => {
        Object.entries(ASSESSMENT_CATEGORY_METADATA).forEach(
          ([categoryName, metadata]) => {
            // Descriptions should be at least 10 characters (not just placeholder text)
            expect(metadata.description.length).toBeGreaterThan(10);
            // Descriptions should not be just the category name
            expect(metadata.description.toLowerCase()).not.toBe(
              categoryName.toLowerCase(),
            );
          },
        );
      });

      it("should have descriptions that match category purpose", () => {
        expect(
          ASSESSMENT_CATEGORY_METADATA.functionality.description,
        ).toContain("functionality");
        expect(ASSESSMENT_CATEGORY_METADATA.security.description).toContain(
          "Security",
        );
        expect(
          ASSESSMENT_CATEGORY_METADATA.documentation.description,
        ).toContain("Documentation");
        expect(
          ASSESSMENT_CATEGORY_METADATA.errorHandling.description,
        ).toContain("Error handling");
        expect(ASSESSMENT_CATEGORY_METADATA.usability.description).toContain(
          "Usability",
        );
      });
    });

    describe("data structure integrity", () => {
      it("should be a plain object with string keys", () => {
        expect(typeof ASSESSMENT_CATEGORY_METADATA).toBe("object");
        expect(Array.isArray(ASSESSMENT_CATEGORY_METADATA)).toBe(false);

        Object.keys(ASSESSMENT_CATEGORY_METADATA).forEach((key) => {
          expect(typeof key).toBe("string");
        });
      });

      it("should have values that conform to AssessmentCategoryMetadata interface", () => {
        Object.values(ASSESSMENT_CATEGORY_METADATA).forEach((metadata) => {
          expect(metadata).toHaveProperty("tier");
          expect(metadata).toHaveProperty("description");
          expect(["core", "optional"]).toContain(metadata.tier);
          expect(typeof metadata.description).toBe("string");

          if (metadata.applicableTo !== undefined) {
            expect(typeof metadata.applicableTo).toBe("string");
          }
        });
      });
    });
  });

  describe("getAllModulesConfig", () => {
    it("should include all modules from ASSESSMENT_CATEGORY_METADATA", () => {
      const config = getAllModulesConfig({});
      const metadataKeys = Object.keys(ASSESSMENT_CATEGORY_METADATA);
      expect(Object.keys(config)).toEqual(metadataKeys);
    });

    it("should enable all modules by default", () => {
      const config = getAllModulesConfig({});
      // All modules except externalAPIScanner (requires sourceCodePath) and temporal should be true
      Object.entries(config).forEach(([key, value]) => {
        if (key === "externalAPIScanner") {
          expect(value).toBe(false); // No sourceCodePath provided
        } else if (key === "temporal") {
          expect(value).toBe(true); // skipTemporal not set
        } else {
          expect(value).toBe(true);
        }
      });
    });

    it("should disable externalAPIScanner when no sourceCodePath", () => {
      const config = getAllModulesConfig({ sourceCodePath: false });
      expect(config.externalAPIScanner).toBe(false);
    });

    it("should enable externalAPIScanner when sourceCodePath provided", () => {
      const config = getAllModulesConfig({ sourceCodePath: true });
      expect(config.externalAPIScanner).toBe(true);
    });

    it("should enable temporal by default", () => {
      const config = getAllModulesConfig({});
      expect(config.temporal).toBe(true);
    });

    it("should disable temporal when skipTemporal is true", () => {
      const config = getAllModulesConfig({ skipTemporal: true });
      expect(config.temporal).toBe(false);
    });

    it("should handle both options together", () => {
      const config = getAllModulesConfig({
        sourceCodePath: true,
        skipTemporal: true,
      });
      expect(config.externalAPIScanner).toBe(true);
      expect(config.temporal).toBe(false);
      expect(config.security).toBe(true);
    });

    it("should have keys matching AssessmentModuleName type", () => {
      const config = getAllModulesConfig({});
      // Type check: all keys from getAllModulesConfig should be valid AssessmentModuleName
      const configKeys = Object.keys(config) as AssessmentModuleName[];
      configKeys.forEach((key) => {
        // This validates that each key exists in ASSESSMENT_CATEGORY_METADATA
        expect(ASSESSMENT_CATEGORY_METADATA[key]).toBeDefined();
      });
    });

    it("should have type-safe return value", () => {
      const config = getAllModulesConfig({});
      // Compile-time type check: accessing known module names should work
      const securityEnabled: boolean = config.security;
      const functionalityEnabled: boolean = config.functionality;
      const temporalEnabled: boolean = config.temporal;
      expect(typeof securityEnabled).toBe("boolean");
      expect(typeof functionalityEnabled).toBe("boolean");
      expect(typeof temporalEnabled).toBe("boolean");
    });
  });
});
