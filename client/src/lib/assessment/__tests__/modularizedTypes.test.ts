/**
 * Modularized Types Test Suite
 *
 * Validates the type system refactor from Issue #164 where 61 types were
 * extracted from extendedTypes.ts into 6 focused domain modules.
 *
 * Tests:
 * - Module import integrity (no circular dependencies)
 * - Backward compatibility via barrel export (index.ts)
 * - Backward compatibility via extendedTypes.ts shim
 * - Type availability at compile-time
 *
 * Note: TypeScript type exports are compile-time only and not available at
 * runtime, so we cannot verify export counts via Object.keys(). Instead,
 * we verify that modules can be imported successfully and types are available
 * to TypeScript for compilation.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/164
 */

describe("Modularized Types (Issue #164)", () => {
  describe("Module Import Integrity", () => {
    test("aupComplianceTypes imports without errors", async () => {
      await expect(import("../aupComplianceTypes")).resolves.toBeDefined();
    });

    test("toolAnnotationTypes imports without errors", async () => {
      await expect(import("../toolAnnotationTypes")).resolves.toBeDefined();
    });

    test("policyComplianceTypes imports without errors", async () => {
      await expect(import("../policyComplianceTypes")).resolves.toBeDefined();
    });

    test("externalServicesTypes imports without errors", async () => {
      await expect(import("../externalServicesTypes")).resolves.toBeDefined();
    });

    test("temporalSecurityTypes imports without errors", async () => {
      await expect(import("../temporalSecurityTypes")).resolves.toBeDefined();
    });

    test("capabilityAssessmentTypes imports without errors", async () => {
      await expect(
        import("../capabilityAssessmentTypes"),
      ).resolves.toBeDefined();
    });

    test("all modules import in parallel without errors", async () => {
      await expect(
        Promise.all([
          import("../aupComplianceTypes"),
          import("../toolAnnotationTypes"),
          import("../policyComplianceTypes"),
          import("../externalServicesTypes"),
          import("../temporalSecurityTypes"),
          import("../capabilityAssessmentTypes"),
        ]),
      ).resolves.toBeDefined();
    });

    test("all modules import in reverse order without errors", async () => {
      // Test for circular dependency issues
      await expect(
        Promise.all([
          import("../capabilityAssessmentTypes"),
          import("../temporalSecurityTypes"),
          import("../externalServicesTypes"),
          import("../policyComplianceTypes"),
          import("../toolAnnotationTypes"),
          import("../aupComplianceTypes"),
        ]),
      ).resolves.toBeDefined();
    });
  });

  describe("Backward Compatibility - Barrel Export", () => {
    test("index.ts imports without errors", async () => {
      await expect(import("../index")).resolves.toBeDefined();
    });

    test("types from all modules are accessible via index.ts", () => {
      // TypeScript compile-time verification
      // If these types are not accessible, TypeScript compilation will fail

      // aupComplianceTypes (4 types)
      type _AUPCategory = import("../index").AUPCategory;
      type _AUPSeverity = import("../index").AUPSeverity;
      type _AUPViolation = import("../index").AUPViolation;
      type _AUPComplianceAssessment =
        import("../index").AUPComplianceAssessment;

      // toolAnnotationTypes (9 types)
      type _AnnotationSource = import("../index").AnnotationSource;
      type _ToolAnnotationResult = import("../index").ToolAnnotationResult;
      type _ToolAnnotationAssessment =
        import("../index").ToolAnnotationAssessment;
      type _DatabaseBackend = import("../index").DatabaseBackend;
      type _TransportMode = import("../index").TransportMode;
      type _ServerArchitectureType = import("../index").ServerArchitectureType;
      type _ArchitectureAnalysis = import("../index").ArchitectureAnalysis;
      type _InferenceSignal = import("../index").InferenceSignal;
      type _EnhancedBehaviorInferenceResult =
        import("../index").EnhancedBehaviorInferenceResult;

      // policyComplianceTypes (16 types)
      type _ProhibitedLibraryCategory =
        import("../index").ProhibitedLibraryCategory;
      type _DependencyUsageStatus = import("../index").DependencyUsageStatus;
      type _ProhibitedLibraryMatch = import("../index").ProhibitedLibraryMatch;
      type _ProhibitedLibrariesAssessment =
        import("../index").ProhibitedLibrariesAssessment;
      type _McpConfigSchema = import("../index").McpConfigSchema;
      type _ManifestServerSchema = import("../index").ManifestServerSchema;
      type _ManifestToolDeclaration =
        import("../index").ManifestToolDeclaration;
      type _ManifestAuthorObject = import("../index").ManifestAuthorObject;
      type _ManifestJsonSchema = import("../index").ManifestJsonSchema;
      type _PrivacyPolicyValidation =
        import("../index").PrivacyPolicyValidation;
      type _ManifestValidationResult =
        import("../index").ManifestValidationResult;
      type _ExtractedContactInfo = import("../index").ExtractedContactInfo;
      type _ExtractedVersionInfo = import("../index").ExtractedVersionInfo;
      type _ManifestValidationAssessment =
        import("../index").ManifestValidationAssessment;
      type _PortabilityIssue = import("../index").PortabilityIssue;
      type _PortabilityAssessment = import("../index").PortabilityAssessment;

      // externalServicesTypes (11 types)
      type _ExternalServiceType = import("../index").ExternalServiceType;
      type _AuthenticationMethod = import("../index").AuthenticationMethod;
      type _DataExfiltrationRisk = import("../index").DataExfiltrationRisk;
      type _ExternalService = import("../index").ExternalService;
      type _ExternalServicesAssessment =
        import("../index").ExternalServicesAssessment;
      type _ApiCredentialPattern = import("../index").ApiCredentialPattern;
      type _ApiCredentialMatch = import("../index").ApiCredentialMatch;
      type _PromptInjectionPattern = import("../index").PromptInjectionPattern;
      type _PoisonedContent = import("../index").PoisonedContent;
      type _PromptInjectionTest = import("../index").PromptInjectionTest;
      type _PromptInjectionAssessment =
        import("../index").PromptInjectionAssessment;

      // temporalSecurityTypes (4 types)
      type _TemporalCheck = import("../index").TemporalCheck;
      type _TemporalSecurityAssessment =
        import("../index").TemporalSecurityAssessment;
      type _VarianceTest = import("../index").VarianceTest;
      type _VarianceAssessment = import("../index").VarianceAssessment;

      // capabilityAssessmentTypes (17 types)
      type _ResourceTest = import("../index").ResourceTest;
      type _ResourceAssessment = import("../index").ResourceAssessment;
      type _PromptTest = import("../index").PromptTest;
      type _PromptAssessment = import("../index").PromptAssessment;
      type _ResourceCompletionOption =
        import("../index").ResourceCompletionOption;
      type _ResourceListChangedNotification =
        import("../index").ResourceListChangedNotification;
      type _ResourceListCapability = import("../index").ResourceListCapability;
      type _ResourceReadCapability = import("../index").ResourceReadCapability;
      type _ResourceTemplatesCapability =
        import("../index").ResourceTemplatesCapability;
      type _ResourceSubscribeCapability =
        import("../index").ResourceSubscribeCapability;
      type _ProtocolCapabilities = import("../index").ProtocolCapabilities;
      type _ProtocolCapabilitiesAssessment =
        import("../index").ProtocolCapabilitiesAssessment;
      type _ProtocolCheck = import("../index").ProtocolCheck;
      type _ConformanceResult = import("../index").ConformanceResult;
      type _ConformanceAssessment = import("../index").ConformanceAssessment;
      type _DeveloperExperienceMetrics =
        import("../index").DeveloperExperienceMetrics;
      type _DeveloperExperienceAssessment =
        import("../index").DeveloperExperienceAssessment;

      // If we reached here, TypeScript compilation succeeded
      expect(true).toBe(true);
    });
  });

  describe("Backward Compatibility - extendedTypes Shim", () => {
    test("extendedTypes.ts imports without errors", async () => {
      await expect(import("../extendedTypes")).resolves.toBeDefined();
    });

    test("all 61 types accessible via extendedTypes.ts", () => {
      // TypeScript compile-time verification
      // Verifies the deprecated shim still provides backward compatibility

      // aupComplianceTypes (4 types)
      type _AUPCategory = import("../extendedTypes").AUPCategory;
      type _AUPSeverity = import("../extendedTypes").AUPSeverity;
      type _AUPViolation = import("../extendedTypes").AUPViolation;
      type _AUPComplianceAssessment =
        import("../extendedTypes").AUPComplianceAssessment;

      // toolAnnotationTypes (9 types)
      type _AnnotationSource = import("../extendedTypes").AnnotationSource;
      type _ToolAnnotationResult =
        import("../extendedTypes").ToolAnnotationResult;
      type _ToolAnnotationAssessment =
        import("../extendedTypes").ToolAnnotationAssessment;
      type _DatabaseBackend = import("../extendedTypes").DatabaseBackend;
      type _TransportMode = import("../extendedTypes").TransportMode;
      type _ServerArchitectureType =
        import("../extendedTypes").ServerArchitectureType;
      type _ArchitectureAnalysis =
        import("../extendedTypes").ArchitectureAnalysis;
      type _InferenceSignal = import("../extendedTypes").InferenceSignal;
      type _EnhancedBehaviorInferenceResult =
        import("../extendedTypes").EnhancedBehaviorInferenceResult;

      // policyComplianceTypes (16 types)
      type _ProhibitedLibraryCategory =
        import("../extendedTypes").ProhibitedLibraryCategory;
      type _DependencyUsageStatus =
        import("../extendedTypes").DependencyUsageStatus;
      type _ProhibitedLibraryMatch =
        import("../extendedTypes").ProhibitedLibraryMatch;
      type _ProhibitedLibrariesAssessment =
        import("../extendedTypes").ProhibitedLibrariesAssessment;
      type _McpConfigSchema = import("../extendedTypes").McpConfigSchema;
      type _ManifestServerSchema =
        import("../extendedTypes").ManifestServerSchema;
      type _ManifestToolDeclaration =
        import("../extendedTypes").ManifestToolDeclaration;
      type _ManifestAuthorObject =
        import("../extendedTypes").ManifestAuthorObject;
      type _ManifestJsonSchema = import("../extendedTypes").ManifestJsonSchema;
      type _PrivacyPolicyValidation =
        import("../extendedTypes").PrivacyPolicyValidation;
      type _ManifestValidationResult =
        import("../extendedTypes").ManifestValidationResult;
      type _ExtractedContactInfo =
        import("../extendedTypes").ExtractedContactInfo;
      type _ExtractedVersionInfo =
        import("../extendedTypes").ExtractedVersionInfo;
      type _ManifestValidationAssessment =
        import("../extendedTypes").ManifestValidationAssessment;
      type _PortabilityIssue = import("../extendedTypes").PortabilityIssue;
      type _PortabilityAssessment =
        import("../extendedTypes").PortabilityAssessment;

      // externalServicesTypes (11 types)
      type _ExternalServiceType =
        import("../extendedTypes").ExternalServiceType;
      type _AuthenticationMethod =
        import("../extendedTypes").AuthenticationMethod;
      type _DataExfiltrationRisk =
        import("../extendedTypes").DataExfiltrationRisk;
      type _ExternalService = import("../extendedTypes").ExternalService;
      type _ExternalServicesAssessment =
        import("../extendedTypes").ExternalServicesAssessment;
      type _ApiCredentialPattern =
        import("../extendedTypes").ApiCredentialPattern;
      type _ApiCredentialMatch = import("../extendedTypes").ApiCredentialMatch;
      type _PromptInjectionPattern =
        import("../extendedTypes").PromptInjectionPattern;
      type _PoisonedContent = import("../extendedTypes").PoisonedContent;
      type _PromptInjectionTest =
        import("../extendedTypes").PromptInjectionTest;
      type _PromptInjectionAssessment =
        import("../extendedTypes").PromptInjectionAssessment;

      // temporalSecurityTypes (4 types)
      type _TemporalCheck = import("../extendedTypes").TemporalCheck;
      type _TemporalSecurityAssessment =
        import("../extendedTypes").TemporalSecurityAssessment;
      type _VarianceTest = import("../extendedTypes").VarianceTest;
      type _VarianceAssessment = import("../extendedTypes").VarianceAssessment;

      // capabilityAssessmentTypes (17 types)
      type _ResourceTest = import("../extendedTypes").ResourceTest;
      type _ResourceAssessment = import("../extendedTypes").ResourceAssessment;
      type _PromptTest = import("../extendedTypes").PromptTest;
      type _PromptAssessment = import("../extendedTypes").PromptAssessment;
      type _ResourceCompletionOption =
        import("../extendedTypes").ResourceCompletionOption;
      type _ResourceListChangedNotification =
        import("../extendedTypes").ResourceListChangedNotification;
      type _ResourceListCapability =
        import("../extendedTypes").ResourceListCapability;
      type _ResourceReadCapability =
        import("../extendedTypes").ResourceReadCapability;
      type _ResourceTemplatesCapability =
        import("../extendedTypes").ResourceTemplatesCapability;
      type _ResourceSubscribeCapability =
        import("../extendedTypes").ResourceSubscribeCapability;
      type _ProtocolCapabilities =
        import("../extendedTypes").ProtocolCapabilities;
      type _ProtocolCapabilitiesAssessment =
        import("../extendedTypes").ProtocolCapabilitiesAssessment;
      type _ProtocolCheck = import("../extendedTypes").ProtocolCheck;
      type _ConformanceResult = import("../extendedTypes").ConformanceResult;
      type _ConformanceAssessment =
        import("../extendedTypes").ConformanceAssessment;
      type _DeveloperExperienceMetrics =
        import("../extendedTypes").DeveloperExperienceMetrics;
      type _DeveloperExperienceAssessment =
        import("../extendedTypes").DeveloperExperienceAssessment;

      // If we reached here, TypeScript compilation succeeded
      expect(true).toBe(true);
    });
  });

  describe("Direct Module Type Access", () => {
    test("aupComplianceTypes exports all 4 types", () => {
      type _AUPCategory = import("../aupComplianceTypes").AUPCategory;
      type _AUPSeverity = import("../aupComplianceTypes").AUPSeverity;
      type _AUPViolation = import("../aupComplianceTypes").AUPViolation;
      type _AUPComplianceAssessment =
        import("../aupComplianceTypes").AUPComplianceAssessment;

      expect(true).toBe(true);
    });

    test("toolAnnotationTypes exports all 9 types", () => {
      type _AnnotationSource =
        import("../toolAnnotationTypes").AnnotationSource;
      type _ToolAnnotationResult =
        import("../toolAnnotationTypes").ToolAnnotationResult;
      type _ToolAnnotationAssessment =
        import("../toolAnnotationTypes").ToolAnnotationAssessment;
      type _DatabaseBackend = import("../toolAnnotationTypes").DatabaseBackend;
      type _TransportMode = import("../toolAnnotationTypes").TransportMode;
      type _ServerArchitectureType =
        import("../toolAnnotationTypes").ServerArchitectureType;
      type _ArchitectureAnalysis =
        import("../toolAnnotationTypes").ArchitectureAnalysis;
      type _InferenceSignal = import("../toolAnnotationTypes").InferenceSignal;
      type _EnhancedBehaviorInferenceResult =
        import("../toolAnnotationTypes").EnhancedBehaviorInferenceResult;

      expect(true).toBe(true);
    });

    test("policyComplianceTypes exports all 16 types", () => {
      type _ProhibitedLibraryCategory =
        import("../policyComplianceTypes").ProhibitedLibraryCategory;
      type _DependencyUsageStatus =
        import("../policyComplianceTypes").DependencyUsageStatus;
      type _ProhibitedLibraryMatch =
        import("../policyComplianceTypes").ProhibitedLibraryMatch;
      type _ProhibitedLibrariesAssessment =
        import("../policyComplianceTypes").ProhibitedLibrariesAssessment;
      type _McpConfigSchema =
        import("../policyComplianceTypes").McpConfigSchema;
      type _ManifestServerSchema =
        import("../policyComplianceTypes").ManifestServerSchema;
      type _ManifestToolDeclaration =
        import("../policyComplianceTypes").ManifestToolDeclaration;
      type _ManifestAuthorObject =
        import("../policyComplianceTypes").ManifestAuthorObject;
      type _ManifestJsonSchema =
        import("../policyComplianceTypes").ManifestJsonSchema;
      type _PrivacyPolicyValidation =
        import("../policyComplianceTypes").PrivacyPolicyValidation;
      type _ManifestValidationResult =
        import("../policyComplianceTypes").ManifestValidationResult;
      type _ExtractedContactInfo =
        import("../policyComplianceTypes").ExtractedContactInfo;
      type _ExtractedVersionInfo =
        import("../policyComplianceTypes").ExtractedVersionInfo;
      type _ManifestValidationAssessment =
        import("../policyComplianceTypes").ManifestValidationAssessment;
      type _PortabilityIssue =
        import("../policyComplianceTypes").PortabilityIssue;
      type _PortabilityAssessment =
        import("../policyComplianceTypes").PortabilityAssessment;

      expect(true).toBe(true);
    });

    test("externalServicesTypes exports all 11 types", () => {
      type _ExternalServiceType =
        import("../externalServicesTypes").ExternalServiceType;
      type _AuthenticationMethod =
        import("../externalServicesTypes").AuthenticationMethod;
      type _DataExfiltrationRisk =
        import("../externalServicesTypes").DataExfiltrationRisk;
      type _ExternalService =
        import("../externalServicesTypes").ExternalService;
      type _ExternalServicesAssessment =
        import("../externalServicesTypes").ExternalServicesAssessment;
      type _ApiCredentialPattern =
        import("../externalServicesTypes").ApiCredentialPattern;
      type _ApiCredentialMatch =
        import("../externalServicesTypes").ApiCredentialMatch;
      type _PromptInjectionPattern =
        import("../externalServicesTypes").PromptInjectionPattern;
      type _PoisonedContent =
        import("../externalServicesTypes").PoisonedContent;
      type _PromptInjectionTest =
        import("../externalServicesTypes").PromptInjectionTest;
      type _PromptInjectionAssessment =
        import("../externalServicesTypes").PromptInjectionAssessment;

      expect(true).toBe(true);
    });

    test("temporalSecurityTypes exports all 4 types", () => {
      type _TemporalCheck = import("../temporalSecurityTypes").TemporalCheck;
      type _TemporalSecurityAssessment =
        import("../temporalSecurityTypes").TemporalSecurityAssessment;
      type _VarianceTest = import("../temporalSecurityTypes").VarianceTest;
      type _VarianceAssessment =
        import("../temporalSecurityTypes").VarianceAssessment;

      expect(true).toBe(true);
    });

    test("capabilityAssessmentTypes exports all 17 types", () => {
      type _ResourceTest = import("../capabilityAssessmentTypes").ResourceTest;
      type _ResourceAssessment =
        import("../capabilityAssessmentTypes").ResourceAssessment;
      type _PromptTest = import("../capabilityAssessmentTypes").PromptTest;
      type _PromptAssessment =
        import("../capabilityAssessmentTypes").PromptAssessment;
      type _ResourceCompletionOption =
        import("../capabilityAssessmentTypes").ResourceCompletionOption;
      type _ResourceListChangedNotification =
        import("../capabilityAssessmentTypes").ResourceListChangedNotification;
      type _ResourceListCapability =
        import("../capabilityAssessmentTypes").ResourceListCapability;
      type _ResourceReadCapability =
        import("../capabilityAssessmentTypes").ResourceReadCapability;
      type _ResourceTemplatesCapability =
        import("../capabilityAssessmentTypes").ResourceTemplatesCapability;
      type _ResourceSubscribeCapability =
        import("../capabilityAssessmentTypes").ResourceSubscribeCapability;
      type _ProtocolCapabilities =
        import("../capabilityAssessmentTypes").ProtocolCapabilities;
      type _ProtocolCapabilitiesAssessment =
        import("../capabilityAssessmentTypes").ProtocolCapabilitiesAssessment;
      type _ProtocolCheck =
        import("../capabilityAssessmentTypes").ProtocolCheck;
      type _ConformanceResult =
        import("../capabilityAssessmentTypes").ConformanceResult;
      type _ConformanceAssessment =
        import("../capabilityAssessmentTypes").ConformanceAssessment;
      type _DeveloperExperienceMetrics =
        import("../capabilityAssessmentTypes").DeveloperExperienceMetrics;
      type _DeveloperExperienceAssessment =
        import("../capabilityAssessmentTypes").DeveloperExperienceAssessment;

      expect(true).toBe(true);
    });
  });

  describe("No Circular Dependencies", () => {
    test("all modules can be imported without circular dependency errors", async () => {
      // Import all modules simultaneously to detect circular dependencies
      const imports = await Promise.all([
        import("../aupComplianceTypes"),
        import("../toolAnnotationTypes"),
        import("../policyComplianceTypes"),
        import("../externalServicesTypes"),
        import("../temporalSecurityTypes"),
        import("../capabilityAssessmentTypes"),
        import("../index"),
        import("../extendedTypes"),
      ]);

      // All imports should be defined
      imports.forEach((module) => {
        expect(module).toBeDefined();
      });
    });

    test("modules can be imported in any order", async () => {
      // Test reverse order
      const reverseImports = await Promise.all([
        import("../extendedTypes"),
        import("../index"),
        import("../capabilityAssessmentTypes"),
        import("../temporalSecurityTypes"),
        import("../externalServicesTypes"),
        import("../policyComplianceTypes"),
        import("../toolAnnotationTypes"),
        import("../aupComplianceTypes"),
      ]);

      reverseImports.forEach((module) => {
        expect(module).toBeDefined();
      });
    });
  });

  describe("Documentation Comments", () => {
    test("all module files exist and are readable", async () => {
      // Verify files exist by importing them
      const modules = await Promise.all([
        import("../aupComplianceTypes"),
        import("../toolAnnotationTypes"),
        import("../policyComplianceTypes"),
        import("../externalServicesTypes"),
        import("../temporalSecurityTypes"),
        import("../capabilityAssessmentTypes"),
      ]);

      expect(modules).toHaveLength(6);
    });
  });
});
