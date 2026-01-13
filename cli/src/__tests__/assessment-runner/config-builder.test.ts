/**
 * Config Builder Unit Tests
 *
 * Tests for buildConfig() that transforms CLI options into AssessmentConfiguration.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";

// Mock dependencies before importing
jest.unstable_mockModule("../../profiles.js", () => ({
  getProfileModules: jest.fn(),
  resolveModuleNames: jest.fn((names: string[]) => names),
  modulesToLegacyConfig: jest.fn(),
}));

jest.unstable_mockModule(
  "../../../../client/lib/lib/assessmentTypes.js",
  () => ({
    DEFAULT_ASSESSMENT_CONFIG: {
      configVersion: 2,
      enableExtendedAssessment: false,
      parallelTesting: false,
      testTimeout: 10000,
      enableSourceCodeAnalysis: false,
    },
    getAllModulesConfig: jest.fn(),
    LogLevel: {},
  }),
);

jest.unstable_mockModule(
  "../../../../client/lib/services/assessment/lib/claudeCodeBridge.js",
  () => ({
    FULL_CLAUDE_CODE_CONFIG: {
      timeout: 60000,
      maxRetries: 2,
    },
  }),
);

jest.unstable_mockModule(
  "../../../../client/lib/services/assessment/config/performanceConfig.js",
  () => ({
    loadPerformanceConfig: jest.fn(),
  }),
);

// Import after mocking
const { buildConfig } =
  await import("../../lib/assessment-runner/config-builder.js");
const { getProfileModules, resolveModuleNames, modulesToLegacyConfig } =
  await import("../../profiles.js");
const { getAllModulesConfig, DEFAULT_ASSESSMENT_CONFIG } =
  await import("../../../../client/lib/lib/assessmentTypes.js");
const { loadPerformanceConfig } =
  await import("../../../../client/lib/services/assessment/config/performanceConfig.js");

describe("buildConfig", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
    delete process.env.INSPECTOR_CLAUDE;
    delete process.env.INSPECTOR_MCP_AUDITOR_URL;
    delete process.env.LOG_LEVEL;

    // Default mock returns
    (getAllModulesConfig as jest.Mock).mockReturnValue({
      functionality: true,
      security: true,
      temporal: true,
    });
    (getProfileModules as jest.Mock).mockReturnValue([
      "functionality",
      "security",
    ]);
    (modulesToLegacyConfig as jest.Mock).mockReturnValue({
      functionality: true,
      security: true,
    });
    (resolveModuleNames as jest.Mock).mockImplementation(
      (names: string[]) => names,
    );
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  afterAll(() => {
    jest.unmock("../../profiles.js");
    jest.unmock("../../../../client/lib/lib/assessmentTypes.js");
    jest.unmock(
      "../../../../client/lib/services/assessment/lib/claudeCodeBridge.js",
    );
    jest.unmock(
      "../../../../client/lib/services/assessment/config/performanceConfig.js",
    );
  });

  describe("default configuration", () => {
    it("should spread DEFAULT_ASSESSMENT_CONFIG", () => {
      const result = buildConfig({ serverName: "test" });
      // Config should include properties from DEFAULT_ASSESSMENT_CONFIG
      expect(result.testTimeout).toBe(30000); // Overridden in buildConfig
      expect(result.parallelTesting).toBe(true); // Overridden in buildConfig
    });

    it("should set enableExtendedAssessment true by default", () => {
      const result = buildConfig({ serverName: "test" });
      expect(result.enableExtendedAssessment).toBe(true);
    });

    it("should set enableExtendedAssessment false when fullAssessment is false", () => {
      const result = buildConfig({ serverName: "test", fullAssessment: false });
      expect(result.enableExtendedAssessment).toBe(false);
    });
  });

  describe("source code analysis", () => {
    it("should set enableSourceCodeAnalysis false when no sourceCodePath", () => {
      const result = buildConfig({ serverName: "test" });
      expect(result.enableSourceCodeAnalysis).toBe(false);
    });

    it("should set enableSourceCodeAnalysis true when sourceCodePath provided", () => {
      const result = buildConfig({
        serverName: "test",
        sourceCodePath: "/path/to/source",
      });
      expect(result.enableSourceCodeAnalysis).toBe(true);
    });
  });

  describe("profile-based module selection", () => {
    it("should use getProfileModules when profile option is set", () => {
      buildConfig({ serverName: "test", profile: "security" });
      expect(getProfileModules).toHaveBeenCalledWith("security", {
        hasSourceCode: false,
        skipTemporal: undefined,
      });
    });

    it("should pass hasSourceCode to getProfileModules", () => {
      buildConfig({
        serverName: "test",
        profile: "full",
        sourceCodePath: "/path",
      });
      expect(getProfileModules).toHaveBeenCalledWith("full", {
        hasSourceCode: true,
        skipTemporal: undefined,
      });
    });

    it("should pass skipTemporal to getProfileModules", () => {
      buildConfig({
        serverName: "test",
        profile: "security",
        skipTemporal: true,
      });
      expect(getProfileModules).toHaveBeenCalledWith("security", {
        hasSourceCode: false,
        skipTemporal: true,
      });
    });

    it("should convert profile modules to legacy config", () => {
      (getProfileModules as jest.Mock).mockReturnValue([
        "functionality",
        "security",
      ]);
      buildConfig({ serverName: "test", profile: "quick" });
      expect(modulesToLegacyConfig).toHaveBeenCalledWith([
        "functionality",
        "security",
      ]);
    });
  });

  describe("module filtering", () => {
    it("should apply --only-modules whitelist filter", () => {
      (getAllModulesConfig as jest.Mock).mockReturnValue({
        functionality: true,
        security: true,
        temporal: true,
        errorHandling: true,
      });
      (resolveModuleNames as jest.Mock).mockReturnValue(["functionality"]);

      const result = buildConfig({
        serverName: "test",
        onlyModules: ["functionality"],
      });

      expect(resolveModuleNames).toHaveBeenCalledWith(["functionality"]);
      // Only functionality should be true
      expect(result.assessmentCategories?.functionality).toBe(true);
      expect(result.assessmentCategories?.security).toBe(false);
      expect(result.assessmentCategories?.temporal).toBe(false);
    });

    it("should apply --skip-modules blacklist filter", () => {
      (getAllModulesConfig as jest.Mock).mockReturnValue({
        functionality: true,
        security: true,
        temporal: true,
      });
      (resolveModuleNames as jest.Mock).mockReturnValue(["temporal"]);

      const result = buildConfig({
        serverName: "test",
        skipModules: ["temporal"],
      });

      expect(resolveModuleNames).toHaveBeenCalledWith(["temporal"]);
      // temporal should be disabled
      expect(result.assessmentCategories?.functionality).toBe(true);
      expect(result.assessmentCategories?.security).toBe(true);
      expect(result.assessmentCategories?.temporal).toBe(false);
    });
  });

  describe("Claude Code configuration", () => {
    it("should not set claudeCode when claudeEnabled is false", () => {
      const result = buildConfig({ serverName: "test", claudeEnabled: false });
      expect(result.claudeCode).toBeUndefined();
    });

    it("should set claudeCode config when claudeEnabled is true", () => {
      const result = buildConfig({ serverName: "test", claudeEnabled: true });
      expect(result.claudeCode).toBeDefined();
      expect(result.claudeCode?.enabled).toBe(true);
      expect(result.claudeCode?.timeout).toBe(60000);
      expect(result.claudeCode?.maxRetries).toBe(2);
    });

    it("should use HTTP transport when claudeHttp flag is set", () => {
      const result = buildConfig({
        serverName: "test",
        claudeEnabled: true,
        claudeHttp: true,
      });
      expect(result.claudeCode?.transport).toBe("http");
      expect(result.claudeCode?.httpConfig?.baseUrl).toBe(
        "http://localhost:8085",
      );
    });

    it("should use HTTP transport when INSPECTOR_CLAUDE env is true", () => {
      process.env.INSPECTOR_CLAUDE = "true";
      const result = buildConfig({ serverName: "test", claudeEnabled: true });
      expect(result.claudeCode?.transport).toBe("http");
    });

    it("should use custom mcpAuditorUrl when provided", () => {
      const result = buildConfig({
        serverName: "test",
        claudeEnabled: true,
        claudeHttp: true,
        mcpAuditorUrl: "http://custom:9000",
      });
      expect(result.claudeCode?.httpConfig?.baseUrl).toBe("http://custom:9000");
    });

    it("should use INSPECTOR_MCP_AUDITOR_URL env when mcpAuditorUrl not provided", () => {
      process.env.INSPECTOR_MCP_AUDITOR_URL = "http://env-url:8000";
      const result = buildConfig({
        serverName: "test",
        claudeEnabled: true,
        claudeHttp: true,
      });
      expect(result.claudeCode?.httpConfig?.baseUrl).toBe(
        "http://env-url:8000",
      );
    });

    it("should enable Claude features when claudeEnabled is true", () => {
      const result = buildConfig({ serverName: "test", claudeEnabled: true });
      expect(result.claudeCode?.features?.intelligentTestGeneration).toBe(true);
      expect(result.claudeCode?.features?.aupSemanticAnalysis).toBe(true);
      expect(result.claudeCode?.features?.annotationInference).toBe(true);
      expect(result.claudeCode?.features?.documentationQuality).toBe(true);
    });
  });

  describe("temporal configuration", () => {
    it("should set temporalInvocations when option provided", () => {
      const result = buildConfig({
        serverName: "test",
        temporalInvocations: 5,
      });
      expect(result.temporalInvocations).toBe(5);
    });

    it("should not set temporalInvocations when option not provided", () => {
      const result = buildConfig({ serverName: "test" });
      expect(result.temporalInvocations).toBeUndefined();
    });
  });

  describe("performance configuration", () => {
    it("should load performance config when path provided", () => {
      (loadPerformanceConfig as jest.Mock).mockReturnValue({
        batchFlushIntervalMs: 100,
        securityBatchSize: 10,
        functionalityBatchSize: 5,
      });

      buildConfig({
        serverName: "test",
        performanceConfigPath: "/path/to/perf.json",
      });

      expect(loadPerformanceConfig).toHaveBeenCalledWith("/path/to/perf.json");
    });

    it("should throw on invalid performance config file", () => {
      (loadPerformanceConfig as jest.Mock).mockImplementation(() => {
        throw new Error("Invalid config");
      });

      expect(() =>
        buildConfig({
          serverName: "test",
          performanceConfigPath: "/invalid/path.json",
        }),
      ).toThrow("Invalid config");
    });
  });

  describe("pattern configuration", () => {
    it("should set patternConfigPath when option provided", () => {
      const result = buildConfig({
        serverName: "test",
        patternConfigPath: "/path/to/patterns.json",
      });
      expect(result.patternConfigPath).toBe("/path/to/patterns.json");
    });
  });

  describe("logging configuration", () => {
    it("should use logLevel from options when provided", () => {
      const result = buildConfig({ serverName: "test", logLevel: "debug" });
      expect(result.logging?.level).toBe("debug");
    });

    it("should use LOG_LEVEL env when options.logLevel not provided", () => {
      process.env.LOG_LEVEL = "warn";
      const result = buildConfig({ serverName: "test" });
      expect(result.logging?.level).toBe("warn");
    });

    it("should default to info when no logLevel specified", () => {
      const result = buildConfig({ serverName: "test" });
      expect(result.logging?.level).toBe("info");
    });

    it("should prioritize options.logLevel over LOG_LEVEL env", () => {
      process.env.LOG_LEVEL = "warn";
      const result = buildConfig({ serverName: "test", logLevel: "error" });
      expect(result.logging?.level).toBe("error");
    });
  });

  describe("config version validation (Issue #107)", () => {
    let consoleWarnSpy: ReturnType<typeof jest.spyOn>;

    beforeEach(() => {
      consoleWarnSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {}) as ReturnType<typeof jest.spyOn>;
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it("should not warn when configVersion is present in defaults", () => {
      // DEFAULT_ASSESSMENT_CONFIG mock includes configVersion: 2
      buildConfig({ serverName: "test" });

      // Should NOT warn because configVersion is set
      expect(consoleWarnSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("Config missing configVersion"),
      );
    });

    it("should still build config successfully with configVersion", () => {
      const result = buildConfig({ serverName: "test" });

      expect(result).toBeDefined();
      expect(result.configVersion).toBe(2);
      expect(result.testTimeout).toBeDefined();
      expect(result.logging).toBeDefined();
    });

    it("should include configVersion in final config", () => {
      const result = buildConfig({ serverName: "test" });

      expect(result.configVersion).toBe(2);
    });

    it("should preserve configVersion through profile-based config", () => {
      (modulesToLegacyConfig as jest.Mock).mockReturnValue({
        functionality: true,
        security: true,
      });

      const result = buildConfig({ serverName: "test", profile: "quick" });

      expect(result.configVersion).toBe(2);
    });

    it("should preserve configVersion through module filtering", () => {
      (getAllModulesConfig as jest.Mock).mockReturnValue({
        functionality: true,
        security: true,
      });
      (resolveModuleNames as jest.Mock).mockReturnValue(["functionality"]);

      const result = buildConfig({
        serverName: "test",
        onlyModules: ["functionality"],
      });

      expect(result.configVersion).toBe(2);
    });
  });
});
