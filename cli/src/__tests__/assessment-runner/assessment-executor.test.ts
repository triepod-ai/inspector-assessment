/**
 * Assessment Executor Unit Tests
 *
 * Tests for runFullAssessment() orchestration logic.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  afterAll,
} from "@jest/globals";

// Mock all dependencies with explicit any types for flexibility
const mockLoadServerConfig = jest.fn<() => unknown>();
const mockConnectToServer = jest.fn<() => Promise<unknown>>();
const mockLoadSourceFiles = jest.fn<() => unknown>();
const mockCreateCallToolWrapper = jest.fn<() => unknown>();
const mockBuildConfig = jest.fn<() => unknown>();

// Mock client with typed functions
const mockClient = {
  listTools: jest.fn<() => Promise<unknown>>(),
  listResources: jest.fn<() => Promise<unknown>>(),
  listPrompts: jest.fn<() => Promise<unknown>>(),
  readResource: jest.fn<() => Promise<unknown>>(),
  getPrompt: jest.fn<() => Promise<unknown>>(),
  getServerVersion: jest.fn<() => unknown>(),
  getServerCapabilities: jest.fn<() => unknown>(),
  close: jest.fn<() => Promise<void>>(),
};

// Mock orchestrator
const mockRunFullAssessment = jest.fn<() => Promise<unknown>>();
const mockIsClaudeEnabled = jest.fn<() => boolean>();
const MockAssessmentOrchestrator = jest.fn().mockImplementation(() => ({
  runFullAssessment: mockRunFullAssessment,
  isClaudeEnabled: mockIsClaudeEnabled,
}));

// Mock state manager
const mockStateExists = jest.fn<() => boolean>();
const mockStateGetSummary = jest.fn<() => unknown>();
const mockStateClear = jest.fn<() => void>();
const MockAssessmentStateManager = jest.fn().mockImplementation(() => ({
  exists: mockStateExists,
  getSummary: mockStateGetSummary,
  clear: mockStateClear,
}));

// Mock JSONL event emitters
const mockEmitServerConnected = jest.fn();
const mockEmitToolDiscovered = jest.fn();
const mockEmitToolsDiscoveryComplete = jest.fn();
const mockEmitAssessmentComplete = jest.fn();
const mockEmitModulesConfigured = jest.fn();

jest.unstable_mockModule(
  "../../lib/assessment-runner/server-config.js",
  () => ({
    loadServerConfig: mockLoadServerConfig,
  }),
);

jest.unstable_mockModule(
  "../../lib/assessment-runner/server-connection.js",
  () => ({
    connectToServer: mockConnectToServer,
  }),
);

jest.unstable_mockModule(
  "../../lib/assessment-runner/source-loader.js",
  () => ({
    loadSourceFiles: mockLoadSourceFiles,
  }),
);

jest.unstable_mockModule("../../lib/assessment-runner/tool-wrapper.js", () => ({
  createCallToolWrapper: mockCreateCallToolWrapper,
}));

jest.unstable_mockModule(
  "../../lib/assessment-runner/config-builder.js",
  () => ({
    buildConfig: mockBuildConfig,
  }),
);

jest.unstable_mockModule(
  "../../../../client/lib/services/assessment/AssessmentOrchestrator.js",
  () => ({
    AssessmentOrchestrator: MockAssessmentOrchestrator,
    AssessmentContext: {},
  }),
);

jest.unstable_mockModule("../../assessmentState.js", () => ({
  AssessmentStateManager: MockAssessmentStateManager,
}));

jest.unstable_mockModule("../../lib/jsonl-events.js", () => ({
  emitServerConnected: mockEmitServerConnected,
  emitToolDiscovered: mockEmitToolDiscovered,
  emitToolsDiscoveryComplete: mockEmitToolsDiscoveryComplete,
  emitAssessmentComplete: mockEmitAssessmentComplete,
  emitTestBatch: jest.fn(),
  emitVulnerabilityFound: jest.fn(),
  emitAnnotationMissing: jest.fn(),
  emitAnnotationMisaligned: jest.fn(),
  emitAnnotationReviewRecommended: jest.fn(),
  emitAnnotationAligned: jest.fn(),
  emitModulesConfigured: mockEmitModulesConfigured,
  // Phase 7 events
  emitPhaseStarted: jest.fn(),
  emitPhaseComplete: jest.fn(),
  emitToolTestComplete: jest.fn(),
  emitValidationSummary: jest.fn(),
}));

jest.unstable_mockModule("fs", () => ({
  existsSync: jest.fn().mockReturnValue(false),
  readFileSync: jest.fn(),
}));

jest.unstable_mockModule(
  "../../../../client/lib/lib/assessmentTypes.js",
  () => ({
    MCPDirectoryAssessment: {},
    ProgressEvent: {},
  }),
);

// Import after mocking
const { runFullAssessment } =
  await import("../../lib/assessment-runner/assessment-executor.js");

describe("runFullAssessment", () => {
  const defaultOptions = {
    serverName: "test-server",
    jsonOnly: true, // Suppress console output in tests
  };

  beforeEach(() => {
    jest.clearAllMocks();

    // Setup default mock returns
    mockLoadServerConfig.mockReturnValue({
      transport: "stdio",
      command: "node",
      args: ["server.js"],
    });

    mockConnectToServer.mockResolvedValue(mockClient);

    mockClient.listTools.mockResolvedValue({
      tools: [
        { name: "tool1", description: "First tool" },
        { name: "tool2", description: "Second tool" },
      ],
    });

    mockClient.listResources.mockResolvedValue({ resources: [] });
    mockClient.listPrompts.mockResolvedValue({ prompts: [] });
    mockClient.getServerVersion.mockReturnValue({
      name: "test-server",
      version: "1.0.0",
    });
    mockClient.getServerCapabilities.mockReturnValue({});
    mockClient.close.mockResolvedValue(undefined);

    mockLoadSourceFiles.mockReturnValue({});
    mockCreateCallToolWrapper.mockReturnValue(jest.fn());
    mockBuildConfig.mockReturnValue({
      assessmentCategories: { functionality: true, security: true },
    });

    mockRunFullAssessment.mockResolvedValue({
      overallStatus: "PASS",
      totalTestsRun: 10,
      executionTime: 5000,
    });

    mockIsClaudeEnabled.mockReturnValue(false);
    mockStateExists.mockReturnValue(false);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  afterAll(() => {
    // Clean up module mocks to prevent memory leaks
    jest.unmock("../../lib/assessment-runner/server-config.js");
    jest.unmock("../../lib/assessment-runner/server-connection.js");
    jest.unmock("../../lib/assessment-runner/source-loader.js");
    jest.unmock("../../lib/assessment-runner/tool-wrapper.js");
    jest.unmock("../../lib/assessment-runner/config-builder.js");
    jest.unmock(
      "../../../../client/lib/services/assessment/AssessmentOrchestrator.js",
    );
    jest.unmock("../../assessmentState.js");
    jest.unmock("../../lib/jsonl-events.js");
    jest.unmock("fs");
    jest.unmock("../../../../client/lib/lib/assessmentTypes.js");
  });

  describe("orchestration flow", () => {
    it("should load server config", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockLoadServerConfig).toHaveBeenCalledWith(
        "test-server",
        undefined,
      );
    });

    it("should connect to server", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockConnectToServer).toHaveBeenCalled();
      expect(mockEmitServerConnected).toHaveBeenCalledWith(
        "test-server",
        "stdio",
      );
    });

    it("should discover tools via client.listTools()", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockClient.listTools).toHaveBeenCalled();
      expect(mockEmitToolDiscovered).toHaveBeenCalledTimes(2);
      expect(mockEmitToolsDiscoveryComplete).toHaveBeenCalledWith(2);
    });

    it("should discover resources via client.listResources()", async () => {
      mockClient.listResources.mockResolvedValue({
        resources: [{ uri: "file://test.txt", name: "Test" }],
      });

      await runFullAssessment(defaultOptions);

      expect(mockClient.listResources).toHaveBeenCalled();
    });

    it("should handle server with zero tools gracefully", async () => {
      mockClient.listTools.mockResolvedValue({ tools: [] });

      await runFullAssessment(defaultOptions);

      expect(mockEmitToolsDiscoveryComplete).toHaveBeenCalledWith(0);
    });

    it("should handle resources not supported by server", async () => {
      mockClient.listResources.mockRejectedValue(
        new Error("Resources not supported"),
      );

      // Should not throw
      await expect(runFullAssessment(defaultOptions)).resolves.toBeDefined();
    });

    it("should handle prompts not supported by server", async () => {
      mockClient.listPrompts.mockRejectedValue(
        new Error("Prompts not supported"),
      );

      // Should not throw
      await expect(runFullAssessment(defaultOptions)).resolves.toBeDefined();
    });
  });

  describe("configuration", () => {
    it("should build config from options", async () => {
      await runFullAssessment({
        ...defaultOptions,
        profile: "security",
      });

      expect(mockBuildConfig).toHaveBeenCalledWith(
        expect.objectContaining({ profile: "security" }),
      );
    });

    it("should emit modules_configured event", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockEmitModulesConfigured).toHaveBeenCalledWith(
        ["functionality", "security"],
        [],
        "default",
      );
    });

    it("should create AssessmentOrchestrator with config", async () => {
      await runFullAssessment(defaultOptions);

      expect(MockAssessmentOrchestrator).toHaveBeenCalledWith(
        expect.objectContaining({
          assessmentCategories: { functionality: true, security: true },
        }),
      );
    });
  });

  describe("source files", () => {
    it("should load source files when sourceCodePath provided", async () => {
      const fs = await import("fs");
      (fs.existsSync as jest.Mock).mockReturnValue(true);

      await runFullAssessment({
        ...defaultOptions,
        sourceCodePath: "/path/to/source",
      });

      expect(mockLoadSourceFiles).toHaveBeenCalledWith(
        "/path/to/source",
        undefined,
      );
    });

    it("should not load source files when path does not exist", async () => {
      const fs = await import("fs");
      (fs.existsSync as jest.Mock).mockReturnValue(false);

      await runFullAssessment({
        ...defaultOptions,
        sourceCodePath: "/nonexistent",
      });

      expect(mockLoadSourceFiles).not.toHaveBeenCalled();
    });
  });

  describe("cleanup", () => {
    it("should close client connection on completion", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockClient.close).toHaveBeenCalled();
    });

    it("should emit assessment complete event", async () => {
      await runFullAssessment(defaultOptions);

      expect(mockEmitAssessmentComplete).toHaveBeenCalledWith(
        "PASS",
        10,
        5000,
        expect.stringContaining("inspector-full-assessment"),
      );
    });
  });

  describe("results", () => {
    it("should return MCPDirectoryAssessment results", async () => {
      const result = await runFullAssessment(defaultOptions);

      expect(result).toEqual({
        overallStatus: "PASS",
        totalTestsRun: 10,
        executionTime: 5000,
      });
    });
  });

  describe("state management", () => {
    it("should check for existing state", async () => {
      await runFullAssessment(defaultOptions);

      expect(MockAssessmentStateManager).toHaveBeenCalledWith("test-server");
      expect(mockStateExists).toHaveBeenCalled();
    });

    it("should clear state when --no-resume is set", async () => {
      mockStateExists.mockReturnValue(true);

      await runFullAssessment({
        ...defaultOptions,
        noResume: true,
      });

      expect(mockStateClear).toHaveBeenCalled();
    });
  });
});
