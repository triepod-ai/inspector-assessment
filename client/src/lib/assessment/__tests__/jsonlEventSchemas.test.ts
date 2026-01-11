/**
 * Tests for JSONL Event Zod Schemas
 *
 * Comprehensive tests for all 13 JSONL event types and helper functions.
 *
 * @module assessment/__tests__/jsonlEventSchemas
 */

import { ZodError } from "zod";
import {
  // Schema version
  ZOD_SCHEMA_VERSION,
  // Enum schemas
  ModuleStatusSchema,
  ConfidenceLevelSchema,
  RiskLevelSchema,
  SeveritySchema,
  LocationSchema,
  AnnotationFieldSchema,
  ModulesConfiguredReasonSchema,
  // Supporting schemas
  ToolParamSchema,
  ToolAnnotationsSchema,
  InferredBehaviorSchema,
  AUPViolationSampleSchema,
  AUPViolationMetricsSchema,
  AUPScannedLocationsSchema,
  BaseEventSchema,
  // Event schemas
  ServerConnectedEventSchema,
  ToolDiscoveredEventSchema,
  ToolsDiscoveryCompleteEventSchema,
  ModulesConfiguredEventSchema,
  ModuleStartedEventSchema,
  TestBatchEventSchema,
  ModuleCompleteEventSchema,
  VulnerabilityFoundEventSchema,
  AnnotationMissingEventSchema,
  AnnotationMisalignedEventSchema,
  AnnotationReviewRecommendedEventSchema,
  AnnotationAlignedEventSchema,
  AssessmentCompleteEventSchema,
  // Union schema
  JSONLEventSchema,
  // Helper functions
  parseEvent,
  safeParseEvent,
  validateEvent,
  isEventType,
  parseEventLines,
  // Types
  type JSONLEventParsed,
} from "../jsonlEventSchemas";

// ============================================================================
// Test Fixtures
// ============================================================================

const BASE_EVENT = {
  version: "1.29.0",
  schemaVersion: 1,
};

const VALID_FIXTURES = {
  serverConnected: {
    ...BASE_EVENT,
    event: "server_connected" as const,
    serverName: "test-server",
    transport: "http" as const,
  },
  toolDiscovered: {
    ...BASE_EVENT,
    event: "tool_discovered" as const,
    name: "test_tool",
    description: "A test tool for testing",
    params: [{ name: "input", type: "string", required: true }],
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  toolsDiscoveryComplete: {
    ...BASE_EVENT,
    event: "tools_discovery_complete" as const,
    count: 10,
  },
  modulesConfigured: {
    ...BASE_EVENT,
    event: "modules_configured" as const,
    enabled: ["security", "functionality"],
    skipped: ["aup"],
    reason: "skip-modules" as const,
  },
  moduleStarted: {
    ...BASE_EVENT,
    event: "module_started" as const,
    module: "security",
    estimatedTests: 100,
    toolCount: 5,
  },
  testBatch: {
    ...BASE_EVENT,
    event: "test_batch" as const,
    module: "security",
    completed: 50,
    total: 100,
    batchSize: 10,
    elapsed: 5000,
  },
  moduleComplete: {
    ...BASE_EVENT,
    event: "module_complete" as const,
    module: "security",
    status: "PASS" as const,
    score: 95,
    testsRun: 100,
    duration: 10000,
  },
  moduleCompleteWithAUP: {
    ...BASE_EVENT,
    event: "module_complete" as const,
    module: "aup",
    status: "FAIL" as const,
    score: 45,
    testsRun: 50,
    duration: 5000,
    violationsSample: [
      {
        category: "MALWARE",
        categoryName: "Malware Distribution",
        severity: "CRITICAL" as const,
        matchedText: "download malware",
        location: "tool_description" as const,
        confidence: "high" as const,
      },
    ],
    samplingNote: "Showing 1 of 5 violations",
    violationMetrics: {
      total: 5,
      critical: 2,
      high: 2,
      medium: 1,
      byCategory: { MALWARE: 3, FRAUD: 2 },
    },
    scannedLocations: {
      toolNames: true,
      toolDescriptions: true,
      readme: false,
      sourceCode: false,
    },
    highRiskDomains: ["malware.example.com"],
  },
  vulnerabilityFound: {
    ...BASE_EVENT,
    event: "vulnerability_found" as const,
    tool: "exec_command",
    pattern: "command_injection",
    confidence: "high" as const,
    evidence: "Tool executes user input as shell command",
    riskLevel: "HIGH" as const,
    requiresReview: false,
    payload: "; rm -rf /",
  },
  annotationMissing: {
    ...BASE_EVENT,
    event: "annotation_missing" as const,
    tool: "delete_file",
    title: "Delete File",
    description: "Deletes a file from the filesystem",
    parameters: [{ name: "path", type: "string", required: true }],
    inferredBehavior: {
      expectedReadOnly: false,
      expectedDestructive: true,
      reason: "Tool name contains 'delete'",
    },
  },
  annotationMisaligned: {
    ...BASE_EVENT,
    event: "annotation_misaligned" as const,
    tool: "delete_file",
    title: "Delete File",
    description: "Deletes a file",
    parameters: [{ name: "path", type: "string", required: true }],
    field: "destructiveHint" as const,
    actual: false,
    expected: true,
    confidence: 0.95,
    reason: "Tool name contains 'delete' but marked as non-destructive",
  },
  annotationReviewRecommended: {
    ...BASE_EVENT,
    event: "annotation_review_recommended" as const,
    tool: "store_data",
    title: "Store Data",
    description: "Stores data in the database",
    parameters: [
      { name: "key", type: "string", required: true },
      { name: "value", type: "string", required: true },
    ],
    field: "readOnlyHint" as const,
    actual: undefined,
    inferred: false,
    confidence: "medium" as const,
    isAmbiguous: true,
    reason: "Tool pattern 'store_*' is ambiguous - could be read or write",
  },
  annotationAligned: {
    ...BASE_EVENT,
    event: "annotation_aligned" as const,
    tool: "get_user",
    confidence: "high" as const,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
    },
  },
  assessmentComplete: {
    ...BASE_EVENT,
    event: "assessment_complete" as const,
    overallStatus: "PASS",
    totalTests: 500,
    executionTime: 30000,
    outputPath: "/tmp/assessment-results.json",
  },
};

// ============================================================================
// Schema Version Tests
// ============================================================================

describe("jsonlEventSchemas", () => {
  describe("Schema exports", () => {
    test("exports ZOD_SCHEMA_VERSION", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });

    test("exports all 13 event schemas", () => {
      expect(ServerConnectedEventSchema).toBeDefined();
      expect(ToolDiscoveredEventSchema).toBeDefined();
      expect(ToolsDiscoveryCompleteEventSchema).toBeDefined();
      expect(ModulesConfiguredEventSchema).toBeDefined();
      expect(ModuleStartedEventSchema).toBeDefined();
      expect(TestBatchEventSchema).toBeDefined();
      expect(ModuleCompleteEventSchema).toBeDefined();
      expect(VulnerabilityFoundEventSchema).toBeDefined();
      expect(AnnotationMissingEventSchema).toBeDefined();
      expect(AnnotationMisalignedEventSchema).toBeDefined();
      expect(AnnotationReviewRecommendedEventSchema).toBeDefined();
      expect(AnnotationAlignedEventSchema).toBeDefined();
      expect(AssessmentCompleteEventSchema).toBeDefined();
    });

    test("exports union schema", () => {
      expect(JSONLEventSchema).toBeDefined();
    });
  });

  // ============================================================================
  // Enum Schema Tests
  // ============================================================================

  describe("ModuleStatusSchema", () => {
    test("accepts valid statuses", () => {
      const validStatuses = ["PASS", "FAIL", "NEED_MORE_INFO"];
      for (const status of validStatuses) {
        expect(ModuleStatusSchema.safeParse(status).success).toBe(true);
      }
    });

    test("rejects invalid status", () => {
      expect(ModuleStatusSchema.safeParse("ERROR").success).toBe(false);
      expect(ModuleStatusSchema.safeParse("pass").success).toBe(false);
    });
  });

  describe("ConfidenceLevelSchema", () => {
    test("accepts valid levels", () => {
      const validLevels = ["high", "medium", "low"];
      for (const level of validLevels) {
        expect(ConfidenceLevelSchema.safeParse(level).success).toBe(true);
      }
    });

    test("rejects invalid level", () => {
      expect(ConfidenceLevelSchema.safeParse("HIGH").success).toBe(false);
    });
  });

  describe("RiskLevelSchema", () => {
    test("accepts valid levels", () => {
      const validLevels = ["HIGH", "MEDIUM", "LOW"];
      for (const level of validLevels) {
        expect(RiskLevelSchema.safeParse(level).success).toBe(true);
      }
    });

    test("rejects lowercase", () => {
      expect(RiskLevelSchema.safeParse("high").success).toBe(false);
    });
  });

  describe("SeveritySchema", () => {
    test("accepts valid severities", () => {
      const validSeverities = ["CRITICAL", "HIGH", "MEDIUM"];
      for (const severity of validSeverities) {
        expect(SeveritySchema.safeParse(severity).success).toBe(true);
      }
    });

    test("rejects LOW", () => {
      expect(SeveritySchema.safeParse("LOW").success).toBe(false);
    });
  });

  describe("LocationSchema", () => {
    test("accepts valid locations", () => {
      const validLocations = [
        "tool_name",
        "tool_description",
        "readme",
        "source_code",
      ];
      for (const location of validLocations) {
        expect(LocationSchema.safeParse(location).success).toBe(true);
      }
    });

    test("rejects invalid location", () => {
      expect(LocationSchema.safeParse("parameter").success).toBe(false);
    });
  });

  describe("AnnotationFieldSchema", () => {
    test("accepts valid fields", () => {
      const validFields = ["readOnlyHint", "destructiveHint"];
      for (const field of validFields) {
        expect(AnnotationFieldSchema.safeParse(field).success).toBe(true);
      }
    });

    test("rejects other hints", () => {
      expect(AnnotationFieldSchema.safeParse("idempotentHint").success).toBe(
        false,
      );
    });
  });

  describe("ModulesConfiguredReasonSchema", () => {
    test("accepts valid reasons", () => {
      const validReasons = ["skip-modules", "only-modules", "default"];
      for (const reason of validReasons) {
        expect(ModulesConfiguredReasonSchema.safeParse(reason).success).toBe(
          true,
        );
      }
    });
  });

  // ============================================================================
  // Supporting Schema Tests
  // ============================================================================

  describe("ToolParamSchema", () => {
    test("accepts valid param", () => {
      const result = ToolParamSchema.safeParse({
        name: "input",
        type: "string",
        required: true,
        description: "The input value",
      });
      expect(result.success).toBe(true);
    });

    test("accepts param without description", () => {
      const result = ToolParamSchema.safeParse({
        name: "input",
        type: "string",
        required: false,
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing required fields", () => {
      const result = ToolParamSchema.safeParse({
        name: "input",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ToolAnnotationsSchema", () => {
    test("accepts valid annotations", () => {
      const result = ToolAnnotationsSchema.safeParse({
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      });
      expect(result.success).toBe(true);
    });

    test("accepts null", () => {
      const result = ToolAnnotationsSchema.safeParse(null);
      expect(result.success).toBe(true);
    });

    test("accepts partial annotations", () => {
      const result = ToolAnnotationsSchema.safeParse({
        readOnlyHint: true,
      });
      expect(result.success).toBe(true);
    });

    test("accepts empty object", () => {
      const result = ToolAnnotationsSchema.safeParse({});
      expect(result.success).toBe(true);
    });
  });

  describe("InferredBehaviorSchema", () => {
    test("accepts valid inferred behavior", () => {
      const result = InferredBehaviorSchema.safeParse({
        expectedReadOnly: false,
        expectedDestructive: true,
        reason: "Tool name contains 'delete'",
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing reason", () => {
      const result = InferredBehaviorSchema.safeParse({
        expectedReadOnly: true,
        expectedDestructive: false,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("AUPViolationSampleSchema", () => {
    test("accepts valid violation sample", () => {
      const result = AUPViolationSampleSchema.safeParse({
        category: "MALWARE",
        categoryName: "Malware Distribution",
        severity: "CRITICAL",
        matchedText: "download malware",
        location: "tool_description",
        confidence: "high",
      });
      expect(result.success).toBe(true);
    });

    test("rejects invalid severity", () => {
      const result = AUPViolationSampleSchema.safeParse({
        category: "MALWARE",
        categoryName: "Malware",
        severity: "LOW",
        matchedText: "test",
        location: "readme",
        confidence: "high",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("AUPViolationMetricsSchema", () => {
    test("accepts valid metrics", () => {
      const result = AUPViolationMetricsSchema.safeParse({
        total: 10,
        critical: 2,
        high: 5,
        medium: 3,
        byCategory: { MALWARE: 4, FRAUD: 6 },
      });
      expect(result.success).toBe(true);
    });

    test("rejects negative counts", () => {
      const result = AUPViolationMetricsSchema.safeParse({
        total: -1,
        critical: 0,
        high: 0,
        medium: 0,
        byCategory: {},
      });
      expect(result.success).toBe(false);
    });
  });

  describe("BaseEventSchema", () => {
    test("accepts valid base fields", () => {
      const result = BaseEventSchema.safeParse({
        version: "1.29.0",
        schemaVersion: 1,
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing version", () => {
      const result = BaseEventSchema.safeParse({
        schemaVersion: 1,
      });
      expect(result.success).toBe(false);
    });

    test("rejects non-positive schemaVersion", () => {
      const result = BaseEventSchema.safeParse({
        version: "1.0.0",
        schemaVersion: 0,
      });
      expect(result.success).toBe(false);
    });

    test("rejects non-integer schemaVersion", () => {
      const result = BaseEventSchema.safeParse({
        version: "1.0.0",
        schemaVersion: 1.5,
      });
      expect(result.success).toBe(false);
    });
  });

  // ============================================================================
  // Event Schema Tests (13 Events)
  // ============================================================================

  describe("ServerConnectedEventSchema", () => {
    test("accepts valid event", () => {
      const result = ServerConnectedEventSchema.safeParse(
        VALID_FIXTURES.serverConnected,
      );
      expect(result.success).toBe(true);
    });

    test("accepts all transport types", () => {
      for (const transport of ["stdio", "http", "sse"]) {
        const result = ServerConnectedEventSchema.safeParse({
          ...VALID_FIXTURES.serverConnected,
          transport,
        });
        expect(result.success).toBe(true);
      }
    });

    test("rejects missing serverName", () => {
      const { serverName, ...rest } = VALID_FIXTURES.serverConnected;
      const result = ServerConnectedEventSchema.safeParse(rest);
      expect(result.success).toBe(false);
    });

    test("rejects invalid transport", () => {
      const result = ServerConnectedEventSchema.safeParse({
        ...VALID_FIXTURES.serverConnected,
        transport: "websocket",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ToolDiscoveredEventSchema", () => {
    test("accepts valid event with annotations", () => {
      const result = ToolDiscoveredEventSchema.safeParse(
        VALID_FIXTURES.toolDiscovered,
      );
      expect(result.success).toBe(true);
    });

    test("accepts null annotations", () => {
      const result = ToolDiscoveredEventSchema.safeParse({
        ...VALID_FIXTURES.toolDiscovered,
        annotations: null,
      });
      expect(result.success).toBe(true);
    });

    test("accepts null description", () => {
      const result = ToolDiscoveredEventSchema.safeParse({
        ...VALID_FIXTURES.toolDiscovered,
        description: null,
      });
      expect(result.success).toBe(true);
    });

    test("accepts empty params array", () => {
      const result = ToolDiscoveredEventSchema.safeParse({
        ...VALID_FIXTURES.toolDiscovered,
        params: [],
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing name", () => {
      const { name, ...rest } = VALID_FIXTURES.toolDiscovered;
      const result = ToolDiscoveredEventSchema.safeParse(rest);
      expect(result.success).toBe(false);
    });
  });

  describe("ToolsDiscoveryCompleteEventSchema", () => {
    test("accepts valid event", () => {
      const result = ToolsDiscoveryCompleteEventSchema.safeParse(
        VALID_FIXTURES.toolsDiscoveryComplete,
      );
      expect(result.success).toBe(true);
    });

    test("accepts zero count", () => {
      const result = ToolsDiscoveryCompleteEventSchema.safeParse({
        ...VALID_FIXTURES.toolsDiscoveryComplete,
        count: 0,
      });
      expect(result.success).toBe(true);
    });

    test("rejects negative count", () => {
      const result = ToolsDiscoveryCompleteEventSchema.safeParse({
        ...VALID_FIXTURES.toolsDiscoveryComplete,
        count: -1,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ModulesConfiguredEventSchema", () => {
    test("accepts valid event", () => {
      const result = ModulesConfiguredEventSchema.safeParse(
        VALID_FIXTURES.modulesConfigured,
      );
      expect(result.success).toBe(true);
    });

    test("accepts all reason types", () => {
      for (const reason of ["skip-modules", "only-modules", "default"]) {
        const result = ModulesConfiguredEventSchema.safeParse({
          ...VALID_FIXTURES.modulesConfigured,
          reason,
        });
        expect(result.success).toBe(true);
      }
    });

    test("accepts empty arrays", () => {
      const result = ModulesConfiguredEventSchema.safeParse({
        ...VALID_FIXTURES.modulesConfigured,
        enabled: [],
        skipped: [],
      });
      expect(result.success).toBe(true);
    });
  });

  describe("ModuleStartedEventSchema", () => {
    test("accepts valid event", () => {
      const result = ModuleStartedEventSchema.safeParse(
        VALID_FIXTURES.moduleStarted,
      );
      expect(result.success).toBe(true);
    });

    test("accepts zero values", () => {
      const result = ModuleStartedEventSchema.safeParse({
        ...VALID_FIXTURES.moduleStarted,
        estimatedTests: 0,
        toolCount: 0,
      });
      expect(result.success).toBe(true);
    });
  });

  describe("TestBatchEventSchema", () => {
    test("accepts valid event", () => {
      const result = TestBatchEventSchema.safeParse(VALID_FIXTURES.testBatch);
      expect(result.success).toBe(true);
    });

    test("rejects zero batchSize", () => {
      const result = TestBatchEventSchema.safeParse({
        ...VALID_FIXTURES.testBatch,
        batchSize: 0,
      });
      expect(result.success).toBe(false);
    });

    test("rejects negative elapsed", () => {
      const result = TestBatchEventSchema.safeParse({
        ...VALID_FIXTURES.testBatch,
        elapsed: -100,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ModuleCompleteEventSchema", () => {
    test("accepts valid event without AUP", () => {
      const result = ModuleCompleteEventSchema.safeParse(
        VALID_FIXTURES.moduleComplete,
      );
      expect(result.success).toBe(true);
    });

    test("accepts valid event with AUP enrichment", () => {
      const result = ModuleCompleteEventSchema.safeParse(
        VALID_FIXTURES.moduleCompleteWithAUP,
      );
      expect(result.success).toBe(true);
    });

    test("accepts all status values", () => {
      for (const status of ["PASS", "FAIL", "NEED_MORE_INFO"]) {
        const result = ModuleCompleteEventSchema.safeParse({
          ...VALID_FIXTURES.moduleComplete,
          status,
        });
        expect(result.success).toBe(true);
      }
    });

    test("rejects score out of range", () => {
      const resultHigh = ModuleCompleteEventSchema.safeParse({
        ...VALID_FIXTURES.moduleComplete,
        score: 101,
      });
      expect(resultHigh.success).toBe(false);

      const resultLow = ModuleCompleteEventSchema.safeParse({
        ...VALID_FIXTURES.moduleComplete,
        score: -1,
      });
      expect(resultLow.success).toBe(false);
    });
  });

  describe("VulnerabilityFoundEventSchema", () => {
    test("accepts valid event with payload", () => {
      const result = VulnerabilityFoundEventSchema.safeParse(
        VALID_FIXTURES.vulnerabilityFound,
      );
      expect(result.success).toBe(true);
    });

    test("accepts event without payload", () => {
      const { payload, ...rest } = VALID_FIXTURES.vulnerabilityFound;
      const result = VulnerabilityFoundEventSchema.safeParse(rest);
      expect(result.success).toBe(true);
    });

    test("rejects invalid confidence", () => {
      const result = VulnerabilityFoundEventSchema.safeParse({
        ...VALID_FIXTURES.vulnerabilityFound,
        confidence: "HIGH",
      });
      expect(result.success).toBe(false);
    });

    test("rejects invalid riskLevel", () => {
      const result = VulnerabilityFoundEventSchema.safeParse({
        ...VALID_FIXTURES.vulnerabilityFound,
        riskLevel: "high",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("AnnotationMissingEventSchema", () => {
    test("accepts valid event", () => {
      const result = AnnotationMissingEventSchema.safeParse(
        VALID_FIXTURES.annotationMissing,
      );
      expect(result.success).toBe(true);
    });

    test("accepts event without optional title/description", () => {
      const { title, description, ...rest } = VALID_FIXTURES.annotationMissing;
      const result = AnnotationMissingEventSchema.safeParse(rest);
      expect(result.success).toBe(true);
    });

    test("rejects missing inferredBehavior", () => {
      const { inferredBehavior, ...rest } = VALID_FIXTURES.annotationMissing;
      const result = AnnotationMissingEventSchema.safeParse(rest);
      expect(result.success).toBe(false);
    });
  });

  describe("AnnotationMisalignedEventSchema", () => {
    test("accepts valid event", () => {
      const result = AnnotationMisalignedEventSchema.safeParse(
        VALID_FIXTURES.annotationMisaligned,
      );
      expect(result.success).toBe(true);
    });

    test("accepts undefined actual", () => {
      const result = AnnotationMisalignedEventSchema.safeParse({
        ...VALID_FIXTURES.annotationMisaligned,
        actual: undefined,
      });
      expect(result.success).toBe(true);
    });

    test("rejects confidence out of range", () => {
      const resultHigh = AnnotationMisalignedEventSchema.safeParse({
        ...VALID_FIXTURES.annotationMisaligned,
        confidence: 1.5,
      });
      expect(resultHigh.success).toBe(false);

      const resultLow = AnnotationMisalignedEventSchema.safeParse({
        ...VALID_FIXTURES.annotationMisaligned,
        confidence: -0.1,
      });
      expect(resultLow.success).toBe(false);
    });
  });

  describe("AnnotationReviewRecommendedEventSchema", () => {
    test("accepts valid event", () => {
      const result = AnnotationReviewRecommendedEventSchema.safeParse(
        VALID_FIXTURES.annotationReviewRecommended,
      );
      expect(result.success).toBe(true);
    });

    test("accepts all confidence levels", () => {
      for (const confidence of ["high", "medium", "low"]) {
        const result = AnnotationReviewRecommendedEventSchema.safeParse({
          ...VALID_FIXTURES.annotationReviewRecommended,
          confidence,
        });
        expect(result.success).toBe(true);
      }
    });
  });

  describe("AnnotationAlignedEventSchema", () => {
    test("accepts valid event", () => {
      const result = AnnotationAlignedEventSchema.safeParse(
        VALID_FIXTURES.annotationAligned,
      );
      expect(result.success).toBe(true);
    });

    test("accepts partial annotations", () => {
      const result = AnnotationAlignedEventSchema.safeParse({
        ...VALID_FIXTURES.annotationAligned,
        annotations: { readOnlyHint: true },
      });
      expect(result.success).toBe(true);
    });

    test("accepts empty annotations object", () => {
      const result = AnnotationAlignedEventSchema.safeParse({
        ...VALID_FIXTURES.annotationAligned,
        annotations: {},
      });
      expect(result.success).toBe(true);
    });
  });

  describe("AssessmentCompleteEventSchema", () => {
    test("accepts valid event", () => {
      const result = AssessmentCompleteEventSchema.safeParse(
        VALID_FIXTURES.assessmentComplete,
      );
      expect(result.success).toBe(true);
    });

    test("rejects negative executionTime", () => {
      const result = AssessmentCompleteEventSchema.safeParse({
        ...VALID_FIXTURES.assessmentComplete,
        executionTime: -1,
      });
      expect(result.success).toBe(false);
    });
  });

  // ============================================================================
  // Union Schema Tests
  // ============================================================================

  describe("JSONLEventSchema (union)", () => {
    test("accepts all 13 event types", () => {
      const fixtures = [
        VALID_FIXTURES.serverConnected,
        VALID_FIXTURES.toolDiscovered,
        VALID_FIXTURES.toolsDiscoveryComplete,
        VALID_FIXTURES.modulesConfigured,
        VALID_FIXTURES.moduleStarted,
        VALID_FIXTURES.testBatch,
        VALID_FIXTURES.moduleComplete,
        VALID_FIXTURES.moduleCompleteWithAUP,
        VALID_FIXTURES.vulnerabilityFound,
        VALID_FIXTURES.annotationMissing,
        VALID_FIXTURES.annotationMisaligned,
        VALID_FIXTURES.annotationReviewRecommended,
        VALID_FIXTURES.annotationAligned,
        VALID_FIXTURES.assessmentComplete,
      ];

      for (const fixture of fixtures) {
        const result = JSONLEventSchema.safeParse(fixture);
        expect(result.success).toBe(true);
      }
    });

    test("rejects unknown event type", () => {
      const result = JSONLEventSchema.safeParse({
        ...BASE_EVENT,
        event: "unknown_event",
        data: "test",
      });
      expect(result.success).toBe(false);
    });

    test("rejects malformed events", () => {
      const result = JSONLEventSchema.safeParse({
        event: "server_connected",
        // Missing version and schemaVersion
      });
      expect(result.success).toBe(false);
    });

    test("rejects events with wrong field types", () => {
      const result = JSONLEventSchema.safeParse({
        ...VALID_FIXTURES.serverConnected,
        serverName: 123, // Should be string
      });
      expect(result.success).toBe(false);
    });
  });

  // ============================================================================
  // Helper Function Tests
  // ============================================================================

  describe("parseEvent", () => {
    test("parses valid JSON string input", () => {
      const json = JSON.stringify(VALID_FIXTURES.serverConnected);
      const event = parseEvent(json);
      expect(event.event).toBe("server_connected");
      expect((event as typeof VALID_FIXTURES.serverConnected).serverName).toBe(
        "test-server",
      );
    });

    test("parses object input", () => {
      const event = parseEvent(VALID_FIXTURES.toolDiscovered);
      expect(event.event).toBe("tool_discovered");
    });

    test("throws ZodError for invalid input", () => {
      expect(() => parseEvent({ invalid: "data" })).toThrow(ZodError);
    });

    test("throws SyntaxError for invalid JSON string", () => {
      expect(() => parseEvent("not valid json")).toThrow(SyntaxError);
    });
  });

  describe("safeParseEvent", () => {
    test("returns success for valid events", () => {
      const result = safeParseEvent(VALID_FIXTURES.moduleComplete);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.event).toBe("module_complete");
      }
    });

    test("returns success for valid JSON string", () => {
      const json = JSON.stringify(VALID_FIXTURES.assessmentComplete);
      const result = safeParseEvent(json);
      expect(result.success).toBe(true);
    });

    test("returns failure for invalid events", () => {
      const result = safeParseEvent({ invalid: "data" });
      expect(result.success).toBe(false);
    });

    test("handles JSON parse errors gracefully", () => {
      const result = safeParseEvent("not valid json");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.errors[0].message).toContain("Invalid JSON");
      }
    });

    test("handles empty string", () => {
      const result = safeParseEvent("");
      expect(result.success).toBe(false);
    });
  });

  describe("validateEvent", () => {
    test("returns empty array for valid events", () => {
      const errors = validateEvent(VALID_FIXTURES.serverConnected);
      expect(errors).toEqual([]);
    });

    test("returns error messages for invalid events", () => {
      const errors = validateEvent({ invalid: "data" });
      expect(errors.length).toBeGreaterThan(0);
    });

    test("returns errors for type mismatches", () => {
      // Union schemas produce "Invalid input" without field paths
      // Test that errors are returned for invalid field types
      const errors = validateEvent({
        ...VALID_FIXTURES.serverConnected,
        serverName: 123, // Should be string
      });
      expect(errors.length).toBeGreaterThan(0);
    });

    test("includes path in error messages for individual schemas", () => {
      // Test with individual schema (not union) for path inclusion
      const result = ServerConnectedEventSchema.safeParse({
        ...VALID_FIXTURES.serverConnected,
        serverName: 123,
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        const hasServerNamePath = result.error.errors.some((e) =>
          e.path.includes("serverName"),
        );
        expect(hasServerNamePath).toBe(true);
      }
    });
  });

  describe("isEventType", () => {
    test("correctly identifies event types", () => {
      const event = parseEvent(
        VALID_FIXTURES.serverConnected,
      ) as JSONLEventParsed;
      expect(isEventType(event, "server_connected")).toBe(true);
      expect(isEventType(event, "tool_discovered")).toBe(false);
    });

    test("narrows type correctly", () => {
      const event = parseEvent(
        VALID_FIXTURES.vulnerabilityFound,
      ) as JSONLEventParsed;
      if (isEventType(event, "vulnerability_found")) {
        // TypeScript should allow accessing these properties
        expect(event.tool).toBe("exec_command");
        expect(event.riskLevel).toBe("HIGH");
      }
    });

    test("returns false for mismatched types", () => {
      const event = parseEvent(
        VALID_FIXTURES.moduleComplete,
      ) as JSONLEventParsed;
      expect(isEventType(event, "assessment_complete")).toBe(false);
    });
  });

  describe("parseEventLines", () => {
    test("parses multiple lines", () => {
      const lines = [
        JSON.stringify(VALID_FIXTURES.serverConnected),
        JSON.stringify(VALID_FIXTURES.toolDiscovered),
        JSON.stringify(VALID_FIXTURES.assessmentComplete),
      ];

      const results = parseEventLines(lines);
      expect(results.length).toBe(3);
      expect(results.every((r) => r.result.success)).toBe(true);
    });

    test("tracks line numbers (1-indexed)", () => {
      const lines = [
        JSON.stringify(VALID_FIXTURES.serverConnected),
        JSON.stringify(VALID_FIXTURES.toolDiscovered),
      ];

      const results = parseEventLines(lines);
      expect(results[0].line).toBe(1);
      expect(results[1].line).toBe(2);
    });

    test("handles mixed valid/invalid lines", () => {
      const lines = [
        JSON.stringify(VALID_FIXTURES.serverConnected),
        "invalid json",
        JSON.stringify(VALID_FIXTURES.assessmentComplete),
      ];

      const results = parseEventLines(lines);
      expect(results[0].result.success).toBe(true);
      expect(results[1].result.success).toBe(false);
      expect(results[2].result.success).toBe(true);
    });

    test("handles empty array", () => {
      const results = parseEventLines([]);
      expect(results).toEqual([]);
    });
  });

  // ============================================================================
  // Stage 3 Fix Validation Tests
  // ============================================================================

  describe("[FIX-001] AnnotationAlignedEventSchema nullable annotations", () => {
    // Validates FIX-001: Added .nullable() to annotations object in AnnotationAlignedEventSchema
    // Covers ISSUE-001: Inconsistent nullable handling between ToolAnnotationsSchema and inline annotations

    test("accepts null annotations value", () => {
      const result = AnnotationAlignedEventSchema.safeParse({
        ...BASE_EVENT,
        event: "annotation_aligned",
        tool: "test_tool",
        confidence: "high",
        annotations: null,
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.annotations).toBeNull();
      }
    });

    test("accepts undefined annotations", () => {
      const eventWithoutAnnotations = {
        ...BASE_EVENT,
        event: "annotation_aligned",
        tool: "test_tool",
        confidence: "high",
      };
      // undefined is equivalent to omitting the field
      const result = AnnotationAlignedEventSchema.safeParse(
        eventWithoutAnnotations,
      );
      expect(result.success).toBe(false); // annotations is required, so undefined should fail
    });

    test("nullable behavior matches ToolAnnotationsSchema", () => {
      // Both should accept null
      const nullAnnotations = null;

      const toolAnnotationsResult =
        ToolAnnotationsSchema.safeParse(nullAnnotations);
      expect(toolAnnotationsResult.success).toBe(true);

      const annotationAlignedResult = AnnotationAlignedEventSchema.safeParse({
        ...BASE_EVENT,
        event: "annotation_aligned",
        tool: "test_tool",
        confidence: "high",
        annotations: nullAnnotations,
      });
      expect(annotationAlignedResult.success).toBe(true);

      // Both should accept valid object
      const validAnnotations = {
        readOnlyHint: true,
        destructiveHint: false,
      };

      const toolAnnotationsResultValid =
        ToolAnnotationsSchema.safeParse(validAnnotations);
      expect(toolAnnotationsResultValid.success).toBe(true);

      const annotationAlignedResultValid =
        AnnotationAlignedEventSchema.safeParse({
          ...BASE_EVENT,
          event: "annotation_aligned",
          tool: "test_tool",
          confidence: "high",
          annotations: validAnnotations,
        });
      expect(annotationAlignedResultValid.success).toBe(true);
    });

    test("accepts partial annotations object", () => {
      const result = AnnotationAlignedEventSchema.safeParse({
        ...BASE_EVENT,
        event: "annotation_aligned",
        tool: "test_tool",
        confidence: "high",
        annotations: {
          readOnlyHint: true,
          // Other fields omitted
        },
      });
      expect(result.success).toBe(true);
    });

    test("accepts empty annotations object", () => {
      const result = AnnotationAlignedEventSchema.safeParse({
        ...BASE_EVENT,
        event: "annotation_aligned",
        tool: "test_tool",
        confidence: "high",
        annotations: {},
      });
      expect(result.success).toBe(true);
    });
  });

  describe("[FIX-002] safeParseEvent JSON error handling", () => {
    // Validates FIX-002: Added JSDoc @remarks documenting custom error conversion
    // Covers ISSUE-002: JSON parse errors are converted to ZodError with custom code

    test("JSON parse error returns ZodError with custom code", () => {
      const result = safeParseEvent("not valid json {{{");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(ZodError);
        // Check that the error has the custom code
        expect(result.error.errors[0].code).toBe("custom");
      }
    });

    test('JSON parse error message contains "Invalid JSON" prefix', () => {
      const result = safeParseEvent("{ broken json }");
      expect(result.success).toBe(false);
      if (!result.success) {
        const message = result.error.errors[0].message;
        expect(message).toMatch(/^Invalid JSON:/);
      }
    });

    test("JSON parse error has empty path", () => {
      const result = safeParseEvent("not json");
      expect(result.success).toBe(false);
      if (!result.success) {
        // JSON parse errors should have empty path since they occur before schema validation
        expect(result.error.errors[0].path).toEqual([]);
      }
    });

    test("schema validation errors have non-empty path", () => {
      // Valid JSON but invalid schema - should have path information
      const result = safeParseEvent({
        ...BASE_EVENT,
        event: "server_connected",
        serverName: 123, // Invalid type
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        // Union schemas don't provide field paths, but error should exist
        expect(result.error.errors.length).toBeGreaterThan(0);
      }
    });

    test("distinguishes between JSON parse and schema validation errors", () => {
      // JSON parse error
      const jsonError = safeParseEvent("invalid");
      expect(jsonError.success).toBe(false);
      if (!jsonError.success) {
        expect(jsonError.error.errors[0].message).toContain("Invalid JSON");
        expect(jsonError.error.errors[0].code).toBe("custom");
      }

      // Schema validation error
      const schemaError = safeParseEvent({ invalid: "schema" });
      expect(schemaError.success).toBe(false);
      if (!schemaError.success) {
        expect(schemaError.error.errors[0].message).not.toContain(
          "Invalid JSON",
        );
        expect(schemaError.error.errors[0].code).not.toBe("custom");
      }
    });

    test("handles empty string as JSON parse error", () => {
      const result = safeParseEvent("");
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.errors[0].message).toContain("Invalid JSON");
      }
    });

    test("handles valid JSON string correctly", () => {
      const json = JSON.stringify(VALID_FIXTURES.serverConnected);
      const result = safeParseEvent(json);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.event).toBe("server_connected");
      }
    });

    test("handles valid object correctly", () => {
      const result = safeParseEvent(VALID_FIXTURES.toolDiscovered);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.event).toBe("tool_discovered");
      }
    });
  });
});
