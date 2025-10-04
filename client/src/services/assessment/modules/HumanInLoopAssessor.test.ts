import { HumanInLoopAssessor } from "./HumanInLoopAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("HumanInLoopAssessor", () => {
  let assessor: HumanInLoopAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new HumanInLoopAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess human-in-the-loop with comprehensive oversight", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        metadata: {
          humanOversight: {
            preExecutionReview: true,
            postExecutionReview: true,
            continuousMonitoring: true,
            reviewThresholds: ["high-risk", "sensitive-data", "financial"],
            overrideCapabilities: ["cancel", "modify", "revert", "pause"],
            auditLogging: true,
            emergencyControls: {
              killSwitch: true,
              safeModeAvailable: true,
              manualOverride: true,
            },
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.category).toBe("humanInLoop");
      expect(result.status).toBe("PASS");
      expect(result.score).toBeGreaterThan(90);
      expect(result.reviewMechanisms.preExecution).toBe(true);
      expect(result.reviewMechanisms.postExecution).toBe(true);
      expect(result.reviewMechanisms.continuous).toBe(true);
      expect(result.overrideCapabilities.canCancel).toBe(true);
      expect(result.emergencyControls.killSwitch).toBe(true);
    });

    it("should detect missing review mechanisms", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        metadata: {
          humanOversight: {
            preExecutionReview: false,
            postExecutionReview: false,
            continuousMonitoring: false,
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.preExecution).toBe(false);
      expect(result.reviewMechanisms.postExecution).toBe(false);
      expect(result.reviewMechanisms.continuous).toBe(false);
      expect(result.criticalFindings).toContain(
        "No review mechanisms detected",
      );
      expect(result.status).toBe("FAIL");
      expect(result.score).toBeLessThan(40);
    });

    it("should assess override capabilities", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        metadata: {
          humanOversight: {
            overrideCapabilities: ["cancel", "pause"],
            emergencyStopAvailable: true,
            modificationAllowed: false,
            revertCapability: false,
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.overrideCapabilities.canCancel).toBe(true);
      expect(result.overrideCapabilities.canPause).toBe(true);
      expect(result.overrideCapabilities.canModify).toBe(false);
      expect(result.overrideCapabilities.canRevert).toBe(false);
      expect(result.criticalFindings).toContain(
        "Limited override capabilities",
      );
    });

    it("should evaluate transparency features", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        metadata: {
          transparency: {
            explainableOutputs: true,
            decisionRationale: true,
            confidenceScores: true,
            auditLogging: true,
            traceabilityEnabled: true,
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transparency.explainability).toBe(true);
      expect(result.transparency.decisionVisibility).toBe(true);
      expect(result.transparency.confidenceScores).toBe(true);
      expect(result.transparency.auditLogging).toBe(true);
      expect(result.transparency.features).toContain("explainable_outputs");
      expect(result.transparency.features).toContain("confidence_scores");
    });

    it("should assess audit trail capabilities", async () => {
      // Arrange
      mockContext.serverInfo = {
        auditTrail: {
          comprehensive: true,
          immutable: true,
          searchable: true,
          retentionPeriod: "7 years",
          tamperEvident: true,
          realTimeLogging: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.auditTrail.comprehensive).toBe(true);
      expect(result.auditTrail.immutable).toBe(true);
      expect(result.auditTrail.searchable).toBe(true);
      expect(result.auditTrail.retention).toBe("7 years");
      expect(result.auditTrail.features).toContain("tamper_evident");
      expect(result.auditTrail.features).toContain("real_time_logging");
    });

    it("should detect inadequate audit trail", async () => {
      // Arrange
      mockContext.serverInfo = {
        auditTrail: {
          comprehensive: false,
          immutable: false,
          searchable: false,
          retentionPeriod: "none",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.auditTrail.comprehensive).toBe(false);
      expect(result.auditTrail.immutable).toBe(false);
      expect(result.auditTrail.searchable).toBe(false);
      expect(result.criticalFindings).toContain("Inadequate audit trail");
      expect(result.criticalFindings).toContain("No data retention policy");
      expect(result.status).toBe("FAIL");
    });

    it("should evaluate emergency control systems", async () => {
      // Arrange
      mockContext.serverInfo = {
        emergencyControls: {
          killSwitch: true,
          safeModeAvailable: true,
          fallbackMechanisms: true,
          manualOverride: true,
          isolationCapability: true,
          gracefulShutdown: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.emergencyControls.killSwitch).toBe(true);
      expect(result.emergencyControls.safeModeAvailable).toBe(true);
      expect(result.emergencyControls.fallbackMechanisms).toBe(true);
      expect(result.emergencyControls.manualOverride).toBe(true);
      expect(result.emergencyControls.controls).toContain("isolation");
      expect(result.emergencyControls.controls).toContain("graceful_shutdown");
    });

    it("should detect missing emergency controls", async () => {
      // Arrange
      mockContext.serverInfo = {
        emergencyControls: {
          killSwitch: false,
          safeModeAvailable: false,
          fallbackMechanisms: false,
          manualOverride: false,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.emergencyControls.killSwitch).toBe(false);
      expect(result.emergencyControls.safeModeAvailable).toBe(false);
      expect(result.emergencyControls.fallbackMechanisms).toBe(false);
      expect(result.emergencyControls.manualOverride).toBe(false);
      expect(result.criticalFindings).toContain(
        "No emergency controls available",
      );
      expect(result.criticalFindings).toContain("No kill switch mechanism");
      expect(result.status).toBe("FAIL");
    });

    it("should test human intervention triggers", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Simulate scenarios that should trigger human intervention
        if (params.operation === "delete_all_data") {
          return createMockCallToolResponse(
            "Human approval required for destructive operation",
            true,
          );
        }
        if (params.confidenceLevel < 0.5) {
          return createMockCallToolResponse(
            "Low confidence - human review needed",
            true,
          );
        }
        if (params.sensitiveData === true) {
          return createMockCallToolResponse(
            "Sensitive data detected - manual review required",
            true,
          );
        }
        return createMockCallToolResponse(
          "Operation completed automatically",
          false,
        );
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.mechanisms).toContain(
        "destructive_operations",
      );
      expect(result.reviewMechanisms.mechanisms).toContain("low_confidence");
      expect(result.reviewMechanisms.mechanisms).toContain("sensitive_data");
      expect(result.score).toBeGreaterThan(70);
    });

    it("should evaluate decision transparency", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return createMockCallToolResponse(
          {
            result: "Operation completed",
            confidence: 0.85,
            reasoning: "Based on pattern analysis and historical data",
            alternatives: ["option_a", "option_b"],
            risk_factors: ["none identified"],
            human_review_recommended: false,
          },
          false,
        );
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transparency.explainability).toBe(true);
      expect(result.transparency.confidenceScores).toBe(true);
      expect(result.transparency.decisionVisibility).toBe(true);
      expect(result.transparency.features).toContain("reasoning_provided");
      expect(result.transparency.features).toContain("alternatives_considered");
    });

    it("should assess escalation mechanisms", async () => {
      // Arrange
      mockContext.serverInfo = {
        escalation: {
          automatedEscalation: true,
          escalationLevels: ["supervisor", "manager", "executive"],
          escalationTriggers: [
            "high_risk",
            "anomaly_detected",
            "error_threshold",
          ],
          responseTimeRequirements: {
            level_1: "1 hour",
            level_2: "4 hours",
            level_3: "24 hours",
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.mechanisms).toContain(
        "escalation_available",
      );
      expect(result.recommendations).toContain(
        "Escalation mechanisms properly configured",
      );
      expect(result.score).toBeGreaterThan(80);
    });

    it("should detect human review bypass attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Simulate attempts to bypass human review
        if (params.bypassReview === true) {
          return createMockCallToolResponse(
            "Review bypassed - potential security risk",
            false,
          );
        }
        if (params.urgentOverride === true) {
          return createMockCallToolResponse(
            "Urgent override used - audit required",
            false,
          );
        }
        return createMockCallToolResponse("Normal operation", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain("Human review bypass detected");
      expect(result.auditTrail.features).toContain("bypass_tracking");
      expect(result.status).toBe("FAIL");
    });

    it("should evaluate training and competency requirements", async () => {
      // Arrange
      mockContext.serverInfo = {
        humanCompetency: {
          trainingRequired: true,
          certificationNeeded: true,
          competencyAssessment: true,
          continuingEducation: true,
          specializedRoles: [
            "ai_reviewer",
            "safety_monitor",
            "compliance_officer",
          ],
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.mechanisms).toContain("trained_reviewers");
      expect(result.recommendations).toContain(
        "Human reviewer competency verified",
      );
      expect(result.score).toBeGreaterThan(85);
    });

    it("should assess real-time monitoring capabilities", async () => {
      // Arrange
      mockContext.serverInfo = {
        realTimeMonitoring: {
          enabled: true,
          dashboards: true,
          alerting: true,
          thresholds: {
            performance_degradation: "10%",
            error_rate: "1%",
            anomaly_score: "0.8",
          },
          responseAutomation: false, // Requires human intervention
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.continuous).toBe(true);
      expect(result.transparency.features).toContain("real_time_monitoring");
      expect(result.recommendations).toContain("Real-time monitoring active");
    });

    it("should evaluate human-AI collaboration patterns", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Simulate collaborative decision making
        if (params.collaborationMode === "human_ai_pair") {
          return createMockCallToolResponse(
            {
              result: "Decision made collaboratively",
              human_input_weight: 0.6,
              ai_recommendation_weight: 0.4,
              consensus_reached: true,
              disagreement_resolution: "human_preference",
            },
            false,
          );
        }
        return createMockCallToolResponse("AI-only decision", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.reviewMechanisms.mechanisms).toContain(
        "human_ai_collaboration",
      );
      expect(result.transparency.features).toContain("collaboration_metrics");
      expect(result.score).toBeGreaterThan(75);
    });

    it("should calculate comprehensive human oversight score", async () => {
      // Arrange - mixed oversight profile
      mockContext.serverInfo = {
        humanOversight: {
          preExecutionReview: true, // Good
          postExecutionReview: false, // Missing
          continuousMonitoring: true, // Good
        },
        overrideCapabilities: ["cancel"], // Limited
        auditLogging: true, // Good
        emergencyControls: {
          killSwitch: false, // Missing
          safeModeAvailable: true, // Good
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.score).toBeGreaterThan(40);
      expect(result.score).toBeLessThan(80);
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.criticalFindings.length).toBeGreaterThan(2);
    });

    it("should provide human oversight recommendations", async () => {
      // Arrange
      mockContext.serverInfo = {
        humanOversight: {
          preExecutionReview: false,
          auditLogging: false,
          emergencyControls: { killSwitch: false },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContain(
        "Implement pre-execution review",
      );
      expect(result.recommendations).toContain(
        "Enable comprehensive audit logging",
      );
      expect(result.recommendations).toContain("Add emergency kill switch");
      expect(result.recommendations).toContain(
        "Establish human oversight protocols",
      );
      expect(result.recommendations.length).toBeGreaterThan(3);
    });

    it("should handle fully automated systems", async () => {
      // Arrange
      mockContext.serverInfo = {
        automationLevel: "fully_automated",
        humanOversight: {
          preExecutionReview: false,
          postExecutionReview: false,
          continuousMonitoring: false,
          emergencyControls: { killSwitch: false },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.score).toBeLessThan(30);
      expect(result.criticalFindings).toContain(
        "Fully automated with no human oversight",
      );
      expect(result.explanation).toContain("No human oversight detected");
    });
  });

  describe("edge cases", () => {
    it("should handle missing human oversight configuration", async () => {
      // Arrange
      mockContext.serverInfo = {};

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.criticalFindings).toContain(
        "No human oversight configuration",
      );
      expect(result.score).toBe(0);
    });

    it("should detect conflicting oversight policies", async () => {
      // Arrange
      mockContext.serverInfo = {
        humanOversight: {
          required: true,
          enabled: false, // Conflict
        },
        automationLevel: "human_supervised",
        actualImplementation: "fully_automated", // Another conflict
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain(
        "Conflicting oversight policies",
      );
      expect(result.status).toBe("FAIL");
    });

    it("should handle malformed oversight configuration", async () => {
      // Arrange
      mockContext.serverInfo = {
        humanOversight: "invalid_config",
        emergencyControls: null,
        auditTrail: undefined,
      } as any;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.criticalFindings).toContain(
        "Malformed oversight configuration",
      );
    });

    it("should test emergency control effectiveness", async () => {
      // Arrange
      let emergencyActivated = false;

      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.emergency === true) {
          emergencyActivated = true;
          return createMockCallToolResponse("Emergency stop activated", false);
        }
        if (emergencyActivated) {
          return createMockCallToolResponse("System in safe mode", false);
        }
        return createMockCallToolResponse("Normal operation", false);
      });

      mockContext.serverInfo = {
        emergencyControls: {
          killSwitch: true,
          testable: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.emergencyControls.killSwitch).toBe(true);
      expect(result.recommendations).toContain(
        "Emergency controls tested successfully",
      );
    });
  });
});
