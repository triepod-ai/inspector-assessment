/**
 * Human-in-the-Loop Assessor Module
 * Evaluates human oversight, review mechanisms, and control capabilities
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentStatus } from "@/lib/assessmentTypes";

export interface HumanInLoopAssessment {
  category: "humanInLoop";
  status: AssessmentStatus;
  score: number;
  reviewMechanisms: {
    preExecution: boolean;
    postExecution: boolean;
    continuous: boolean;
    mechanisms: string[];
  };
  overrideCapabilities: {
    canCancel: boolean;
    canModify: boolean;
    canRevert: boolean;
    canPause: boolean;
    capabilities: string[];
  };
  transparency: {
    explainability: boolean;
    auditLogging: boolean;
    decisionVisibility: boolean;
    confidenceScores: boolean;
    features: string[];
  };
  auditTrail: {
    comprehensive: boolean;
    immutable: boolean;
    searchable: boolean;
    retention: string;
    features: string[];
  };
  emergencyControls: {
    killSwitch: boolean;
    safeModeAvailable: boolean;
    fallbackMechanisms: boolean;
    manualOverride: boolean;
    controls: string[];
  };
  criticalFindings: string[];
  recommendations: string[];
  explanation: string;
}

export class HumanInLoopAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<HumanInLoopAssessment> {
    this.log("Starting human-in-the-loop assessment");

    const reviewMechanisms = await this.assessReviewMechanisms(context);
    const overrideCapabilities = await this.assessOverrideCapabilities(context);
    const transparency = await this.assessTransparency(context);
    const auditTrail = await this.assessAuditTrail(context);
    const emergencyControls = await this.assessEmergencyControls(context);

    const score = this.calculateHumanInLoopScore(
      reviewMechanisms,
      overrideCapabilities,
      transparency,
      auditTrail,
      emergencyControls,
    );

    const status = this.determineStatus(score, 100, 70);

    const criticalFindings = this.identifyCriticalFindings(
      reviewMechanisms,
      overrideCapabilities,
      transparency,
      auditTrail,
      emergencyControls,
    );

    const recommendations = this.generateRecommendations(
      reviewMechanisms,
      overrideCapabilities,
      transparency,
      auditTrail,
      emergencyControls,
    );

    const explanation = this.generateExplanation(
      reviewMechanisms,
      overrideCapabilities,
      transparency,
      auditTrail,
      emergencyControls,
    );

    return {
      category: "humanInLoop",
      status,
      score,
      reviewMechanisms,
      overrideCapabilities,
      transparency,
      auditTrail,
      emergencyControls,
      criticalFindings,
      recommendations,
      explanation,
    };
  }

  private async assessReviewMechanisms(context: AssessmentContext): Promise<{
    preExecution: boolean;
    postExecution: boolean;
    continuous: boolean;
    mechanisms: string[];
  }> {
    this.log("Assessing review mechanisms");

    const mechanisms = {
      preExecution: false,
      postExecution: false,
      continuous: false,
      mechanisms: [] as string[],
    };

    // Check for review-related tools and features
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Pre-execution review
      if (
        name.includes("preview") ||
        desc.includes("preview") ||
        name.includes("confirm") ||
        desc.includes("confirm") ||
        name.includes("approve") ||
        desc.includes("approval")
      ) {
        mechanisms.preExecution = true;
        mechanisms.mechanisms.push("Pre-execution approval");
      }

      // Post-execution review
      if (
        name.includes("review") ||
        desc.includes("review") ||
        name.includes("validate") ||
        desc.includes("validate")
      ) {
        mechanisms.postExecution = true;
        mechanisms.mechanisms.push("Post-execution review");
      }

      // Continuous monitoring
      if (
        name.includes("monitor") ||
        desc.includes("monitor") ||
        name.includes("watch") ||
        desc.includes("watch") ||
        name.includes("observe") ||
        desc.includes("observe")
      ) {
        mechanisms.continuous = true;
        mechanisms.mechanisms.push("Continuous monitoring");
      }

      // Specific review mechanisms
      if (desc.includes("human review")) {
        mechanisms.mechanisms.push("Explicit human review requirement");
      }

      if (desc.includes("queue") || desc.includes("pending")) {
        mechanisms.mechanisms.push("Review queue system");
      }

      if (desc.includes("flag") || desc.includes("alert")) {
        mechanisms.mechanisms.push("Flagging system for review");
      }
    }

    // Check server metadata for review features
    if (context.serverInfo?.metadata) {
      const metadata = JSON.stringify(
        context.serverInfo.metadata,
      ).toLowerCase();

      if (metadata.includes("review") || metadata.includes("approval")) {
        if (!mechanisms.preExecution && metadata.includes("before")) {
          mechanisms.preExecution = true;
        }
        if (!mechanisms.postExecution && metadata.includes("after")) {
          mechanisms.postExecution = true;
        }
      }
    }

    return mechanisms;
  }

  private async assessOverrideCapabilities(
    context: AssessmentContext,
  ): Promise<{
    canCancel: boolean;
    canModify: boolean;
    canRevert: boolean;
    canPause: boolean;
    capabilities: string[];
  }> {
    this.log("Assessing override capabilities");

    const capabilities = {
      canCancel: false,
      canModify: false,
      canRevert: false,
      canPause: false,
      capabilities: [] as string[],
    };

    // Check serverInfo metadata for override configuration
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const oversightConfig = metadata?.humanOversight as
      | Record<string, unknown>
      | undefined;
    if (oversightConfig) {
      const overrideCaps = oversightConfig.overrideCapabilities as
        | string[]
        | undefined;
      if (overrideCaps) {
        if (overrideCaps.includes("cancel")) {
          capabilities.canCancel = true;
          capabilities.capabilities.push("Cancel operations");
        }
        if (overrideCaps.includes("pause")) {
          capabilities.canPause = true;
          capabilities.capabilities.push("Pause operations");
        }
        if (overrideCaps.includes("modify")) {
          capabilities.canModify = true;
          capabilities.capabilities.push("Modify operations");
        }
        if (overrideCaps.includes("revert")) {
          capabilities.canRevert = true;
          capabilities.capabilities.push("Revert changes");
        }
      }
      if (oversightConfig.modificationAllowed) {
        capabilities.canModify = true;
        if (!capabilities.capabilities.includes("Modify operations")) {
          capabilities.capabilities.push("Modify operations");
        }
      }
      if (oversightConfig.revertCapability) {
        capabilities.canRevert = true;
        if (!capabilities.capabilities.includes("Revert changes")) {
          capabilities.capabilities.push("Revert changes");
        }
      }
    }

    // Check for override-related tools
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Cancellation capability
      if (
        name.includes("cancel") ||
        desc.includes("cancel") ||
        name.includes("stop") ||
        desc.includes("stop") ||
        name.includes("abort") ||
        desc.includes("abort")
      ) {
        capabilities.canCancel = true;
        capabilities.capabilities.push("Cancel operations");
      }

      // Modification capability
      if (
        name.includes("modify") ||
        desc.includes("modify") ||
        name.includes("edit") ||
        desc.includes("edit") ||
        name.includes("update") ||
        desc.includes("update")
      ) {
        capabilities.canModify = true;
        capabilities.capabilities.push("Modify operations");
      }

      // Revert capability
      if (
        name.includes("revert") ||
        desc.includes("revert") ||
        name.includes("rollback") ||
        desc.includes("rollback") ||
        name.includes("undo") ||
        desc.includes("undo")
      ) {
        capabilities.canRevert = true;
        capabilities.capabilities.push("Revert changes");
      }

      // Pause capability
      if (
        name.includes("pause") ||
        desc.includes("pause") ||
        name.includes("suspend") ||
        desc.includes("suspend") ||
        name.includes("hold") ||
        desc.includes("hold")
      ) {
        capabilities.canPause = true;
        capabilities.capabilities.push("Pause operations");
      }

      // Additional override capabilities
      if (desc.includes("override")) {
        capabilities.capabilities.push("Manual override");
      }

      if (desc.includes("force") || desc.includes("bypass")) {
        capabilities.capabilities.push("Force/bypass controls");
      }
    }

    return capabilities;
  }

  private async assessTransparency(context: AssessmentContext): Promise<{
    explainability: boolean;
    auditLogging: boolean;
    decisionVisibility: boolean;
    confidenceScores: boolean;
    features: string[];
  }> {
    this.log("Assessing transparency features");

    const transparency = {
      explainability: false,
      auditLogging: false,
      decisionVisibility: false,
      confidenceScores: false,
      features: [] as string[],
    };

    // Check serverInfo metadata for transparency configuration
    const metadata = context.serverInfo?.metadata as
      | Record<string, unknown>
      | undefined;
    const transparencyConfig = metadata?.transparency as
      | Record<string, unknown>
      | undefined;
    if (transparencyConfig) {
      if (transparencyConfig.explainableOutputs) {
        transparency.explainability = true;
        transparency.features.push("explainable_outputs");
      }
      if (transparencyConfig.decisionRationale) {
        transparency.decisionVisibility = true;
        transparency.features.push("decision_rationale");
      }
      if (transparencyConfig.confidenceScores) {
        transparency.confidenceScores = true;
        transparency.features.push("confidence_scores");
      }
      if (transparencyConfig.auditLogging) {
        transparency.auditLogging = true;
        transparency.features.push("audit_logging");
      }
    }

    // Check for transparency-related features in tools
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Explainability
      if (
        name.includes("explain") ||
        desc.includes("explain") ||
        name.includes("reason") ||
        desc.includes("reasoning") ||
        desc.includes("justif")
      ) {
        transparency.explainability = true;
        transparency.features.push("Decision explanation");
      }

      // Audit logging
      if (
        name.includes("log") ||
        desc.includes("log") ||
        name.includes("audit") ||
        desc.includes("audit") ||
        name.includes("record") ||
        desc.includes("record")
      ) {
        transparency.auditLogging = true;
        transparency.features.push("Audit logging");
      }

      // Decision visibility
      if (
        name.includes("trace") ||
        desc.includes("trace") ||
        name.includes("track") ||
        desc.includes("track") ||
        desc.includes("visibility")
      ) {
        transparency.decisionVisibility = true;
        transparency.features.push("Decision tracking");
      }

      // Confidence scores
      if (
        name.includes("confidence") ||
        desc.includes("confidence") ||
        name.includes("score") ||
        desc.includes("score") ||
        desc.includes("probability")
      ) {
        transparency.confidenceScores = true;
        transparency.features.push("Confidence scoring");
      }

      // Additional transparency features
      if (desc.includes("debug") || desc.includes("diagnostic")) {
        transparency.features.push("Debug information");
      }

      if (desc.includes("metric") || desc.includes("telemetry")) {
        transparency.features.push("Performance metrics");
      }
    }

    return transparency;
  }

  private async assessAuditTrail(context: AssessmentContext): Promise<{
    comprehensive: boolean;
    immutable: boolean;
    searchable: boolean;
    retention: string;
    features: string[];
  }> {
    this.log("Assessing audit trail capabilities");

    const auditTrail = {
      comprehensive: false,
      immutable: false,
      searchable: false,
      retention: "unknown",
      features: [] as string[],
    };

    // Check for audit trail features
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Comprehensive logging
      if (
        (name.includes("audit") || name.includes("log")) &&
        (desc.includes("all") ||
          desc.includes("complete") ||
          desc.includes("comprehensive"))
      ) {
        auditTrail.comprehensive = true;
        auditTrail.features.push("Comprehensive logging");
      }

      // Immutability
      if (
        desc.includes("immutable") ||
        desc.includes("tamper") ||
        desc.includes("append-only") ||
        desc.includes("blockchain")
      ) {
        auditTrail.immutable = true;
        auditTrail.features.push("Immutable audit logs");
      }

      // Searchability
      if (
        (name.includes("search") || name.includes("query")) &&
        (name.includes("log") || name.includes("audit"))
      ) {
        auditTrail.searchable = true;
        auditTrail.features.push("Searchable audit logs");
      }

      // Retention period
      const retentionMatch = desc.match(/(\d+)\s*(day|week|month|year)/i);
      if (retentionMatch && (desc.includes("audit") || desc.includes("log"))) {
        auditTrail.retention = `${retentionMatch[1]} ${retentionMatch[2]}(s)`;
      }

      // Additional audit features
      if (desc.includes("timestamp")) {
        auditTrail.features.push("Timestamped entries");
      }

      if (desc.includes("user") && desc.includes("action")) {
        auditTrail.features.push("User action tracking");
      }

      if (
        desc.includes("export") &&
        (desc.includes("log") || desc.includes("audit"))
      ) {
        auditTrail.features.push("Audit log export");
      }
    }

    // Set default retention if not found
    if (auditTrail.retention === "unknown" && auditTrail.comprehensive) {
      auditTrail.retention = "Not specified";
    }

    return auditTrail;
  }

  private async assessEmergencyControls(context: AssessmentContext): Promise<{
    killSwitch: boolean;
    safeModeAvailable: boolean;
    fallbackMechanisms: boolean;
    manualOverride: boolean;
    controls: string[];
  }> {
    this.log("Assessing emergency control mechanisms");

    const controls = {
      killSwitch: false,
      safeModeAvailable: false,
      fallbackMechanisms: false,
      manualOverride: false,
      controls: [] as string[],
    };

    // Check for emergency control features
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Kill switch
      if (
        name.includes("kill") ||
        desc.includes("kill switch") ||
        (name.includes("emergency") && name.includes("stop")) ||
        desc.includes("emergency stop")
      ) {
        controls.killSwitch = true;
        controls.controls.push("Emergency kill switch");
      }

      // Safe mode
      if (
        name.includes("safe") ||
        desc.includes("safe mode") ||
        desc.includes("restricted mode") ||
        desc.includes("limited mode")
      ) {
        controls.safeModeAvailable = true;
        controls.controls.push("Safe mode operation");
      }

      // Fallback mechanisms
      if (
        name.includes("fallback") ||
        desc.includes("fallback") ||
        name.includes("backup") ||
        desc.includes("backup") ||
        desc.includes("failover")
      ) {
        controls.fallbackMechanisms = true;
        controls.controls.push("Fallback mechanisms");
      }

      // Manual override
      if (
        name.includes("manual") ||
        desc.includes("manual") ||
        name.includes("override") ||
        desc.includes("override")
      ) {
        controls.manualOverride = true;
        controls.controls.push("Manual override");
      }

      // Additional emergency controls
      if (desc.includes("circuit breaker")) {
        controls.controls.push("Circuit breaker pattern");
      }

      if (desc.includes("rate limit") || desc.includes("throttl")) {
        controls.controls.push("Rate limiting/throttling");
      }

      if (desc.includes("quarantine") || desc.includes("isolat")) {
        controls.controls.push("Quarantine/isolation mode");
      }
    }

    return controls;
  }

  private calculateHumanInLoopScore(
    reviewMechanisms: any,
    overrideCapabilities: any,
    transparency: any,
    auditTrail: any,
    emergencyControls: any,
  ): number {
    let score = 0;

    // Review mechanisms (max 25 points)
    if (reviewMechanisms.preExecution) score += 10;
    if (reviewMechanisms.postExecution) score += 8;
    if (reviewMechanisms.continuous) score += 7;

    // Override capabilities (max 20 points)
    if (overrideCapabilities.canCancel) score += 6;
    if (overrideCapabilities.canModify) score += 5;
    if (overrideCapabilities.canRevert) score += 5;
    if (overrideCapabilities.canPause) score += 4;

    // Transparency (max 20 points)
    if (transparency.explainability) score += 6;
    if (transparency.auditLogging) score += 5;
    if (transparency.decisionVisibility) score += 5;
    if (transparency.confidenceScores) score += 4;

    // Audit trail (max 20 points)
    if (auditTrail.comprehensive) score += 7;
    if (auditTrail.immutable) score += 6;
    if (auditTrail.searchable) score += 4;
    if (auditTrail.retention !== "unknown") score += 3;

    // Emergency controls (max 15 points)
    if (emergencyControls.killSwitch) score += 5;
    if (emergencyControls.safeModeAvailable) score += 4;
    if (emergencyControls.fallbackMechanisms) score += 3;
    if (emergencyControls.manualOverride) score += 3;

    return Math.min(100, score);
  }

  private identifyCriticalFindings(
    reviewMechanisms: any,
    overrideCapabilities: any,
    transparency: any,
    auditTrail: any,
    emergencyControls: any,
  ): string[] {
    const findings: string[] = [];

    if (!reviewMechanisms.preExecution && !reviewMechanisms.postExecution) {
      findings.push("No human review mechanisms detected");
    }

    if (!overrideCapabilities.canCancel && !emergencyControls.killSwitch) {
      findings.push("CRITICAL: No ability to stop operations");
    }

    if (!transparency.auditLogging && !auditTrail.comprehensive) {
      findings.push("Insufficient audit trail for accountability");
    }

    if (!transparency.explainability) {
      findings.push("Lack of decision explainability");
    }

    if (!emergencyControls.killSwitch && !emergencyControls.safeModeAvailable) {
      findings.push("No emergency control mechanisms");
    }

    return findings;
  }

  private generateRecommendations(
    reviewMechanisms: any,
    overrideCapabilities: any,
    transparency: any,
    auditTrail: any,
    emergencyControls: any,
  ): string[] {
    const recommendations: string[] = [];

    if (!reviewMechanisms.preExecution) {
      recommendations.push("Implement pre-execution approval mechanisms");
    }

    if (!reviewMechanisms.continuous) {
      recommendations.push("Add continuous monitoring capabilities");
    }

    if (!overrideCapabilities.canCancel) {
      recommendations.push("Add operation cancellation capability");
    }

    if (!overrideCapabilities.canRevert) {
      recommendations.push("Implement rollback/undo functionality");
    }

    if (!transparency.explainability) {
      recommendations.push("Add decision explanation features");
    }

    if (!transparency.confidenceScores) {
      recommendations.push("Include confidence scores in outputs");
    }

    if (!auditTrail.immutable) {
      recommendations.push("Implement tamper-proof audit logging");
    }

    if (!emergencyControls.killSwitch) {
      recommendations.push("Implement emergency stop mechanism");
    }

    recommendations.push("Establish clear human oversight protocols");
    recommendations.push("Regular training for human operators");

    return recommendations;
  }

  private generateExplanation(
    reviewMechanisms: any,
    overrideCapabilities: any,
    transparency: any,
    _auditTrail: any,
    emergencyControls: any,
  ): string {
    const parts: string[] = [];

    const reviewCount = [
      reviewMechanisms.preExecution,
      reviewMechanisms.postExecution,
      reviewMechanisms.continuous,
    ].filter(Boolean).length;

    parts.push(`Found ${reviewCount}/3 review mechanism types.`);

    const overrideCount = [
      overrideCapabilities.canCancel,
      overrideCapabilities.canModify,
      overrideCapabilities.canRevert,
      overrideCapabilities.canPause,
    ].filter(Boolean).length;

    parts.push(`${overrideCount}/4 override capabilities available.`);

    const transparencyCount = [
      transparency.explainability,
      transparency.auditLogging,
      transparency.decisionVisibility,
      transparency.confidenceScores,
    ].filter(Boolean).length;

    parts.push(`${transparencyCount}/4 transparency features detected.`);

    if (emergencyControls.killSwitch || emergencyControls.safeModeAvailable) {
      parts.push("Emergency controls available.");
    } else {
      parts.push("No emergency controls detected.");
    }

    return parts.join(" ");
  }
}
