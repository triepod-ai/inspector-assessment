#!/usr/bin/env node

/**
 * Test script to verify enhanced usability assessment
 */

const {
  MCPAssessmentService,
} = require("./client/dist/services/assessmentService.js");

// Mock tools with different naming patterns and descriptions
const mockTools = [
  {
    name: "get_user_data",
    description:
      "Retrieves user information from the database with proper validation",
    inputSchema: {
      type: "object",
      required: ["userId"],
      properties: {
        userId: {
          type: "string",
          description: "The unique identifier for the user",
        },
        includeMetadata: {
          type: "boolean",
          description: "Whether to include additional metadata in the response",
        },
      },
    },
  },
  {
    name: "update_user_profile",
    description: "Updates user profile information",
    inputSchema: {
      type: "object",
      required: ["userId", "data"],
      properties: {
        userId: {
          type: "string",
          description: "The user ID to update",
        },
        data: {
          type: "object",
          description: "Profile data to update",
        },
      },
    },
  },
  {
    name: "deleteUserAccount", // Different naming pattern (camelCase)
    description: "Permanently deletes a user account",
    inputSchema: {
      type: "object",
      required: ["userId"],
      properties: {
        userId: {
          type: "string",
          // Missing description
        },
      },
    },
  },
  {
    name: "list_all_users",
    description: "Lists all users in the system with pagination support",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "number",
          description: "Maximum number of users to return",
        },
        offset: {
          type: "number",
          // Missing description
        },
      },
    },
  },
  {
    name: "search_users",
    description: "Search for users by various criteria",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query string",
        },
        filters: {
          type: "object",
          description: "Additional search filters",
        },
      },
    },
  },
];

// Mock callTool function
async function mockCallTool(name, params) {
  return {
    content: [{ type: "text", text: JSON.stringify({ success: true }) }],
    isError: false,
  };
}

async function testUsabilityAssessment() {
  console.log("Testing Enhanced Usability Assessment\n");
  console.log("=".repeat(50));

  const assessor = new MCPAssessmentService();

  // Run assessment
  const assessment = await assessor.runFullAssessment(
    "test-server",
    mockTools,
    mockCallTool,
    "# Test README\n\nThis is a test readme with some examples.",
  );

  console.log("\nUsability Assessment Results:");
  console.log("-".repeat(40));
  console.log("Status:", assessment.usability.status);
  console.log("Explanation:", assessment.usability.explanation);

  if (assessment.usability.metrics.detailedAnalysis) {
    const details = assessment.usability.metrics.detailedAnalysis;

    console.log("\nDetailed Scoring Breakdown:");
    console.log("Overall Score:", details.overallScore + "/100");
    console.log("\nComponent Scores:");
    console.log(
      "  - Naming Consistency:",
      details.bestPracticeScore.naming + "/25",
    );
    console.log(
      "  - Description Quality:",
      details.bestPracticeScore.descriptions + "/25",
    );
    console.log(
      "  - Schema Completeness:",
      details.bestPracticeScore.schemas + "/25",
    );
    console.log(
      "  - Parameter Clarity:",
      details.bestPracticeScore.clarity + "/25",
    );

    console.log("\nNaming Analysis:");
    console.log("  - Patterns Found:", details.naming.patterns.join(", "));
    console.log("  - Dominant Pattern:", details.naming.dominant);
    console.log("  - Pattern Breakdown:");
    Object.entries(details.naming.breakdown).forEach(([pattern, count]) => {
      console.log(`    • ${pattern}: ${count} tools`);
    });

    console.log("\nDescription Analysis:");
    console.log(
      "  - Tools with Descriptions:",
      details.descriptions.withDescriptions + "/" + details.tools.length,
    );
    console.log(
      "  - Average Description Length:",
      details.descriptions.averageLength,
      "chars",
    );
    console.log(
      "  - Too Short:",
      details.descriptions.tooShort.length,
      "tools",
    );
    console.log("  - Adequate:", details.descriptions.adequate.length, "tools");
    console.log("  - Detailed:", details.descriptions.detailed.length, "tools");

    if (details.parameterIssues.length > 0) {
      console.log("\nParameter Issues Found:");
      details.parameterIssues.forEach((issue) => {
        console.log("  •", issue);
      });
    }

    console.log("\nTool-by-Tool Analysis:");
    details.tools.forEach((tool) => {
      console.log(`  ${tool.toolName}:`);
      console.log(`    - Naming Pattern: ${tool.namingPattern}`);
      console.log(`    - Description Length: ${tool.descriptionLength} chars`);
      console.log(`    - Schema Quality: ${tool.schemaQuality}`);
      console.log(
        `    - Parameters: ${tool.parameterCount} (${tool.hasRequiredParams ? "has required" : "no required"})`,
      );
    });
  }

  if (assessment.usability.recommendations.length > 0) {
    console.log("\nRecommendations:");
    assessment.usability.recommendations.forEach((rec) => {
      console.log("  •", rec);
    });
  }

  console.log("\n" + "=".repeat(50));
  console.log("Test Complete!");
}

// Run the test
testUsabilityAssessment().catch(console.error);
