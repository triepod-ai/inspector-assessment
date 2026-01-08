/**
 * Tests for ArchitectureDetector
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import {
  detectArchitecture,
  hasDatabaseToolPatterns,
  extractDatabasesFromDependencies,
  type ArchitectureContext,
} from "../modules/annotations/ArchitectureDetector";

describe("ArchitectureDetector", () => {
  describe("detectArchitecture", () => {
    describe("database detection", () => {
      it("should detect Neo4j from tool descriptions", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "atlas_query",
              description: "Query the Neo4j graph database using Cypher",
            },
            {
              name: "atlas_create_node",
              description: "Creates a new node in the Neo4j database",
            },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends).toContain("neo4j");
        expect(result.evidence.databaseIndicators.length).toBeGreaterThan(0);
      });

      it("should detect MongoDB from source imports", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "store_data", description: "Store data" }],
          sourceCodeFiles: new Map([
            [
              "index.js",
              `
              import mongoose from 'mongoose';
              import { MongoClient } from 'mongodb';
              const client = new MongoClient('mongodb://localhost:27017');
            `,
            ],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends).toContain("mongodb");
      });

      it("should detect PostgreSQL from package.json dependencies", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "query_users", description: "Query users" }],
          packageJson: {
            dependencies: {
              pg: "^8.0.0",
              "pg-pool": "^3.0.0",
            },
          },
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends).toContain("postgresql");
      });

      it("should detect SQLite from tool descriptions", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "init_db",
              description: "Initialize the SQLite database file",
            },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends).toContain("sqlite");
      });

      it("should detect multiple database backends", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "query_graph", description: "Query Neo4j graph database" },
            { name: "cache_data", description: "Cache data in Redis" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends.length).toBeGreaterThanOrEqual(2);
        expect(result.databaseBackends).toContain("neo4j");
        expect(result.databaseBackends).toContain("redis");
      });

      it("should set primary database from first detection", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "neo4j_query", description: "Query Neo4j" },
            { name: "redis_cache", description: "Redis cache" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackend).toBeDefined();
        expect(result.databaseBackends).toContain(result.databaseBackend);
      });
    });

    describe("transport detection", () => {
      it("should detect stdio transport from source code", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool1" }],
          sourceCodeFiles: new Map([
            [
              "server.ts",
              `
              const server = new McpServer();
              server.connect(process.stdin, process.stdout);
            `,
            ],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.transportModes).toContain("stdio");
      });

      it("should detect HTTP transport from source code", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool1" }],
          sourceCodeFiles: new Map([
            [
              "server.ts",
              `
              import express from 'express';
              const app = express();
              app.listen(3000);
            `,
            ],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.transportModes).toContain("http");
      });

      it("should detect SSE transport from source code", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool1" }],
          sourceCodeFiles: new Map([
            [
              "server.ts",
              `
              res.setHeader('Content-Type', 'text/event-stream');
              res.setHeader('Cache-Control', 'no-cache');
            `,
            ],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.transportModes).toContain("sse");
      });

      it("should include transport from connection context", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool1" }],
          transportType: "http",
        };

        const result = detectArchitecture(context);

        expect(result.transportModes).toContain("http");
        expect(result.evidence.transportIndicators).toEqual(
          expect.arrayContaining([
            expect.stringContaining("Connection transport"),
          ]),
        );
      });

      it("should default to stdio if no transport detected", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "simple_tool" }],
        };

        const result = detectArchitecture(context);

        expect(result.transportModes).toContain("stdio");
      });
    });

    describe("server type classification", () => {
      it("should classify as local for stdio-only without network", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "read_file",
              description: "Reads a local file from the filesystem",
            },
          ],
          transportType: "stdio",
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("local");
        expect(result.requiresNetworkAccess).toBe(false);
      });

      it("should classify as remote for HTTP-only transport", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "api_call" }],
          transportType: "http",
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("remote");
      });

      it("should classify as hybrid for stdio with network access", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "fetch_api",
              description: "Fetches data from https://api.example.com",
            },
          ],
          transportType: "stdio",
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("hybrid");
        expect(result.requiresNetworkAccess).toBe(true);
      });

      it("should classify as hybrid for multiple transports", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool1" }],
          sourceCodeFiles: new Map([
            [
              "server.ts",
              `
              // Supports both stdio and HTTP
              server.connect(process.stdin, process.stdout);
              app.listen(3000);
            `,
            ],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("hybrid");
      });

      it("should classify as hybrid with external services", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "github_pr", description: "Create GitHub PR" },
            { name: "local_file", description: "Read local file" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("hybrid");
        expect(result.externalDependencies).toContain("github");
      });

      it("should classify as remote with many external services", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "github_api", description: "GitHub API integration" },
            { name: "aws_s3", description: "AWS S3 storage" },
            { name: "openai_chat", description: "OpenAI API calls" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.serverType).toBe("remote");
      });
    });

    describe("network access detection", () => {
      it("should detect network access from HTTPS URLs", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "fetch_data",
              description: "Fetches data from https://api.example.com/data",
            },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.requiresNetworkAccess).toBe(true);
        expect(result.evidence.networkIndicators.length).toBeGreaterThan(0);
      });

      it("should detect network access from HTTP client libraries", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "api" }],
          sourceCodeFiles: new Map([
            ["client.js", "import axios from 'axios';"],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.requiresNetworkAccess).toBe(true);
      });

      it("should detect network access from fetch usage", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "api" }],
          sourceCodeFiles: new Map([
            ["client.js", "const data = await fetch('/api/data');"],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.requiresNetworkAccess).toBe(true);
      });

      it("should not require network for local file operations", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "read_file", description: "Read local file" },
            { name: "write_file", description: "Write to local file" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.requiresNetworkAccess).toBe(false);
      });
    });

    describe("external service detection", () => {
      it("should detect GitHub service", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "create_pr",
              description: "Create a pull request on github.com",
            },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.externalDependencies).toContain("github");
      });

      it("should detect AWS service", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "s3_upload" }],
          packageJson: {
            dependencies: {
              "aws-sdk": "^2.0.0",
            },
          },
        };

        const result = detectArchitecture(context);

        expect(result.externalDependencies).toContain("aws");
      });

      it("should detect OpenAI service", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "generate_text",
              description: "Generate text using OpenAI API",
            },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.externalDependencies).toContain("openai");
      });

      it("should detect multiple external services", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "github_sync", description: "Sync with GitHub" },
            { name: "slack_notify", description: "Send Slack notification" },
          ],
        };

        const result = detectArchitecture(context);

        expect(result.externalDependencies).toContain("github");
        expect(result.externalDependencies).toContain("slack");
      });
    });

    describe("confidence calculation", () => {
      it("should have high confidence with transport and source code", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "query", description: "Query the Neo4j database" },
            { name: "create", description: "Create a new record" },
            { name: "delete", description: "Delete a record" },
          ],
          transportType: "http",
          sourceCodeFiles: new Map([
            ["index.js", "import neo4j from 'neo4j';"],
          ]),
        };

        const result = detectArchitecture(context);

        expect(result.confidence).toBe("high");
      });

      it("should have medium confidence with just tools", () => {
        const context: ArchitectureContext = {
          tools: [
            { name: "query", description: "Query the database" },
            { name: "create", description: "Create a record" },
          ],
        };

        const result = detectArchitecture(context);

        expect(["medium", "low"]).toContain(result.confidence);
      });

      it("should have low confidence with minimal information", () => {
        const context: ArchitectureContext = {
          tools: [{ name: "tool" }],
        };

        const result = detectArchitecture(context);

        expect(result.confidence).toBe("low");
      });
    });

    describe("atlas-mcp-server example (Issue #57)", () => {
      it("should detect architecture from atlas-style tools", () => {
        const context: ArchitectureContext = {
          tools: [
            {
              name: "atlas_project_create",
              description: "Creates a new project in the Neo4j graph database",
            },
            {
              name: "atlas_project_list",
              description:
                "Lists all projects using Cypher query against graph database",
            },
            {
              name: "atlas_task_update",
              description: "Updates task properties in Neo4j",
            },
          ],
          transportType: "stdio",
        };

        const result = detectArchitecture(context);

        expect(result.databaseBackends).toContain("neo4j");
        expect(result.serverType).toBe("local");
        expect(result.transportModes).toContain("stdio");
      });
    });
  });

  describe("hasDatabaseToolPatterns", () => {
    it("should return true for query tool", () => {
      const tools = [{ name: "query_users", description: "Query users table" }];
      expect(hasDatabaseToolPatterns(tools)).toBe(true);
    });

    it("should return true for select tool", () => {
      const tools = [{ name: "select_records" }];
      expect(hasDatabaseToolPatterns(tools)).toBe(true);
    });

    it("should return true for tool with database description", () => {
      const tools = [
        { name: "get_data", description: "Runs aggregate query on collection" },
      ];
      expect(hasDatabaseToolPatterns(tools)).toBe(true);
    });

    it("should return false for non-database tools", () => {
      const tools = [
        { name: "read_file", description: "Read a local file" },
        { name: "write_file", description: "Write to a file" },
      ];
      expect(hasDatabaseToolPatterns(tools)).toBe(false);
    });
  });

  describe("extractDatabasesFromDependencies", () => {
    it("should extract PostgreSQL from pg dependency", () => {
      const deps = { pg: "^8.0.0" };
      expect(extractDatabasesFromDependencies(deps)).toContain("postgresql");
    });

    it("should extract MongoDB from mongoose dependency", () => {
      const deps = { mongoose: "^6.0.0" };
      expect(extractDatabasesFromDependencies(deps)).toContain("mongodb");
    });

    it("should extract multiple databases", () => {
      const deps = {
        pg: "^8.0.0",
        redis: "^4.0.0",
        mongoose: "^6.0.0",
      };
      const result = extractDatabasesFromDependencies(deps);
      expect(result).toContain("postgresql");
      expect(result).toContain("redis");
      expect(result).toContain("mongodb");
    });

    it("should return empty array for no database dependencies", () => {
      const deps = { express: "^4.0.0", lodash: "^4.0.0" };
      expect(extractDatabasesFromDependencies(deps)).toHaveLength(0);
    });
  });
});
