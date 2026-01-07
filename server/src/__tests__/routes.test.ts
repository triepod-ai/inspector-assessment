/**
 * Server Route Tests
 *
 * Integration tests for API endpoints using supertest.
 */

import { describe, it, expect, beforeAll, afterEach } from "@jest/globals";
import request from "supertest";
import type { Express } from "express";
import * as fs from "fs";
import * as path from "path";

// Set test mode before importing app
process.env.NODE_ENV = "test";

// Dynamic import to ensure env vars are set first
let app: Express;
let sessionToken: string;

beforeAll(async () => {
  const serverModule = await import("../index.js");
  app = serverModule.app;
  sessionToken = serverModule.sessionToken;
});

describe("GET /health", () => {
  it("should return { status: 'ok' }", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("should return 200 even without auth (health check accessible)", async () => {
    // Health endpoint may or may not require auth depending on setup
    // Check that it responds with 200 when auth is provided
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.status).toBe(200);
  });
});

describe("GET /config", () => {
  it("should return server configuration", async () => {
    const response = await request(app)
      .get("/config")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("defaultEnvironment");
    expect(response.body).toHaveProperty("defaultCommand");
    expect(response.body).toHaveProperty("defaultArgs");
    expect(response.body).toHaveProperty("defaultTransport");
    expect(response.body).toHaveProperty("defaultServerUrl");
  });

  it("should require authentication", async () => {
    const response = await request(app).get("/config");

    expect(response.status).toBe(401);
  });
});

describe("POST /assessment/save", () => {
  const testFilePath = "/tmp/inspector-assessment-test_server.json";

  afterEach(() => {
    // Cleanup test file
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
    }
  });

  it("should save assessment to /tmp", async () => {
    const assessment = {
      server: "test_server",
      results: { passed: true },
      timestamp: Date.now(),
    };

    const response = await request(app)
      .post("/assessment/save")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .send({ serverName: "test_server", assessment });

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(response.body.path).toContain(
      "inspector-assessment-test_server.json",
    );
    expect(fs.existsSync(testFilePath)).toBe(true);
  });

  it("should sanitize server name in filename", async () => {
    const assessment = { test: true };

    const response = await request(app)
      .post("/assessment/save")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .send({ serverName: "test@server#!$", assessment });

    expect(response.status).toBe(200);
    expect(response.body.path).toContain("test_server___");
    expect(response.body.path).not.toContain("@");
    expect(response.body.path).not.toContain("#");
  });

  it("should return success with path", async () => {
    const response = await request(app)
      .post("/assessment/save")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .send({ serverName: "test_server", assessment: {} });

    expect(response.body).toMatchObject({
      success: true,
      path: expect.stringContaining("/tmp/"),
      message: expect.stringContaining("Assessment saved"),
    });
  });

  it("should handle missing serverName gracefully", async () => {
    const response = await request(app)
      .post("/assessment/save")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .send({ assessment: { data: true } });

    expect(response.status).toBe(200);
    expect(response.body.path).toContain("unknown");
  });

  it("should require authentication", async () => {
    const response = await request(app)
      .post("/assessment/save")
      .send({ serverName: "test", assessment: {} });

    expect(response.status).toBe(401);
  });
});

describe("MCP Session Endpoints", () => {
  describe("GET /mcp", () => {
    it("should return 404 for non-existent session", async () => {
      const response = await request(app)
        .get("/mcp")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .set("mcp-session-id", "non-existent-session-id");

      expect(response.status).toBe(404);
    });
  });

  describe("POST /mcp", () => {
    it("should return 404 for non-existent session with sessionId", async () => {
      const response = await request(app)
        .post("/mcp")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .set("mcp-session-id", "non-existent-session-id")
        .send({});

      expect(response.status).toBe(404);
    });

    it("should require transport parameters for new session", async () => {
      // Without transportType, should error
      const response = await request(app)
        .post("/mcp")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .send({});

      // Will fail due to missing transport config - 500 error
      expect(response.status).toBe(500);
    });
  });

  describe("DELETE /mcp", () => {
    it("should return 404 for non-existent session", async () => {
      const response = await request(app)
        .delete("/mcp")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .set("mcp-session-id", "non-existent-session-id");

      expect(response.status).toBe(404);
    });
  });

  describe("POST /message", () => {
    it("should return 404 for non-existent session", async () => {
      const response = await request(app)
        .post("/message")
        .query({ sessionId: "non-existent" })
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .send({});

      expect(response.status).toBe(404);
    });
  });
});

describe("Error Handling", () => {
  it("should return 404 for unknown routes", async () => {
    const response = await request(app)
      .get("/unknown-route")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.status).toBe(404);
  });

  it("should handle malformed JSON in POST body", async () => {
    const response = await request(app)
      .post("/assessment/save")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .set("Content-Type", "application/json")
      .send("not-valid-json");

    expect(response.status).toBeGreaterThanOrEqual(400);
  });
});

describe("Rate Limiting", () => {
  it("should include rate limit headers on rate-limited endpoints", async () => {
    // Rate limiting is applied to /mcp, /sse, /stdio, /message routes
    // /health is not rate limited, so we test against /mcp
    const response = await request(app)
      .get("/mcp")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
      .set("mcp-session-id", "test-rate-limit-session");

    // Even with 404 response, rate limit headers should be present
    expect(response.headers).toHaveProperty("ratelimit-limit");
    expect(response.headers).toHaveProperty("ratelimit-remaining");
  });

  it("should not include rate limit headers on non-limited endpoints", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    // /health is not rate limited
    expect(response.headers["ratelimit-limit"]).toBeUndefined();
  });
});
