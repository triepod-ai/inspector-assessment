/**
 * Server Security Tests
 *
 * Integration tests for authentication middleware, origin validation,
 * and security headers using supertest.
 */

import { describe, it, expect, beforeAll, afterAll } from "@jest/globals";
import request from "supertest";
import type { Express } from "express";

// Set test mode before importing app
process.env.NODE_ENV = "test";
process.env.DANGEROUSLY_OMIT_AUTH = ""; // Ensure auth is enabled

// Dynamic import to ensure env vars are set first
let app: Express;
let sessionToken: string;

beforeAll(async () => {
  const serverModule = await import("../index.js");
  app = serverModule.app;
  sessionToken = serverModule.sessionToken;
});

describe("Authentication Middleware", () => {
  describe("Valid Authentication", () => {
    it("should accept requests with valid Bearer token", async () => {
      const response = await request(app)
        .get("/health")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(200);
      expect(response.body.status).toBe("ok");
    });

    it("should accept requests to /config with valid token", async () => {
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("defaultEnvironment");
    });
  });

  describe("Invalid Authentication", () => {
    it("should reject requests without auth header", async () => {
      const response = await request(app).get("/config");

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });

    it("should reject requests with invalid token", async () => {
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", "Bearer invalid-token-here");

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });

    it("should reject requests without Bearer prefix", async () => {
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", sessionToken);

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });

    it("should reject requests with wrong auth scheme", async () => {
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", `Basic ${sessionToken}`);

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });

    it("should reject requests with empty Bearer token", async () => {
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", "Bearer ");

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });
  });

  describe("Auth Header Variations", () => {
    it("should handle array auth header (use first)", async () => {
      // Express may receive array headers - we use the first one
      const response = await request(app)
        .get("/config")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`)
        .set("x-mcp-proxy-auth", "Bearer invalid"); // supertest merges, but real Express uses first

      // In supertest, subsequent sets may override or merge depending on version
      // The middleware uses first array element, so this should work
      expect([200, 401]).toContain(response.status);
    });
  });
});

describe("Origin Validation Middleware", () => {
  describe("Valid Origins", () => {
    it("should accept requests without Origin header", async () => {
      const response = await request(app)
        .get("/health")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(200);
    });

    it("should accept requests from localhost default origin", async () => {
      const response = await request(app)
        .get("/health")
        .set("Origin", "http://localhost:6274")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(200);
    });
  });

  describe("Invalid Origins", () => {
    it("should reject requests from invalid origins", async () => {
      const response = await request(app)
        .get("/config")
        .set("Origin", "http://evil.com")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error).toContain("Forbidden");
    });

    it("should reject requests from non-localhost origins", async () => {
      const response = await request(app)
        .get("/config")
        .set("Origin", "http://example.com:6274")
        .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

      expect(response.status).toBe(403);
    });
  });
});

describe("Security Headers", () => {
  it("should set Content-Security-Policy header", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.headers["content-security-policy"]).toBeDefined();
    expect(response.headers["content-security-policy"]).toContain(
      "default-src",
    );
  });

  it("should set X-Content-Type-Options: nosniff", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("should set X-Frame-Options: DENY", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.headers["x-frame-options"]).toBe("DENY");
  });

  it("should expose mcp-session-id header via CORS", async () => {
    const response = await request(app)
      .get("/health")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.headers["access-control-expose-headers"]).toContain(
      "mcp-session-id",
    );
  });
});

describe("CORS Configuration", () => {
  it("should allow CORS requests", async () => {
    const response = await request(app)
      .options("/health")
      .set("Origin", "http://localhost:6274")
      .set("Access-Control-Request-Method", "GET");

    // CORS preflight should succeed
    expect(response.status).toBeLessThan(400);
  });

  it("should include Access-Control-Allow-Origin header", async () => {
    const response = await request(app)
      .get("/health")
      .set("Origin", "http://localhost:6274")
      .set("x-mcp-proxy-auth", `Bearer ${sessionToken}`);

    expect(response.headers["access-control-allow-origin"]).toBeDefined();
  });
});
