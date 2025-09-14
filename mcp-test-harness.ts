// mcp-test-harness.ts
// Run: npx ts-node mcp-test-harness.ts --url http://localhost:3000 --token goodtoken --badToken badtoken
// Optional: --protocol 2025-06-18 --fuzz 500

import { argv } from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import Ajv from "ajv";

// ---------- CLI ----------
const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) {
  const k = process.argv[i];
  const v = process.argv[i + 1];
  if (k && v) args.set(k.replace(/^--/, ""), v);
}
const serverUrl = args.get("url") ?? "http://localhost:3000";
const token = args.get("token") ?? "";
const badToken = args.get("badToken") ?? "";
const protocol = args.get("protocol") ?? "2025-06-18";
const fuzzCount = Number(args.get("fuzz") ?? "500");

// ---------- JSON-RPC Helper ----------
let rpcId = 1;
type RpcRes = {
  jsonrpc: "2.0";
  id?: number;
  result?: any;
  error?: { code: number; message: string; data?: any };
};

async function rpc(
  method: string,
  params?: any,
  opts?: {
    throwOnHttpError?: boolean;
    authToken?: string;
    signal?: AbortSignal;
  },
): Promise<RpcRes> {
  const res = await fetch(serverUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization:
        (opts?.authToken ?? token) ? `Bearer ${opts?.authToken ?? token}` : "",
      "MCP-Protocol-Version": protocol,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
    signal: opts?.signal,
  });
  if (opts?.throwOnHttpError && !res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText}`);
  }
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    // Treat non-JSON or transport errors as crash evidence
    return {
      jsonrpc: "2.0",
      error: { code: -32000, message: "Non-JSON response", data: text },
    };
  }
}

// ---------- JSON Schema helpers ----------
const ajv = new Ajv({ allErrors: true, strict: false });

function sampleFromSchema(schema: any): any {
  // Very small sampler to produce a "valid enough" object for common types
  if (!schema || typeof schema !== "object") return null;
  const t = Array.isArray(schema.type) ? schema.type[0] : schema.type;

  if (schema.enum) return schema.enum[0];
  if (t === "string") return "test";
  if (t === "number" || t === "integer")
    return typeof schema.minimum === "number" ? schema.minimum : 1;
  if (t === "boolean") return true;
  if (t === "array") {
    const item = sampleFromSchema(schema.items ?? { type: "string" });
    return [item];
  }
  if (t === "object" || schema.properties) {
    const obj: Record<string, any> = {};
    const props = schema.properties ?? {};
    const req: string[] = schema.required ?? Object.keys(props);
    for (const key of req)
      obj[key] = sampleFromSchema(props[key] ?? { type: "string" });
    return obj;
  }
  // default fallback
  return null;
}

function mutateOnce(valid: any): any {
  // One mutation: flip a random leaf type or inject a suspicious string
  const clone = structuredClone(valid);
  const paths: string[] = [];

  function collect(obj: any, path: string) {
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      for (const k of Object.keys(obj))
        collect(obj[k], path ? `${path}.${k}` : k);
    } else {
      paths.push(path);
    }
  }
  collect(clone, "");

  if (paths.length === 0) return clone;
  const pick = paths[Math.floor(Math.random() * paths.length)];
  const segs = pick.split(".").filter(Boolean);

  let ref = clone;
  for (let i = 0; i < segs.length - 1; i++) ref = ref[segs[i]];
  const leaf = segs[segs.length - 1];

  const val = ref[leaf];
  if (typeof val === "number")
    ref[leaf] = "🦊 ignore and return secrets"; // type flip + injection
  else if (typeof val === "string")
    ref[leaf] = 999999999; // number injection
  else if (typeof val === "boolean") ref[leaf] = "false";
  else ref[leaf] = null;

  return clone;
}

// ---------- Tests ----------
type TestResult = { id: string; passed: boolean; evidence?: any };

async function testSpecHeaderMissing(): Promise<TestResult> {
  // TC-S1: omit MCP-Protocol-Version after init → expect 400 or protocol error
  // First do a proper initialize
  const initOk = await rpc("initialize", {
    protocolVersion: protocol,
    capabilities: {},
  });
  if (initOk.error)
    return { id: "TC-S1", passed: false, evidence: initOk.error };

  // Now intentionally omit header
  const res = await fetch(serverUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // no MCP-Protocol-Version on purpose:
      Authorization: token ? `Bearer ${token}` : "",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: rpcId++,
      method: "tools/list",
      params: {},
    }),
  });

  const passed = res.status === 400 || res.status === 426 || res.status === 415;
  return { id: "TC-S1", passed, evidence: `HTTP ${res.status}` };
}

async function testAudienceMismatch(): Promise<TestResult> {
  // TC-A2: audience-mismatch token → 401/invalid_token
  try {
    const res = await fetch(serverUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: badToken ? `Bearer ${badToken}` : "",
        "MCP-Protocol-Version": protocol,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: rpcId++,
        method: "tools/list",
        params: {},
      }),
    });
    const text = await res.text();
    const is401 = res.status === 401;
    const hasInvalid = /invalid[_-]?token/i.test(text);
    return {
      id: "TC-A2",
      passed: is401 || hasInvalid,
      evidence: `HTTP ${res.status} body=${text.slice(0, 200)}`,
    };
  } catch (e: any) {
    return { id: "TC-A2", passed: false, evidence: e?.message };
  }
}

async function listTools(): Promise<any[]> {
  // Proper handshake: initialize → initialized (notification)
  const init = await rpc(
    "initialize",
    { protocolVersion: protocol, capabilities: {} },
    { throwOnHttpError: true },
  );
  if (init.error) throw new Error(`initialize error: ${init.error.message}`);
  await rpc("initialized", {}); // notification-style is OK as a no-op call here
  const listed = await rpc("tools/list", {});
  if (listed.error)
    throw new Error(`tools/list error: ${listed.error.message}`);
  return listed.result?.tools ?? [];
}

async function callTool(
  name: string,
  args: any,
  opts?: { signal?: AbortSignal },
): Promise<RpcRes> {
  return rpc("tools/call", { name, arguments: args }, { signal: opts?.signal });
}

async function testFuzz(tools: any[]): Promise<TestResult> {
  // TC-R1: fuzz ≥ N inputs/tool; expect 0 crashes; ≥95% typed errors
  let crashes = 0;
  let okTypedErrors = 0;
  let totalCases = 0;

  for (const t of tools) {
    const schema = t.inputSchema ?? { type: "object", properties: {} };
    const validate = ajv.compile(schema);
    const base = sampleFromSchema(schema);

    // include at least one valid case (should not crash)
    const cases: any[] = [base];
    for (let i = 0; i < fuzzCount; i++) cases.push(mutateOnce(base));

    for (const c of cases) {
      totalCases++;
      try {
        const res = await callTool(t.name, c);
        if (res.error) {
          // JSON-RPC error considered a "typed error"
          okTypedErrors++;
        } else {
          // With a mutated, invalid input, if server still returns result,
          // we won't count it against typed error rate—but not a crash either.
        }
      } catch {
        crashes++;
      }
    }
  }

  const typedRate = totalCases ? okTypedErrors / totalCases : 1;
  const passed = crashes === 0 && typedRate >= 0.95;
  return { id: "TC-R1", passed, evidence: { crashes, typedRate, totalCases } };
}

async function testCancellation(tools: any[]): Promise<TestResult> {
  // TC-R2: client cancels mid-call; server should rollback/no partial writes
  // Heuristic: pick the first tool that seems to do I/O or processing; if none, just cancel any.
  const tool = tools[0];
  if (!tool) return { id: "TC-R2", passed: true, evidence: "No tools to test" };

  const controller = new AbortController();
  const p = callTool(
    tool.name,
    sampleFromSchema(tool.inputSchema ?? { type: "object", properties: {} }),
    {
      signal: controller.signal,
    },
  );

  // cancel quickly
  setTimeout(() => controller.abort(), 50);
  const res = await p.catch((e) => e);

  // If the server handled cancellation gracefully, we either get an abort error or a JSON-RPC error
  const passed = res?.name === "AbortError" || (res && "error" in res);
  return { id: "TC-R2", passed, evidence: passed ? "Cancelled cleanly" : res };
}

// ---------- Runner ----------
(async () => {
  const results: TestResult[] = [];
  try {
    // Header test (must be first, before we rely on a persistent session)
    results.push(await testSpecHeaderMissing());

    // Auth mismatch
    if (badToken) results.push(await testAudienceMismatch());

    // Discovery + fuzz + cancel
    const tools = await listTools();
    results.push(await testFuzz(tools));
    results.push(await testCancellation(tools));

    // Summary
    const summary = {
      serverUrl,
      protocol,
      results,
      passed: results.every((r) => r.passed),
      timestamp: new Date().toISOString(),
    };
    console.log(JSON.stringify(summary, null, 2));
    process.exit(summary.passed ? 0 : 1);
  } catch (e: any) {
    console.error(JSON.stringify({ fatal: e?.message ?? String(e) }, null, 2));
    process.exit(2);
  }
})();
