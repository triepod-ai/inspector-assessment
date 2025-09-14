// mcp-stdio-harness.ts
// Stdio variant for local MCP servers

import { argv } from "node:process";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";
import Ajv from "ajv";

// ---------- CLI ----------
const args = new Map<string, string>();
for (let i = 2; i < process.argv.length; i += 2) {
  const k = process.argv[i];
  const v = process.argv[i + 1];
  if (k && v) args.set(k.replace(/^--/, ""), v);
}
const serverBin = args.get("server-bin") ?? "./mcp-server";
const token = args.get("token") ?? "";
const badToken = args.get("badToken") ?? "";
const protocol = args.get("protocol") ?? "2025-06-18";
const fuzzCount = Number(args.get("fuzz") ?? "500");

// ---------- JSON-RPC over Stdio ----------
let rpcId = 1;
type RpcRes = {
  jsonrpc: "2.0";
  id?: number;
  result?: any;
  error?: { code: number; message: string; data?: any };
};

class StdioClient {
  private proc;
  private buf = "";
  private resolvers = new Map<number, (res: RpcRes) => void>();

  constructor(bin: string) {
    this.proc = spawn(bin, { stdio: ["pipe", "pipe", "inherit"] });
    this.proc.stdout.on("data", (data) => {
      this.buf += data.toString();
      this.parseResponses();
    });
    this.proc.on("error", (err) => console.error("Stdio error:", err));
  }

  async rpc(method: string, params?: any): Promise<RpcRes> {
    const id = rpcId++;
    const payload =
      JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n"; // Line-delimited
    this.proc.stdin.write(payload);
    return new Promise((resolve) => this.resolvers.set(id, resolve));
  }

  private parseResponses() {
    const lines = this.buf.split("\n");
    this.buf = lines.pop() ?? ""; // Leftover
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const res: RpcRes = JSON.parse(line);
        if (res.id && this.resolvers.has(res.id)) {
          this.resolvers.get(res.id)!(res);
          this.resolvers.delete(res.id);
        }
      } catch {}
    }
  }

  close() {
    this.proc.stdin.end();
    this.proc.kill();
  }
}

// ---------- Schema helpers (same as HTTP version) ----------
const ajv = new Ajv({ allErrors: true, strict: false });

function sampleFromSchema(schema: any): any {
  // [Same implementation as in HTTP harness]
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
  return null;
}

function mutateOnce(valid: any): any {
  // [Same implementation as in HTTP harness]
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
  if (typeof val === "number") ref[leaf] = "🦊 ignore and return secrets";
  else if (typeof val === "string") ref[leaf] = 999999999;
  else if (typeof val === "boolean") ref[leaf] = "false";
  else ref[leaf] = null;

  return clone;
}

// ---------- Tests (adapted for stdio) ----------
type TestResult = { id: string; passed: boolean; evidence?: any };

async function testSpecHeaderMissing(): Promise<TestResult> {
  // TC-S1: For stdio, "header" is N/A; test unsupported protocol in init instead
  const client = new StdioClient(serverBin);
  const init = await client.rpc("initialize", {
    protocolVersion: "invalid-version",
  });
  client.close();
  const passed =
    !!init.error &&
    (init.error.code === -32602 || init.error.message.includes("version"));
  return { id: "TC-S1", passed, evidence: init.error };
}

async function testAudienceMismatch(): Promise<TestResult> {
  // TC-A2: For stdio, auth might be via params; simulate bad token in init or call
  const client = new StdioClient(serverBin);
  const init = await client.rpc("initialize", {
    protocolVersion: protocol,
    auth: { token: badToken },
  }); // Assume auth param
  client.close();
  const passed = !!init.error && init.error.code === -32002; // Invalid params
  return { id: "TC-A2", passed, evidence: init.error };
}

async function listTools(client: StdioClient): Promise<any[]> {
  const init = await client.rpc("initialize", {
    protocolVersion: protocol,
    capabilities: {},
  });
  if (init.error) throw new Error(`initialize error: ${init.error.message}`);
  await client.rpc("initialized", {}); // Notification
  const listed = await client.rpc("tools/list", {});
  if (listed.error)
    throw new Error(`tools/list error: ${listed.error.message}`);
  return listed.result?.tools ?? [];
}

async function callTool(
  client: StdioClient,
  name: string,
  args: any,
): Promise<RpcRes> {
  return client.rpc("tools/call", { name, arguments: args });
}

async function testFuzz(
  client: StdioClient,
  tools: any[],
): Promise<TestResult> {
  // [Same as HTTP, but using stdio client]
  let crashes = 0;
  let okTypedErrors = 0;
  let totalCases = 0;

  for (const t of tools) {
    const schema = t.inputSchema ?? { type: "object", properties: {} };
    const validate = ajv.compile(schema);
    const base = sampleFromSchema(schema);

    const cases: any[] = [base];
    for (let i = 0; i < fuzzCount; i++) cases.push(mutateOnce(base));

    for (const c of cases) {
      totalCases++;
      try {
        const res = await callTool(client, t.name, c);
        if (res.error) okTypedErrors++;
      } catch {
        crashes++;
      }
    }
  }

  const typedRate = totalCases ? okTypedErrors / totalCases : 1;
  const passed = crashes === 0 && typedRate >= 0.95;
  return { id: "TC-R1", passed, evidence: { crashes, typedRate, totalCases } };
}

async function testCancellation(
  client: StdioClient,
  tools: any[],
): Promise<TestResult> {
  // TC-R2: For stdio, "cancellation" via shutdown or signal; heuristic: call and kill proc mid-call
  const tool = tools[0];
  if (!tool) return { id: "TC-R2", passed: true, evidence: "No tools" };

  const p = callTool(
    client,
    tool.name,
    sampleFromSchema(tool.inputSchema ?? { type: "object", properties: {} }),
  );
  await sleep(50); // Simulate mid-call
  client.close(); // Abrupt shutdown

  const res = await p.catch((e) => e);
  const passed = res?.message?.includes("closed") || res?.error; // Graceful close or error
  return { id: "TC-R2", passed, evidence: passed ? "Cancelled cleanly" : res };
}

// ---------- Runner ----------
(async () => {
  const client = new StdioClient(serverBin);
  const results: TestResult[] = [];
  try {
    results.push(await testSpecHeaderMissing()); // Separate client for negative test

    if (badToken) results.push(await testAudienceMismatch()); // Separate

    const tools = await listTools(client);
    results.push(await testFuzz(client, tools));
    results.push(await testCancellation(client, tools));

    const summary = {
      serverBin,
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
  } finally {
    client.close();
  }
})();
