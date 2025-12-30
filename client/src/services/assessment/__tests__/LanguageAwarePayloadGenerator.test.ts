/**
 * Unit tests for LanguageAwarePayloadGenerator
 *
 * Tests language detection accuracy and payload generation for code execution tools
 */

import { LanguageAwarePayloadGenerator } from "../LanguageAwarePayloadGenerator";

describe("LanguageAwarePayloadGenerator", () => {
  let generator: LanguageAwarePayloadGenerator;

  beforeEach(() => {
    generator = new LanguageAwarePayloadGenerator();
  });

  describe("detectLanguage", () => {
    describe("Python detection", () => {
      it("should detect Python from param name 'python_code'", () => {
        expect(generator.detectLanguage("python_code", "execute", "")).toBe(
          "python",
        );
      });

      it("should detect Python from param name 'py_script'", () => {
        expect(generator.detectLanguage("py_script", "runner", "")).toBe(
          "python",
        );
      });

      it("should detect Python from tool name containing 'python'", () => {
        expect(generator.detectLanguage("code", "execute_python", "")).toBe(
          "python",
        );
      });

      it("should detect Python from description mentioning Python", () => {
        expect(
          generator.detectLanguage("source", "executor", "Execute Python code"),
        ).toBe("python");
      });

      it("should detect Python from param name 'exec_python'", () => {
        expect(generator.detectLanguage("exec_python", "tool", "")).toBe(
          "python",
        );
      });
    });

    describe("JavaScript detection", () => {
      it("should detect JavaScript from param name 'js_code'", () => {
        expect(generator.detectLanguage("js_code", "runner", "")).toBe(
          "javascript",
        );
      });

      it("should detect JavaScript from param name 'javascript'", () => {
        expect(generator.detectLanguage("javascript", "execute", "")).toBe(
          "javascript",
        );
      });

      it("should detect JavaScript from tool name containing 'node'", () => {
        expect(generator.detectLanguage("code", "node_executor", "")).toBe(
          "javascript",
        );
      });

      it("should detect JavaScript from tool name containing 'nodejs'", () => {
        expect(generator.detectLanguage("script", "nodejs_runner", "")).toBe(
          "javascript",
        );
      });

      it("should detect JavaScript from description", () => {
        expect(
          generator.detectLanguage("source", "executor", "Run JavaScript code"),
        ).toBe("javascript");
      });
    });

    describe("SQL detection", () => {
      it("should detect SQL from param name 'sql'", () => {
        expect(generator.detectLanguage("sql", "database", "")).toBe("sql");
      });

      it("should detect SQL from param name 'query'", () => {
        expect(generator.detectLanguage("query", "database", "")).toBe("sql");
      });

      it("should detect SQL from param name 'statement'", () => {
        expect(generator.detectLanguage("statement", "db_tool", "")).toBe(
          "sql",
        );
      });

      it("should NOT detect SQL for NoSQL tools", () => {
        expect(
          generator.detectLanguage("query", "mongodb_tool", "NoSQL database"),
        ).not.toBe("sql");
      });

      it("should NOT detect SQL for DynamoDB tools", () => {
        expect(generator.detectLanguage("query", "dynamodb_scan", "")).not.toBe(
          "sql",
        );
      });
    });

    describe("Shell detection", () => {
      it("should detect shell from param name 'command'", () => {
        expect(generator.detectLanguage("command", "runner", "")).toBe("shell");
      });

      it("should detect shell from param name 'cmd'", () => {
        expect(generator.detectLanguage("cmd", "executor", "")).toBe("shell");
      });

      it("should detect shell from tool name containing 'shell'", () => {
        expect(generator.detectLanguage("input", "shell_exec", "")).toBe(
          "shell",
        );
      });

      it("should detect shell from tool name containing 'bash'", () => {
        expect(generator.detectLanguage("script", "bash_runner", "")).toBe(
          "shell",
        );
      });
    });

    describe("Generic fallback", () => {
      it("should return generic for unrecognized param names", () => {
        expect(generator.detectLanguage("data", "processor", "")).toBe(
          "generic",
        );
      });

      it("should return generic for generic tool names", () => {
        expect(generator.detectLanguage("input", "tool", "")).toBe("generic");
      });

      it("should default 'code' param to Python when tool is generic", () => {
        // When param is 'code' but no language context, default to Python
        expect(generator.detectLanguage("code", "tool", "")).toBe("python");
      });

      it("should default 'script' param to Python when tool is generic", () => {
        expect(generator.detectLanguage("script", "runner", "")).toBe("python");
      });
    });

    describe("DVMCP Challenge 8 simulation", () => {
      it("should detect Python for execute_python_code tool", () => {
        expect(
          generator.detectLanguage(
            "code",
            "execute_python_code",
            "Execute Python code",
          ),
        ).toBe("python");
      });
    });
  });

  describe("getPayloadsForLanguage", () => {
    describe("Python payloads", () => {
      it("should return Python-specific payloads", () => {
        const payloads = generator.getPayloadsForLanguage("python");
        expect(payloads.length).toBeGreaterThan(0);
        expect(payloads.every((p) => p.language === "python")).toBe(true);
      });

      it("should include subprocess payload", () => {
        const payloads = generator.getPayloadsForLanguage("python");
        const subprocessPayload = payloads.find((p) =>
          p.payload.includes("subprocess"),
        );
        expect(subprocessPayload).toBeDefined();
      });

      it("should include os.system payload", () => {
        const payloads = generator.getPayloadsForLanguage("python");
        const osPayload = payloads.find((p) =>
          p.payload.includes("__import__('os')"),
        );
        expect(osPayload).toBeDefined();
      });

      it("should include file read payload", () => {
        const payloads = generator.getPayloadsForLanguage("python");
        const filePayload = payloads.find((p) =>
          p.payload.includes("/etc/passwd"),
        );
        expect(filePayload).toBeDefined();
      });

      it("should have valid evidence patterns", () => {
        const payloads = generator.getPayloadsForLanguage("python");
        payloads.forEach((p) => {
          expect(p.evidence).toBeInstanceOf(RegExp);
        });
      });
    });

    describe("JavaScript payloads", () => {
      it("should return JavaScript-specific payloads", () => {
        const payloads = generator.getPayloadsForLanguage("javascript");
        expect(payloads.length).toBeGreaterThan(0);
        expect(payloads.every((p) => p.language === "javascript")).toBe(true);
      });

      it("should include execSync payload", () => {
        const payloads = generator.getPayloadsForLanguage("javascript");
        const execPayload = payloads.find((p) =>
          p.payload.includes("execSync"),
        );
        expect(execPayload).toBeDefined();
      });

      it("should include fs.readFileSync payload", () => {
        const payloads = generator.getPayloadsForLanguage("javascript");
        const fsPayload = payloads.find((p) =>
          p.payload.includes("readFileSync"),
        );
        expect(fsPayload).toBeDefined();
      });
    });

    describe("SQL payloads", () => {
      it("should return SQL-specific payloads", () => {
        const payloads = generator.getPayloadsForLanguage("sql");
        expect(payloads.length).toBeGreaterThan(0);
        expect(payloads.every((p) => p.language === "sql")).toBe(true);
      });

      it("should include DROP TABLE payload", () => {
        const payloads = generator.getPayloadsForLanguage("sql");
        const dropPayload = payloads.find((p) =>
          p.payload.includes("DROP TABLE"),
        );
        expect(dropPayload).toBeDefined();
      });

      it("should include UNION SELECT payload", () => {
        const payloads = generator.getPayloadsForLanguage("sql");
        const unionPayload = payloads.find((p) =>
          p.payload.includes("UNION SELECT"),
        );
        expect(unionPayload).toBeDefined();
      });
    });

    describe("Shell payloads", () => {
      it("should return shell-specific payloads", () => {
        const payloads = generator.getPayloadsForLanguage("shell");
        expect(payloads.length).toBeGreaterThan(0);
        expect(payloads.every((p) => p.language === "shell")).toBe(true);
      });

      it("should include whoami payload", () => {
        const payloads = generator.getPayloadsForLanguage("shell");
        const whoamiPayload = payloads.find((p) => p.payload === "whoami");
        expect(whoamiPayload).toBeDefined();
      });
    });

    describe("Generic payloads", () => {
      it("should return mixed payloads for generic", () => {
        const payloads = generator.getPayloadsForLanguage("generic");
        expect(payloads.length).toBeGreaterThan(0);
      });

      it("should include both shell and Python fallback payloads", () => {
        const payloads = generator.getPayloadsForLanguage("generic");
        const hasShell = payloads.some((p) => p.language === "shell");
        const hasGeneric = payloads.some((p) => p.language === "generic");
        expect(hasShell || hasGeneric).toBe(true);
      });
    });
  });

  describe("isCodeExecutionParameter", () => {
    it("should return true for 'code' param", () => {
      expect(generator.isCodeExecutionParameter("code")).toBe(true);
    });

    it("should return true for 'script' param", () => {
      expect(generator.isCodeExecutionParameter("script")).toBe(true);
    });

    it("should return true for 'source' param", () => {
      expect(generator.isCodeExecutionParameter("source")).toBe(true);
    });

    it("should return true for 'expression' param", () => {
      expect(generator.isCodeExecutionParameter("expression")).toBe(true);
    });

    it("should return true for 'eval_code' param", () => {
      expect(generator.isCodeExecutionParameter("eval_code")).toBe(true);
    });

    it("should return false for 'name' param", () => {
      expect(generator.isCodeExecutionParameter("name")).toBe(false);
    });

    it("should return false for 'data' param", () => {
      expect(generator.isCodeExecutionParameter("data")).toBe(false);
    });
  });

  describe("Payload evidence patterns", () => {
    it("Python evidence should match typical command output", () => {
      const payloads = generator.getPayloadsForLanguage("python");
      const subprocessPayload = payloads.find((p) =>
        p.payload.includes("subprocess"),
      );
      expect(subprocessPayload?.evidence.test("root")).toBe(true);
      expect(subprocessPayload?.evidence.test("ubuntu")).toBe(true);
    });

    it("Python file read evidence should match /etc/passwd content", () => {
      const payloads = generator.getPayloadsForLanguage("python");
      const filePayload = payloads.find((p) =>
        p.payload.includes("/etc/passwd"),
      );
      expect(filePayload?.evidence.test("root:x:0:0")).toBe(true);
      expect(filePayload?.evidence.test("/bin/bash")).toBe(true);
    });

    it("JavaScript evidence should match command output", () => {
      const payloads = generator.getPayloadsForLanguage("javascript");
      const execPayload = payloads.find((p) => p.payload.includes("execSync"));
      expect(execPayload?.evidence.test("node")).toBe(true);
      expect(execPayload?.evidence.test("root")).toBe(true);
    });
  });
});
