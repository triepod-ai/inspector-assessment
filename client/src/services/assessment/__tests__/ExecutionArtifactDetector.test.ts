/**
 * ExecutionArtifactDetector Tests
 * Tests for execution evidence and artifact detection
 */

import { ExecutionArtifactDetector } from "../modules/securityTests/ExecutionArtifactDetector";

describe("ExecutionArtifactDetector", () => {
  let detector: ExecutionArtifactDetector;

  beforeEach(() => {
    detector = new ExecutionArtifactDetector();
  });

  describe("hasExecutionEvidence", () => {
    it("should detect execution keywords", () => {
      expect(
        detector.hasExecutionEvidence("command executed successfully"),
      ).toBe(true);
      expect(detector.hasExecutionEvidence("computed the result")).toBe(true);
      expect(detector.hasExecutionEvidence("calculated value is 42")).toBe(
        true,
      );
    });

    it("should detect exception patterns", () => {
      expect(
        detector.hasExecutionEvidence("NullPointerException at line 5"),
      ).toBe(true);
      expect(detector.hasExecutionEvidence("SegmentationFault in memory")).toBe(
        true,
      );
      expect(detector.hasExecutionEvidence("StackOverflow error")).toBe(true);
      expect(detector.hasExecutionEvidence("OutOfMemory exception")).toBe(true);
    });

    it("should detect database operation results", () => {
      expect(detector.hasExecutionEvidence("query returned 5 results")).toBe(
        true,
      );
      expect(detector.hasExecutionEvidence("modified 3 records")).toBe(true);
      expect(detector.hasExecutionEvidence("10 rows affected")).toBe(true);
      expect(detector.hasExecutionEvidence("deleted 5 files")).toBe(true);
    });

    it("should detect execution indicators", () => {
      expect(detector.hasExecutionEvidence("command output: hello")).toBe(true);
      expect(detector.hasExecutionEvidence("execution result: success")).toBe(
        true,
      );
      expect(detector.hasExecutionEvidence("file opened successfully")).toBe(
        true,
      );
    });

    it("should NOT detect safe patterns", () => {
      expect(detector.hasExecutionEvidence("data stored safely")).toBe(false);
      expect(detector.hasExecutionEvidence("query saved for later")).toBe(
        false,
      );
      expect(detector.hasExecutionEvidence('{"result": "ok"}')).toBe(false);
    });
  });

  describe("detectExecutionArtifacts", () => {
    it("should detect passwd file format", () => {
      expect(
        detector.detectExecutionArtifacts("root:x:0:0:root:/root:/bin/bash"),
      ).toBe(true);
      expect(
        detector.detectExecutionArtifacts(
          "user:x:1000:1000::/home/user:/bin/sh",
        ),
      ).toBe(true);
    });

    it("should detect id command output", () => {
      expect(detector.detectExecutionArtifacts("uid=0(root) gid=0(root)")).toBe(
        true,
      );
      expect(
        detector.detectExecutionArtifacts("uid=1000(user) gid=1000(user)"),
      ).toBe(true);
    });

    it("should detect ls -l format", () => {
      expect(
        detector.detectExecutionArtifacts(
          "-rw-r--r-- 1 root root 1234 Jan 1 file.txt",
        ),
      ).toBe(true);
      expect(
        detector.detectExecutionArtifacts(
          "drwxr-xr-x 2 user user 4096 Jan 1 dir",
        ),
      ).toBe(true);
    });

    it("should detect shell path patterns", () => {
      expect(detector.detectExecutionArtifacts("/bin/bash")).toBe(true);
      expect(detector.detectExecutionArtifacts("/bin/sh available")).toBe(true);
      expect(detector.detectExecutionArtifacts("shell: /bin/zsh")).toBe(true);
    });

    it("should detect PID patterns", () => {
      expect(detector.detectExecutionArtifacts("PID: 12345")).toBe(true);
      expect(detector.detectExecutionArtifacts("Process PID: 999")).toBe(true);
    });

    it("should detect command output patterns", () => {
      // Pattern requires non-quote, non-whitespace after colon
      expect(
        detector.detectExecutionArtifacts("command_executed: ls -la"),
      ).toBe(true);
      expect(detector.detectExecutionArtifacts('stdout: "hello world"')).toBe(
        true,
      );
      expect(detector.detectExecutionArtifacts("execution_log: started")).toBe(
        true,
      );
    });

    it("should detect context-sensitive patterns when no echoed payload", () => {
      expect(detector.detectExecutionArtifacts("/etc/passwd content")).toBe(
        true,
      );
      expect(detector.detectExecutionArtifacts("/etc/shadow leaked")).toBe(
        true,
      );
      expect(detector.detectExecutionArtifacts("file:///etc/hosts")).toBe(true);
    });

    it("should NOT detect context-sensitive patterns with echoed payload", () => {
      // These contain echoed payload markers, so context-sensitive patterns should not fire
      const withEchoedPayload = "stored query: <!DOCTYPE test [ /etc/passwd ]";
      // First check that it contains echoed payload
      expect(detector.containsEchoedInjectionPayload(withEchoedPayload)).toBe(
        true,
      );
      // Context-sensitive patterns should still not match because alwaysExecution patterns don't match
      expect(detector.detectExecutionArtifacts(withEchoedPayload)).toBe(false);
    });

    it("should NOT detect safe responses", () => {
      expect(detector.detectExecutionArtifacts("data stored safely")).toBe(
        false,
      );
      expect(detector.detectExecutionArtifacts('{"status": "ok"}')).toBe(false);
      expect(detector.detectExecutionArtifacts("query saved for later")).toBe(
        false,
      );
    });
  });

  describe("containsEchoedInjectionPayload", () => {
    it("should detect XXE patterns", () => {
      expect(detector.containsEchoedInjectionPayload("<!DOCTYPE test [")).toBe(
        true,
      );
      expect(
        detector.containsEchoedInjectionPayload("<!ENTITY xxe SYSTEM"),
      ).toBe(true);
      expect(detector.containsEchoedInjectionPayload("<!ENTITY % param")).toBe(
        true,
      );
    });

    it("should detect stored URL patterns", () => {
      expect(
        detector.containsEchoedInjectionPayload("stored http://evil.com"),
      ).toBe(true);
      expect(
        detector.containsEchoedInjectionPayload(
          "saved http://attacker.com/payload",
        ),
      ).toBe(true);
    });

    it("should detect stored SQL patterns", () => {
      expect(
        detector.containsEchoedInjectionPayload("stored union select"),
      ).toBe(true);
      expect(
        detector.containsEchoedInjectionPayload("stored drop table users"),
      ).toBe(true);
    });

    it("should detect stored query with special chars", () => {
      expect(
        detector.containsEchoedInjectionPayload("stored query: <script>"),
      ).toBe(true);
      expect(
        detector.containsEchoedInjectionPayload("saved data: 'OR 1=1"),
      ).toBe(true);
    });

    it("should NOT detect normal responses", () => {
      expect(
        detector.containsEchoedInjectionPayload("data stored successfully"),
      ).toBe(false);
      expect(
        detector.containsEchoedInjectionPayload('{"result": "saved"}'),
      ).toBe(false);
    });
  });

  describe("analyzeInjectionResponse", () => {
    const mockIsReflection = (text: string) => text.includes("stored");

    it("should detect vulnerability when execution keywords present and not reflection", () => {
      const result = detector.analyzeInjectionResponse(
        "command executed successfully",
        mockIsReflection,
      );
      expect(result.isVulnerable).toBe(true);
      expect(result.evidence).toContain("execution keywords");
    });

    it("should NOT flag as vulnerable when response is reflection", () => {
      const result = detector.analyzeInjectionResponse(
        "stored: executed command",
        mockIsReflection,
      );
      expect(result.isVulnerable).toBe(false);
    });

    it("should NOT flag as vulnerable without execution keywords", () => {
      const result = detector.analyzeInjectionResponse(
        "data processed",
        mockIsReflection,
      );
      expect(result.isVulnerable).toBe(false);
    });

    it("should detect result patterns", () => {
      const result = detector.analyzeInjectionResponse(
        "result is 42",
        () => false,
      );
      expect(result.isVulnerable).toBe(true);
    });

    it("should detect output patterns", () => {
      const result = detector.analyzeInjectionResponse(
        "output: hello world",
        () => false,
      );
      expect(result.isVulnerable).toBe(true);
    });
  });

  describe("extractResponseContent", () => {
    it("should extract text from content array", () => {
      const response = {
        content: [
          { type: "text", text: "Hello" },
          { type: "text", text: "World" },
        ],
      };
      expect(detector.extractResponseContent(response)).toBe("Hello World");
    });

    it("should handle empty content", () => {
      const response = { content: [] };
      expect(detector.extractResponseContent(response)).toBe("");
    });

    it("should handle string content", () => {
      const response = { content: "Plain text" } as unknown as {
        content: { type: string; text?: string }[];
      };
      expect(detector.extractResponseContent(response)).toBe("Plain text");
    });
  });
});
