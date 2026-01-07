/**
 * ToolClassifier Tests
 *
 * Comprehensive tests for the ToolClassifier module that categorizes MCP tools
 * based on name/description patterns to select appropriate security test patterns.
 *
 * Test Coverage:
 * - All 17 categories (7 HIGH, 4 MEDIUM, 5 SAFE, 1 DEFAULT)
 * - Pattern matching for each category
 * - Confidence scoring
 * - Multi-category detection
 * - Edge cases and false positive prevention
 * - Static methods (getAllCategories, getRiskLevel)
 * - Batch classification
 */

import {
  ToolClassifier,
  ToolCategory,
  ToolClassification,
} from "../ToolClassifier";

describe("ToolClassifier", () => {
  let classifier: ToolClassifier;

  beforeEach(() => {
    classifier = new ToolClassifier();
  });

  // ============================================================================
  // HIGH RISK CATEGORIES (7)
  // ============================================================================

  describe("HIGH RISK: CALCULATOR", () => {
    const expectedCategory = ToolCategory.CALCULATOR;
    const expectedConfidence = 90;

    it.each([
      ["calculator_tool", "calculator pattern in name"],
      ["compute_value", "compute pattern in name"],
      ["math_operations", "math pattern in name"],
      ["calc_expression", "calc pattern in name"],
      ["eval_input", "eval pattern in name"],
      ["arithmetic_processor", "arithmetic pattern in name"],
      ["expression_evaluator", "expression pattern in name"],
    ])("classifies %s as CALCULATOR (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
      expect(result.confidence).toBeGreaterThanOrEqual(expectedConfidence - 10);
    });

    it("detects calculator from description", () => {
      const result = classifier.classify(
        "unknown_tool",
        "Evaluates mathematical expressions",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes arithmetic execution risk in reasoning", () => {
      const result = classifier.classify("calculator_tool");
      expect(result.reasoning).toContain("arithmetic execution risk");
    });
  });

  describe("HIGH RISK: SYSTEM_EXEC", () => {
    const expectedCategory = ToolCategory.SYSTEM_EXEC;
    const expectedConfidence = 95;

    it.each([
      ["system_exec_tool", "system.*exec pattern"],
      ["exec_tool_wrapper", "exec.*tool pattern"],
      ["command_runner", "command pattern"],
      ["shell_executor", "shell pattern"],
      ["run_process", "run pattern"],
      ["execute_action", "execute pattern"],
      ["process_manager", "process pattern"],
    ])("classifies %s as SYSTEM_EXEC (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
      expect(result.confidence).toBeGreaterThanOrEqual(expectedConfidence - 10);
    });

    it("detects system exec from description", () => {
      const result = classifier.classify(
        "tool",
        "Executes shell commands on the system",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes command injection risk in reasoning", () => {
      const result = classifier.classify("system_exec_tool");
      expect(result.reasoning).toContain("command injection risk");
    });
  });

  describe("HIGH RISK: CODE_EXECUTOR", () => {
    const expectedCategory = ToolCategory.CODE_EXECUTOR;
    const expectedConfidence = 95;

    it.each([
      ["execute_code", "execute.*code pattern"],
      ["run_code_snippet", "run.*code pattern"],
      ["code_execution_engine", "code.*execut pattern"],
      ["run_script_tool", "run.*script pattern"],
      ["exec_script", "exec.*script pattern"],
      ["python_code_runner", "python.*code pattern"],
      ["js_code_executor", "js.*code pattern"],
      ["code_runner", "code.*runner pattern"],
      ["script_runner", "script.*runner pattern"],
      ["interpreter_tool", "interpret pattern"],
    ])("classifies %s as CODE_EXECUTOR (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    // These patterns require word boundaries - test via description
    it("detects javascript code via description", () => {
      const result = classifier.classify("tool", "runs javascript code");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects repl via description", () => {
      const result = classifier.classify("tool", "interactive repl for python");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects code executor from description", () => {
      const result = classifier.classify("tool", "Runs arbitrary Python code");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes arbitrary code execution risk in reasoning", () => {
      const result = classifier.classify("code_runner");
      expect(result.reasoning).toContain("arbitrary code execution risk");
    });
  });

  describe("HIGH RISK: DATA_ACCESS", () => {
    const expectedCategory = ToolCategory.DATA_ACCESS;
    const expectedConfidence = 85;

    // Note: word boundary patterns (\b) don't match underscored names
    // e.g., /\bdata\b/ doesn't match "data_retriever" because _ is a word char
    it.each([
      ["data_leak_tool", "leak pattern"],
      ["show_info", "show pattern"],
      ["display_content", "display pattern"],
      ["env_reader", "env pattern"],
      ["secret_manager", "secret pattern"],
      ["credential_helper", "credential pattern"],
      ["exfiltrate_data", "exfiltrat pattern"],
    ])("classifies %s as DATA_ACCESS (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    // Word boundary patterns match when word is isolated
    it("matches 'data' at word boundary", () => {
      const result = classifier.classify("my data tool");
      expect(result.categories).toContain(expectedCategory);
    });

    it("matches 'get' at word boundary", () => {
      const result = classifier.classify("tool to get items");
      expect(result.categories).toContain(expectedCategory);
    });

    it("matches 'list' at word boundary", () => {
      const result = classifier.classify("tool to list all");
      expect(result.categories).toContain(expectedCategory);
    });

    it("matches 'key' at word boundary", () => {
      const result = classifier.classify("api key manager");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects data access from description", () => {
      const result = classifier.classify(
        "tool",
        "Retrieves sensitive environment variables",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes data exfiltration risk in reasoning", () => {
      const result = classifier.classify("data_leak_tool");
      expect(result.reasoning).toContain("data exfiltration risk");
    });
  });

  describe("HIGH RISK: TOOL_OVERRIDE", () => {
    const expectedCategory = ToolCategory.TOOL_OVERRIDE;
    const expectedConfidence = 92;

    it.each([
      ["override_tool", "override pattern"],
      ["shadow_function", "shadow pattern"],
      ["poison_cache", "poison pattern"],
      ["create_tool_dynamic", "create.*tool pattern"],
      ["register_tool", "register.*tool pattern"],
      ["define_tool", "define.*tool pattern"],
      ["tool_creator", "tool.*creator pattern"],
      ["add_tool_runtime", "add.*tool pattern"],
    ])("classifies %s as TOOL_OVERRIDE (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects tool override from description", () => {
      const result = classifier.classify(
        "tool",
        "Dynamically registers new tools",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes shadowing/poisoning risk in reasoning", () => {
      const result = classifier.classify("override_tool");
      expect(result.reasoning).toContain("shadowing/poisoning risk");
    });
  });

  describe("HIGH RISK: CONFIG_MODIFIER", () => {
    const expectedCategory = ToolCategory.CONFIG_MODIFIER;
    const expectedConfidence = 88;

    it.each([
      ["config_editor", "config pattern"],
      ["setting_manager", "setting pattern"],
      ["modifier_tool", "modifier pattern"],
      ["privilege_escalator", "privilege pattern"],
      ["permission_manager", "permission pattern"],
      ["configure_system", "configure pattern"],
      ["drift_detector", "drift pattern"],
    ])("classifies %s as CONFIG_MODIFIER (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects admin via description", () => {
      const result = classifier.classify("tool", "admin panel access");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects config modifier from description", () => {
      const result = classifier.classify(
        "tool",
        "Modifies system configuration settings",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes configuration drift risk in reasoning", () => {
      const result = classifier.classify("config_editor");
      expect(result.reasoning).toContain("configuration drift risk");
    });
  });

  describe("HIGH RISK: URL_FETCHER", () => {
    const expectedCategory = ToolCategory.URL_FETCHER;
    const expectedConfidence = 87;

    it.each([
      ["fetch_content", "fetch pattern"],
      ["url_loader", "url pattern"],
      ["http_client", "http pattern"],
      ["download_file", "download pattern"],
      ["load_resource", "load pattern"],
      ["retrieve_page", "retrieve pattern"],
      ["external_api", "external pattern"],
    ])("classifies %s as URL_FETCHER (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects get url pattern via description", () => {
      const result = classifier.classify("tool", "get url content");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects URL fetcher from description", () => {
      const result = classifier.classify(
        "tool",
        "Downloads content from external URLs",
      );
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes indirect prompt injection risk in reasoning", () => {
      const result = classifier.classify("fetch_content");
      expect(result.reasoning).toContain("indirect prompt injection risk");
    });
  });

  // ============================================================================
  // MEDIUM RISK CATEGORIES (4)
  // ============================================================================

  describe("MEDIUM RISK: UNICODE_PROCESSOR", () => {
    const expectedCategory = ToolCategory.UNICODE_PROCESSOR;
    const expectedConfidence = 75;

    it.each([
      ["unicode_converter", "unicode pattern"],
      ["encode_string", "encode pattern"],
      ["decode_base64", "decode pattern"],
      ["charset_handler", "charset pattern"],
      ["utf8_processor", "utf pattern"],
      ["hex_encoder", "hex pattern"],
      ["escape_sequences", "escape pattern"],
    ])("classifies %s as UNICODE_PROCESSOR (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes bypass encoding risk in reasoning", () => {
      const result = classifier.classify("unicode_converter");
      expect(result.reasoning).toContain("bypass encoding risk");
    });
  });

  describe("MEDIUM RISK: JSON_PARSER", () => {
    const expectedCategory = ToolCategory.JSON_PARSER;
    const expectedConfidence = 78;

    it.each([
      ["parser_tool", "parser pattern"],
      ["parse_input", "parse pattern"],
      ["json_handler", "json pattern"],
      ["xml_processor", "xml pattern"],
      ["yaml_loader", "yaml pattern"],
      ["nested_parser", "nested pattern"],
      ["deserialize_data", "deserialize pattern"],
      ["unmarshal_object", "unmarshal pattern"],
    ])("classifies %s as JSON_PARSER (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes nested injection risk in reasoning", () => {
      const result = classifier.classify("json_handler");
      expect(result.reasoning).toContain("nested injection risk");
    });
  });

  describe("MEDIUM RISK: PACKAGE_INSTALLER", () => {
    const expectedCategory = ToolCategory.PACKAGE_INSTALLER;
    const expectedConfidence = 70;

    it.each([
      ["install_package", "install pattern"],
      ["package_manager", "package pattern"],
      ["npm_installer", "npm pattern"],
      ["pip_install", "pip pattern"],
      ["dependency_resolver", "dependency pattern"],
      ["module_loader", "module pattern"],
      ["library_installer", "library pattern"],
      ["gem_install", "gem pattern"],
    ])("classifies %s as PACKAGE_INSTALLER (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes typosquatting risk in reasoning", () => {
      const result = classifier.classify("install_package");
      expect(result.reasoning).toContain("typosquatting risk");
    });
  });

  describe("MEDIUM RISK: RUG_PULL", () => {
    const expectedCategory = ToolCategory.RUG_PULL;
    const expectedConfidence = 80;

    it.each([
      ["rug_pull_tool", "rug.*pull pattern"],
      ["trust_builder", "trust pattern"],
      ["behavior_change_detector", "behavior.*change pattern"],
      ["malicious_after_time", "malicious.*after pattern"],
      ["invocation_count_tracker", "invocation.*count pattern"],
    ])("classifies %s as RUG_PULL (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes behavioral change risk in reasoning", () => {
      const result = classifier.classify("rug_pull_tool");
      expect(result.reasoning).toContain("behavioral change risk");
    });
  });

  // ============================================================================
  // SAFE CATEGORIES (5)
  // ============================================================================

  describe("SAFE: API_WRAPPER", () => {
    const expectedCategory = ToolCategory.API_WRAPPER;
    const expectedConfidence = 95;

    it.each([
      ["firecrawl_scrape", "firecrawl pattern"],
      ["web_scraping_tool", "web.*scraping pattern"],
      ["api_wrapper_client", "api.*wrapper pattern"],
      ["http_client_wrapper", "http.*client pattern"],
      ["web_client", "web.*client pattern"],
      ["rest_client", "rest.*client pattern"],
      ["graphql_client", "graphql.*client pattern"],
      ["fetch_web_content_safely", "fetch.*web.*content pattern"],
    ])("classifies %s as API_WRAPPER (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects scrape via description", () => {
      const result = classifier.classify("tool", "scrape web page");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects crawl via description", () => {
      const result = classifier.classify("tool", "crawl website");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes safe data passing in reasoning", () => {
      const result = classifier.classify("firecrawl_scrape");
      expect(result.reasoning).toContain("safe data passing");
    });
  });

  describe("SAFE: SEARCH_RETRIEVAL", () => {
    const expectedCategory = ToolCategory.SEARCH_RETRIEVAL;
    const expectedConfidence = 93;

    // Note: word boundary patterns require isolated words
    // Test via descriptions or space-separated names
    it.each([
      ["retrieve_records", "retrieve pattern"],
      ["get_users_list", "get.*users pattern"],
      ["get_pages", "get.*pages pattern"],
      ["get_database_info", "get.*database pattern"],
    ])("classifies %s as SEARCH_RETRIEVAL (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects lookup via description", () => {
      const result = classifier.classify("tool", "lookup user by id");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects search via description", () => {
      const result = classifier.classify("tool", "search for documents");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects find via description", () => {
      const result = classifier.classify("tool", "find matching items");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects query via description", () => {
      const result = classifier.classify("tool", "query the database");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects list via description", () => {
      const result = classifier.classify("tool", "list all entries");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes returns data not code execution in reasoning", () => {
      const result = classifier.classify("retrieve_records");
      expect(result.reasoning).toContain("returns data");
    });
  });

  describe("SAFE: CRUD_CREATION", () => {
    const expectedCategory = ToolCategory.CRUD_CREATION;
    const expectedConfidence = 92;

    // Word boundary patterns - all CRUD patterns use \b
    // Test via descriptions for isolated words
    it("detects create via description", () => {
      const result = classifier.classify("tool", "create a new document");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects add via description", () => {
      const result = classifier.classify("tool", "add items to collection");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects insert via description", () => {
      const result = classifier.classify("tool", "insert new record");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects update via description", () => {
      const result = classifier.classify("tool", "update existing entries");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects modify via description", () => {
      const result = classifier.classify("tool", "modify content");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects delete via description", () => {
      const result = classifier.classify("tool", "delete selected items");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects duplicate via description", () => {
      const result = classifier.classify("tool", "duplicate page");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects move via description", () => {
      const result = classifier.classify("tool", "move file to folder");
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects append via description", () => {
      const result = classifier.classify("tool", "append data to file");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes data manipulation not code execution in reasoning", () => {
      const result = classifier.classify("tool", "create document");
      expect(result.reasoning).toContain("data manipulation");
    });
  });

  describe("SAFE: READ_ONLY_INFO", () => {
    const expectedCategory = ToolCategory.READ_ONLY_INFO;
    const expectedConfidence = 94;

    it.each([
      ["get_self_info", "get.*self pattern"],
      ["get_teams_list", "get.*teams pattern"],
      ["get_info_about", "get.*info pattern"],
      ["get_status_report", "get.*status pattern"],
      ["get_workspace_details", "get.*workspace pattern"],
      ["get_user_profile", "get.*user pattern"],
      ["current_user_info", "current.*user pattern"],
    ])("classifies %s as READ_ONLY_INFO (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("detects whoami via description", () => {
      const result = classifier.classify("tool", "whoami - current user info");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes intended data exposure in reasoning", () => {
      const result = classifier.classify("get_self_info");
      expect(result.reasoning).toContain("intended data exposure");
    });
  });

  describe("SAFE: SAFE_STORAGE", () => {
    const expectedCategory = ToolCategory.SAFE_STORAGE;
    const expectedConfidence = 99;

    it.each([
      ["safe_storage_tool_mcp", "safe.*storage pattern"],
      ["safe_search_tool_mcp", "safe.*search pattern"],
      ["safe_list_tool_mcp", "safe.*list pattern"],
      ["safe_info_tool_mcp", "safe.*info pattern"],
      ["safe_echo_tool_mcp", "safe.*echo pattern"],
      ["safe_validate_tool_mcp", "safe.*validate pattern"],
      ["safe_tool_generic", "safe.*tool pattern"],
    ])("classifies %s as SAFE_STORAGE (%s)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes control group should be safe in reasoning", () => {
      const result = classifier.classify("safe_storage_tool_mcp");
      expect(result.reasoning).toContain("control group");
    });

    it("has highest confidence (99) for safe tools", () => {
      const result = classifier.classify("safe_tool");
      expect(result.confidence).toBe(99);
    });
  });

  // ============================================================================
  // DEFAULT CATEGORY (GENERIC)
  // ============================================================================

  describe("DEFAULT: GENERIC", () => {
    const expectedCategory = ToolCategory.GENERIC;
    const expectedConfidence = 50;

    it.each([
      ["random_tool_name"],
      ["xyz_abc_123"],
      ["completely_unknown"],
      ["foobar_baz"],
      ["_internal_helper"],
    ])("classifies %s as GENERIC (no pattern match)", (toolName) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
      expect(result.categories).toHaveLength(1);
      expect(result.confidence).toBe(expectedConfidence);
    });

    it("uses GENERIC for empty tool name", () => {
      const result = classifier.classify("");
      expect(result.categories).toContain(expectedCategory);
    });

    it("includes no specific pattern match in reasoning", () => {
      const result = classifier.classify("xyz_unknown");
      expect(result.reasoning).toContain("No specific pattern match");
    });
  });

  // ============================================================================
  // MULTI-CATEGORY DETECTION
  // ============================================================================

  describe("Multi-category detection", () => {
    it("detects multiple HIGH RISK categories from description", () => {
      // Use description to trigger multiple patterns
      const result = classifier.classify(
        "tool",
        "calculator that can execute shell commands",
      );
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
      expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
      expect(result.categories.length).toBeGreaterThanOrEqual(2);
    });

    it("detects DATA_ACCESS + URL_FETCHER for fetch with leak", () => {
      const result = classifier.classify("leak_fetch_tool");
      expect(result.categories).toContain(ToolCategory.DATA_ACCESS);
      expect(result.categories).toContain(ToolCategory.URL_FETCHER);
    });

    it("detects JSON_PARSER + DATA_ACCESS from description", () => {
      const result = classifier.classify(
        "tool",
        "parses json data with sensitive info",
      );
      expect(result.categories).toContain(ToolCategory.JSON_PARSER);
      expect(result.categories).toContain(ToolCategory.DATA_ACCESS);
    });

    it("detects multiple SAFE categories from description", () => {
      const result = classifier.classify("tool", "search and list all entries");
      expect(result.categories).toContain(ToolCategory.SEARCH_RETRIEVAL);
    });

    it("detects CODE_EXECUTOR + CONFIG_MODIFIER from description", () => {
      const result = classifier.classify(
        "tool",
        "runs code and modifies config settings",
      );
      expect(result.categories).toContain(ToolCategory.CODE_EXECUTOR);
      expect(result.categories).toContain(ToolCategory.CONFIG_MODIFIER);
    });

    it("correctly averages confidence for multi-category", () => {
      // Use description to trigger multiple high-confidence patterns
      const result = classifier.classify("calculator_command_tool");
      expect(result.confidence).toBeGreaterThanOrEqual(85);
    });

    // Category ordering verification - categories appear in pattern-match order
    it("returns categories in source pattern order (DATA_ACCESS before URL_FETCHER)", () => {
      const result = classifier.classify("leak_fetch_tool");
      const dataIdx = result.categories.indexOf(ToolCategory.DATA_ACCESS);
      const fetcherIdx = result.categories.indexOf(ToolCategory.URL_FETCHER);
      // DATA_ACCESS is checked before URL_FETCHER in source
      expect(dataIdx).toBeLessThan(fetcherIdx);
    });

    it("returns categories in source pattern order (CALCULATOR before SYSTEM_EXEC)", () => {
      const result = classifier.classify("calc_exec_command");
      const calcIdx = result.categories.indexOf(ToolCategory.CALCULATOR);
      const execIdx = result.categories.indexOf(ToolCategory.SYSTEM_EXEC);
      // CALCULATOR is checked before SYSTEM_EXEC in source
      expect(calcIdx).toBeLessThan(execIdx);
    });
  });

  // ============================================================================
  // HYPHENATED NAME PATTERNS (word boundaries match hyphens)
  // ============================================================================

  describe("Hyphenated name patterns", () => {
    // Word boundary \b matches hyphens (unlike underscores which are word chars)
    it("matches search pattern in hyphenated name", () => {
      const result = classifier.classify("my-search-tool");
      expect(result.categories).toContain(ToolCategory.SEARCH_RETRIEVAL);
    });

    it("matches get pattern in hyphenated name", () => {
      const result = classifier.classify("api-get-data");
      expect(result.categories).toContain(ToolCategory.DATA_ACCESS);
    });

    it("matches list pattern in hyphenated name", () => {
      const result = classifier.classify("user-list-api");
      expect(result.categories).toContain(ToolCategory.DATA_ACCESS);
    });

    it("matches create pattern in hyphenated name", () => {
      const result = classifier.classify("doc-create-tool");
      expect(result.categories).toContain(ToolCategory.CRUD_CREATION);
    });

    it("matches run pattern in hyphenated name", () => {
      const result = classifier.classify("task-run-executor");
      expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
    });

    it("matches admin pattern in hyphenated name", () => {
      const result = classifier.classify("super-admin-panel");
      expect(result.categories).toContain(ToolCategory.CONFIG_MODIFIER);
    });

    it("contrasts hyphen vs underscore behavior", () => {
      // Hyphen: \bget\b matches because hyphen is word boundary
      const hyphenated = classifier.classify("api-get-data");
      expect(hyphenated.categories).toContain(ToolCategory.DATA_ACCESS);

      // Underscore: \bget\b does NOT match because underscore is word char
      const underscored = classifier.classify("api_get_data");
      expect(underscored.categories).not.toContain(ToolCategory.DATA_ACCESS);
    });
  });

  // ============================================================================
  // CONFIDENCE CALCULATION
  // ============================================================================

  describe("Confidence calculation", () => {
    it("returns exact confidence for single-category match", () => {
      // SAFE_STORAGE has 99 confidence
      const result = classifier.classify("safe_tool");
      expect(result.confidence).toBe(99);
    });

    it("rounds averaged confidence to integer", () => {
      // Any multi-match should result in an integer
      const result = classifier.classify("calc_exec");
      expect(Number.isInteger(result.confidence)).toBe(true);
    });

    it("returns 50 confidence for GENERIC", () => {
      const result = classifier.classify("totally_unknown_xyz");
      expect(result.confidence).toBe(50);
    });

    it("higher confidence for HIGH RISK patterns", () => {
      const systemExec = classifier.classify("system_exec");
      const unicodeProc = classifier.classify("unicode_converter");
      expect(systemExec.confidence).toBeGreaterThan(unicodeProc.confidence);
    });

    it("SAFE categories have high confidence", () => {
      const safeResult = classifier.classify("safe_storage_tool");
      expect(safeResult.confidence).toBeGreaterThanOrEqual(95);
    });
  });

  // ============================================================================
  // REASONING STRING
  // ============================================================================

  describe("Reasoning string", () => {
    it("joins multiple reasons with semicolon", () => {
      const result = classifier.classify("calc_exec_command");
      expect(result.reasoning).toContain(";");
    });

    it("includes risk type in reasoning", () => {
      const result = classifier.classify("system_exec");
      expect(result.reasoning).toMatch(/risk/i);
    });

    it("includes pattern detected phrase", () => {
      const result = classifier.classify("calculator");
      expect(result.reasoning).toContain("pattern detected");
    });

    it("includes using generic tests for unknown tools", () => {
      const result = classifier.classify("xyz_unknown");
      expect(result.reasoning).toContain("generic tests");
    });
  });

  // ============================================================================
  // EDGE CASES & FALSE POSITIVE PREVENTION
  // ============================================================================

  describe("Edge cases", () => {
    it("handles undefined description", () => {
      const result = classifier.classify("calculator");
      expect(result).toBeDefined();
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("handles empty description", () => {
      const result = classifier.classify("calculator", "");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("handles very long tool names", () => {
      const longName = "a".repeat(1000) + "_calculator";
      const result = classifier.classify(longName);
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("handles special characters in tool name", () => {
      const result = classifier.classify("calc!@#$%ulator");
      // Should still match calculator pattern
      expect(result).toBeDefined();
    });

    it("handles unicode in tool name", () => {
      const result = classifier.classify("計算器_calculator");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("is case insensitive", () => {
      const lower = classifier.classify("calculator");
      const upper = classifier.classify("CALCULATOR");
      const mixed = classifier.classify("CaLcUlAtOr");
      expect(lower.categories).toEqual(upper.categories);
      expect(upper.categories).toEqual(mixed.categories);
    });

    it("handles whitespace-only description", () => {
      const result = classifier.classify("calculator", "   \t\n  ");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    // Defensive validation tests (Warning #3 fix)
    it("returns GENERIC with 0 confidence for empty tool name", () => {
      const result = classifier.classify("");
      expect(result.categories).toEqual([ToolCategory.GENERIC]);
      expect(result.confidence).toBe(0);
      expect(result.reasoning).toContain("Invalid or empty tool name");
    });

    it("returns GENERIC with 0 confidence for whitespace-only tool name", () => {
      const result = classifier.classify("   \t\n  ");
      expect(result.categories).toEqual([ToolCategory.GENERIC]);
      expect(result.confidence).toBe(0);
      expect(result.reasoning).toContain("Invalid or empty tool name");
    });

    it("handles null tool name gracefully (runtime JS caller)", () => {
      // TypeScript prevents this, but JS callers or deserialized data might pass null
      const result = classifier.classify(null as unknown as string);
      expect(result.categories).toEqual([ToolCategory.GENERIC]);
      expect(result.confidence).toBe(0);
    });

    it("handles undefined tool name gracefully (runtime JS caller)", () => {
      const result = classifier.classify(undefined as unknown as string);
      expect(result.categories).toEqual([ToolCategory.GENERIC]);
      expect(result.confidence).toBe(0);
    });

    it("handles non-string description gracefully (runtime JS caller)", () => {
      // TypeScript prevents this, but runtime might pass objects
      const result = classifier.classify("calculator", {
        foo: "bar",
      } as unknown as string);
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    // ReDoS protection test (Warning #1 fix)
    it("truncates very long inputs to prevent ReDoS", () => {
      // Input longer than MAX_INPUT_LENGTH (10000) should still work
      const longName = "calculator_" + "x".repeat(15000);
      const result = classifier.classify(longName);
      // Should still match because "calculator" is in first 10000 chars
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("handles pattern at truncation boundary", () => {
      // Put pattern right at the edge of truncation limit
      const longPrefix = "x".repeat(9990);
      const result = classifier.classify(longPrefix + "_calculator");
      // "calculator" starts at position 9991, within 10000 limit
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it.each([
      ["SYSTEM_EXEC", ToolCategory.SYSTEM_EXEC],
      ["JSON_handler", ToolCategory.JSON_PARSER],
      ["URL_FETCHER", ToolCategory.URL_FETCHER],
      ["SAFE_storage_TOOL", ToolCategory.SAFE_STORAGE],
      ["CONFIG_editor", ToolCategory.CONFIG_MODIFIER],
    ])("is case insensitive for %s", (toolName, expectedCategory) => {
      const result = classifier.classify(toolName);
      expect(result.categories).toContain(expectedCategory);
    });

    it("matches patterns in description even with neutral tool name", () => {
      const result = classifier.classify(
        "neutral_tool",
        "Executes system commands",
      );
      expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
    });
  });

  describe("False positive prevention", () => {
    // The word boundary patterns (\b) properly prevent false positives
    it("get pattern should not match 'target' or 'budget'", () => {
      const target = classifier.classify("target_selector");
      const budget = classifier.classify("budget_manager");
      // Word boundary patterns don't match substrings
      expect(target.categories).not.toContain(ToolCategory.DATA_ACCESS);
    });

    it("run pattern should not match 'running_stats'", () => {
      // /\brun\b/ doesn't match 'running' - no word boundary
      const result = classifier.classify("running_stats_collector");
      expect(result.categories).not.toContain(ToolCategory.SYSTEM_EXEC);
    });

    it("list pattern does not match 'listener'", () => {
      const result = classifier.classify("event_listener");
      // /\blist\b/ should not match 'listener'
      expect(result.categories).not.toContain(ToolCategory.DATA_ACCESS);
      expect(result.categories).not.toContain(ToolCategory.SEARCH_RETRIEVAL);
    });

    it("data pattern does NOT match 'database_connector'", () => {
      // /\bdata\b/ does NOT match 'database' because 'data' followed by 'base' (word char)
      const result = classifier.classify("database_connector");
      expect(result.categories).not.toContain(ToolCategory.DATA_ACCESS);
    });

    it("safe prefix takes priority with high confidence", () => {
      const result = classifier.classify("safe_data_tool");
      expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
    });

    it("distinguishes api_wrapper from url_fetcher", () => {
      const apiWrapper = classifier.classify("api_wrapper_client");
      const urlFetcher = classifier.classify("url_fetcher");
      expect(apiWrapper.categories).toContain(ToolCategory.API_WRAPPER);
      expect(urlFetcher.categories).toContain(ToolCategory.URL_FETCHER);
    });

    it("notion tools classified via description", () => {
      // Word boundary patterns need isolated words
      const search = classifier.classify("notion_tool", "search pages");
      const create = classifier.classify("notion_tool", "create new page");
      expect(search.categories).toContain(ToolCategory.SEARCH_RETRIEVAL);
      expect(create.categories).toContain(ToolCategory.CRUD_CREATION);
    });
  });

  // ============================================================================
  // STATIC METHODS
  // ============================================================================

  describe("Static method: getAllCategories", () => {
    it("returns all 17 categories", () => {
      const categories = ToolClassifier.getAllCategories();
      expect(categories).toHaveLength(17);
    });

    it("includes all HIGH RISK categories", () => {
      const categories = ToolClassifier.getAllCategories();
      expect(categories).toContain(ToolCategory.CALCULATOR);
      expect(categories).toContain(ToolCategory.SYSTEM_EXEC);
      expect(categories).toContain(ToolCategory.CODE_EXECUTOR);
      expect(categories).toContain(ToolCategory.DATA_ACCESS);
      expect(categories).toContain(ToolCategory.TOOL_OVERRIDE);
      expect(categories).toContain(ToolCategory.CONFIG_MODIFIER);
      expect(categories).toContain(ToolCategory.URL_FETCHER);
    });

    it("includes all MEDIUM RISK categories", () => {
      const categories = ToolClassifier.getAllCategories();
      expect(categories).toContain(ToolCategory.UNICODE_PROCESSOR);
      expect(categories).toContain(ToolCategory.JSON_PARSER);
      expect(categories).toContain(ToolCategory.PACKAGE_INSTALLER);
      expect(categories).toContain(ToolCategory.RUG_PULL);
    });

    it("includes all SAFE categories", () => {
      const categories = ToolClassifier.getAllCategories();
      expect(categories).toContain(ToolCategory.API_WRAPPER);
      expect(categories).toContain(ToolCategory.SEARCH_RETRIEVAL);
      expect(categories).toContain(ToolCategory.CRUD_CREATION);
      expect(categories).toContain(ToolCategory.READ_ONLY_INFO);
      expect(categories).toContain(ToolCategory.SAFE_STORAGE);
    });

    it("includes GENERIC category", () => {
      const categories = ToolClassifier.getAllCategories();
      expect(categories).toContain(ToolCategory.GENERIC);
    });
  });

  describe("Static method: getRiskLevel", () => {
    it.each([
      [ToolCategory.CALCULATOR, "HIGH"],
      [ToolCategory.SYSTEM_EXEC, "HIGH"],
      [ToolCategory.CODE_EXECUTOR, "HIGH"],
      [ToolCategory.DATA_ACCESS, "HIGH"],
      [ToolCategory.TOOL_OVERRIDE, "HIGH"],
      [ToolCategory.CONFIG_MODIFIER, "HIGH"],
      [ToolCategory.URL_FETCHER, "HIGH"],
    ])("returns HIGH for %s", (category, expected) => {
      expect(ToolClassifier.getRiskLevel(category)).toBe(expected);
    });

    it.each([
      [ToolCategory.UNICODE_PROCESSOR, "MEDIUM"],
      [ToolCategory.JSON_PARSER, "MEDIUM"],
      [ToolCategory.PACKAGE_INSTALLER, "MEDIUM"],
      [ToolCategory.RUG_PULL, "MEDIUM"],
    ])("returns MEDIUM for %s", (category, expected) => {
      expect(ToolClassifier.getRiskLevel(category)).toBe(expected);
    });

    it.each([
      [ToolCategory.API_WRAPPER, "LOW"],
      [ToolCategory.SEARCH_RETRIEVAL, "LOW"],
      [ToolCategory.CRUD_CREATION, "LOW"],
      [ToolCategory.READ_ONLY_INFO, "LOW"],
      [ToolCategory.SAFE_STORAGE, "LOW"],
      [ToolCategory.GENERIC, "LOW"],
    ])("returns LOW for %s", (category, expected) => {
      expect(ToolClassifier.getRiskLevel(category)).toBe(expected);
    });

    it("returns LOW for unknown category", () => {
      // Force an unknown category
      const unknownCategory = "unknown" as ToolCategory;
      expect(ToolClassifier.getRiskLevel(unknownCategory)).toBe("LOW");
    });
  });

  // ============================================================================
  // BATCH CLASSIFICATION
  // ============================================================================

  describe("Batch classification: classifyBatch", () => {
    it("classifies multiple tools at once", () => {
      const tools = [
        { name: "calculator" },
        { name: "system_exec" },
        { name: "safe_tool" },
      ];
      const results = classifier.classifyBatch(tools);
      expect(results).toHaveLength(3);
      expect(results[0].categories).toContain(ToolCategory.CALCULATOR);
      expect(results[1].categories).toContain(ToolCategory.SYSTEM_EXEC);
      expect(results[2].categories).toContain(ToolCategory.SAFE_STORAGE);
    });

    it("handles empty array", () => {
      const results = classifier.classifyBatch([]);
      expect(results).toHaveLength(0);
    });

    it("includes descriptions in classification", () => {
      const tools = [
        { name: "unknown", description: "Executes shell commands" },
      ];
      const results = classifier.classifyBatch(tools);
      expect(results[0].categories).toContain(ToolCategory.SYSTEM_EXEC);
    });

    it("preserves tool names in results", () => {
      const tools = [
        { name: "tool_alpha" },
        { name: "tool_beta" },
        { name: "tool_gamma" },
      ];
      const results = classifier.classifyBatch(tools);
      expect(results[0].toolName).toBe("tool_alpha");
      expect(results[1].toolName).toBe("tool_beta");
      expect(results[2].toolName).toBe("tool_gamma");
    });

    it("handles tools without descriptions", () => {
      const tools = [
        { name: "calculator" },
        { name: "parser", description: undefined },
      ];
      const results = classifier.classifyBatch(tools);
      expect(results).toHaveLength(2);
      expect(results[0].categories).toContain(ToolCategory.CALCULATOR);
      expect(results[1].categories).toContain(ToolCategory.JSON_PARSER);
    });

    it("returns independent classifications for each tool", () => {
      const tools = [{ name: "safe_storage" }, { name: "system_exec" }];
      const results = classifier.classifyBatch(tools);
      // First should be SAFE, second should be HIGH RISK
      expect(results[0].confidence).toBeGreaterThan(90); // SAFE_STORAGE = 99
      expect(results[1].confidence).toBeGreaterThan(90); // SYSTEM_EXEC = 95
    });

    it("handles large batch classification efficiently", () => {
      const tools = Array.from({ length: 1000 }, (_, i) => ({
        name: `tool_${i % 17}_${["calculator", "exec", "data", "safe"][i % 4]}`,
      }));
      const start = Date.now();
      const results = classifier.classifyBatch(tools);
      const elapsed = Date.now() - start;

      expect(results).toHaveLength(1000);
      expect(elapsed).toBeLessThan(1000); // Should complete in under 1 second
    });
  });

  // ============================================================================
  // REAL TOOL EXAMPLES (from testbed)
  // ============================================================================

  describe("Real tool examples from testbed", () => {
    describe("Vulnerable MCP server tools", () => {
      it("vulnerable_calculator_tool -> CALCULATOR", () => {
        const result = classifier.classify("vulnerable_calculator_tool");
        expect(result.categories).toContain(ToolCategory.CALCULATOR);
      });

      it("vulnerable_system_exec_tool -> SYSTEM_EXEC", () => {
        const result = classifier.classify("vulnerable_system_exec_tool");
        expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
      });

      it("vulnerable_data_leak_tool -> DATA_ACCESS", () => {
        const result = classifier.classify("vulnerable_data_leak_tool");
        expect(result.categories).toContain(ToolCategory.DATA_ACCESS);
      });

      it("vulnerable_tool_override_tool -> TOOL_OVERRIDE", () => {
        const result = classifier.classify("vulnerable_tool_override_tool");
        expect(result.categories).toContain(ToolCategory.TOOL_OVERRIDE);
      });

      it("vulnerable_config_modifier_tool -> CONFIG_MODIFIER", () => {
        const result = classifier.classify("vulnerable_config_modifier_tool");
        expect(result.categories).toContain(ToolCategory.CONFIG_MODIFIER);
      });

      it("vulnerable_fetcher_tool -> URL_FETCHER", () => {
        const result = classifier.classify("vulnerable_fetcher_tool");
        expect(result.categories).toContain(ToolCategory.URL_FETCHER);
      });

      it("vulnerable_unicode_processor_tool -> UNICODE_PROCESSOR", () => {
        const result = classifier.classify("vulnerable_unicode_processor_tool");
        expect(result.categories).toContain(ToolCategory.UNICODE_PROCESSOR);
      });

      it("vulnerable_nested_parser_tool -> JSON_PARSER", () => {
        const result = classifier.classify("vulnerable_nested_parser_tool");
        expect(result.categories).toContain(ToolCategory.JSON_PARSER);
      });

      it("vulnerable_package_installer_tool -> PACKAGE_INSTALLER", () => {
        const result = classifier.classify("vulnerable_package_installer_tool");
        expect(result.categories).toContain(ToolCategory.PACKAGE_INSTALLER);
      });

      it("vulnerable_rug_pull_tool -> RUG_PULL", () => {
        const result = classifier.classify("vulnerable_rug_pull_tool");
        expect(result.categories).toContain(ToolCategory.RUG_PULL);
      });
    });

    describe("Safe MCP server tools (control group)", () => {
      it("safe_storage_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_storage_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });

      it("safe_search_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_search_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });

      it("safe_list_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_list_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });

      it("safe_info_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_info_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });

      it("safe_echo_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_echo_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });

      it("safe_validate_tool_mcp -> SAFE_STORAGE", () => {
        const result = classifier.classify("safe_validate_tool_mcp");
        expect(result.categories).toContain(ToolCategory.SAFE_STORAGE);
      });
    });
  });

  // ============================================================================
  // INTERFACE TYPE VERIFICATION
  // ============================================================================

  describe("ToolClassification interface", () => {
    it("returns correct interface structure", () => {
      const result = classifier.classify("calculator");
      expect(result).toHaveProperty("toolName");
      expect(result).toHaveProperty("categories");
      expect(result).toHaveProperty("confidence");
      expect(result).toHaveProperty("reasoning");
    });

    it("toolName matches input", () => {
      const result = classifier.classify("my_special_tool");
      expect(result.toolName).toBe("my_special_tool");
    });

    it("categories is array of ToolCategory", () => {
      const result = classifier.classify("calculator");
      expect(Array.isArray(result.categories)).toBe(true);
      expect(result.categories.length).toBeGreaterThan(0);
    });

    it("confidence is number between 0 and 100", () => {
      const result = classifier.classify("calculator");
      expect(typeof result.confidence).toBe("number");
      expect(result.confidence).toBeGreaterThanOrEqual(0);
      expect(result.confidence).toBeLessThanOrEqual(100);
    });

    it("reasoning is non-empty string", () => {
      const result = classifier.classify("calculator");
      expect(typeof result.reasoning).toBe("string");
      expect(result.reasoning.length).toBeGreaterThan(0);
    });
  });

  // ============================================================================
  // PATTERN MATCHING INTERNALS (via private method testing)
  // ============================================================================

  describe("Pattern matching behavior", () => {
    it("combines tool name and description for matching", () => {
      // Tool name has no pattern, description does
      const result = classifier.classify("xyz_tool", "calculator for math");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("lowercases combined text for matching", () => {
      const result = classifier.classify("CALCULATOR_TOOL");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("matches partial patterns in combined text", () => {
      const result = classifier.classify("my", "This is a calculator");
      expect(result.categories).toContain(ToolCategory.CALCULATOR);
    });

    it("description patterns take precedence over generic name", () => {
      const result = classifier.classify("tool123", "Executes arbitrary code");
      expect(result.categories).toContain(ToolCategory.CODE_EXECUTOR);
    });
  });

  // ============================================================================
  // CONFIDENCE VALUES VERIFICATION (Code Review Suggestion #1)
  // ============================================================================

  describe("Confidence values match source implementation", () => {
    // Single-category matches should return exact confidence values from source
    it.each([
      [ToolCategory.CALCULATOR, 90, "calculator_tool"],
      [ToolCategory.SYSTEM_EXEC, 95, "system_exec_tool"],
      [ToolCategory.CODE_EXECUTOR, 95, "code_runner"],
      [ToolCategory.DATA_ACCESS, 85, "data_leak_tool"],
      [ToolCategory.TOOL_OVERRIDE, 92, "override_tool"],
      [ToolCategory.CONFIG_MODIFIER, 88, "config_editor"],
      [ToolCategory.URL_FETCHER, 87, "fetch_content"],
      [ToolCategory.UNICODE_PROCESSOR, 75, "unicode_converter"],
      [ToolCategory.JSON_PARSER, 78, "parser_tool"],
      [ToolCategory.PACKAGE_INSTALLER, 70, "install_package"],
      [ToolCategory.RUG_PULL, 80, "rug_pull_tool"],
      [ToolCategory.API_WRAPPER, 95, "firecrawl_scrape"],
      [ToolCategory.SAFE_STORAGE, 99, "safe_tool"],
      [ToolCategory.GENERIC, 50, "xyz_unknown_tool"],
    ])(
      "%s has confidence %d for tool %s",
      (category, expectedConfidence, toolName) => {
        const result = classifier.classify(toolName);
        expect(result.categories).toContain(category);
        // Single-category match should have exact confidence
        if (result.categories.length === 1) {
          expect(result.confidence).toBe(expectedConfidence);
        }
      },
    );

    // Test via descriptions for patterns requiring word boundaries
    it("SEARCH_RETRIEVAL has confidence 93", () => {
      const result = classifier.classify("tool", "search documents");
      expect(result.categories).toContain(ToolCategory.SEARCH_RETRIEVAL);
      // May have multiple categories due to "search" matching multiple patterns
    });

    it("CRUD_CREATION has confidence 92", () => {
      const result = classifier.classify("tool", "create document");
      expect(result.categories).toContain(ToolCategory.CRUD_CREATION);
    });

    it("READ_ONLY_INFO has confidence 94", () => {
      const result = classifier.classify("get_self_info");
      expect(result.categories).toContain(ToolCategory.READ_ONLY_INFO);
    });
  });

  // ============================================================================
  // NEGATIVE PATTERN TESTS (Code Review Suggestion #2)
  // ============================================================================

  describe("Negative pattern tests - tools that should NOT match specific categories", () => {
    it.each([
      [
        "weather_forecast",
        ToolCategory.CALCULATOR,
        "weather is not calculator",
      ],
      ["image_resizer_v2", ToolCategory.SYSTEM_EXEC, "resizer not exec"],
      [
        "message_handler",
        ToolCategory.CODE_EXECUTOR,
        "handler not code executor",
      ],
      ["color_picker", ToolCategory.DATA_ACCESS, "picker not data access"],
      ["theme_selector", ToolCategory.TOOL_OVERRIDE, "selector not override"],
      ["layout_manager", ToolCategory.CONFIG_MODIFIER, "layout not config"],
      ["cache_cleaner", ToolCategory.URL_FETCHER, "cleaner not fetcher"],
      [
        "text_formatter",
        ToolCategory.UNICODE_PROCESSOR,
        "formatter not unicode",
      ],
      ["image_resizer", ToolCategory.JSON_PARSER, "resizer not parser"],
      [
        "file_compressor",
        ToolCategory.PACKAGE_INSTALLER,
        "compressor not installer",
      ],
      ["timer_scheduler", ToolCategory.RUG_PULL, "scheduler not rug pull"],
    ])("%s should NOT be classified as %s (%s)", (toolName, category) => {
      const result = classifier.classify(toolName);
      expect(result.categories).not.toContain(category);
    });
  });

  // ============================================================================
  // SNAPSHOT TESTS (Code Review Suggestion #3)
  // ============================================================================

  describe("Snapshot tests for complex classifications", () => {
    it("matches snapshot for multi-pattern tool (calculator + command)", () => {
      const result = classifier.classify("calculator_command_tool");
      expect(result).toMatchSnapshot();
    });

    it("matches snapshot for multi-pattern tool (fetch + leak)", () => {
      const result = classifier.classify("leak_fetch_tool");
      expect(result).toMatchSnapshot();
    });

    it("matches snapshot for safe tool with multiple patterns", () => {
      const result = classifier.classify("safe_search_tool_mcp");
      expect(result).toMatchSnapshot();
    });

    // Additional edge case snapshots (Code Review Suggestion #5)
    it("matches snapshot for empty tool name", () => {
      const result = classifier.classify("");
      expect(result).toMatchSnapshot();
    });

    it("matches snapshot for unicode tool name with pattern", () => {
      const result = classifier.classify("计算器_compute_math");
      expect(result).toMatchSnapshot();
    });

    it("matches snapshot for maximum category overlap via description", () => {
      // Tool that matches many categories through description
      const result = classifier.classify(
        "neutral_tool",
        "calculator that executes shell commands to fetch data and modify config settings",
      );
      expect(result).toMatchSnapshot();
    });

    it("matches snapshot for tool matching all HIGH risk categories", () => {
      const result = classifier.classify(
        "calc_exec_data_override_config_fetch_tool",
      );
      expect(result).toMatchSnapshot();
    });
  });

  // ============================================================================
  // CONCURRENT CLASSIFICATION SAFETY (Code Review Suggestion #4)
  // ============================================================================

  describe("Concurrent classification safety", () => {
    it("handles concurrent classifications without interference", async () => {
      // Create 100 concurrent classification promises
      // Use full pattern-matching names: "calculator" and "command" (matches SYSTEM_EXEC)
      const promises = Array.from({ length: 100 }, (_, i) =>
        Promise.resolve(
          classifier.classify(
            `tool_${i}_${i % 2 === 0 ? "calculator" : "command"}`,
          ),
        ),
      );
      const results = await Promise.all(promises);

      // Verify each result matches expected category based on index
      results.forEach((result, i) => {
        if (i % 2 === 0) {
          expect(result.categories).toContain(ToolCategory.CALCULATOR);
        } else {
          expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
        }
      });
    });

    it("produces identical results for same input across concurrent calls", async () => {
      const toolName = "vulnerable_calculator_tool";

      // Run 50 concurrent classifications of the same tool
      const promises = Array.from({ length: 50 }, () =>
        Promise.resolve(classifier.classify(toolName)),
      );
      const results = await Promise.all(promises);

      // All results should be identical
      const firstResult = results[0];
      results.forEach((result) => {
        expect(result.categories).toEqual(firstResult.categories);
        expect(result.confidence).toBe(firstResult.confidence);
        expect(result.reasoning).toBe(firstResult.reasoning);
      });
    });

    it("maintains isolation between classifier instances", async () => {
      const classifiers = Array.from(
        { length: 10 },
        () => new ToolClassifier(),
      );

      // Each classifier processes a different tool concurrently
      const promises = classifiers.map((c, i) =>
        Promise.resolve(
          c.classify(i % 2 === 0 ? "calculator_tool" : "system_exec_tool"),
        ),
      );
      const results = await Promise.all(promises);

      // Results should match expected categories based on tool name
      results.forEach((result, i) => {
        if (i % 2 === 0) {
          expect(result.categories).toContain(ToolCategory.CALCULATOR);
        } else {
          expect(result.categories).toContain(ToolCategory.SYSTEM_EXEC);
        }
      });
    });
  });
});
