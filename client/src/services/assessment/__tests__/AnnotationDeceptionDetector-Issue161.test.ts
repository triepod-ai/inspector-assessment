/**
 * AnnotationDeceptionDetector Issue #161 Tests
 *
 * Tests for false positive fix when "post" is a noun (Reddit post) vs verb (POST method).
 * Issue #161: get_post_details with readOnlyHint=true should NOT be flagged as deceptive.
 *
 * @group unit
 * @group annotations
 * @group issue-161
 */

import {
  detectAnnotationDeception,
  isNounInReadOnlyContext,
  READONLY_PREFIX_PATTERNS,
  NOUN_KEYWORDS_IN_READONLY_CONTEXT,
} from "../modules/annotations/AnnotationDeceptionDetector";

describe("isNounInReadOnlyContext - Issue #161", () => {
  describe("post keyword", () => {
    it("should return true for get_post_details (post is noun)", () => {
      expect(isNounInReadOnlyContext("get_post_details", "post")).toBe(true);
    });

    it("should return true for list_posts (post is noun)", () => {
      expect(isNounInReadOnlyContext("list_posts", "post")).toBe(true);
    });

    it("should return true for fetch_post (post is noun)", () => {
      expect(isNounInReadOnlyContext("fetch_post", "post")).toBe(true);
    });

    it("should return true for read_post_content (post is noun)", () => {
      expect(isNounInReadOnlyContext("read_post_content", "post")).toBe(true);
    });

    it("should return true for search_posts (post is noun)", () => {
      expect(isNounInReadOnlyContext("search_posts", "post")).toBe(true);
    });

    it("should return false for post_message (post is verb)", () => {
      expect(isNounInReadOnlyContext("post_message", "post")).toBe(false);
    });

    it("should return false for submit_post (post is noun but submit is verb prefix)", () => {
      // submit_ is not a read-only prefix, so post could still be a verb action
      expect(isNounInReadOnlyContext("submit_post", "post")).toBe(false);
    });

    it("should return false for create_post (post is noun but create is verb prefix)", () => {
      expect(isNounInReadOnlyContext("create_post", "post")).toBe(false);
    });
  });

  describe("message keyword", () => {
    it("should return true for get_message (message is noun)", () => {
      expect(isNounInReadOnlyContext("get_message", "message")).toBe(true);
    });

    it("should return true for list_messages (message is noun)", () => {
      expect(isNounInReadOnlyContext("list_messages", "message")).toBe(true);
    });

    it("should return false for send_message (message is noun but send is verb)", () => {
      expect(isNounInReadOnlyContext("send_message", "message")).toBe(false);
    });
  });

  describe("other noun keywords", () => {
    it("should return true for get_comment (comment is noun)", () => {
      expect(isNounInReadOnlyContext("get_comment", "comment")).toBe(true);
    });

    it("should return true for list_threads (thread is noun)", () => {
      expect(isNounInReadOnlyContext("list_threads", "thread")).toBe(true);
    });

    it("should return true for fetch_log_entries (log is noun)", () => {
      expect(isNounInReadOnlyContext("fetch_log_entries", "log")).toBe(true);
    });

    it("should return true for read_record (record is noun)", () => {
      expect(isNounInReadOnlyContext("read_record", "record")).toBe(true);
    });
  });

  describe("non-noun keywords", () => {
    it("should return false for get_exec (exec not in noun list)", () => {
      expect(isNounInReadOnlyContext("get_exec", "exec")).toBe(false);
    });

    it("should return false for get_write_result (write not in noun list)", () => {
      expect(isNounInReadOnlyContext("get_write_result", "write")).toBe(false);
    });
  });
});

describe("detectAnnotationDeception - Issue #161", () => {
  describe("should NOT flag as deceptive (noun context)", () => {
    it("get_post_details with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("get_post_details", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("list_posts with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("list_posts", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("fetch_post_comments with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("fetch_post_comments", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("get_message_details with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("get_message_details", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("search_thread with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("search_thread", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("view_log with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("view_log", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });

    it("query_records with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("query_records", {
        readOnlyHint: true,
      });
      expect(result).toBeNull();
    });
  });

  describe("should STILL flag as deceptive (verb context)", () => {
    it("post_message with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("post_message", {
        readOnlyHint: true,
      });
      expect(result).not.toBeNull();
      expect(result?.field).toBe("readOnlyHint");
      expect(result?.matchedKeyword).toBe("post");
    });

    it("send_message with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("send_message", {
        readOnlyHint: true,
      });
      expect(result).not.toBeNull();
      expect(result?.field).toBe("readOnlyHint");
      expect(result?.matchedKeyword).toBe("send");
    });

    it("submit_post with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("submit_post", {
        readOnlyHint: true,
      });
      expect(result).not.toBeNull();
      expect(result?.field).toBe("readOnlyHint");
      // Note: "post" comes before "submit" in READONLY_CONTRADICTION_KEYWORDS,
      // so it matches first. Both would correctly flag this as deceptive.
      expect(result?.matchedKeyword).toBe("post");
    });

    it("create_comment with readOnlyHint=true", () => {
      const result = detectAnnotationDeception("create_comment", {
        readOnlyHint: true,
      });
      expect(result).not.toBeNull();
      expect(result?.field).toBe("readOnlyHint");
      expect(result?.matchedKeyword).toBe("create");
    });
  });

  describe("should NOT flag when readOnlyHint is false or undefined", () => {
    it("post_message with readOnlyHint=false", () => {
      const result = detectAnnotationDeception("post_message", {
        readOnlyHint: false,
      });
      expect(result).toBeNull();
    });

    it("get_post_details with no annotations", () => {
      const result = detectAnnotationDeception("get_post_details", {});
      expect(result).toBeNull();
    });
  });
});

describe("READONLY_PREFIX_PATTERNS", () => {
  it("should match get_ prefix", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("get_something"))).toBe(
      true,
    );
  });

  it("should match get- prefix (kebab case)", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("get-something"))).toBe(
      true,
    );
  });

  it("should match list_ prefix", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("list_items"))).toBe(
      true,
    );
  });

  it("should match fetch_ prefix", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("fetch_data"))).toBe(
      true,
    );
  });

  it("should NOT match post_ prefix", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("post_message"))).toBe(
      false,
    );
  });

  it("should NOT match create_ prefix", () => {
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("create_item"))).toBe(
      false,
    );
  });

  it("should NOT match getItem (no separator)", () => {
    // Pattern requires separator after prefix
    expect(READONLY_PREFIX_PATTERNS.some((p) => p.test("getItem"))).toBe(false);
  });
});

describe("NOUN_KEYWORDS_IN_READONLY_CONTEXT", () => {
  it("should include post", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("post");
  });

  it("should include message", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("message");
  });

  it("should include comment", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("comment");
  });

  it("should include thread", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("thread");
  });

  it("should include log", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("log");
  });

  it("should include record", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).toContain("record");
  });

  it("should NOT include exec (always a verb)", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).not.toContain("exec");
  });

  it("should NOT include delete (always a verb)", () => {
    expect(NOUN_KEYWORDS_IN_READONLY_CONTEXT).not.toContain("delete");
  });
});

describe("Reddit MCP real-world scenario - Issue #161", () => {
  it("should correctly handle Reddit MCP tools with readOnlyHint=true", () => {
    // Simulating Reddit MCP tools from the original issue
    const redditTools = [
      { name: "get_post_details", readOnlyHint: true },
      { name: "list_subreddit_posts", readOnlyHint: true },
      { name: "search_posts", readOnlyHint: true },
      { name: "get_user_posts", readOnlyHint: true },
      { name: "fetch_comments", readOnlyHint: true },
    ];

    const deceptions = redditTools
      .map((t) =>
        detectAnnotationDeception(t.name, { readOnlyHint: t.readOnlyHint }),
      )
      .filter((r) => r !== null);

    // None should be flagged as deceptive
    expect(deceptions).toHaveLength(0);
  });
});
