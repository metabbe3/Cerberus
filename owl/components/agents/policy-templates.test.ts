import { describe, expect, test, beforeEach } from "vitest";
import {
  BUILTIN_TEMPLATES,
  deleteCustomTemplate,
  getCustomTemplates,
  getTemplateIcon,
  saveCustomTemplate,
  TEMPLATE_STORAGE_KEY,
} from "./policy-templates";

describe("Policy Templates Library", () => {
  test("storage key is owl-templates-v1", () => {
    expect(TEMPLATE_STORAGE_KEY).toBe("owl-templates-v1");
  });
  test("defines exactly 8 built-in templates", () => {
    expect(BUILTIN_TEMPLATES).toHaveLength(8);
    const ids = BUILTIN_TEMPLATES.map((t) => t.id);
    expect(ids).toEqual([
      "open",
      "readonly",
      "researcher",
      "operator",
      "coder",
      "nightly",
      "llm-light",
      "llm-pro",
    ]);
  });

  test("built-in templates have required non-empty metadata", () => {
    for (const t of BUILTIN_TEMPLATES) {
      expect(t.id).toBeTruthy();
      expect(t.name).toBeTruthy();
      expect(t.description).toBeTruthy();
      expect(t.icon).toBeTruthy();
      expect(typeof t.payload).toBe("object");
    }
  });

  test("template 'open' has empty payload", () => {
    const openTemplate = BUILTIN_TEMPLATES.find((t) => t.id === "open");
    expect(openTemplate?.payload).toEqual({});
  });

  test("template 'readonly' has read/get/list/search/grep allowlist", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "readonly");
    expect(t?.payload.allowed_tool_calls).toEqual([
      "read*",
      "get*",
      "list*",
      "search*",
      "grep*",
    ]);
  });

  test("template 'researcher' has web tools, restricted tools, rate 120 rpm, budget 5", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "researcher");
    expect(t?.payload.allowed_tool_calls).toEqual([
      "http_get",
      "fetch*",
      "search*",
      "read*",
    ]);
    expect(t?.payload.restricted_tool_calls).toEqual([
      "*exec*",
      "*write*",
      "ssh*",
    ]);
    expect(t?.payload.rate_limit?.requests_per_minute).toBe(120);
    expect(t?.payload.budget_limit).toBe(5);
  });

  test("template 'operator' has ssh/docker/shell, rate 60 rpm, prod_access false", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "operator");
    expect(t?.payload.allowed_tool_calls).toEqual([
      "ssh*",
      "docker*",
      "shell*",
    ]);
    expect(t?.payload.rate_limit?.requests_per_minute).toBe(60);
    expect(t?.payload.prod_access).toBe(false);
  });

  test("template 'coder' has shell/file/grep, restricted docker/ssh, budget 10", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "coder");
    expect(t?.payload.allowed_tool_calls).toEqual([
      "shell*",
      "file*",
      "grep*",
    ]);
    expect(t?.payload.restricted_tool_calls).toEqual(["docker*", "ssh*"]);
    expect(t?.payload.budget_limit).toBe(10);
  });

  test("template 'nightly' has batch allowlist, rate 30 rpm, budget 2", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "nightly");
    expect(t?.payload.allowed_tool_calls).toEqual([
      "http_get",
      "fetch*",
      "report*",
    ]);
    expect(t?.payload.rate_limit?.requests_per_minute).toBe(30);
    expect(t?.payload.budget_limit).toBe(2);
  });

  test("template 'llm-light' has cheap models, budget 1, rate 60", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "llm-light");
    expect(t?.payload.allowed_models).toEqual(["*mini*", "*flash*", "*haiku*"]);
    expect(t?.payload.budget_limit).toBe(1);
    expect(t?.payload.rate_limit?.requests_per_minute).toBe(60);
  });

  test("template 'llm-pro' has full models, budget 50, rate 300", () => {
    const t = BUILTIN_TEMPLATES.find((x) => x.id === "llm-pro");
    expect(t?.payload.allowed_models).toEqual(["*"]);
    expect(t?.payload.budget_limit).toBe(50);
    expect(t?.payload.rate_limit?.requests_per_minute).toBe(300);
  });

  describe("Custom Templates LocalStorage CRUD", () => {
    let store: Record<string, string> = {};

    beforeEach(() => {
      store = {};
      const mockStorage = {
        getItem: (k: string) => store[k] ?? null,
        setItem: (k: string, v: string) => {
          store[k] = v;
        },
        removeItem: (k: string) => {
          delete store[k];
        },
        clear: () => {
          store = {};
        },
      };

      Object.defineProperty(globalThis, "window", {
        value: { localStorage: mockStorage },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(globalThis, "localStorage", {
        value: mockStorage,
        writable: true,
        configurable: true,
      });
    });

    test("saves and loads custom templates", () => {
      expect(getCustomTemplates()).toEqual([]);

      const created = saveCustomTemplate("My Custom Coder", {
        allowed_tool_calls: ["shell*"],
        budget_limit: 25,
      });

      expect(created.id).toBe("custom-my-custom-coder");
      expect(created.name).toBe("My Custom Coder");
      expect(created.isCustom).toBe(true);

      const loaded = getCustomTemplates();
      expect(loaded).toHaveLength(1);
      expect(loaded[0].id).toBe("custom-my-custom-coder");
      expect(loaded[0].payload.budget_limit).toBe(25);
    });

    test("deletes custom templates", () => {
      saveCustomTemplate("Template A", { budget_limit: 10 });
      saveCustomTemplate("Template B", { budget_limit: 20 });

      expect(getCustomTemplates()).toHaveLength(2);

      deleteCustomTemplate("custom-template-a");
      const remaining = getCustomTemplates();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].id).toBe("custom-template-b");
    });
  });

  describe("getTemplateIcon", () => {
    test("returns a valid icon component", () => {
      const icon = getTemplateIcon("search");
      expect(icon).toBeDefined();

      const fallback = getTemplateIcon("non-existent-icon");
      expect(fallback).toBeDefined();
    });
  });
});
