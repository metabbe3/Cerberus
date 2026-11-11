import type { LucideIcon } from "lucide-react";
import {
  Sparkles,
  Shield,
  Search,
  Terminal,
  Code,
  Clock,
  Zap,
  Cpu,
  Bookmark,
} from "lucide-react";
import type { Agent } from "@/lib/schema";

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
  payload: Partial<Agent>;
  isCustom?: boolean;
}

export const TEMPLATE_STORAGE_KEY = "owl-templates-v1";

export const BUILTIN_TEMPLATES: PolicyTemplate[] = [
  {
    id: "open",
    name: "Open Access",
    description: "Semua tool dan model diizinkan tanpa batasan kuota.",
    icon: "sparkles",
    payload: {},
  },
  {
    id: "readonly",
    name: "Read-Only Observer",
    description: "Hanya operasi observasi data (read, get, list, search, grep).",
    icon: "shield",
    payload: {
      allowed_tool_calls: ["read*", "get*", "list*", "search*", "grep*"],
    },
  },
  {
    id: "researcher",
    name: "Web Researcher",
    description: "Pencarian web dan fetch data dengan isolasi dari eksekusi shell.",
    icon: "search",
    payload: {
      allowed_tool_calls: ["http_get", "fetch*", "search*", "read*"],
      restricted_tool_calls: ["*exec*", "*write*", "ssh*"],
      budget_limit: 5,
      rate_limit: {
        requests_per_minute: 120,
      },
    },
  },
  {
    id: "operator",
    name: "Ops Operator (SSH terbatas)",
    description: "Operasi infra dan container tanpa akses server produksi.",
    icon: "terminal",
    payload: {
      allowed_tool_calls: ["ssh*", "docker*", "shell*"],
      prod_access: false,
      rate_limit: {
        requests_per_minute: 60,
      },
    },
  },
  {
    id: "coder",
    name: "Coder Sandbox",
    description: "Akses shell dan file lokal dengan blokir akses container & remote SSH.",
    icon: "code",
    payload: {
      allowed_tool_calls: ["shell*", "file*", "grep*"],
      restricted_tool_calls: ["docker*", "ssh*"],
      budget_limit: 10,
    },
  },
  {
    id: "nightly",
    name: "Nightly Batch",
    description: "Pekerjaan batch berkala hemat resource dengan batasan rate sopan.",
    icon: "clock",
    payload: {
      allowed_tool_calls: ["http_get", "fetch*", "report*"],
      budget_limit: 2,
      rate_limit: {
        requests_per_minute: 30,
      },
    },
  },
  {
    id: "llm-light",
    name: "LLM Cheap-Only",
    description: "Model LLM ringan dan hemat biaya untuk tugas rutin frekuensi tinggi.",
    icon: "zap",
    payload: {
      allowed_models: ["*mini*", "*flash*", "*haiku*"],
      budget_limit: 1,
      rate_limit: {
        requests_per_minute: 60,
      },
    },
  },
  {
    id: "llm-pro",
    name: "LLM Full",
    description: "Akses model LLM mutakhir tanpa batasan untuk penalaran kompleks.",
    icon: "cpu",
    payload: {
      allowed_models: ["*"],
      budget_limit: 50,
      rate_limit: {
        requests_per_minute: 300,
      },
    },
  },
];

export const TEMPLATE_ICONS: Record<string, LucideIcon> = {
  sparkles: Sparkles,
  shield: Shield,
  search: Search,
  terminal: Terminal,
  code: Code,
  clock: Clock,
  zap: Zap,
  cpu: Cpu,
  bookmark: Bookmark,
};

export function getTemplateIcon(iconName?: string): LucideIcon {
  if (!iconName) return Bookmark;
  return TEMPLATE_ICONS[iconName.toLowerCase()] || Bookmark;
}

export function getCustomTemplates(): PolicyTemplate[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(TEMPLATE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => ({
        ...item,
        isCustom: true,
      }));
    }
    return [];
  } catch (e) {
    console.error("Gagal membaca template kustom dari localStorage:", e);
    return [];
  }
}

export function saveCustomTemplate(name: string, payload: Partial<Agent>): PolicyTemplate {
  const cleanName = name.trim();
  const slug = cleanName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const id = `custom-${slug || Date.now()}`;

  const newTemplate: PolicyTemplate = {
    id,
    name: cleanName || "Custom Template",
    description: "Template kustom pengguna",
    icon: "bookmark",
    payload,
    isCustom: true,
  };

  const existing = getCustomTemplates();
  const filtered = existing.filter((t) => t.id !== id);
  const updated = [newTemplate, ...filtered];

  if (typeof window !== "undefined") {
    localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(updated));
  }

  return newTemplate;
}

export function deleteCustomTemplate(id: string): void {
  const existing = getCustomTemplates();
  const updated = existing.filter((t) => t.id !== id);
  if (typeof window !== "undefined") {
    localStorage.setItem(TEMPLATE_STORAGE_KEY, JSON.stringify(updated));
  }
}
