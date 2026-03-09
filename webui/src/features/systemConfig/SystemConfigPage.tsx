import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Plus, RefreshCw, RotateCcw, Save, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Input } from "../../components/ui/Input";
import { Switch } from "../../components/ui/Switch";
import { Textarea } from "../../components/ui/Textarea";
import { ToastContainer } from "../../components/ui/Toast";
import { useToast } from "../../hooks/useToast";
import i18next, { useI18n } from "../../i18n";
import { formatApiErrorMessage } from "../../lib/error-message";
import { listPlatforms } from "../platforms/api";
import { getEnvConfig, getInboundStatuses, getSecurityAudit, patchSystemConfig, getSystemConfig, getDefaultSystemConfig } from "./api";
import type { InboundListener, RuntimeConfig, RuntimeConfigPatch } from "./types";

type RuntimeConfigForm = {
  user_agent: string;
  request_log_enabled: boolean;
  reverse_proxy_log_detail_enabled: boolean;
  reverse_proxy_log_req_headers_max_bytes: string;
  reverse_proxy_log_req_body_max_bytes: string;
  reverse_proxy_log_resp_headers_max_bytes: string;
  reverse_proxy_log_resp_body_max_bytes: string;
  max_consecutive_failures: string;
  max_latency_test_interval: string;
  max_authority_latency_test_interval: string;
  max_egress_test_interval: string;
  latency_test_url: string;
  latency_authorities_raw: string;
  p2c_latency_window: string;
  latency_decay_window: string;
  cache_flush_interval: string;
  cache_flush_dirty_threshold: string;
  extra_inbound_listeners: InboundListener[];
};

const EDITABLE_FIELDS: Array<keyof RuntimeConfig> = [
  "user_agent",
  "request_log_enabled",
  "reverse_proxy_log_detail_enabled",
  "reverse_proxy_log_req_headers_max_bytes",
  "reverse_proxy_log_req_body_max_bytes",
  "reverse_proxy_log_resp_headers_max_bytes",
  "reverse_proxy_log_resp_body_max_bytes",
  "max_consecutive_failures",
  "max_latency_test_interval",
  "max_authority_latency_test_interval",
  "max_egress_test_interval",
  "latency_test_url",
  "latency_authorities",
  "p2c_latency_window",
  "latency_decay_window",
  "cache_flush_interval",
  "cache_flush_dirty_threshold",
  "extra_inbound_listeners",
];

const ALLOCATION_POLICY_LABELS: Record<string, string> = {
  BALANCED: "均衡",
  PREFER_LOW_LATENCY: "优先低延迟",
  PREFER_IDLE_IP: "优先空闲出口 IP",
};

const MISS_ACTION_LABELS: Record<string, string> = {
  TREAT_AS_EMPTY: "按空账号处理",
  REJECT: "拒绝代理请求",
};

const EMPTY_ACCOUNT_BEHAVIOR_LABELS: Record<string, string> = {
  RANDOM: "随机路由",
  FIXED_HEADER: "提取指定请求头作为 Account",
  ACCOUNT_HEADER_RULE: "按照全局请求头规则提取 Account",
};

function configToForm(config: RuntimeConfig): RuntimeConfigForm {
  return {
    user_agent: config.user_agent,
    request_log_enabled: config.request_log_enabled,
    reverse_proxy_log_detail_enabled: config.reverse_proxy_log_detail_enabled,
    reverse_proxy_log_req_headers_max_bytes: String(config.reverse_proxy_log_req_headers_max_bytes),
    reverse_proxy_log_req_body_max_bytes: String(config.reverse_proxy_log_req_body_max_bytes),
    reverse_proxy_log_resp_headers_max_bytes: String(config.reverse_proxy_log_resp_headers_max_bytes),
    reverse_proxy_log_resp_body_max_bytes: String(config.reverse_proxy_log_resp_body_max_bytes),
    max_consecutive_failures: String(config.max_consecutive_failures),
    max_latency_test_interval: config.max_latency_test_interval,
    max_authority_latency_test_interval: config.max_authority_latency_test_interval,
    max_egress_test_interval: config.max_egress_test_interval,
    latency_test_url: config.latency_test_url,
    latency_authorities_raw: config.latency_authorities.join("\n"),
    p2c_latency_window: config.p2c_latency_window,
    latency_decay_window: config.latency_decay_window,
    cache_flush_interval: config.cache_flush_interval,
    cache_flush_dirty_threshold: String(config.cache_flush_dirty_threshold),
    extra_inbound_listeners: config.extra_inbound_listeners.map((item) => ({ ...item })),
  };
}

function requiredFieldLabel(field: string): string {
  return i18next.t(field);
}

function parseNonNegativeInt(field: string, raw: string): number {
  const value = raw.trim();
  if (!value) {
    throw new Error(i18next.t("{{field}} 不能为空", { field: requiredFieldLabel(field) }));
  }
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(i18next.t("{{field}} 必须是非负整数", { field: requiredFieldLabel(field) }));
  }
  return parsed;
}

function parseDurationField(field: string, raw: string): string {
  const value = raw.trim();
  if (!value) {
    throw new Error(i18next.t("{{field}} 不能为空", { field: requiredFieldLabel(field) }));
  }
  return value;
}

function parseAuthorities(raw: string): string[] {
  const items = raw
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);

  return Array.from(new Set(items));
}

function parseInboundListeners(items: InboundListener[]): InboundListener[] {
  const endpointSet = new Set<string>();
  return items.map((item, idx) => {
    const protocol = String(item.protocol ?? "").trim();
    if (protocol !== "http_forward" && protocol !== "socks5") {
      throw new Error(`额外入站监听第 ${idx + 1} 项 protocol 非法`);
    }
    const listenAddress = String(item.listen_address ?? "").trim();
    if (!listenAddress) {
      throw new Error(`额外入站监听第 ${idx + 1} 项 listen_address 不能为空`);
    }
    const port = Number(item.port ?? 0);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`额外入站监听第 ${idx + 1} 项 port 非法`);
    }
    const endpoint = `${listenAddress.toLowerCase()}:${port}`;
    if (endpointSet.has(endpoint)) {
      throw new Error(`额外入站监听第 ${idx + 1} 项与其他监听重复: ${listenAddress}:${port}`);
    }
    endpointSet.add(endpoint);
    const platformName = String(item.platform_name ?? "").trim();
    const allowAnonymous = typeof item.allow_anonymous === "boolean"
      ? item.allow_anonymous
      : platformName !== "";
    if (allowAnonymous && !platformName) {
      throw new Error(`额外入站监听第 ${idx + 1} 项启用了匿名接入，但未设置固定平台`);
    }
    return {
      protocol: protocol as InboundListener["protocol"],
      listen_address: listenAddress,
      port,
      platform_name: platformName,
      allow_anonymous: allowAnonymous,
    } as InboundListener;
  });
}

function parseForm(form: RuntimeConfigForm): RuntimeConfig {
  const userAgent = form.user_agent.trim();
  if (!userAgent) {
    throw new Error("User-Agent 不能为空");
  }

  const latencyURL = form.latency_test_url.trim();
  if (!latencyURL) {
    throw new Error("延迟测试目标 URL 不能为空");
  }
  if (!latencyURL.startsWith("http://") && !latencyURL.startsWith("https://")) {
    throw new Error("延迟测试目标 URL 必须是 http/https 地址");
  }

  return {
    user_agent: userAgent,
    request_log_enabled: form.request_log_enabled,
    reverse_proxy_log_detail_enabled: form.reverse_proxy_log_detail_enabled,
    reverse_proxy_log_req_headers_max_bytes: parseNonNegativeInt(
      "请求头最大字节数",
      form.reverse_proxy_log_req_headers_max_bytes,
    ),
    reverse_proxy_log_req_body_max_bytes: parseNonNegativeInt("请求体最大字节数", form.reverse_proxy_log_req_body_max_bytes),
    reverse_proxy_log_resp_headers_max_bytes: parseNonNegativeInt(
      "响应头最大字节数",
      form.reverse_proxy_log_resp_headers_max_bytes,
    ),
    reverse_proxy_log_resp_body_max_bytes: parseNonNegativeInt(
      "响应体最大字节数",
      form.reverse_proxy_log_resp_body_max_bytes,
    ),
    max_consecutive_failures: parseNonNegativeInt("最大连续失败次数", form.max_consecutive_failures),
    max_latency_test_interval: parseDurationField("节点延迟最大测试间隔", form.max_latency_test_interval),
    max_authority_latency_test_interval: parseDurationField(
      "权威域名最大测试间隔",
      form.max_authority_latency_test_interval,
    ),
    max_egress_test_interval: parseDurationField("出口 IP 更新检查间隔", form.max_egress_test_interval),
    latency_test_url: latencyURL,
    latency_authorities: parseAuthorities(form.latency_authorities_raw),
    p2c_latency_window: parseDurationField("P2C 延迟衰减窗口", form.p2c_latency_window),
    latency_decay_window: parseDurationField("历史延迟衰减窗口", form.latency_decay_window),
    cache_flush_interval: parseDurationField("缓存异步刷盘间隔", form.cache_flush_interval),
    cache_flush_dirty_threshold: parseNonNegativeInt("缓存刷盘脏阈值", form.cache_flush_dirty_threshold),
    extra_inbound_listeners: parseInboundListeners(form.extra_inbound_listeners),
  };
}

function displayAllocationPolicy(value: string): string {
  return ALLOCATION_POLICY_LABELS[value] ?? value;
}

function displayMissAction(value: string): string {
  return MISS_ACTION_LABELS[value] ?? value;
}

function displayEmptyAccountBehavior(value: string): string {
  return EMPTY_ACCOUNT_BEHAVIOR_LABELS[value] ?? value;
}

function arrayEquals(a: unknown[], b: unknown[]): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (JSON.stringify(a[i]) !== JSON.stringify(b[i])) {
      return false;
    }
  }
  return true;
}

function generateSecureToken(length = 40): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_";
  const out: string[] = [];
  if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
    const buf = new Uint32Array(length);
    window.crypto.getRandomValues(buf);
    for (let i = 0; i < length; i += 1) {
      out.push(chars[buf[i] % chars.length]);
    }
    return out.join("");
  }
  for (let i = 0; i < length; i += 1) {
    out.push(chars[Math.floor(Math.random() * chars.length)]);
  }
  return out.join("");
}

function buildPatch(current: RuntimeConfig, next: RuntimeConfig): RuntimeConfigPatch {
  const patch: RuntimeConfigPatch = {};
  const patchMutable = patch as Record<string, unknown>;

  for (const field of EDITABLE_FIELDS) {
    const currentValue = current[field];
    const nextValue = next[field];

    if (Array.isArray(currentValue) && Array.isArray(nextValue)) {
      if (!arrayEquals(currentValue, nextValue)) {
        patchMutable[field] = nextValue;
      }
      continue;
    }

    if (currentValue !== nextValue) {
      patchMutable[field] = nextValue;
    }
  }

  return patch;
}

export function SystemConfigPage() {
  const { t } = useI18n();
  const [draftForm, setDraftForm] = useState<RuntimeConfigForm | null>(null);
  const [batchProtocol, setBatchProtocol] = useState<InboundListener["protocol"]>("http_forward");
  const [batchListenAddress, setBatchListenAddress] = useState("0.0.0.0");
  const [batchStartPort, setBatchStartPort] = useState("13128");
  const [batchCount, setBatchCount] = useState("1");
  const [batchPlatformName, setBatchPlatformName] = useState("");
  const [batchAllowAnonymous, setBatchAllowAnonymous] = useState(true);
  const [importInboundJSON, setImportInboundJSON] = useState("");
  const [generatedAdminToken, setGeneratedAdminToken] = useState("");
  const [generatedProxyToken, setGeneratedProxyToken] = useState("");
  const { toasts, showToast, dismissToast } = useToast();
  const queryClient = useQueryClient();

  const configQuery = useQuery({
    queryKey: ["system-config"],
    queryFn: getSystemConfig,
    staleTime: 30_000,
  });

  const defaultConfigQuery = useQuery({
    queryKey: ["system-config-default"],
    queryFn: getDefaultSystemConfig,
    staleTime: 30_000,
  });
  const platformListQuery = useQuery({
    queryKey: ["platforms", "for-system-config"],
    queryFn: () => listPlatforms({ limit: 500, offset: 0 }),
    staleTime: 60_000,
  });

  const envConfigQuery = useQuery({
    queryKey: ["system-config-env"],
    queryFn: getEnvConfig,
    staleTime: Infinity, // Env config does not change at runtime
  });
  const inboundStatusQuery = useQuery({
    queryKey: ["system-inbounds-status"],
    queryFn: getInboundStatuses,
    staleTime: 5_000,
    refetchInterval: 15_000,
  });
  const securityAuditQuery = useQuery({
    queryKey: ["system-security-audit"],
    queryFn: getSecurityAudit,
    staleTime: 10_000,
    refetchInterval: 30_000,
  });

  const baseline = configQuery.data ?? null;
  const defaultBaseline = defaultConfigQuery.data ?? null;
  const envBaseline = envConfigQuery.data ?? null;

  const form = useMemo(() => {
    if (!baseline) {
      return null;
    }
    return draftForm ?? configToForm(baseline);
  }, [baseline, draftForm]);
  const platformNameOptions = useMemo(
    () =>
      Array.from(
        new Set(
          (platformListQuery.data?.items ?? [])
            .map((item) => String(item.name ?? "").trim())
            .filter(Boolean)
        )
      ).sort((a, b) => a.localeCompare(b)),
    [platformListQuery.data?.items]
  );

  const parsedResult = useMemo(() => {
    if (!form) {
      return { config: null as RuntimeConfig | null, error: "" };
    }

    try {
      return { config: parseForm(form), error: "" };
    } catch (error) {
      return { config: null, error: formatApiErrorMessage(error, t) };
    }
  }, [form, t]);

  const patchPreview = useMemo<RuntimeConfigPatch>(() => {
    if (!baseline || !parsedResult.config) {
      return {};
    }
    return buildPatch(baseline, parsedResult.config);
  }, [baseline, parsedResult.config]);

  const changedKeys = useMemo(() => Object.keys(patchPreview) as Array<keyof RuntimeConfig>, [patchPreview]);
  const hasUnsavedChanges = changedKeys.length > 0;

  const saveMutation = useMutation({
    mutationFn: async () => {
      if (!baseline || !form) {
        throw new Error("配置尚未加载完成");
      }
      const parsed = parseForm(form);
      const patchToSend = buildPatch(baseline, parsed);

      const changedCount = Object.keys(patchToSend).length;
      if (!changedCount) {
        throw new Error("没有可提交的变更");
      }
      const updated = await patchSystemConfig(patchToSend);
      return { updated, changedCount };
    },
    onSuccess: ({ updated, changedCount }) => {
      queryClient.setQueryData(["system-config"], updated);
      setDraftForm(null);
      showToast("success", t("配置已更新（{{count}} 项变更）", { count: changedCount }));
    },
    onError: (error) => {
      showToast("error", formatApiErrorMessage(error, t));
    },
  });

  const setFormField = <K extends keyof RuntimeConfigForm>(key: K, value: RuntimeConfigForm[K]) => {
    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      return { ...source, [key]: value };
    });
  };

  const updateInboundListener = <K extends keyof InboundListener>(
    index: number,
    key: K,
    value: InboundListener[K],
  ) => {
    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      const next = source.extra_inbound_listeners.map((item, i) => {
        if (i !== index) {
          return item;
        }
        const updated = { ...item, [key]: value };
        if (key === "platform_name" && !String(value ?? "").trim()) {
          updated.allow_anonymous = false;
        }
        return updated;
      });
      return { ...source, extra_inbound_listeners: next };
    });
  };

  const addInboundListener = (protocol: InboundListener["protocol"]) => {
    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      const existingPorts = new Set(source.extra_inbound_listeners.map((item) => item.port));
      let candidatePort = protocol === "http_forward" ? 13128 : 13129;
      while (existingPorts.has(candidatePort) && candidatePort < 65535) {
        candidatePort += 1;
      }
      return {
        ...source,
        extra_inbound_listeners: [
          ...source.extra_inbound_listeners,
          {
            protocol,
            listen_address: "0.0.0.0",
            port: candidatePort,
            platform_name: "",
            allow_anonymous: false,
          },
        ],
      };
    });
  };

  const removeInboundListener = (index: number) => {
    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      return {
        ...source,
        extra_inbound_listeners: source.extra_inbound_listeners.filter((_, i) => i !== index),
      };
    });
  };

  const addInboundListenerBatch = () => {
    const listenAddress = batchListenAddress.trim();
    if (!listenAddress) {
      showToast("error", t("监听地址不能为空"));
      return;
    }
    const startPort = Number(batchStartPort);
    const count = Number(batchCount);
    if (!Number.isInteger(startPort) || startPort < 1 || startPort > 65535) {
      showToast("error", t("起始端口必须是 1-65535 的整数"));
      return;
    }
    if (!Number.isInteger(count) || count < 1 || count > 1000) {
      showToast("error", t("数量必须是 1-1000 的整数"));
      return;
    }
    if (startPort+count-1 > 65535) {
      showToast("error", t("端口范围超出 65535"));
      return;
    }

    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      const existing = new Set(source.extra_inbound_listeners.map((item) => `${item.listen_address.toLowerCase()}:${item.port}`));
      const added: InboundListener[] = [];
      for (let i = 0; i < count; i += 1) {
        const port = startPort + i;
        const endpoint = `${listenAddress.toLowerCase()}:${port}`;
        if (existing.has(endpoint)) {
          continue;
        }
        existing.add(endpoint);
        added.push({
          protocol: batchProtocol,
          listen_address: listenAddress,
          port,
          platform_name: batchPlatformName.trim(),
          allow_anonymous: batchPlatformName.trim() ? batchAllowAnonymous : false,
        });
      }
      if (added.length === 0) {
        showToast("error", t("没有新增任何监听（可能都与现有端口重复）"));
        return source;
      }
      showToast("success", t("已新增 {{count}} 个监听", { count: added.length }));
      return {
        ...source,
        extra_inbound_listeners: [...source.extra_inbound_listeners, ...added],
      };
    });
  };

  const applyInboundTemplate = (template: "http_pool" | "socks5_pool" | "mixed_pool") => {
    setDraftForm((prev) => {
      if (!baseline) {
        return prev;
      }
      const source = prev ?? configToForm(baseline);
      const byTemplate: Record<typeof template, InboundListener[]> = {
        http_pool: [0, 1, 2, 3].map((offset) => ({
          protocol: "http_forward",
          listen_address: "0.0.0.0",
          port: 13128 + offset,
          platform_name: "",
          allow_anonymous: false,
        })),
        socks5_pool: [0, 1, 2, 3].map((offset) => ({
          protocol: "socks5",
          listen_address: "0.0.0.0",
          port: 13129 + offset,
          platform_name: "",
          allow_anonymous: false,
        })),
        mixed_pool: [
          { protocol: "http_forward", listen_address: "0.0.0.0", port: 13128, platform_name: "", allow_anonymous: false },
          { protocol: "http_forward", listen_address: "0.0.0.0", port: 13130, platform_name: "", allow_anonymous: false },
          { protocol: "socks5", listen_address: "0.0.0.0", port: 13129, platform_name: "", allow_anonymous: false },
          { protocol: "socks5", listen_address: "0.0.0.0", port: 13131, platform_name: "", allow_anonymous: false },
        ],
      };
      const next = byTemplate[template];
      showToast("success", t("已应用端口模板"));
      return { ...source, extra_inbound_listeners: next };
    });
  };

  const exportInboundListenersJSON = async () => {
    if (!form) {
      return;
    }
    const text = JSON.stringify(form.extra_inbound_listeners, null, 2);
    try {
      await navigator.clipboard.writeText(text);
      showToast("success", t("已复制监听配置 JSON 到剪贴板"));
    } catch {
      showToast("error", t("复制失败，请使用下载功能"));
    }
  };

  const downloadInboundListenersJSON = () => {
    if (!form) {
      return;
    }
    const text = JSON.stringify(form.extra_inbound_listeners, null, 2);
    const blob = new Blob([text], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "resin-extra-inbounds.json";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const importInboundListenersFromJSON = (mode: "replace" | "append") => {
    const raw = importInboundJSON.trim();
    if (!raw) {
      showToast("error", t("请先粘贴 JSON"));
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      showToast("error", t("JSON 格式错误"));
      return;
    }
    if (!Array.isArray(parsed)) {
      showToast("error", t("JSON 顶层必须是数组"));
      return;
    }
    try {
      const imported = parseInboundListeners(parsed as InboundListener[]);
      setDraftForm((prev) => {
        if (!baseline) {
          return prev;
        }
        const source = prev ?? configToForm(baseline);
        const merged = mode === "replace"
          ? imported
          : parseInboundListeners([...source.extra_inbound_listeners, ...imported]);
        return { ...source, extra_inbound_listeners: merged };
      });
      showToast("success", mode === "replace" ? t("已覆盖导入监听配置") : t("已追加导入监听配置"));
    } catch (err) {
      showToast("error", formatApiErrorMessage(err, t));
    }
  };

  const copyText = async (text: string, successMessage: string) => {
    if (!text.trim()) {
      showToast("error", t("内容为空，无法复制"));
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      showToast("success", successMessage);
    } catch {
      showToast("error", t("复制失败，请手动复制"));
    }
  };

  const handleRestoreDefault = (key: keyof RuntimeConfigForm) => {
    if (!defaultBaseline || !baseline) {
      showToast("error", "默认配置尚未加载");
      return;
    }

    const defaultForm = configToForm(defaultBaseline);
    const value = defaultForm[key];

    setDraftForm((prev) => {
      const source = prev ?? configToForm(baseline);
      return { ...source, [key]: value };
    });
  };

  const renderRestoreButton = (fieldKey: keyof RuntimeConfigForm) => {
    const displayVal = defaultBaseline ? (() => {
      const val = configToForm(defaultBaseline)[fieldKey];
      if (Array.isArray(val)) return t("共 {{count}} 项", { count: val.length });
      if (typeof val === "boolean") return val ? t("开启") : t("关闭");
      if (val === "") return t("空");
      return String(val);
    })() : "";

    return (
      <button
        type="button"
        title={displayVal ? t("恢复为默认值: {{value}}", { value: displayVal }) : t("恢复为默认值")}
        onClick={() => handleRestoreDefault(fieldKey)}
        style={{
          background: "transparent",
          border: "none",
          cursor: "pointer",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          color: "var(--text-muted, #888)",
          padding: "4px",
          marginLeft: "4px",
          opacity: 0.6,
          transition: "opacity 0.2s"
        }}
        onMouseEnter={(e) => e.currentTarget.style.opacity = "1"}
        onMouseLeave={(e) => e.currentTarget.style.opacity = "0.6"}
      >
        <RotateCcw size={14} />
      </button>
    );
  };

  const resetDraft = () => {
    setDraftForm(null);
  };

  const reloadFromServer = async () => {
    if (hasUnsavedChanges) {
      const confirmed = window.confirm(t("当前有未保存变更，确认丢弃并重新加载运行时配置？"));
      if (!confirmed) {
        return;
      }
    }

    setDraftForm(null);
    const result = await configQuery.refetch();
    if (result.data) {
      showToast("success", t("已加载最新运行时配置"));
    }
  };

  const isSaveDisabled = saveMutation.isPending || Boolean(parsedResult.error) || !hasUnsavedChanges;

  return (
    <section className="syscfg-page">
      <header className="module-header">
        <div>
          <h2>{t("系统配置")}</h2>
          <p className="module-description">{t("按需调整系统参数，保存后立即生效。")}</p>
        </div>
        {form ? (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap", justifyContent: "flex-end" }}>
            <Badge variant={hasUnsavedChanges ? "warning" : "neutral"}>
              {hasUnsavedChanges ? t("待保存 {{count}} 项", { count: changedKeys.length }) : t("无待保存变更")}
            </Badge>
            <Button onClick={() => void saveMutation.mutateAsync()} disabled={isSaveDisabled}>
              <Save size={14} />
              {saveMutation.isPending ? t("保存中...") : t("保存配置")}
            </Button>
            <Button variant="ghost" onClick={resetDraft} disabled={!hasUnsavedChanges || saveMutation.isPending}>
              <RotateCcw size={14} />
              {t("重置草稿")}
            </Button>
          </div>
        ) : null}
      </header>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {!form ? (
        <Card className="syscfg-form-card platform-directory-card">
          {(configQuery.isLoading || envConfigQuery.isLoading) ? <p className="muted">{t("正在加载配置...")}</p> : null}
          {configQuery.isError ? (
            <div className="callout callout-error">
              <AlertTriangle size={14} />
              <span>{formatApiErrorMessage(configQuery.error, t)}</span>
            </div>
          ) : null}
          {envConfigQuery.isError ? (
            <div className="callout callout-error">
              <AlertTriangle size={14} />
              <span>{t("静态配置加载失败")}: {formatApiErrorMessage(envConfigQuery.error, t)}</span>
            </div>
          ) : null}
        </Card>
      ) : (
        <div className="syscfg-layout">
          <div className="syscfg-main">
            <Card className="syscfg-form-card platform-directory-card">
              <div className="detail-header">
                <div>
                  <h3>{t("运行时配置")}</h3>
                  <p>{t("按分类查看和修改设置，可随时撤销未保存更改。")}</p>
                </div>
                <Button variant="secondary" size="sm" onClick={() => void reloadFromServer()} disabled={configQuery.isFetching}>
                  <RefreshCw size={16} className={configQuery.isFetching ? "spin" : undefined} />
                  {t("刷新")}
                </Button>
              </div>
              {parsedResult.error ? (
                <div className="callout callout-error" style={{ marginTop: "10px" }}>
                  <AlertTriangle size={14} />
                  <span>{parsedResult.error}</span>
                </div>
              ) : null}

              <section className="syscfg-section">
                <h4>{t("基础与健康检查")}</h4>
                <div className="form-grid">
                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-user-agent" style={{ margin: 0 }}>
                        User-Agent
                      </label>
                      {renderRestoreButton("user_agent")}
                    </div>
                    <Input
                      id="sys-user-agent"
                      value={form.user_agent}
                      onChange={(event) => setFormField("user_agent", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-max-fail" style={{ margin: 0 }}>
                        {t("最大连续失败次数")}
                      </label>
                      {renderRestoreButton("max_consecutive_failures")}
                    </div>
                    <Input
                      id="sys-max-fail"
                      type="number"
                      min={0}
                      value={form.max_consecutive_failures}
                      onChange={(event) => setFormField("max_consecutive_failures", event.target.value)}
                    />
                  </div>
                </div>
              </section>

              <section className="syscfg-section">
                <h4>{t("请求日志")}</h4>
                <div className="syscfg-checkbox-grid">
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "var(--surface-sunken, rgba(0,0,0,0.02))", padding: "12px 16px", borderRadius: "8px", border: "1px solid var(--border)" }}>
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <span className="field-label" style={{ margin: 0, fontWeight: 500 }}>{t("启用请求日志")}</span>
                      {renderRestoreButton("request_log_enabled")}
                    </div>
                    <Switch
                      checked={form.request_log_enabled}
                      onChange={(event) => setFormField("request_log_enabled", event.target.checked)}
                    />
                  </div>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "var(--surface-sunken, rgba(0,0,0,0.02))", padding: "12px 16px", borderRadius: "8px", border: "1px solid var(--border)" }}>
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <span className="field-label" style={{ margin: 0, fontWeight: 500 }}>{t("记录详细反代日志")}</span>
                      {renderRestoreButton("reverse_proxy_log_detail_enabled")}
                    </div>
                    <Switch
                      checked={form.reverse_proxy_log_detail_enabled}
                      onChange={(event) => setFormField("reverse_proxy_log_detail_enabled", event.target.checked)}
                    />
                  </div>
                </div>

                <div className="form-grid syscfg-form-grid-spacious">
                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-req-h-max" style={{ margin: 0 }}>
                        {t("请求头最大字节数")}
                      </label>
                      {renderRestoreButton("reverse_proxy_log_req_headers_max_bytes")}
                    </div>
                    <Input
                      id="sys-req-h-max"
                      type="number"
                      min={0}
                      value={form.reverse_proxy_log_req_headers_max_bytes}
                      onChange={(event) => setFormField("reverse_proxy_log_req_headers_max_bytes", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-req-b-max" style={{ margin: 0 }}>
                        {t("请求体最大字节数")}
                      </label>
                      {renderRestoreButton("reverse_proxy_log_req_body_max_bytes")}
                    </div>
                    <Input
                      id="sys-req-b-max"
                      type="number"
                      min={0}
                      value={form.reverse_proxy_log_req_body_max_bytes}
                      onChange={(event) => setFormField("reverse_proxy_log_req_body_max_bytes", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-resp-h-max" style={{ margin: 0 }}>
                        {t("响应头最大字节数")}
                      </label>
                      {renderRestoreButton("reverse_proxy_log_resp_headers_max_bytes")}
                    </div>
                    <Input
                      id="sys-resp-h-max"
                      type="number"
                      min={0}
                      value={form.reverse_proxy_log_resp_headers_max_bytes}
                      onChange={(event) => setFormField("reverse_proxy_log_resp_headers_max_bytes", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-resp-b-max" style={{ margin: 0 }}>
                        {t("响应体最大字节数")}
                      </label>
                      {renderRestoreButton("reverse_proxy_log_resp_body_max_bytes")}
                    </div>
                    <Input
                      id="sys-resp-b-max"
                      type="number"
                      min={0}
                      value={form.reverse_proxy_log_resp_body_max_bytes}
                      onChange={(event) => setFormField("reverse_proxy_log_resp_body_max_bytes", event.target.value)}
                    />
                  </div>
                </div>
              </section>

              <section className="syscfg-section">
                <h4>{t("探测与路由")}</h4>
                <div className="form-grid">
                  <div className="field-group field-span-2">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-latency-url" style={{ margin: 0 }}>
                        {t("延迟测试目标 URL")}
                      </label>
                      {renderRestoreButton("latency_test_url")}
                    </div>
                    <Input
                      id="sys-latency-url"
                      value={form.latency_test_url}
                      onChange={(event) => setFormField("latency_test_url", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-max-latency-int" style={{ margin: 0 }}>
                        {t("节点延迟最大测试间隔")}
                      </label>
                      {renderRestoreButton("max_latency_test_interval")}
                    </div>
                    <Input
                      id="sys-max-latency-int"
                      value={form.max_latency_test_interval}
                      onChange={(event) => setFormField("max_latency_test_interval", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-max-auth-latency-int" style={{ margin: 0 }}>
                        {t("权威域名最大测试间隔")}
                      </label>
                      {renderRestoreButton("max_authority_latency_test_interval")}
                    </div>
                    <Input
                      id="sys-max-auth-latency-int"
                      value={form.max_authority_latency_test_interval}
                      onChange={(event) => setFormField("max_authority_latency_test_interval", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-max-egress-int" style={{ margin: 0 }}>
                        {t("出口 IP 更新检查间隔")}
                      </label>
                      {renderRestoreButton("max_egress_test_interval")}
                    </div>
                    <Input
                      id="sys-max-egress-int"
                      value={form.max_egress_test_interval}
                      onChange={(event) => setFormField("max_egress_test_interval", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-p2c-window" style={{ margin: 0 }}>
                        {t("P2C 延迟衰减窗口")}
                      </label>
                      {renderRestoreButton("p2c_latency_window")}
                    </div>
                    <Input
                      id="sys-p2c-window"
                      value={form.p2c_latency_window}
                      onChange={(event) => setFormField("p2c_latency_window", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-decay-window" style={{ margin: 0 }}>
                        {t("历史延迟衰减窗口")}
                      </label>
                      {renderRestoreButton("latency_decay_window")}
                    </div>
                    <Input
                      id="sys-decay-window"
                      value={form.latency_decay_window}
                      onChange={(event) => setFormField("latency_decay_window", event.target.value)}
                    />
                  </div>

                  <div className="field-group field-span-2">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-latency-authorities" style={{ margin: 0 }}>
                        {t("延迟测试权威域名列表")}
                      </label>
                      {renderRestoreButton("latency_authorities_raw")}
                    </div>
                    <Textarea
                      id="sys-latency-authorities"
                      rows={4}
                      placeholder={"gstatic.com\ngoogle.com\ncloudflare.com"}
                      value={form.latency_authorities_raw}
                      onChange={(event) => setFormField("latency_authorities_raw", event.target.value)}
                    />
                  </div>
                </div>
              </section>

              <section className="syscfg-section">
                <h4>{t("持久化策略")}</h4>
                <div className="form-grid">
                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-cache-flush-int" style={{ margin: 0 }}>
                        {t("缓存异步刷盘间隔")}
                      </label>
                      {renderRestoreButton("cache_flush_interval")}
                    </div>
                    <Input
                      id="sys-cache-flush-int"
                      value={form.cache_flush_interval}
                      onChange={(event) => setFormField("cache_flush_interval", event.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div style={{ display: "flex", alignItems: "center" }}>
                      <label className="field-label" htmlFor="sys-cache-threshold" style={{ margin: 0 }}>
                        {t("缓存刷盘脏阈值")}
                      </label>
                      {renderRestoreButton("cache_flush_dirty_threshold")}
                    </div>
                    <Input
                      id="sys-cache-threshold"
                      type="number"
                      min={0}
                      value={form.cache_flush_dirty_threshold}
                      onChange={(event) => setFormField("cache_flush_dirty_threshold", event.target.value)}
                    />
                  </div>
                  <div className="field-group field-span-2">
                    <div className="syscfg-inbound-header">
                      <div style={{ display: "flex", alignItems: "center" }}>
                        <label className="field-label" style={{ margin: 0 }}>
                          {t("额外入站监听")}
                        </label>
                        {renderRestoreButton("extra_inbound_listeners")}
                      </div>
                      <div className="syscfg-inbound-actions">
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() => applyInboundTemplate("http_pool")}
                        >
                          {t("HTTP 模板")}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() => applyInboundTemplate("socks5_pool")}
                        >
                          {t("SOCKS5 模板")}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() => applyInboundTemplate("mixed_pool")}
                        >
                          {t("混合模板")}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() => addInboundListener("http_forward")}
                        >
                          <Plus size={14} />
                          {t("新增 HTTP")}
                        </Button>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          onClick={() => addInboundListener("socks5")}
                        >
                          <Plus size={14} />
                          {t("新增 SOCKS5")}
                        </Button>
                        <Button type="button" variant="secondary" size="sm" onClick={exportInboundListenersJSON}>
                          {t("复制 JSON")}
                        </Button>
                        <Button type="button" variant="secondary" size="sm" onClick={downloadInboundListenersJSON}>
                          {t("下载 JSON")}
                        </Button>
                      </div>
                    </div>
                    <div className="syscfg-inbound-stack">
                      <datalist id="syscfg-platform-name-options">
                        {platformNameOptions.map((name) => (
                          <option key={name} value={name} />
                        ))}
                      </datalist>
                      <div className="syscfg-inbound-block">
                        <div style={{ fontWeight: 600, marginBottom: "8px" }}>{t("批量新增监听")}</div>
                        <div className="syscfg-inbound-batch-grid">
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("协议")}</label>
                            <select
                              className="input"
                              value={batchProtocol}
                              onChange={(event) => setBatchProtocol(event.target.value === "socks5" ? "socks5" : "http_forward")}
                            >
                              <option value="http_forward">http_forward</option>
                              <option value="socks5">socks5</option>
                            </select>
                          </div>
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("监听地址")}</label>
                            <Input value={batchListenAddress} onChange={(event) => setBatchListenAddress(event.target.value)} />
                          </div>
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("起始端口")}</label>
                            <Input type="number" min={1} max={65535} value={batchStartPort} onChange={(event) => setBatchStartPort(event.target.value)} />
                          </div>
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("数量")}</label>
                            <Input type="number" min={1} max={1000} value={batchCount} onChange={(event) => setBatchCount(event.target.value)} />
                          </div>
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("固定平台(可选)")}</label>
                            <Input
                              list="syscfg-platform-name-options"
                              value={batchPlatformName}
                              onChange={(event) => setBatchPlatformName(event.target.value)}
                            />
                          </div>
                          <div>
                            <label className="field-label" style={{ marginBottom: "6px" }}>{t("允许匿名接入")}</label>
                            <div className="syscfg-inline-switch">
                              <Switch
                                checked={batchAllowAnonymous}
                                disabled={!batchPlatformName.trim()}
                                onChange={(event) => setBatchAllowAnonymous(event.target.checked)}
                              />
                              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                                {batchPlatformName.trim() ? t("端口直连") : t("需先设置固定平台")}
                              </span>
                            </div>
                          </div>
                          <Button type="button" variant="secondary" size="sm" onClick={addInboundListenerBatch}>
                            <Plus size={14} />
                            {t("批量添加")}
                          </Button>
                        </div>
                      </div>
                      <div className="syscfg-inbound-block">
                        <div style={{ fontWeight: 600, marginBottom: "8px" }}>{t("导入监听 JSON")}</div>
                        <Textarea
                          rows={5}
                          placeholder={'[{"protocol":"http_forward","listen_address":"0.0.0.0","port":13128,"platform_name":"Default","allow_anonymous":true}]'}
                          value={importInboundJSON}
                          onChange={(event) => setImportInboundJSON(event.target.value)}
                        />
                        <div className="syscfg-inline-actions">
                          <Button type="button" variant="secondary" size="sm" onClick={() => importInboundListenersFromJSON("replace")}>
                            {t("覆盖导入")}
                          </Button>
                          <Button type="button" variant="secondary" size="sm" onClick={() => importInboundListenersFromJSON("append")}>
                            {t("追加导入")}
                          </Button>
                        </div>
                      </div>
                      {form.extra_inbound_listeners.map((listener, index) => (
                        <div key={`${listener.protocol}-${listener.listen_address}-${listener.port}-${index}`} className="syscfg-inbound-item">
                          <div className="syscfg-inbound-item-grid">
                            <div>
                              <label className="field-label" style={{ marginBottom: "6px" }}>{t("协议")}</label>
                              <select
                                className="input"
                                value={listener.protocol}
                                onChange={(event) => {
                                  const v = event.target.value === "socks5" ? "socks5" : "http_forward";
                                  updateInboundListener(index, "protocol", v);
                                }}
                              >
                                <option value="http_forward">http_forward</option>
                                <option value="socks5">socks5</option>
                              </select>
                            </div>
                            <div>
                              <label className="field-label" style={{ marginBottom: "6px" }}>{t("监听地址")}</label>
                              <Input
                                value={listener.listen_address}
                                onChange={(event) => updateInboundListener(index, "listen_address", event.target.value)}
                                placeholder="0.0.0.0"
                              />
                            </div>
                            <div>
                              <label className="field-label" style={{ marginBottom: "6px" }}>{t("端口")}</label>
                              <Input
                                type="number"
                                min={1}
                                max={65535}
                                value={String(listener.port)}
                                onChange={(event) => {
                                  const n = Number(event.target.value);
                                  updateInboundListener(index, "port", Number.isFinite(n) ? n : 0);
                                }}
                              />
                            </div>
                            <div>
                              <label className="field-label" style={{ marginBottom: "6px" }}>{t("固定平台(可选)")}</label>
                              <Input
                                list="syscfg-platform-name-options"
                                value={listener.platform_name}
                                onChange={(event) => updateInboundListener(index, "platform_name", event.target.value)}
                                placeholder={t("留空表示不固定平台")}
                              />
                            </div>
                            <div>
                              <label className="field-label" style={{ marginBottom: "6px" }}>{t("允许匿名接入")}</label>
                              <div className="syscfg-inline-switch">
                                <Switch
                                  checked={Boolean(listener.allow_anonymous)}
                                  disabled={!listener.platform_name.trim()}
                                  onChange={(event) => updateInboundListener(index, "allow_anonymous", event.target.checked)}
                                />
                                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                                  {listener.platform_name.trim() ? t("端口直连") : t("需先设置固定平台")}
                                </span>
                              </div>
                            </div>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => removeInboundListener(index)}
                            >
                              <Trash2 size={14} />
                              {t("删除")}
                            </Button>
                          </div>
                        </div>
                      ))}
                      {form.extra_inbound_listeners.length === 0 ? (
                        <div className="field-hint">{t("暂无额外监听。可通过上方按钮快速新增。")}</div>
                      ) : null}
                    </div>
                    <p className="field-hint">
                      {t("提示：每个监听地址+端口必须唯一；保存后写入运行时配置，重启 Resin 后生效。")}
                    </p>
                    <p className="field-hint">
                      {t("当监听设置了固定平台后，可直接使用 ip:port 作为代理入口，无需在请求路径或账号中再携带平台名。")}
                    </p>
                    {platformListQuery.isError ? (
                      <p className="field-hint" style={{ color: "var(--danger)" }}>
                        {t("平台列表加载失败，固定平台仍可手动输入。")}
                      </p>
                    ) : null}
                  </div>
                </div>
              </section>

              <section className="syscfg-section">
                <div className="detail-header" style={{ marginBottom: "8px" }}>
                  <div>
                    <h4 style={{ margin: 0 }}>{t("入站监听健康")}</h4>
                    <p style={{ margin: "4px 0 0", color: "var(--text-muted)" }}>{t("周期性探测各入站端口是否可建立 TCP 连接。")}</p>
                  </div>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={async () => {
                      const result = await inboundStatusQuery.refetch();
                      if (result.data) showToast("success", t("已刷新入站监听状态"));
                    }}
                    disabled={inboundStatusQuery.isFetching}
                  >
                    <RefreshCw size={16} className={inboundStatusQuery.isFetching ? "spin" : undefined} />
                    {t("刷新")}
                  </Button>
                </div>
                {inboundStatusQuery.isError ? (
                  <div className="callout callout-error" style={{ marginBottom: "10px" }}>
                    <AlertTriangle size={14} />
                    <span>{formatApiErrorMessage(inboundStatusQuery.error, t)}</span>
                  </div>
                ) : null}
                <div style={{ border: "1px solid var(--border)", borderRadius: "10px", overflow: "hidden" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                    <thead>
                      <tr style={{ background: "var(--surface-sunken, rgba(0,0,0,0.03))" }}>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("名称")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("协议")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("监听")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("来源")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("状态")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("延迟")}</th>
                        <th style={{ textAlign: "left", padding: "8px" }}>{t("错误")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(inboundStatusQuery.data?.items ?? []).map((item) => (
                        <tr key={`${item.name}-${item.listen_address}-${item.port}-${item.protocol}`} style={{ borderTop: "1px solid var(--border)" }}>
                          <td style={{ padding: "8px" }}>{item.name}</td>
                          <td style={{ padding: "8px", fontFamily: "monospace" }}>{item.protocol}</td>
                          <td style={{ padding: "8px", fontFamily: "monospace" }}>
                            {item.listen_address}:{item.port}
                            {item.platform_name ? ` (${item.platform_name})` : ""}
                          </td>
                          <td style={{ padding: "8px" }}>{item.source}</td>
                          <td style={{ padding: "8px", color: item.reachable ? "var(--success)" : "var(--danger)", fontWeight: 600 }}>
                            {item.reachable ? t("可达") : t("不可达")}
                          </td>
                          <td style={{ padding: "8px" }}>{item.probe_latency_ms}ms</td>
                          <td style={{ padding: "8px", color: "var(--text-muted)" }}>{item.probe_error ?? "-"}</td>
                        </tr>
                      ))}
                      {(inboundStatusQuery.data?.items?.length ?? 0) === 0 ? (
                        <tr>
                          <td colSpan={7} style={{ padding: "10px", color: "var(--text-muted)" }}>
                            {inboundStatusQuery.isLoading ? t("正在探测...") : t("暂无监听数据")}
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                <p className="field-hint">
                  {t("最近探测时间")}: {inboundStatusQuery.data?.generated_at || "-"}
                </p>
              </section>

              <section className="syscfg-section">
                <div className="detail-header" style={{ marginBottom: "8px" }}>
                  <div>
                    <h4 style={{ margin: 0 }}>{t("安全策略中心")}</h4>
                    <p style={{ margin: "4px 0 0", color: "var(--text-muted)" }}>
                      {t("自动检查常见安全风险，并提供强令牌生成与复制。")}
                    </p>
                  </div>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={async () => {
                      const result = await securityAuditQuery.refetch();
                      if (result.data) showToast("success", t("已刷新安全审计结果"));
                    }}
                    disabled={securityAuditQuery.isFetching}
                  >
                    <RefreshCw size={16} className={securityAuditQuery.isFetching ? "spin" : undefined} />
                    {t("刷新")}
                  </Button>
                </div>
                {securityAuditQuery.isError ? (
                  <div className="callout callout-error" style={{ marginBottom: "10px" }}>
                    <AlertTriangle size={14} />
                    <span>{formatApiErrorMessage(securityAuditQuery.error, t)}</span>
                  </div>
                ) : null}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                  <Card className="platform-directory-card" style={{ margin: 0 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                      <strong>{t("安全评分")}</strong>
                      <span
                        style={{
                          fontWeight: 700,
                          color: securityAuditQuery.data?.level === "critical"
                            ? "var(--danger)"
                            : securityAuditQuery.data?.level === "warning"
                              ? "var(--warning)"
                              : "var(--success)",
                        }}
                      >
                        {securityAuditQuery.data?.score ?? 0}
                      </span>
                    </div>
                    <div className="muted" style={{ fontSize: "12px", marginBottom: "8px" }}>
                      {t("等级")}: {securityAuditQuery.data?.level ?? "-"}
                    </div>
                    <div className="muted" style={{ fontSize: "12px" }}>
                      {t("最近审计时间")}: {securityAuditQuery.data?.generated_at ?? "-"}
                    </div>
                  </Card>
                  <Card className="platform-directory-card" style={{ margin: 0 }}>
                    <div style={{ fontWeight: 600, marginBottom: "8px" }}>{t("强令牌生成")}</div>
                    <div style={{ display: "grid", gap: "8px" }}>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "8px", alignItems: "center" }}>
                        <Input value={generatedAdminToken} readOnly placeholder={t("点击生成 Admin Token")} />
                        <Button type="button" variant="secondary" size="sm" onClick={() => setGeneratedAdminToken(generateSecureToken(40))}>
                          {t("生成")}
                        </Button>
                        <Button type="button" variant="secondary" size="sm" onClick={() => void copyText(generatedAdminToken, t("已复制 Admin Token"))}>
                          {t("复制")}
                        </Button>
                      </div>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "8px", alignItems: "center" }}>
                        <Input value={generatedProxyToken} readOnly placeholder={t("点击生成 Proxy Token")} />
                        <Button type="button" variant="secondary" size="sm" onClick={() => setGeneratedProxyToken(generateSecureToken(40))}>
                          {t("生成")}
                        </Button>
                        <Button type="button" variant="secondary" size="sm" onClick={() => void copyText(generatedProxyToken, t("已复制 Proxy Token"))}>
                          {t("复制")}
                        </Button>
                      </div>
                    </div>
                    <p className="field-hint" style={{ marginTop: "8px" }}>
                      {t("提示：更新 token 后需修改容器环境变量并重启服务。")}
                    </p>
                  </Card>
                </div>
                <div style={{ display: "grid", gap: "8px", marginTop: "10px" }}>
                  {(securityAuditQuery.data?.findings ?? []).map((finding) => (
                    <div
                      key={finding.code}
                      style={{
                        border: "1px solid var(--border)",
                        borderRadius: "8px",
                        padding: "10px",
                        background: finding.severity === "high"
                          ? "rgba(239,68,68,0.08)"
                          : finding.severity === "medium"
                            ? "rgba(245,158,11,0.08)"
                            : "rgba(59,130,246,0.08)",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "10px" }}>
                        <strong>{finding.title}</strong>
                        <span style={{ fontSize: "12px", fontFamily: "monospace" }}>{finding.severity}</span>
                      </div>
                      <div style={{ fontSize: "13px", marginTop: "4px" }}>{finding.detail}</div>
                      <div className="muted" style={{ fontSize: "12px", marginTop: "6px" }}>
                        {t("建议")}: {finding.recommendation}
                      </div>
                    </div>
                  ))}
                  {(securityAuditQuery.data?.findings?.length ?? 0) === 0 ? (
                    <div className="field-hint">{t("未发现高风险项。")}</div>
                  ) : null}
                </div>
              </section>
            </Card>

            {envBaseline && (
              <Card className="syscfg-form-card platform-directory-card syscfg-static-card">
                <div className="detail-header">
                  <div>
                    <h3>{t("静态配置")}</h3>
                    <p>{t("来自环境变量和启动参数的只读配置。")}</p>
                  </div>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={async () => {
                      const result = await envConfigQuery.refetch();
                      if (result.data) showToast("success", t("已加载最新静态配置"));
                    }}
                    disabled={envConfigQuery.isFetching}
                  >
                    <RefreshCw size={16} className={envConfigQuery.isFetching ? "spin" : undefined} />
                    {t("刷新")}
                  </Button>
                </div>

                <section className="syscfg-section">
                  <h4>{t("目录与端口")}</h4>
                  <div className="form-grid">
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("数据缓存目录")}</label>
                      <Input readOnly disabled value={envBaseline.cache_dir} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("状态存储目录")}</label>
                      <Input readOnly disabled value={envBaseline.state_dir} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("日志保留目录")}</label>
                      <Input readOnly disabled value={envBaseline.log_dir} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("统一监听地址")}</label>
                      <Input readOnly disabled value={envBaseline.listen_address} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("统一服务端口")}</label>
                      <Input readOnly disabled value={String(envBaseline.resin_port)} />
                    </div>
                    <div className="field-group field-span-2">
                      <label className="field-label" style={{ margin: 0 }}>{t("额外入站监听(环境变量)")}</label>
                      <Textarea
                        readOnly
                        disabled
                        rows={6}
                        value={JSON.stringify(envBaseline.extra_inbound_listeners ?? [], null, 2)}
                      />
                    </div>
                  </div>
                </section>

                <section className="syscfg-section">
                  <h4>{t("全局限额与性能调优")}</h4>
                  <div className="form-grid">
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("控制面最大请求体")}</label>
                      <Input readOnly disabled value={String(envBaseline.api_max_body_bytes)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("最大延迟表条目数")}</label>
                      <Input readOnly disabled value={String(envBaseline.max_latency_table_entries)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("节点拨测并发数")}</label>
                      <Input readOnly disabled value={String(envBaseline.probe_concurrency)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("拨测超时时间")}</label>
                      <Input readOnly disabled value={envBaseline.probe_timeout} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("资源获取超时时间")}</label>
                      <Input readOnly disabled value={envBaseline.resource_fetch_timeout} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("GeoIP 更新计划")}</label>
                      <Input readOnly disabled value={envBaseline.geoip_update_schedule} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("代理传输最大空闲连接")}</label>
                      <Input readOnly disabled value={String(envBaseline.proxy_transport_max_idle_conns)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("单主机最大空闲连接")}</label>
                      <Input readOnly disabled value={String(envBaseline.proxy_transport_max_idle_conns_per_host)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("空闲连接超时时间")}</label>
                      <Input readOnly disabled value={envBaseline.proxy_transport_idle_conn_timeout} />
                    </div>
                  </div>
                </section>

                <section className="syscfg-section">
                  <h4>{t("默认平台回退规则")}</h4>
                  <div className="form-grid">
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认粘性会话 TTL")}</label>
                      <Input readOnly disabled value={envBaseline.default_platform_sticky_ttl} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认节点分配策略")}</label>
                      <Input readOnly disabled value={t(displayAllocationPolicy(envBaseline.default_platform_allocation_policy))} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认反代不匹配行为")}</label>
                      <Input readOnly disabled value={t(displayMissAction(envBaseline.default_platform_reverse_proxy_miss_action))} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认反代空账号行为")}</label>
                      <Input
                        readOnly
                        disabled
                        value={t(displayEmptyAccountBehavior(envBaseline.default_platform_reverse_proxy_empty_account_behavior))}
                      />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认反代固定账号 Header 列表")}</label>
                      <Textarea
                        readOnly
                        disabled
                        rows={3}
                        value={envBaseline.default_platform_reverse_proxy_fixed_account_header || t("无")}
                      />
                    </div>
                    <div className="field-group field-span-2">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认正则黑名单")}</label>
                      <Textarea readOnly disabled rows={3} value={envBaseline.default_platform_regex_filters?.join("\n") || t("无")} />
                    </div>
                    <div className="field-group field-span-2">
                      <label className="field-label" style={{ margin: 0 }}>{t("默认地区黑名单")}</label>
                      <Textarea readOnly disabled rows={2} value={envBaseline.default_platform_region_filters?.join(",") || t("无")} />
                    </div>
                  </div>
                </section>

                <section className="syscfg-section">
                  <h4>{t("请求日志落库")}</h4>
                  <div className="form-grid">
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("队列大小")}</label>
                      <Input readOnly disabled value={String(envBaseline.request_log_queue_size)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("落盘批大小")}</label>
                      <Input readOnly disabled value={String(envBaseline.request_log_queue_flush_batch_size)} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("落盘间隔")}</label>
                      <Input readOnly disabled value={envBaseline.request_log_queue_flush_interval} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("数据库保留阈值")}</label>
                      <Input readOnly disabled value={envBaseline.request_log_db_max_mb + " MB"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("数据库旧分片保留数")}</label>
                      <Input readOnly disabled value={String(envBaseline.request_log_db_retain_count)} />
                    </div>
                  </div>
                </section>

                <section className="syscfg-section">
                  <h4>{t("可观测性指标")}</h4>
                  <div className="form-grid">
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("吞吐量抽样间隔")}</label>
                      <Input readOnly disabled value={envBaseline.metric_throughput_interval_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("吞吐量保留时间")}</label>
                      <Input readOnly disabled value={envBaseline.metric_throughput_retention_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("连接数抽样间隔")}</label>
                      <Input readOnly disabled value={envBaseline.metric_connections_interval_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("连接数保留时间")}</label>
                      <Input readOnly disabled value={envBaseline.metric_connections_retention_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("租期与连接指标分桶数")}</label>
                      <Input readOnly disabled value={envBaseline.metric_bucket_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("租期抽样间隔")}</label>
                      <Input readOnly disabled value={envBaseline.metric_leases_interval_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("租期保留时间")}</label>
                      <Input readOnly disabled value={envBaseline.metric_leases_retention_seconds + "s"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("延迟统计桶宽")}</label>
                      <Input readOnly disabled value={envBaseline.metric_latency_bin_width_ms + "ms"} />
                    </div>
                    <div className="field-group">
                      <label className="field-label" style={{ margin: 0 }}>{t("延迟统计截断值")}</label>
                      <Input readOnly disabled value={envBaseline.metric_latency_bin_overflow_ms + "ms"} />
                    </div>
                  </div>
                </section>

                <section className="syscfg-section">
                  <h4>{t("服务鉴权状态")}</h4>
                  <div className="syscfg-checkbox-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "var(--surface-sunken, rgba(0,0,0,0.02))", padding: "12px 16px", borderRadius: "8px", border: "1px solid var(--border)", opacity: 0.7 }}>
                      <span className="field-label" style={{ margin: 0, fontWeight: 500 }}>{t("已配置管理端令牌")}</span>
                      <Switch checked={envBaseline.admin_token_set} disabled />
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", background: "var(--surface-sunken, rgba(0,0,0,0.02))", padding: "12px 16px", borderRadius: "8px", border: "1px solid var(--border)", opacity: 0.7 }}>
                      <span className="field-label" style={{ margin: 0, fontWeight: 500 }}>{t("已配置代理令牌")}</span>
                      <Switch checked={envBaseline.proxy_token_set} disabled />
                    </div>
                  </div>
                </section>
              </Card>
            )}
          </div>

        </div>
      )}
    </section>
  );
}
