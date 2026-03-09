import { apiRequest } from "../../lib/api-client";
import type { EnvConfig, InboundListener, InboundStatusResponse, RuntimeConfig, RuntimeConfigPatch, SecurityAuditResponse } from "./types";

const path = "/api/v1/system/config";
const inboundStatusPath = "/api/v1/system/inbounds/status";
const securityAuditPath = "/api/v1/system/security/audit";

const DEFAULT_CONFIG: RuntimeConfig = {
  user_agent: "",
  request_log_enabled: true,
  reverse_proxy_log_detail_enabled: false,
  reverse_proxy_log_req_headers_max_bytes: 0,
  reverse_proxy_log_req_body_max_bytes: 0,
  reverse_proxy_log_resp_headers_max_bytes: 0,
  reverse_proxy_log_resp_body_max_bytes: 0,
  max_consecutive_failures: 0,
  max_latency_test_interval: "",
  max_authority_latency_test_interval: "",
  max_egress_test_interval: "",
  latency_test_url: "",
  latency_authorities: [],
  p2c_latency_window: "",
  latency_decay_window: "",
  cache_flush_interval: "",
  cache_flush_dirty_threshold: 0,
  extra_inbound_listeners: [],
};

function normalizeInboundListeners(raw: unknown): InboundListener[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw
    .map((item) => {
      if (!item || typeof item !== "object") {
        return null;
      }
      const rec = item as Record<string, unknown>;
      const protocol = String(rec.protocol ?? "").trim().toLowerCase();
      if (protocol !== "http_forward" && protocol !== "socks5") {
        return null;
      }
      const platformName = asString(rec.platform_name, "");
      const allowAnonymousRaw = rec.allow_anonymous;
      const allowAnonymous = typeof allowAnonymousRaw === "boolean"
        ? allowAnonymousRaw
        : platformName.trim() !== "";
      return {
        protocol,
        listen_address: asString(rec.listen_address, "0.0.0.0"),
        port: asNumber(rec.port, 0),
        platform_name: platformName,
        allow_anonymous: allowAnonymous,
      } as InboundListener;
    })
    .filter((item): item is InboundListener => item !== null && item.port > 0);
}

function asNumber(raw: unknown, fallback: number): number {
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    return fallback;
  }
  return value;
}

function asString(raw: unknown, fallback: string): string {
  if (typeof raw !== "string") {
    return fallback;
  }
  return raw;
}

function normalizeRuntimeConfig(raw: Partial<RuntimeConfig> | null | undefined): RuntimeConfig {
  if (!raw) {
    return DEFAULT_CONFIG;
  }

  return {
    user_agent: asString(raw.user_agent, DEFAULT_CONFIG.user_agent),
    request_log_enabled: Boolean(raw.request_log_enabled),
    reverse_proxy_log_detail_enabled: Boolean(raw.reverse_proxy_log_detail_enabled),
    reverse_proxy_log_req_headers_max_bytes: asNumber(
      raw.reverse_proxy_log_req_headers_max_bytes,
      DEFAULT_CONFIG.reverse_proxy_log_req_headers_max_bytes,
    ),
    reverse_proxy_log_req_body_max_bytes: asNumber(
      raw.reverse_proxy_log_req_body_max_bytes,
      DEFAULT_CONFIG.reverse_proxy_log_req_body_max_bytes,
    ),
    reverse_proxy_log_resp_headers_max_bytes: asNumber(
      raw.reverse_proxy_log_resp_headers_max_bytes,
      DEFAULT_CONFIG.reverse_proxy_log_resp_headers_max_bytes,
    ),
    reverse_proxy_log_resp_body_max_bytes: asNumber(
      raw.reverse_proxy_log_resp_body_max_bytes,
      DEFAULT_CONFIG.reverse_proxy_log_resp_body_max_bytes,
    ),
    max_consecutive_failures: asNumber(raw.max_consecutive_failures, DEFAULT_CONFIG.max_consecutive_failures),
    max_latency_test_interval: asString(raw.max_latency_test_interval, DEFAULT_CONFIG.max_latency_test_interval),
    max_authority_latency_test_interval: asString(
      raw.max_authority_latency_test_interval,
      DEFAULT_CONFIG.max_authority_latency_test_interval,
    ),
    max_egress_test_interval: asString(raw.max_egress_test_interval, DEFAULT_CONFIG.max_egress_test_interval),
    latency_test_url: asString(raw.latency_test_url, DEFAULT_CONFIG.latency_test_url),
    latency_authorities: Array.isArray(raw.latency_authorities)
      ? raw.latency_authorities.filter((item): item is string => typeof item === "string")
      : DEFAULT_CONFIG.latency_authorities,
    p2c_latency_window: asString(raw.p2c_latency_window, DEFAULT_CONFIG.p2c_latency_window),
    latency_decay_window: asString(raw.latency_decay_window, DEFAULT_CONFIG.latency_decay_window),
    cache_flush_interval: asString(raw.cache_flush_interval, DEFAULT_CONFIG.cache_flush_interval),
    cache_flush_dirty_threshold: asNumber(
      raw.cache_flush_dirty_threshold,
      DEFAULT_CONFIG.cache_flush_dirty_threshold,
    ),
    extra_inbound_listeners: normalizeInboundListeners(raw.extra_inbound_listeners),
  };
}

export async function getSystemConfig(): Promise<RuntimeConfig> {
  const data = await apiRequest<RuntimeConfig>(path);
  return normalizeRuntimeConfig(data);
}

export async function getDefaultSystemConfig(): Promise<RuntimeConfig> {
  const data = await apiRequest<RuntimeConfig>(path + "/default");
  return normalizeRuntimeConfig(data);
}

export async function patchSystemConfig(patch: RuntimeConfigPatch): Promise<RuntimeConfig> {
  const data = await apiRequest<RuntimeConfig>(path, {
    method: "PATCH",
    body: patch,
  });
  return normalizeRuntimeConfig(data);
}

export async function getEnvConfig(): Promise<EnvConfig> {
  return await apiRequest<EnvConfig>(path + "/env");
}

export async function getInboundStatuses(): Promise<InboundStatusResponse> {
  const data = await apiRequest<InboundStatusResponse>(inboundStatusPath);
  return {
    generated_at: data?.generated_at ?? "",
    items: Array.isArray(data?.items) ? data.items : [],
  };
}

export async function getSecurityAudit(): Promise<SecurityAuditResponse> {
  const data = await apiRequest<SecurityAuditResponse>(securityAuditPath);
  return {
    generated_at: data?.generated_at ?? "",
    score: Number.isFinite(Number(data?.score)) ? Number(data.score) : 0,
    level: data?.level === "critical" || data?.level === "warning" ? data.level : "good",
    findings: Array.isArray(data?.findings) ? data.findings : [],
  };
}
