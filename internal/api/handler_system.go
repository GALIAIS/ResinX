package api

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/service"
)

type systemEnvConfigResponse struct {
	CacheDir                                        string                   `json:"cache_dir"`
	StateDir                                        string                   `json:"state_dir"`
	LogDir                                          string                   `json:"log_dir"`
	ListenAddress                                   string                   `json:"listen_address"`
	ResinPort                                       int                      `json:"resin_port"`
	APIMaxBodyBytes                                 int                      `json:"api_max_body_bytes"`
	MaxLatencyTableEntries                          int                      `json:"max_latency_table_entries"`
	ProbeConcurrency                                int                      `json:"probe_concurrency"`
	GeoIPUpdateSchedule                             string                   `json:"geoip_update_schedule"`
	DefaultPlatformStickyTTL                        config.Duration          `json:"default_platform_sticky_ttl"`
	DefaultPlatformRegexFilters                     []string                 `json:"default_platform_regex_filters"`
	DefaultPlatformRegionFilters                    []string                 `json:"default_platform_region_filters"`
	DefaultPlatformReverseProxyMissAction           string                   `json:"default_platform_reverse_proxy_miss_action"`
	DefaultPlatformReverseProxyEmptyAccountBehavior string                   `json:"default_platform_reverse_proxy_empty_account_behavior"`
	DefaultPlatformReverseProxyFixedAccountHeader   string                   `json:"default_platform_reverse_proxy_fixed_account_header"`
	DefaultPlatformAllocationPolicy                 string                   `json:"default_platform_allocation_policy"`
	ProbeTimeout                                    config.Duration          `json:"probe_timeout"`
	ResourceFetchTimeout                            config.Duration          `json:"resource_fetch_timeout"`
	ProxyTransportMaxIdleConns                      int                      `json:"proxy_transport_max_idle_conns"`
	ProxyTransportMaxIdleConnsPerHost               int                      `json:"proxy_transport_max_idle_conns_per_host"`
	ProxyTransportIdleConnTimeout                   config.Duration          `json:"proxy_transport_idle_conn_timeout"`
	RequestLogQueueSize                             int                      `json:"request_log_queue_size"`
	RequestLogQueueFlushBatchSize                   int                      `json:"request_log_queue_flush_batch_size"`
	RequestLogQueueFlushInterval                    config.Duration          `json:"request_log_queue_flush_interval"`
	RequestLogDBMaxMB                               int                      `json:"request_log_db_max_mb"`
	RequestLogDBRetainCount                         int                      `json:"request_log_db_retain_count"`
	MetricThroughputIntervalSeconds                 int                      `json:"metric_throughput_interval_seconds"`
	MetricThroughputRetentionSeconds                int                      `json:"metric_throughput_retention_seconds"`
	MetricBucketSeconds                             int                      `json:"metric_bucket_seconds"`
	MetricConnectionsIntervalSeconds                int                      `json:"metric_connections_interval_seconds"`
	MetricConnectionsRetentionSeconds               int                      `json:"metric_connections_retention_seconds"`
	MetricLeasesIntervalSeconds                     int                      `json:"metric_leases_interval_seconds"`
	MetricLeasesRetentionSeconds                    int                      `json:"metric_leases_retention_seconds"`
	MetricLatencyBinWidthMS                         int                      `json:"metric_latency_bin_width_ms"`
	MetricLatencyBinOverflowMS                      int                      `json:"metric_latency_bin_overflow_ms"`
	AdminTokenSet                                   bool                     `json:"admin_token_set"`
	ProxyTokenSet                                   bool                     `json:"proxy_token_set"`
	AdminTokenWeak                                  bool                     `json:"admin_token_weak"`
	ProxyTokenWeak                                  bool                     `json:"proxy_token_weak"`
	ExtraInboundListeners                           []config.InboundListener `json:"extra_inbound_listeners"`
}

type systemInboundStatusResponse struct {
	GeneratedAt string                    `json:"generated_at"`
	Items       []systemInboundStatusItem `json:"items"`
}

type systemInboundStatusItem struct {
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	ListenAddress  string `json:"listen_address"`
	Port           int    `json:"port"`
	PlatformName   string `json:"platform_name,omitempty"`
	Source         string `json:"source"`
	ProbeTarget    string `json:"probe_target"`
	Reachable      bool   `json:"reachable"`
	ProbeLatencyMs int64  `json:"probe_latency_ms"`
	ProbeError     string `json:"probe_error,omitempty"`
}

type systemSecurityAuditResponse struct {
	GeneratedAt string                  `json:"generated_at"`
	Score       int                     `json:"score"`
	Level       string                  `json:"level"`
	Findings    []systemSecurityFinding `json:"findings"`
}

type systemSecurityFinding struct {
	Code           string `json:"code"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

// HandleSystemInfo returns a handler for GET /api/v1/system/info.
func HandleSystemInfo(info service.SystemInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, info)
	}
}

// HandleSystemConfig returns a handler for GET /api/v1/system/config.
func HandleSystemConfig(runtimeCfg *atomic.Pointer[config.RuntimeConfig]) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if runtimeCfg == nil {
			WriteJSON(w, http.StatusOK, nil)
			return
		}
		WriteJSON(w, http.StatusOK, runtimeCfg.Load())
	}
}

// HandleSystemDefaultConfig returns a handler for GET /api/v1/system/config/default.
func HandleSystemDefaultConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, config.NewDefaultRuntimeConfig())
	}
}

// HandleSystemEnvConfig returns a handler for GET /api/v1/system/config/env.
func HandleSystemEnvConfig(envCfg *config.EnvConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, systemEnvConfigSnapshot(envCfg))
	}
}

// HandleSystemInboundStatuses returns a handler for GET /api/v1/system/inbounds/status.
func HandleSystemInboundStatuses(runtimeCfg *atomic.Pointer[config.RuntimeConfig], envCfg *config.EnvConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if envCfg == nil {
			WriteJSON(w, http.StatusOK, systemInboundStatusResponse{
				GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Items:       []systemInboundStatusItem{},
			})
			return
		}

		items := make([]systemInboundStatusItem, 0, 1+len(envCfg.ExtraInboundListeners))
		items = append(items, probeInboundStatus(systemInboundStatusItem{
			Name:          "main",
			Protocol:      "mixed",
			ListenAddress: envCfg.ListenAddress,
			Port:          envCfg.ResinPort,
			Source:        "core",
		}))

		extra, source := effectiveExtraInboundListeners(runtimeCfg, envCfg)
		for i, listener := range extra {
			items = append(items, probeInboundStatus(systemInboundStatusItem{
				Name:          "extra-" + strconv.Itoa(i+1),
				Protocol:      string(listener.Protocol),
				ListenAddress: listener.ListenAddress,
				Port:          listener.Port,
				PlatformName:  listener.PlatformName,
				Source:        source,
			}))
		}

		WriteJSON(w, http.StatusOK, systemInboundStatusResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Items:       items,
		})
	}
}

// HandlePatchSystemConfig returns a handler for PATCH /api/v1/system/config.
func HandlePatchSystemConfig(cp *service.ControlPlaneService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readRawBodyOrWriteInvalid(w, r)
		if !ok {
			return
		}
		result, err := cp.PatchRuntimeConfig(body)
		if err != nil {
			writeServiceError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, result)
	}
}

// HandleSystemSecurityAudit returns a handler for GET /api/v1/system/security/audit.
func HandleSystemSecurityAudit(runtimeCfg *atomic.Pointer[config.RuntimeConfig], envCfg *config.EnvConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if envCfg == nil {
			WriteJSON(w, http.StatusOK, systemSecurityAuditResponse{
				GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
				Score:       0,
				Level:       "critical",
				Findings: []systemSecurityFinding{
					{
						Code:           "ENV_CONFIG_MISSING",
						Severity:       "high",
						Title:          "Environment configuration unavailable",
						Detail:         "System env config snapshot is nil.",
						Recommendation: "Restart service and verify env loading.",
					},
				},
			})
			return
		}

		findings := make([]systemSecurityFinding, 0, 8)
		add := func(code, severity, title, detail, recommendation string) {
			findings = append(findings, systemSecurityFinding{
				Code:           code,
				Severity:       severity,
				Title:          title,
				Detail:         detail,
				Recommendation: recommendation,
			})
		}

		if envCfg.AdminToken == "" {
			add(
				"ADMIN_TOKEN_EMPTY",
				"high",
				"Admin token is empty",
				"Control plane API authentication is effectively disabled.",
				"Set RESIN_ADMIN_TOKEN to a strong random value.",
			)
		} else if config.IsWeakToken(envCfg.AdminToken) {
			add(
				"ADMIN_TOKEN_WEAK",
				"medium",
				"Admin token is weak",
				"Current admin token has low entropy.",
				"Replace RESIN_ADMIN_TOKEN with a longer random token.",
			)
		}

		if envCfg.ProxyToken == "" {
			add(
				"PROXY_TOKEN_EMPTY",
				"high",
				"Proxy token is empty",
				"Forward/reverse proxy authentication is disabled.",
				"Set RESIN_PROXY_TOKEN to a strong random value.",
			)
		} else if config.IsWeakToken(envCfg.ProxyToken) {
			add(
				"PROXY_TOKEN_WEAK",
				"medium",
				"Proxy token is weak",
				"Current proxy token has low entropy.",
				"Replace RESIN_PROXY_TOKEN with a longer random token.",
			)
		}

		if strings.TrimSpace(envCfg.ListenAddress) == "0.0.0.0" || strings.TrimSpace(envCfg.ListenAddress) == "::" {
			add(
				"LISTEN_WILDCARD",
				"medium",
				"Service is listening on all interfaces",
				"Main mixed inbound is exposed to every network interface.",
				"Use firewall allow-list or bind to specific interfaces when possible.",
			)
		}

		extra, source := effectiveExtraInboundListeners(runtimeCfg, envCfg)
		if len(extra) > 0 && envCfg.ProxyToken == "" {
			add(
				"EXTRA_INBOUND_OPEN_PROXY",
				"high",
				"Extra inbound listeners are open without proxy token",
				"At least one extra inbound listener exists while proxy auth token is empty.",
				"Set RESIN_PROXY_TOKEN and restart, or remove unnecessary public listeners.",
			)
		}
		for i, listener := range extra {
			addr := strings.TrimSpace(listener.ListenAddress)
			if addr == "0.0.0.0" || addr == "::" || addr == "" {
				add(
					"EXTRA_INBOUND_PUBLIC_"+strconv.Itoa(i+1),
					"low",
					"Extra inbound listens on wildcard address",
					fmt.Sprintf("Listener #%d (%s:%d, protocol=%s, source=%s) is public.", i+1, listener.ListenAddress, listener.Port, listener.Protocol, source),
					"Restrict by firewall/security-group if this port is not intended for public access.",
				)
			}
		}

		score := 100
		for _, f := range findings {
			switch f.Severity {
			case "high":
				score -= 30
			case "medium":
				score -= 15
			default:
				score -= 5
			}
		}
		if score < 0 {
			score = 0
		}
		level := "good"
		switch {
		case score < 40:
			level = "critical"
		case score < 70:
			level = "warning"
		}

		WriteJSON(w, http.StatusOK, systemSecurityAuditResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Score:       score,
			Level:       level,
			Findings:    findings,
		})
	}
}

func systemEnvConfigSnapshot(envCfg *config.EnvConfig) *systemEnvConfigResponse {
	if envCfg == nil {
		return nil
	}
	adminTokenSet := envCfg.AdminToken != ""
	proxyTokenSet := envCfg.ProxyToken != ""
	return &systemEnvConfigResponse{
		CacheDir:                              envCfg.CacheDir,
		StateDir:                              envCfg.StateDir,
		LogDir:                                envCfg.LogDir,
		ListenAddress:                         envCfg.ListenAddress,
		ResinPort:                             envCfg.ResinPort,
		APIMaxBodyBytes:                       envCfg.APIMaxBodyBytes,
		MaxLatencyTableEntries:                envCfg.MaxLatencyTableEntries,
		ProbeConcurrency:                      envCfg.ProbeConcurrency,
		GeoIPUpdateSchedule:                   envCfg.GeoIPUpdateSchedule,
		DefaultPlatformStickyTTL:              config.Duration(envCfg.DefaultPlatformStickyTTL),
		DefaultPlatformRegexFilters:           append([]string(nil), envCfg.DefaultPlatformRegexFilters...),
		DefaultPlatformRegionFilters:          append([]string(nil), envCfg.DefaultPlatformRegionFilters...),
		DefaultPlatformReverseProxyMissAction: envCfg.DefaultPlatformReverseProxyMissAction,
		DefaultPlatformReverseProxyEmptyAccountBehavior: envCfg.DefaultPlatformReverseProxyEmptyAccountBehavior,
		DefaultPlatformReverseProxyFixedAccountHeader:   envCfg.DefaultPlatformReverseProxyFixedAccountHeader,
		DefaultPlatformAllocationPolicy:                 envCfg.DefaultPlatformAllocationPolicy,
		ProbeTimeout:                                    config.Duration(envCfg.ProbeTimeout),
		ResourceFetchTimeout:                            config.Duration(envCfg.ResourceFetchTimeout),
		ProxyTransportMaxIdleConns:                      envCfg.ProxyTransportMaxIdleConns,
		ProxyTransportMaxIdleConnsPerHost:               envCfg.ProxyTransportMaxIdleConnsPerHost,
		ProxyTransportIdleConnTimeout:                   config.Duration(envCfg.ProxyTransportIdleConnTimeout),
		RequestLogQueueSize:                             envCfg.RequestLogQueueSize,
		RequestLogQueueFlushBatchSize:                   envCfg.RequestLogQueueFlushBatchSize,
		RequestLogQueueFlushInterval:                    config.Duration(envCfg.RequestLogQueueFlushInterval),
		RequestLogDBMaxMB:                               envCfg.RequestLogDBMaxMB,
		RequestLogDBRetainCount:                         envCfg.RequestLogDBRetainCount,
		MetricThroughputIntervalSeconds:                 envCfg.MetricThroughputIntervalSeconds,
		MetricThroughputRetentionSeconds:                envCfg.MetricThroughputRetentionSeconds,
		MetricBucketSeconds:                             envCfg.MetricBucketSeconds,
		MetricConnectionsIntervalSeconds:                envCfg.MetricConnectionsIntervalSeconds,
		MetricConnectionsRetentionSeconds:               envCfg.MetricConnectionsRetentionSeconds,
		MetricLeasesIntervalSeconds:                     envCfg.MetricLeasesIntervalSeconds,
		MetricLeasesRetentionSeconds:                    envCfg.MetricLeasesRetentionSeconds,
		MetricLatencyBinWidthMS:                         envCfg.MetricLatencyBinWidthMS,
		MetricLatencyBinOverflowMS:                      envCfg.MetricLatencyBinOverflowMS,
		AdminTokenSet:                                   adminTokenSet,
		ProxyTokenSet:                                   proxyTokenSet,
		AdminTokenWeak:                                  adminTokenSet && config.IsWeakToken(envCfg.AdminToken),
		ProxyTokenWeak:                                  proxyTokenSet && config.IsWeakToken(envCfg.ProxyToken),
		ExtraInboundListeners:                           append([]config.InboundListener(nil), envCfg.ExtraInboundListeners...),
	}
}

func effectiveExtraInboundListeners(runtimeCfg *atomic.Pointer[config.RuntimeConfig], envCfg *config.EnvConfig) ([]config.InboundListener, string) {
	if runtimeCfg != nil {
		if cfg := runtimeCfg.Load(); cfg != nil && len(cfg.ExtraInboundListeners) > 0 {
			return append([]config.InboundListener(nil), cfg.ExtraInboundListeners...), "runtime"
		}
	}
	return append([]config.InboundListener(nil), envCfg.ExtraInboundListeners...), "env"
}

func probeInboundStatus(item systemInboundStatusItem) systemInboundStatusItem {
	targetHost := probeHostForListenAddress(item.ListenAddress)
	item.ProbeTarget = net.JoinHostPort(targetHost, strconv.Itoa(item.Port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", item.ProbeTarget, 800*time.Millisecond)
	if err != nil {
		item.Reachable = false
		item.ProbeError = err.Error()
		item.ProbeLatencyMs = time.Since(start).Milliseconds()
		return item
	}
	_ = conn.Close()
	item.Reachable = true
	item.ProbeLatencyMs = time.Since(start).Milliseconds()
	return item
}

func probeHostForListenAddress(addr string) string {
	s := strings.TrimSpace(strings.ToLower(addr))
	switch s {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "::1"
	default:
		return strings.Trim(addr, "[]")
	}
}
