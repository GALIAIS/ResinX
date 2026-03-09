package config

import (
	"fmt"
	"strings"

	"github.com/Resinat/Resin/internal/platform"
)

type InboundProtocol string

const (
	InboundProtocolHTTPForward InboundProtocol = "http_forward"
	InboundProtocolSOCKS5      InboundProtocol = "socks5"
)

type InboundListener struct {
	Protocol       InboundProtocol `json:"protocol"`
	ListenAddress  string          `json:"listen_address"`
	Port           int             `json:"port"`
	PlatformName   string          `json:"platform_name"`
	AllowAnonymous *bool           `json:"allow_anonymous,omitempty"`
}

func boolPtr(v bool) *bool {
	b := v
	return &b
}

func (l InboundListener) EffectiveAllowAnonymous() bool {
	if l.AllowAnonymous != nil {
		return *l.AllowAnonymous
	}
	return strings.TrimSpace(l.PlatformName) != ""
}

func normalizeInboundProtocol(raw string) InboundProtocol {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case string(InboundProtocolHTTPForward):
		return InboundProtocolHTTPForward
	case string(InboundProtocolSOCKS5):
		return InboundProtocolSOCKS5
	default:
		return ""
	}
}

func normalizeInboundListener(raw InboundListener, defaultListenAddress string) (InboundListener, error) {
	out := InboundListener{
		Protocol:     normalizeInboundProtocol(string(raw.Protocol)),
		Port:         raw.Port,
		PlatformName: platform.NormalizePlatformName(raw.PlatformName),
	}
	if raw.AllowAnonymous != nil {
		out.AllowAnonymous = boolPtr(*raw.AllowAnonymous)
	}
	out.ListenAddress = strings.TrimSpace(raw.ListenAddress)
	if out.ListenAddress == "" {
		out.ListenAddress = defaultListenAddress
	}

	if out.Protocol == "" {
		return InboundListener{}, fmt.Errorf("protocol: invalid value %q (allowed: %q, %q)", raw.Protocol, InboundProtocolHTTPForward, InboundProtocolSOCKS5)
	}
	if out.ListenAddress == "" {
		return InboundListener{}, fmt.Errorf("listen_address: must not be empty")
	}
	if out.Port < 1 || out.Port > 65535 {
		return InboundListener{}, fmt.Errorf("port: must be 1-65535, got %d", out.Port)
	}
	if out.PlatformName != "" {
		if err := platform.ValidatePlatformName(out.PlatformName); err != nil {
			return InboundListener{}, fmt.Errorf("platform_name: %v", err)
		}
	}
	if out.EffectiveAllowAnonymous() && out.PlatformName == "" {
		return InboundListener{}, fmt.Errorf("allow_anonymous: requires non-empty platform_name")
	}
	return out, nil
}

// NormalizeInboundListenerForRuntime normalizes a runtime-config listener.
// Runtime config requires explicit listen address; empty listen address defaults to 0.0.0.0.
func NormalizeInboundListenerForRuntime(raw InboundListener) (InboundListener, error) {
	return normalizeInboundListener(raw, "0.0.0.0")
}
