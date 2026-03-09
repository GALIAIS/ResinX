package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/Resinat/Resin/internal/config"
	"github.com/Resinat/Resin/internal/netutil"
	"github.com/Resinat/Resin/internal/outbound"
	"github.com/Resinat/Resin/internal/routing"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	socks5Version              = 0x05
	socks5UserPassVersion      = 0x01
	socks5AuthNone             = 0x00
	socks5AuthUserPass         = 0x02
	socks5AuthNoAcceptable     = 0xFF
	socks5CmdConnect           = 0x01
	socks5AtypIPv4             = 0x01
	socks5AtypDomain           = 0x03
	socks5AtypIPv6             = 0x04
	socks5RepSuccess           = 0x00
	socks5RepGeneralFailure    = 0x01
	socks5RepConnectionRefused = 0x05
	socks5RepCommandNotSupport = 0x07
	socks5RepAddrTypeNotSup    = 0x08
)

type Socks5ProxyConfig struct {
	ProxyToken     string
	AuthVersion    string
	ForcedPlatform string
	AllowAnonymous bool
	Router         *routing.Router
	Pool           outbound.PoolAccessor
	Health         HealthRecorder
	Events         EventEmitter
}

type Socks5Proxy struct {
	token          string
	authVersion    config.AuthVersion
	forcedPlatform string
	allowAnonymous bool
	router         *routing.Router
	pool           outbound.PoolAccessor
	health         HealthRecorder
	events         EventEmitter
}

func NewSocks5Proxy(cfg Socks5ProxyConfig) *Socks5Proxy {
	ev := cfg.Events
	if ev == nil {
		ev = NoOpEventEmitter{}
	}
	authVersion := config.NormalizeAuthVersion(cfg.AuthVersion)
	if authVersion == "" {
		authVersion = config.AuthVersionLegacyV0
	}
	return &Socks5Proxy{
		token:          cfg.ProxyToken,
		authVersion:    authVersion,
		forcedPlatform: strings.TrimSpace(cfg.ForcedPlatform),
		allowAnonymous: cfg.AllowAnonymous,
		router:         cfg.Router,
		pool:           cfg.Pool,
		health:         cfg.Health,
		events:         ev,
	}
}

func (p *Socks5Proxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go p.handleConn(conn)
	}
}

func (p *Socks5Proxy) effectiveAuthVersion() config.AuthVersion {
	if p == nil {
		return config.AuthVersionLegacyV0
	}
	if p.authVersion == config.AuthVersionV1 {
		return config.AuthVersionV1
	}
	return config.AuthVersionLegacyV0
}

func (p *Socks5Proxy) applyPlatformPolicy(platformName string) string {
	if p == nil {
		return platformName
	}
	if p.forcedPlatform != "" {
		return p.forcedPlatform
	}
	return platformName
}

func (p *Socks5Proxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	lifecycle := newRequestLifecycle(p.events, nil, ProxyTypeForward, true)
	lifecycle.log.HTTPMethod = "CONNECT"
	lifecycle.log.ClientIP = clientRemoteIP(clientConn)
	defer lifecycle.finish()

	platformName, account, authOK := p.negotiateAndAuthenticate(clientConn)
	if !authOK {
		lifecycle.setProxyError(ErrAuthFailed)
		lifecycle.setHTTPStatus(ErrAuthFailed.HTTPCode)
		lifecycle.setNetOK(false)
		return
	}
	platformName = p.applyPlatformPolicy(platformName)
	lifecycle.setAccount(account)

	target, rep, ok := readSocks5ConnectTarget(clientConn)
	if !ok {
		_ = writeSocks5Reply(clientConn, rep)
		lifecycle.setProxyError(ErrURLParseError)
		lifecycle.setHTTPStatus(ErrURLParseError.HTTPCode)
		lifecycle.setNetOK(false)
		return
	}
	lifecycle.setTarget(target, "")

	routed, routeErr := resolveRoutedOutbound(p.router, p.pool, platformName, account, target)
	if routeErr != nil {
		_ = writeSocks5Reply(clientConn, mapProxyErrorToSocks5Rep(routeErr))
		lifecycle.setProxyError(routeErr)
		lifecycle.setHTTPStatus(routeErr.HTTPCode)
		lifecycle.setNetOK(false)
		return
	}
	lifecycle.setRouteResult(routed.Route)
	go p.health.RecordLatency(routed.Route.NodeHash, netutil.ExtractDomain(target), nil)

	upstreamConn, err := routed.Outbound.DialContext(context.Background(), "tcp", M.ParseSocksaddr(target))
	if err != nil {
		proxyErr := classifyConnectError(err)
		if proxyErr == nil {
			lifecycle.setNetOK(true)
			return
		}
		_ = writeSocks5Reply(clientConn, mapProxyErrorToSocks5Rep(proxyErr))
		lifecycle.setProxyError(proxyErr)
		lifecycle.setHTTPStatus(proxyErr.HTTPCode)
		lifecycle.setUpstreamError("socks5_dial", err)
		lifecycle.setNetOK(false)
		go p.health.RecordResult(routed.Route.NodeHash, false)
		return
	}
	defer upstreamConn.Close()

	if err := writeSocks5Reply(clientConn, socks5RepSuccess); err != nil {
		lifecycle.setProxyError(ErrUpstreamRequestFailed)
		lifecycle.setHTTPStatus(ErrUpstreamRequestFailed.HTTPCode)
		lifecycle.setUpstreamError("socks5_reply", err)
		lifecycle.setNetOK(false)
		go p.health.RecordResult(routed.Route.NodeHash, false)
		return
	}
	lifecycle.setHTTPStatus(200)

	type copyResult struct {
		n   int64
		err error
	}
	egressCh := make(chan copyResult, 1)
	go func() {
		n, copyErr := io.Copy(upstreamConn, clientConn)
		egressCh <- copyResult{n: n, err: copyErr}
		_ = upstreamConn.Close()
	}()
	ingressBytes, ingressErr := io.Copy(clientConn, upstreamConn)
	_ = clientConn.Close()
	_ = upstreamConn.Close()
	egressRes := <-egressCh

	lifecycle.addIngressBytes(ingressBytes)
	lifecycle.addEgressBytes(egressRes.n)

	okResult := ingressBytes > 0 && egressRes.n > 0
	if !okResult {
		lifecycle.setProxyError(ErrUpstreamRequestFailed)
		switch {
		case ingressErr != nil:
			lifecycle.setUpstreamError("socks5_upstream_to_client_copy", ingressErr)
		case egressRes.err != nil:
			lifecycle.setUpstreamError("socks5_client_to_upstream_copy", egressRes.err)
		default:
			lifecycle.setUpstreamError("socks5_zero_traffic", nil)
		}
	}
	lifecycle.setNetOK(okResult)
	go p.health.RecordResult(routed.Route.NodeHash, okResult)
}

func clientRemoteIP(conn net.Conn) string {
	if conn == nil {
		return ""
	}
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err == nil {
		return host
	}
	return conn.RemoteAddr().String()
}

func (p *Socks5Proxy) negotiateAndAuthenticate(conn net.Conn) (platformName string, account string, ok bool) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", "", false
	}
	if head[0] != socks5Version {
		return "", "", false
	}
	methodCount := int(head[1])
	if methodCount <= 0 {
		return "", "", false
	}
	methods := make([]byte, methodCount)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", "", false
	}

	method := p.selectAuthMethod(methods)
	if _, err := conn.Write([]byte{socks5Version, method}); err != nil {
		return "", "", false
	}
	if method == socks5AuthNoAcceptable {
		return "", "", false
	}
	if method == socks5AuthNone {
		return "", "", true
	}
	return p.authenticateUserPass(conn)
}

func (p *Socks5Proxy) selectAuthMethod(methods []byte) byte {
	hasNoAuth := false
	hasUserPass := false
	for _, m := range methods {
		if m == socks5AuthNone {
			hasNoAuth = true
		}
		if m == socks5AuthUserPass {
			hasUserPass = true
		}
	}
	if p.token != "" {
		if p.allowAnonymous && strings.TrimSpace(p.forcedPlatform) != "" && hasNoAuth {
			return socks5AuthNone
		}
		if hasUserPass {
			return socks5AuthUserPass
		}
		return socks5AuthNoAcceptable
	}
	if hasUserPass {
		return socks5AuthUserPass
	}
	if hasNoAuth {
		return socks5AuthNone
	}
	return socks5AuthNoAcceptable
}

func (p *Socks5Proxy) authenticateUserPass(conn net.Conn) (platformName string, account string, ok bool) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return p.writeUserPassAuthResult(conn, false)
	}
	if head[0] != socks5UserPassVersion {
		return p.writeUserPassAuthResult(conn, false)
	}
	userLen := int(head[1])
	if userLen <= 0 {
		return p.writeUserPassAuthResult(conn, false)
	}
	usernameBytes := make([]byte, userLen)
	if _, err := io.ReadFull(conn, usernameBytes); err != nil {
		return p.writeUserPassAuthResult(conn, false)
	}
	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return p.writeUserPassAuthResult(conn, false)
	}
	passLen := int(passLenBuf[0])
	passwordBytes := make([]byte, passLen)
	if _, err := io.ReadFull(conn, passwordBytes); err != nil {
		return p.writeUserPassAuthResult(conn, false)
	}

	username := string(usernameBytes)
	password := string(passwordBytes)
	switch p.effectiveAuthVersion() {
	case config.AuthVersionV1:
		if p.token != "" && password != p.token {
			return p.writeUserPassAuthResult(conn, false)
		}
		platformName, account = parseV1PlatformAccountIdentity(username)
		return p.writeUserPassAuthResult(conn, true, platformName, account)
	default:
		if p.token != "" {
			if username != p.token {
				return p.writeUserPassAuthResult(conn, false)
			}
			platformName, account = parseLegacyPlatformAccountIdentity(password)
			return p.writeUserPassAuthResult(conn, true, platformName, account)
		}
		platformName, account = parseLegacyPlatformAccountIdentity(username)
		return p.writeUserPassAuthResult(conn, true, platformName, account)
	}
}

func (p *Socks5Proxy) writeUserPassAuthResult(conn net.Conn, success bool, values ...string) (string, string, bool) {
	status := byte(0x01)
	if success {
		status = 0x00
	}
	_, _ = conn.Write([]byte{socks5UserPassVersion, status})
	if !success {
		return "", "", false
	}
	platformName := ""
	account := ""
	if len(values) > 0 {
		platformName = values[0]
	}
	if len(values) > 1 {
		account = values[1]
	}
	return platformName, account, true
}

func readSocks5ConnectTarget(conn net.Conn) (target string, rep byte, ok bool) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", socks5RepGeneralFailure, false
	}
	if head[0] != socks5Version {
		return "", socks5RepGeneralFailure, false
	}
	if head[1] != socks5CmdConnect {
		return "", socks5RepCommandNotSupport, false
	}

	host, ok := readSocks5Host(conn, head[3])
	if !ok {
		return "", socks5RepAddrTypeNotSup, false
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", socks5RepGeneralFailure, false
	}
	port := binary.BigEndian.Uint16(portBytes)
	target = net.JoinHostPort(host, strconv.Itoa(int(port)))
	return target, socks5RepSuccess, true
}

func readSocks5Host(conn net.Conn, atyp byte) (string, bool) {
	switch atyp {
	case socks5AtypIPv4:
		ip := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", false
		}
		return net.IP(ip).String(), true
	case socks5AtypIPv6:
		ip := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", false
		}
		return net.IP(ip).String(), true
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", false
		}
		domainLen := int(lenBuf[0])
		if domainLen <= 0 {
			return "", false
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", false
		}
		return string(domain), true
	default:
		return "", false
	}
}

func writeSocks5Reply(conn net.Conn, rep byte) error {
	// BND.ADDR = 0.0.0.0, BND.PORT = 0
	_, err := conn.Write([]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func mapProxyErrorToSocks5Rep(pe *ProxyError) byte {
	if pe == nil {
		return socks5RepGeneralFailure
	}
	switch pe {
	case ErrUpstreamConnectFailed:
		return socks5RepConnectionRefused
	case ErrUpstreamTimeout:
		return socks5RepGeneralFailure
	case ErrNoAvailableNodes, ErrPlatformNotFound:
		return socks5RepGeneralFailure
	default:
		return socks5RepGeneralFailure
	}
}
