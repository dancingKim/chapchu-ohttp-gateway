// Copyright (c) 2026 Cloudflare, Inc. and Chapchu contributors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxGatewayRequestBytes       = 12 << 20
	maxGatewayResponseBytes      = 16 << 20
	maxGatewayConcurrentRequests = 2
	guardianPIRHost              = "url-filter-dev.chapchu.worthyilife.com"
	guardianPIRTarget            = "pir:8082"
)

var errGatewayConfiguration = errors.New("invalid gateway security configuration")

// Only this mounted secret file is accepted. Never log its bytes or raw errors.
func loadGatewaySeed(path string) ([]byte, error) {
	if path == "" {
		return nil, errGatewayConfiguration
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 128 {
		return nil, errGatewayConfiguration
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errGatewayConfiguration
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(contents) > 128 {
		return nil, errGatewayConfiguration
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(contents)))
	if err != nil || len(seed) != defaultSeedLength {
		return nil, errGatewayConfiguration
	}
	return seed, nil
}

func guardianGatewayConfiguration() ([]byte, error) {
	if os.Getenv(secretSeedEnvironmentVariable) != "" || getBoolEnv(logSecretsEnvironmentVariable, false) ||
		getBoolEnv(gatewayDebugEnvironmentVariable, false) ||
		os.Getenv(targetOriginAllowList) != guardianPIRHost {
		return nil, errGatewayConfiguration
	}
	var rewrites map[string]TargetRewrite
	if json.Unmarshal([]byte(os.Getenv(targetRewritesVariables)), &rewrites) != nil || len(rewrites) != 1 {
		return nil, errGatewayConfiguration
	}
	rewrite, ok := rewrites[guardianPIRHost]
	if !ok || rewrite.Scheme != "http" || rewrite.Host != guardianPIRTarget {
		return nil, errGatewayConfiguration
	}
	return loadGatewaySeed(os.Getenv("SEED_SECRET_FILE"))
}

func boundedHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // The private Docker target must not use ambient HTTP_PROXY.
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.DisableCompression = true
	return &http.Client{Transport: transport, Timeout: 35 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// The issuer's directory/token-key/issue endpoints remain direct HTTPS routes on
// the PIR service. Only encrypted PIR POSTs are forwarded through this gateway.
type GuardianPIRRequestHandler struct {
	client HTTPRequestHandler
	origin string
	target url.URL
}

func (h GuardianPIRRequestHandler) Handle(req *http.Request, metrics Metrics) (*http.Response, error) {
	u := req.URL
	if u == nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Hostname() != h.origin || (u.Port() != "" && u.Port() != "443") || req.Host != u.Host ||
		req.Method != http.MethodPost || (u.Path != "/config" && u.Path != "/key" && u.Path != "/queries") ||
		u.RawPath != "" {
		metrics.Fire(metricsResultTargetRequestForbidden)
		return nil, GatewayTargetForbiddenError
	}
	forwarded := req.Clone(req.Context())
	forwarded.URL.Scheme = h.target.Scheme
	forwarded.URL.Host = h.target.Host
	forwarded.Host = h.origin
	forwarded.Header.Del("Host")
	return h.client.Handle(forwarded, metrics)
}

func boundedResponse(response *http.Response) (*http.Response, error) {
	if response.Body == nil {
		return response, nil
	}
	defer response.Body.Close()
	if response.ContentLength > maxGatewayResponseBytes {
		return nil, GatewayInternalServerError
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxGatewayResponseBytes+1))
	if err != nil || len(body) > maxGatewayResponseBytes {
		return nil, GatewayInternalServerError
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	if response.Header == nil {
		response.Header = make(http.Header)
	}
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return response, nil
}

func guardianMux(target *gatewayResource) *http.ServeMux {
	mux := http.NewServeMux()
	slots := make(chan struct{}, maxGatewayConcurrentRequests)
	mux.HandleFunc(defaultGatewayEndpoint, func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
			target.gatewayHandler(w, r)
		default:
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}
	})
	mux.HandleFunc(defaultConfigEndpoint, target.configHandler)
	mux.HandleFunc(defaultLegacyConfigEndpoint, target.legacyConfigHandler)
	mux.HandleFunc(defaultHealthEndpoint, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	return mux
}

func boundedGatewayServer(address string, handler http.Handler) *http.Server {
	return &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 35 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10}
}
