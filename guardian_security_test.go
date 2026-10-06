// Copyright (c) 2026 Cloudflare, Inc. and Chapchu contributors.
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chris-wood/ohttp-go"
	"github.com/cloudflare/circl/hpke"
)

func guardianTestGateway(t *testing.T, backend string, client *http.Client) *gatewayResource {
	t.Helper()
	targetURL, err := url.Parse(backend)
	if err != nil {
		t.Fatal(err)
	}
	gateway := createGateway(t)
	return &gatewayResource{legacyKeyID: LEGACY_KEY_ID, gateway: gateway,
		metricsFactory: &MockMetricsFactory{},
		encapsulationHandlers: map[string]EncapsulationHandler{defaultGatewayEndpoint: DefaultEncapsulationHandler{
			gateway: gateway, appHandler: BinaryHTTPAppHandler{httpHandler: GuardianPIRRequestHandler{
				client: HTTPClientRequestHandler{client: client}, origin: guardianPIRHost, target: *targetURL,
			}},
		}},
	}
}

// Exercise the production mux and handler through real client encryption and
// response decryption, including authorization forwarded to the private target.
func guardianEncryptedRequest(t *testing.T, target *gatewayResource, inner *http.Request, keyID uint8) *http.Response {
	t.Helper()
	config, err := target.gateway.Config(keyID)
	if err != nil {
		t.Fatal(err)
	}
	// This upstream client's serializer takes URL.Path literally. Preserve the
	// original wire request-target (including escaped path/query) in these tests.
	wire := inner.Clone(inner.Context())
	wire.URL.Path = inner.URL.RequestURI()
	binary := ohttp.BinaryRequest(*wire)
	message, err := binary.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	request, context, err := ohttp.NewDefaultClient(config).EncapsulateRequest(message)
	if err != nil {
		t.Fatal(err)
	}
	outer := httptest.NewRequest(http.MethodPost, defaultGatewayEndpoint, bytes.NewReader(request.Marshal()))
	outer.Header.Set("Content-Type", ohttpRequestContentType)
	recorder := httptest.NewRecorder()
	guardianMux(target).ServeHTTP(recorder, outer)
	if recorder.Code != http.StatusOK {
		t.Fatalf("outer status %d", recorder.Code)
	}
	encapsulated, err := ohttp.UnmarshalEncapsulatedResponse(recorder.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := context.DecapsulateResponse(encapsulated)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ohttp.UnmarshalBinaryResponse(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

func TestGuardianOHTTPPrivateTargetRoundTrip(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != guardianPIRHost || r.Method != http.MethodPost || r.Header.Get("Authorization") != "PrivateToken test-only" {
			t.Error("target did not receive required origin, method, or authorization")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != "encrypted-pir-query" {
			t.Error("target payload changed")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, "encrypted-pir-response")
	}))
	defer backend.Close()
	target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
	for _, keyID := range []uint8{LEGACY_KEY_ID, CURRENT_KEY_ID} {
		for _, path := range []string{"/config", "/key", "/queries"} {
			t.Run(fmt.Sprintf("%d%s", keyID, path), func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+path, strings.NewReader("encrypted-pir-query"))
				req.Header.Set("Authorization", "PrivateToken test-only")
				response := guardianEncryptedRequest(t, target, req, keyID)
				body, _ := io.ReadAll(response.Body)
				if response.StatusCode != 200 || string(body) != "encrypted-pir-response" {
					t.Fatal("encrypted roundtrip failed")
				}
			})
		}
	}
}

func TestGuardianOHTTPRejectsUnapprovedTargets(t *testing.T) {
	var calls atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer backend.Close()
	target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
	for _, address := range []string{
		"https://other.example/config", "http://" + guardianPIRHost + "/config",
		"https://" + guardianPIRHost + ":8443/config", "https://" + guardianPIRHost + "/issue",
		"https://" + guardianPIRHost + "/.well-known/private-token-issuer-directory",
		"https://" + guardianPIRHost + "/token-key-for-user-token", "https://" + guardianPIRHost + "/config?x=1",
		"https://" + guardianPIRHost + "/%63onfig", "https://" + guardianPIRHost + "/config/",
	} {
		t.Run(address, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, address, nil)
			if response := guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID); response.StatusCode != 403 {
				t.Fatalf("forbidden target yielded %d", response.StatusCode)
			}
		})
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+guardianPIRHost+"/queries", nil)
	if guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID).StatusCode != 403 {
		t.Fatal("GET reached target")
	}
	if calls.Load() != 0 {
		t.Fatal("a rejected target reached the backend")
	}
}

func TestGuardianOHTTPDoesNotFollowRedirect(t *testing.T) {
	var redirected atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer trap.Close()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, trap.URL, http.StatusTemporaryRedirect)
	}))
	defer backend.Close()
	target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
	req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+"/config", nil)
	response := guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID)
	if response.StatusCode != 307 || redirected.Load() != 0 {
		t.Fatal("gateway followed a target redirect")
	}
}

func TestGuardianOHTTPBoundsStreamedResponses(t *testing.T) {
	for _, knownLength := range []bool{true, false} {
		t.Run(fmt.Sprint(knownLength), func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if knownLength {
					w.Header().Set("Content-Length", fmt.Sprint(maxGatewayResponseBytes+1))
				} else {
					w.(http.Flusher).Flush()
				}
				chunk := bytes.Repeat([]byte{'x'}, 1<<16)
				for count := 0; count < maxGatewayResponseBytes+1; count += len(chunk) {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
			}))
			defer backend.Close()
			target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
			req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+"/queries", nil)
			response := guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID)
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != 500 || len(body) > 1024 {
				t.Fatal("unbounded response escaped encrypted error handling")
			}
		})
	}
}

func TestGuardianOHTTPTimeout(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer backend.Close()
	client := boundedHTTPClient()
	client.Timeout = 50 * time.Millisecond
	target := guardianTestGateway(t, backend.URL, client)
	req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+"/queries", nil)
	started := time.Now()
	if guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID).StatusCode != 500 {
		t.Fatal("timeout did not fail closed")
	}
	if time.Since(started) > 3*time.Second {
		t.Fatal("target request exceeded timeout")
	}
}

func TestGuardianRequestLimitAndPublicRoutes(t *testing.T) {
	target := guardianTestGateway(t, "http://127.0.0.1:1", boundedHTTPClient())
	req := httptest.NewRequest(http.MethodPost, defaultGatewayEndpoint, bytes.NewReader(make([]byte, maxGatewayRequestBytes+1)))
	req.Header.Set("Content-Type", ohttpRequestContentType)
	recorder := httptest.NewRecorder()
	guardianMux(target).ServeHTTP(recorder, req)
	if recorder.Code != 413 {
		t.Fatalf("oversized request status %d", recorder.Code)
	}
	for _, path := range []string{"/", defaultEchoEndpoint, defaultMetadataEndpoint, "/issue", "/config", "/gateway/child"} {
		recorder := httptest.NewRecorder()
		guardianMux(target).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != 404 {
			t.Fatalf("unexpected exposed route %s: %d", path, recorder.Code)
		}
	}
	for _, path := range []string{defaultConfigEndpoint, defaultLegacyConfigEndpoint, defaultHealthEndpoint} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			recorder := httptest.NewRecorder()
			guardianMux(target).ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
			expected := 200
			if method != http.MethodGet {
				expected = 405
			}
			if recorder.Code != expected {
				t.Fatalf("%s %s: %d", method, path, recorder.Code)
			}
		}
	}
}

func TestGuardianSeedFileAndStableKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seed")
	encoded := strings.Repeat("a1", 32)
	if err := os.WriteFile(path, []byte(encoded+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, err := loadGatewaySeed(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadGatewaySeed(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("seed changed between restarts")
	}
	a, _ := ohttp.NewConfigFromSeed(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM, first)
	b, _ := ohttp.NewConfigFromSeed(1, hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM, second)
	if !bytes.Equal(a.Config().Marshal(), b.Config().Marshal()) {
		t.Fatal("cached gateway key invalid after restart")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{"", dir, filepath.Join(dir, "missing"), link} {
		if _, err := loadGatewaySeed(candidate); err != errGatewayConfiguration {
			t.Fatal("unsafe seed path accepted")
		}
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadGatewaySeed(path); err != errGatewayConfiguration {
		t.Fatal("readable seed accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, contents := range []string{"not-a-seed", hex.EncodeToString(first[:31]), strings.Repeat("f", 129)} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadGatewaySeed(path); err != errGatewayConfiguration || strings.Contains(err.Error(), contents) {
			t.Fatal("bad seed accepted or revealed")
		}
	}
}

func TestGuardianRequiresFixedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seed")
	if err := os.WriteFile(path, []byte(strings.Repeat("12", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SEED_SECRET_FILE", path)
	t.Setenv(secretSeedEnvironmentVariable, "")
	t.Setenv(logSecretsEnvironmentVariable, "false")
	t.Setenv(gatewayDebugEnvironmentVariable, "false")
	t.Setenv(targetOriginAllowList, guardianPIRHost)
	t.Setenv(targetRewritesVariables, `{"`+guardianPIRHost+`":{"Scheme":"http","Host":"pir:8082"}}`)
	if _, err := guardianGatewayConfiguration(); err != nil {
		t.Fatal("valid private target configuration rejected")
	}
	for _, invalid := range [][2]string{
		{secretSeedEnvironmentVariable, "do-not-log"}, {logSecretsEnvironmentVariable, "true"},
		{gatewayDebugEnvironmentVariable, "true"}, {targetOriginAllowList, ""},
		{targetOriginAllowList, guardianPIRHost + ",other.example"}, {targetRewritesVariables, "{}"},
		{targetRewritesVariables, `{"` + guardianPIRHost + `":{"Scheme":"http","Host":"other:8082"}}`},
	} {
		t.Run(invalid[0]+invalid[1], func(t *testing.T) {
			t.Setenv(invalid[0], invalid[1])
			if _, err := guardianGatewayConfiguration(); err != errGatewayConfiguration {
				t.Fatal("unsafe gateway configuration accepted")
			}
		})
	}
}

// Hold actual encrypted requests in the backend: a third outer request must be
// refused before any body read, then released capacity must accept another key.
type guardianUntouchedReader struct{ read bool }

func (r *guardianUntouchedReader) Read(_ []byte) (int, error) { r.read = true; return 0, io.EOF }
func TestGuardianConcurrentRequestLimit(t *testing.T) {
	entered := make(chan struct{}, maxGatewayConcurrentRequests)
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		_, _ = io.WriteString(w, "done")
	}))
	defer backend.Close()
	target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
	// MockMetricsFactory deliberately tracks mutable assertions in old tests;
	// use the real no-op statsd metrics for concurrent requests instead.
	stats, err := createStatsDClient("", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()
	target.metricsFactory = &StatsDMetricsFactory{client: stats, metricsName: "test", serviceName: "test"}
	handler := guardianMux(target)
	results := make(chan int, maxGatewayConcurrentRequests)
	config, _ := target.gateway.Config(CURRENT_KEY_ID)
	for i := 0; i < maxGatewayConcurrentRequests; i++ {
		req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+"/queries", nil)
		binary := ohttp.BinaryRequest(*req)
		payload, _ := binary.Marshal()
		encrypted, _, err := ohttp.NewDefaultClient(config).EncapsulateRequest(payload)
		if err != nil {
			t.Fatal(err)
		}
		go func(body []byte) {
			outer := httptest.NewRequest(http.MethodPost, defaultGatewayEndpoint, bytes.NewReader(body))
			outer.Header.Set("Content-Type", ohttpRequestContentType)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, outer)
			results <- recorder.Code
		}(encrypted.Marshal())
	}
	for i := 0; i < maxGatewayConcurrentRequests; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(release)
			t.Fatal("request did not reach target")
		}
	}
	reader := &guardianUntouchedReader{}
	rejected := httptest.NewRequest(http.MethodPost, defaultGatewayEndpoint, reader)
	rejected.Header.Set("Content-Type", ohttpRequestContentType)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, rejected)
	if recorder.Code != 503 || reader.read {
		close(release)
		t.Fatal("excess request was queued or read")
	}
	// Health checks stay available during expensive encrypted operations.
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, defaultHealthEndpoint, nil))
	if health.Code != 200 {
		close(release)
		t.Fatal("health was concurrency limited")
	}
	close(release)
	for i := 0; i < maxGatewayConcurrentRequests; i++ {
		if <-results != 200 {
			t.Fatal("in-flight request failed")
		}
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, defaultGatewayEndpoint, nil))
	if recorder.Code == 503 {
		t.Fatal("capacity was not released")
	}
}

func TestGuardianOHTTPTenMiBKeyUpload(t *testing.T) {
	const keyBytes = 10 << 20
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size, err := io.Copy(io.Discard, r.Body)
		if err != nil || size != keyBytes {
			t.Error("PIR key body lost bytes")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	target := guardianTestGateway(t, backend.URL, boundedHTTPClient())
	req, _ := http.NewRequest(http.MethodPost, "https://"+guardianPIRHost+"/key", bytes.NewReader(make([]byte, keyBytes)))
	response := guardianEncryptedRequest(t, target, req, CURRENT_KEY_ID)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("valid PIR key upload status %d", response.StatusCode)
	}
}
