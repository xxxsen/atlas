package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func freeHTTPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func TestPprofServerLifecycleAndRuntimeSnapshot(t *testing.T) {
	address := freeHTTPAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runPprofServer(ctx, address, zap.NewNop(), func() any {
			return map[string]int{"requests": 7}
		})
	}()

	client := &http.Client{Timeout: 200 * time.Millisecond}
	var response *http.Response
	var err error
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		response, err = client.Get("http://" + address + "/debug/atlas")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("debug server did not become ready: %v", err)
	}
	defer response.Body.Close()
	var snapshot map[string]int
	if err := json.NewDecoder(response.Body).Decode(&snapshot); err != nil {
		cancel()
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || snapshot["requests"] != 7 {
		cancel()
		t.Fatalf("unexpected runtime snapshot: status=%d data=%v", response.StatusCode, snapshot)
	}

	for _, path := range []string{"/debug/pprof/", "/debug/vars"} {
		result, err := client.Get("http://" + address + path)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		_ = result.Body.Close()
		if result.StatusCode != http.StatusOK {
			cancel()
			t.Fatalf("%s status=%d", path, result.StatusCode)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pprof shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pprof server did not shut down")
	}
}

func TestPprofBindFailureIsReturned(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	err = runPprofServer(context.Background(), listener.Addr().String(), zap.NewNop())
	if err == nil || !strings.Contains(err.Error(), "listen for pprof") {
		t.Fatalf("expected bind error, got %v", err)
	}
}
