package main

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	runtimepprof "runtime/pprof"
	"strings"
	"time"

	"go.uber.org/zap"
)

const defaultPprofBind = "127.0.0.1:6060"

func runPprofServer(ctx context.Context, bind string, logger *zap.Logger, snapshots ...func() any) error {
	address := strings.TrimSpace(bind)
	if address == "" {
		address = defaultPprofBind
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for pprof on %s: %w", address, err)
	}
	mux := newDebugMux(snapshots...)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
	logger.Info("pprof server ready", zap.String("bind", address))

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve pprof: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown pprof: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve pprof during shutdown: %w", err)
		}
		return nil
	}
}

func newDebugMux(snapshots ...func() any) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	for _, profile := range runtimepprof.Profiles() {
		mux.Handle("/debug/pprof/"+profile.Name(), httppprof.Handler(profile.Name()))
	}
	mux.Handle("/debug/vars", expvar.Handler())
	if len(snapshots) > 0 && snapshots[0] != nil {
		mux.HandleFunc("/debug/atlas", func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(writer).Encode(snapshots[0]()); err != nil {
				http.Error(writer, err.Error(), http.StatusInternalServerError)
			}
		})
	}
	return mux
}
