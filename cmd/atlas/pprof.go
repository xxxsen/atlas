package main

import (
	"context"
	"net/http"
	"strings"

	_ "net/http/pprof"

	"go.uber.org/zap"
)

const defaultPprofBind = ":6060"

func startPprofServer(ctx context.Context, bind string, logkit *zap.Logger) {
	addr := strings.TrimSpace(bind)
	if addr == "" {
		addr = defaultPprofBind
	}

	go func() {
		// pprof 服务器，将暴露在 6060 端口
		if err := http.ListenAndServe(addr, nil); err != nil {
			panic(err)
		}
	}()
	logkit.Debug("start pprof server", zap.String("bind", addr))
}
