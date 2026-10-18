package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/bootstrap"
	"github.com/xxxsen/atlas/internal/hosts"
	"github.com/xxxsen/atlas/internal/resolver"
)

func TestServerSignedBootstrapWithRealUpstream(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Second)
	makeWire := func(version int64, ip string) string {
		value, err := bootstrap.Sign(private, bootstrap.Record{Domain: "disk.sendev.cc", IssuedAt: version, ExpiresAt: now.Add(time.Hour).UnixMilli(), A: []string{ip}})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	good := makeWire(now.UnixMilli(), "1.2.3.4")
	rollback := makeWire(now.UnixMilli()-1, "2.3.4.5")
	newer := makeWire(now.UnixMilli()+1, "3.4.5.6")
	var stage, upstreamCalls atomic.Int64
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metadata := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		upstreamCalls.Add(1)
		if req.Question[0].Name != "_atlas.disk.sendev.cc." || req.Question[0].Qtype != dns.TypeTXT {
			t.Errorf("unexpected bootstrap query: %v", req.Question)
		}
		wire := good
		switch stage.Load() {
		case 1:
			wire = "2.3.4.5"
		case 2:
			wire = rollback
		case 3:
			wire = newer
		}
		var parts []string
		for len(wire) > 255 {
			parts = append(parts, wire[:255])
			wire = wire[255:]
		}
		parts = append(parts, wire)
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0}, Txt: parts}}
		if err := w.WriteMsg(msg); err != nil {
			t.Errorf("write metadata: %v", err)
		}
	})}
	ready := make(chan struct{})
	metadata.NotifyStartedFunc = func() { close(ready) }
	done := make(chan error, 1)
	go func() { done <- metadata.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := metadata.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	dir := t.TempDir()
	publicPath, domainsPath := filepath.Join(dir, "bootstrap.pub"), filepath.Join(dir, "domains.txt")
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(domainsPath, []byte("disk.sendev.cc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := bootstrap.New(context.Background(), bootstrap.Config{ServerList: []string{"udp://" + packet.LocalAddr().String()}, Files: []string{domainsPath}, PublicKeys: []string{publicPath}}, bootstrap.Options{Cache: resolver.CacheOptions{Size: 10}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	store, err := hosts.New(map[string]string{"local.test": "192.168.50.187"})
	if err != nil {
		t.Fatal(err)
	}
	var ordinaryCalls atomic.Int64
	engine := engineFunc(func(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
		ordinaryCalls.Add(1)
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("2.3.4.5").To4()}}
		return msg, nil
	})
	running := startTestServer(t, engine, WithBootstrapResolver(manager), WithHostResolver(store))
	request := new(dns.Msg)
	request.SetQuestion("disk.sendev.cc.", dns.TypeA)
	for _, network := range []string{"udp", "tcp"} {
		msg := exchange(t, network, running.bind, request)
		if msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "1.2.3.4" {
			t.Fatalf("verified bootstrap not returned over %s: %v", network, msg)
		}
	}
	for _, current := range []int64{1, 2} {
		stage.Store(current)
		msg := exchange(t, "udp", running.bind, request)
		if msg.Rcode != dns.RcodeServerFailure || len(msg.Answer) != 0 {
			t.Fatalf("invalid record or rollback must fail closed, stage=%d: %v", current, msg)
		}
	}
	stage.Store(3)
	if msg := exchange(t, "udp", running.bind, request); len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "3.4.5.6" {
		t.Fatalf("new signed migration was not accepted: %v", msg)
	}
	request.SetQuestion("disk.sendev.cc.", dns.TypeAAAA)
	if msg := exchange(t, "tcp", running.bind, request); msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		t.Fatalf("unsigned missing family must be NODATA: %v", msg)
	}
	before := upstreamCalls.Load()
	request.SetQuestion("disk.sendev.cc.", dns.TypeHTTPS)
	if msg := exchange(t, "udp", running.bind, request); msg.Rcode != dns.RcodeSuccess || len(msg.Answer) != 0 {
		t.Fatalf("protected HTTPS query escaped: %v", msg)
	}
	if upstreamCalls.Load() != before || ordinaryCalls.Load() != 0 {
		t.Fatal("protected names fell through to an ordinary resolver")
	}
	request.SetQuestion("local.test.", dns.TypeA)
	if msg := exchange(t, "udp", running.bind, request); len(msg.Answer) != 1 || msg.Answer[0].(*dns.A).A.String() != "192.168.50.187" {
		t.Fatalf("hosts stopped working: %v", msg)
	}
	request.SetQuestion("ordinary.test.", dns.TypeA)
	if msg := exchange(t, "udp", running.bind, request); len(msg.Answer) != 1 || ordinaryCalls.Load() != 1 {
		t.Fatalf("ordinary rule dispatch stopped working: %v", msg)
	}
}
