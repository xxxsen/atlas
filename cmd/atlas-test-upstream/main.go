package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/miekg/dns"
)

var counter atomic.Uint32

func main() {
	bind := flag.String("bind", "127.0.0.1:15354", "UDP/TCP bind address")
	flag.Parse()

	handler := dns.HandlerFunc(handleDNS)
	udp := &dns.Server{Addr: *bind, Net: "udp", UDPSize: 4096, Handler: handler}
	tcp := &dns.Server{Addr: *bind, Net: "tcp", Handler: handler}
	errCh := make(chan error, 2)
	go func() { errCh <- udp.ListenAndServe() }()
	go func() { errCh <- tcp.ListenAndServe() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("atlas test upstream listening on %s (UDP/TCP)", *bind)

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("test upstream failed: %v", err)
		}
	}
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
}

func handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	if len(req.Question) != 1 {
		resp.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(resp)
		return
	}

	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if name == "truncated.test." && strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
		resp.Truncated = true
		_ = w.WriteMsg(resp)
		return
	}

	switch name {
	case "example.test.":
		appendAddress(resp, q, net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10"))
	case "truncated.test.":
		appendAddress(resp, q, net.ParseIP("192.0.2.20"), net.ParseIP("2001:db8::20"))
	case "counter.test.":
		n := counter.Add(1)%200 + 1
		appendAddress(resp, q, net.IPv4(192, 0, 2, byte(n)), nil)
	case "large.test.":
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
			for i := 1; i <= 40; i++ {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: rrHeader(q, dns.TypeA),
					A:   net.IPv4(198, 51, 100, byte(i)),
				})
			}
		}
	default:
		resp.Rcode = dns.RcodeNameError
		resp.Ns = append(resp.Ns, &dns.SOA{
			Hdr:     dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 30},
			Ns:      "ns.test.",
			Mbox:    "hostmaster.test.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  300,
			Minttl:  30,
		})
	}

	if strings.HasPrefix(w.RemoteAddr().Network(), "udp") {
		size := uint16(dns.MinMsgSize)
		if opt := req.IsEdns0(); opt != nil && opt.UDPSize() > size {
			size = opt.UDPSize()
		}
		resp.Truncate(int(size))
	}
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("write response for %s failed: %v", q.Name, err)
	}
}

func appendAddress(resp *dns.Msg, q dns.Question, ipv4, ipv6 net.IP) {
	switch q.Qtype {
	case dns.TypeA:
		if ipv4 != nil {
			resp.Answer = append(resp.Answer, &dns.A{Hdr: rrHeader(q, dns.TypeA), A: ipv4.To4()})
		}
	case dns.TypeAAAA:
		if ipv6 != nil {
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: rrHeader(q, dns.TypeAAAA), AAAA: ipv6.To16()})
		}
	case dns.TypeTXT:
		resp.Answer = append(resp.Answer, &dns.TXT{Hdr: rrHeader(q, dns.TypeTXT), Txt: []string{"atlas-dev"}})
	case dns.TypeANY:
		appendAddress(resp, dns.Question{Name: q.Name, Qtype: dns.TypeA, Qclass: q.Qclass}, ipv4, ipv6)
		appendAddress(resp, dns.Question{Name: q.Name, Qtype: dns.TypeAAAA, Qclass: q.Qclass}, ipv4, ipv6)
	default:
		resp.Rcode = dns.RcodeSuccess
	}
}

func rrHeader(q dns.Question, typ uint16) dns.RR_Header {
	return dns.RR_Header{Name: q.Name, Rrtype: typ, Class: q.Qclass, Ttl: 30}
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix(fmt.Sprintf("[%d atlas-upstream] ", os.Getpid()))
}
