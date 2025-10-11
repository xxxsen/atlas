package host

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestHostActionPerform(t *testing.T) {
	act, err := createHostAction("host", &config{
		Records: map[string]string{
			"example.com": "1.1.1.1, 2001:4860:4860::8888",
		},
	})
	if err != nil {
		t.Fatalf("createHostAction error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeANY)
	resp, err := act.Perform(context.Background(), req)
	if err != nil {
		t.Fatalf("Perform error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 answers, got %d", len(resp.Answer))
	}
	if resp.Answer[0].Header().Ttl != defaultHostRecordTTL {
		t.Fatalf("unexpected ttl: %d", resp.Answer[0].Header().Ttl)
	}
}

func TestHostActionNoMatch(t *testing.T) {
	act, err := createHostAction("host", &config{
		Records: map[string]string{
			"example.com": "1.1.1.1",
		},
	})
	if err != nil {
		t.Fatalf("createHostAction error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("nomatch.com.", dns.TypeA)
	if _, err := act.Perform(context.Background(), req); err == nil {
		t.Fatalf("expected error when no record matched")
	}
}

func TestHostActionLoadFromFile(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "host-records-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp error: %v", err)
	}
	defer tmpFile.Close()

	fmt.Fprintln(tmpFile, "# comment")
	fmt.Fprintln(tmpFile, "filedomain.com 3.3.3.3 2001:4860:4860::8844")
	fmt.Fprintln(tmpFile, "merge.com 4.4.4.4,5.5.5.5")

	act, err := createHostAction("file", &config{
		Files: []string{tmpFile.Name()},
	})
	if err != nil {
		t.Fatalf("createHostAction error: %v", err)
	}

	req := new(dns.Msg)
	req.SetQuestion("filedomain.com.", dns.TypeANY)
	resp, err := act.Perform(context.Background(), req)
	if err != nil {
		t.Fatalf("Perform error: %v", err)
	}
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 answers from file domain, got %d", len(resp.Answer))
	}

	req2 := new(dns.Msg)
	req2.SetQuestion("merge.com.", dns.TypeA)
	resp2, err := act.Perform(context.Background(), req2)
	if err != nil {
		t.Fatalf("Perform error for merged domain: %v", err)
	}
	if len(resp2.Answer) != 2 {
		t.Fatalf("expected two A answers for merge.com, got %d", len(resp2.Answer))
	}
}
