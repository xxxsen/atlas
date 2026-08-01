package resolver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xxxsen/atlas/internal/resolver/model"
)

type stubDNSResolver struct {
	err error
}

var registerStubResolver sync.Once

func (s *stubDNSResolver) Name() string { return "stub" }
func (s *stubDNSResolver) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if s.err != nil {
		return nil, s.err
	}
	msg := new(dns.Msg)
	msg.SetReply(req)
	return msg, nil
}

func TestRegisterAndMakeResolver(t *testing.T) {
	registerStubResolver.Do(func() {
		Register("stub", func(schema string, host string, params *model.Params) (IDNSResolver, error) {
			return &stubDNSResolver{}, nil
		})
	})

	r, err := MakeResolver("stub://resolver")
	if err != nil {
		t.Fatalf("MakeResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := r.Query(context.Background(), req); err != nil {
		t.Fatalf("Query error: %v", err)
	}
}

func TestGroupResolver(t *testing.T) {
	success := &stubDNSResolver{}
	fail := &stubDNSResolver{err: errors.New("failure")}

	group, err := NewGroupResolver("a", []IDNSResolver{fail, success}, 2)
	if err != nil {
		t.Fatalf("NewGroupResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := group.Query(context.Background(), req); err != nil {
		t.Fatalf("group.Query error: %v", err)
	}

	groupFail, err := NewGroupResolver("a", []IDNSResolver{fail}, 1)
	if err != nil {
		t.Fatalf("NewGroupResolver error: %v", err)
	}
	if _, err := groupFail.Query(context.Background(), req); err == nil {
		t.Fatalf("expected group resolver failure")
	}
}

type countingResolver struct {
	response *dns.Msg
	err      error
	calls    atomic.Int64
}

func (r *countingResolver) Name() string { return "counting" }
func (r *countingResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.calls.Add(1)
	if r.err != nil {
		return nil, r.err
	}
	if r.response != nil {
		msg := r.response.Copy()
		msg.Id = req.Id
		msg.Question = append([]dns.Question(nil), req.Question...)
		return msg, nil
	}
	msg := new(dns.Msg)
	msg.SetReply(req)
	return msg, nil
}

func TestGroupResolverFallsBackBeyondParallelWindow(t *testing.T) {
	failOne := &countingResolver{err: errors.New("one failed")}
	failTwo := &countingResolver{err: errors.New("two failed")}
	success := &countingResolver{}
	group, err := NewGroupResolver("fallback", []IDNSResolver{failOne, failTwo, success}, 1)
	if err != nil {
		t.Fatalf("NewGroupResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := group.Query(context.Background(), req); err != nil {
		t.Fatalf("group.Query should reach the healthy resolver: %v", err)
	}
	if failOne.calls.Load() != 1 || failTwo.calls.Load() != 1 || success.calls.Load() != 1 {
		t.Fatalf("expected all three resolvers to be attempted once, got %d/%d/%d", failOne.calls.Load(), failTwo.calls.Load(), success.calls.Load())
	}
}

func TestGroupResolverRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewGroupResolver("empty", nil, 1); err == nil {
		t.Fatal("expected empty resolver list to fail")
	}
	if _, err := NewGroupResolver("zero", []IDNSResolver{&stubDNSResolver{}}, 0); err == nil {
		t.Fatal("expected zero concurrency to fail")
	}
	if _, err := NewGroupResolver("large", []IDNSResolver{&stubDNSResolver{}}, 2); err == nil {
		t.Fatal("expected excessive concurrency to fail")
	}
	if _, err := NewGroupResolver("nil", []IDNSResolver{nil}, 1); err == nil {
		t.Fatal("expected nil child to fail")
	}
}

func TestGroupResolverRetriesServfail(t *testing.T) {
	servfailMsg := new(dns.Msg)
	servfailMsg.Response = true
	servfailMsg.Rcode = dns.RcodeServerFailure
	servfail := &countingResolver{response: servfailMsg}
	success := &countingResolver{}
	group, err := NewGroupResolver("rcode", []IDNSResolver{servfail, success}, 1)
	if err != nil {
		t.Fatalf("NewGroupResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	if _, err := group.Query(context.Background(), req); err != nil {
		t.Fatalf("expected fallback after SERVFAIL: %v", err)
	}
	if servfail.calls.Load() != 1 || success.calls.Load() != 1 {
		t.Fatalf("expected SERVFAIL and fallback resolver to run once")
	}
}

type invalidResponseResolver struct{}

func (*invalidResponseResolver) Name() string { return "invalid-response" }
func (*invalidResponseResolver) Query(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.Id = request.Id
	response.Question = append([]dns.Question(nil), request.Question...)
	return response, nil
}

func TestGroupResolverSkipsProtocolInvalidResponse(t *testing.T) {
	healthy := &countingResolver{}
	group, err := NewGroupResolver("validation", []IDNSResolver{&invalidResponseResolver{}, healthy}, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("validation.test.", dns.TypeA)
	if _, err := group.Query(context.Background(), request); err != nil {
		t.Fatalf("group did not fall back after an invalid response: %v", err)
	}
	if healthy.calls.Load() != 1 {
		t.Fatal("healthy fallback was not queried")
	}
}

type cancellationResolver struct {
	canceled chan struct{}
	once     sync.Once
}

func (*cancellationResolver) Name() string { return "wait-for-cancel" }
func (r *cancellationResolver) Query(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	<-ctx.Done()
	r.once.Do(func() { close(r.canceled) })
	return nil, ctx.Err()
}

func TestGroupResolverCancelsLosingAttemptAndRejectsAfterClose(t *testing.T) {
	loser := &cancellationResolver{canceled: make(chan struct{})}
	group, err := NewGroupResolver("winner", []IDNSResolver{&stubDNSResolver{}, loser}, 2)
	if err != nil {
		t.Fatal(err)
	}
	request := new(dns.Msg)
	request.SetQuestion("winner.test.", dns.TypeA)
	if _, err := group.Query(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-loser.canceled:
	case <-time.After(time.Second):
		t.Fatal("losing resolver was not canceled")
	}
	if err := group.(ResolverCloser).Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := group.Query(context.Background(), request); err == nil {
		t.Fatal("closed group accepted a query")
	}
}

type synchronizedPackingResolver struct {
	ready *sync.WaitGroup
	start <-chan struct{}
}

type inflightGateResolver struct {
	calls   atomic.Int64
	entered chan struct{}
	release chan struct{}
}

func (r *inflightGateResolver) Name() string { return "inflight-gate" }
func (r *inflightGateResolver) Query(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
	if r.calls.Add(1) == 1 {
		close(r.entered)
	}
	<-r.release
	response := new(dns.Msg)
	response.SetReply(request)
	return response, nil
}

func TestLimitedResolverBoundsUpstreamConcurrency(t *testing.T) {
	base := &inflightGateResolver{entered: make(chan struct{}), release: make(chan struct{})}
	item := newLimitedResolver(base, 1)
	request := new(dns.Msg)
	request.SetQuestion("bounded.test.", dns.TypeA)
	firstDone := make(chan error, 1)
	go func() {
		_, err := item.Query(context.Background(), request.Copy())
		firstDone <- err
	}()
	select {
	case <-base.entered:
	case <-time.After(time.Second):
		t.Fatal("first resolver query did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := item.Query(ctx, request.Copy()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("queued resolver query should honor context, got %v", err)
	}
	if base.calls.Load() != 1 {
		t.Fatalf("upstream limit was exceeded: calls=%d", base.calls.Load())
	}
	close(base.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestLimitedResolverCloseUnblocksQueuedQueries(t *testing.T) {
	base := &inflightGateResolver{entered: make(chan struct{}), release: make(chan struct{})}
	item := newLimitedResolver(base, 1)
	request := new(dns.Msg)
	request.SetQuestion("close-bounded.test.", dns.TypeA)
	firstDone := make(chan error, 1)
	go func() {
		_, err := item.Query(context.Background(), request.Copy())
		firstDone <- err
	}()
	select {
	case <-base.entered:
	case <-time.After(time.Second):
		t.Fatal("first resolver query did not start")
	}
	queued := make(chan error, 1)
	go func() {
		_, err := item.Query(context.Background(), request.Copy())
		queued <- err
	}()
	if err := item.(ResolverCloser).Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-queued:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("queued query returned %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queued query was not released by Close")
	}
	if _, err := item.Query(context.Background(), request.Copy()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed resolver accepted a query: %v", err)
	}
	close(base.release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func (r *synchronizedPackingResolver) Name() string { return "packer" }
func (r *synchronizedPackingResolver) Query(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	r.ready.Done()
	<-r.start
	for i := 0; i < 100; i++ {
		if _, err := req.Pack(); err != nil {
			return nil, err
		}
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	return resp, nil
}

func TestGroupResolverIsolatesEDNSRequests(t *testing.T) {
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	children := []IDNSResolver{
		&synchronizedPackingResolver{ready: &ready, start: start},
		&synchronizedPackingResolver{ready: &ready, start: start},
	}
	group, err := NewGroupResolver("race", children, 2)
	if err != nil {
		t.Fatalf("NewGroupResolver error: %v", err)
	}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, true)
	done := make(chan error, 1)
	go func() {
		_, err := group.Query(context.Background(), req)
		done <- err
	}()
	ready.Wait()
	close(start)
	if err := <-done; err != nil {
		t.Fatalf("group.Query error: %v", err)
	}
}
