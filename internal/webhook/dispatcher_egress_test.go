package webhook_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hadesgate/hadesgate/internal/proxy"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

// TestDispatcher_EgressTransportRejectsRedirects proves the webhook client
// refuses to follow a redirect, whose destination escapes address validation.
func TestDispatcher_EgressTransportRejectsRedirects(t *testing.T) {
	upstream := proxy.NewUpstreamDispatcher(proxy.UpstreamConfig{})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	d := webhook.NewDispatcher(webhook.Config{})
	defer d.Close()
	d.SetTransport(upstream.EgressTransport())

	err := d.TestDispatchTarget(redirector.URL, "", webhook.Event{Event: "test_ping"})
	if err == nil {
		t.Fatal("expected the 302 to be reported instead of followed")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("expected a 302 error, got %v", err)
	}
}

// TestDispatcher_UpdateConfigWhileDelivering exercises the hot-reload path
// against in-flight deliveries: UpdateConfig used to rewrite the shared HTTP
// client timeout while workers were reading it through client.Do.
func TestDispatcher_UpdateConfigWhileDelivering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	d := webhook.NewDispatcher(webhook.Config{URL: server.URL, Secret: "s", Events: map[string]bool{"*": true}})
	defer d.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			d.UpdateConfig(webhook.Config{URL: server.URL, Secret: "s", Timeout: time.Duration(2+i%3) * time.Second})
		}
	}()

	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := d.TestDispatchTarget(server.URL, "", webhook.Event{Event: "test_ping"}); err != nil {
					t.Errorf("dispatch failed during reload: %v", err)
					return
				}
			}
		}()
	}

	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
}
