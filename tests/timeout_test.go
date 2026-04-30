package tests

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptest"
	tls_client "github.com/bogdanfinn/tls-client"
	tls_client_cffi_src "github.com/bogdanfinn/tls-client/cffi_src"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin down the cffi timeout-resolution contract. The motivating
// regression: callers passing TimeoutSeconds=0 / TimeoutMilliseconds=0 expected
// "no deadline" (because the underlying tls_client.WithTimeoutSeconds(0)
// documents 0 as "Unlimited"), but the cffi treated 0 as "field omitted" and
// silently fell through to DefaultTimeoutSeconds (30s). That made it
// impossible to consume long-lived SSE streams without hitting a 30 s reset.
//
// The fix: a negative value means "disable the deadline". 0 still means
// "default" so existing callers keep working.

// startSlowServer returns an httptest server whose handler blocks for `delay`
// before responding 200 OK. Used to provoke client timeouts on demand.
func startSlowServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// doWithTimeoutOption builds a client carrying only the option under test plus
// the bare minimum required by NewHttpClient and runs a GET against url. Returns
// the elapsed duration and the error (if any). Caller is responsible for
// closing the response body when err == nil.
func doWithTimeoutOption(t *testing.T, opt tls_client.HttpClientOption, url string) (time.Duration, error) {
	t.Helper()
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opt)
	require.NoError(t, err, "NewHttpClient")

	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err, "NewRequest")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return elapsed, err
}

// isTimeoutErr returns true if err looks like a client-side deadline-exceeded
// error. Different transports word the message differently.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "context canceled")
}

// -----------------------------------------------------------------------------
// ResolveTimeout: the exact mapping, no network involved.
// -----------------------------------------------------------------------------

func TestResolveTimeout_Mapping(t *testing.T) {
	cases := []struct {
		name    string
		seconds int
		millis  int
		want    time.Duration
	}{
		{"both zero uses the default", 0, 0, time.Duration(tls_client.DefaultTimeoutSeconds) * time.Second},
		{"positive seconds", 5, 0, 5 * time.Second},
		{"positive milliseconds", 0, 1500, 1500 * time.Millisecond},
		{"negative seconds disables", -1, 0, 0},
		{"negative milliseconds disables", 0, -1, 0},
		// Direct Go callers only: CreateClient rejects requests that set both.
		{"negative wins over positive", 1, -1, 0},
		{"milliseconds win over seconds", 60, 100, 100 * time.Millisecond},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, tls_client_cffi_src.ResolveTimeout(c.seconds, c.millis))
		})
	}
}

func TestCreateClient_RejectsBothTimeoutFields(t *testing.T) {
	// Through the cffi exports at most one timeout field can be non-zero; pin
	// that contract, which the Readme and the RequestInput docs rely on.
	_, _, _, err := tls_client_cffi_src.CreateClient(tls_client_cffi_src.RequestInput{
		TLSClientIdentifier: "chrome_150",
		TimeoutSeconds:      -1,
		TimeoutMilliseconds: 5000,
	})
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "both defined timeout")
}

// -----------------------------------------------------------------------------
// ResolveTimeoutOption: the option takes effect on a real client.
// -----------------------------------------------------------------------------

func TestResolveTimeoutOption_PositiveSeconds_AppliesDeadline(t *testing.T) {
	// Server delays 1.5 s, deadline is 1 s → must time out (and not fall back
	// to the 30 s default).
	srv := startSlowServer(t, 1500*time.Millisecond)

	opt := tls_client_cffi_src.ResolveTimeoutOption(1, 0)
	elapsed, err := doWithTimeoutOption(t, opt, srv.URL)

	require.Error(t, err, "expected the 1 s deadline to fire, got success after %v", elapsed)
	assert.True(t, isTimeoutErr(err), "expected timeout-shaped error, got: %v", err)
	assert.Less(t, elapsed, 1400*time.Millisecond, "timeout fired too late: %v", elapsed)
}

func TestResolveTimeoutOption_PositiveMilliseconds_AppliesDeadline(t *testing.T) {
	// Server delays 500 ms, deadline 100 ms → must time out.
	srv := startSlowServer(t, 500*time.Millisecond)

	opt := tls_client_cffi_src.ResolveTimeoutOption(0, 100)
	elapsed, err := doWithTimeoutOption(t, opt, srv.URL)

	require.Error(t, err, "expected timeout, got success after %v", elapsed)
	assert.True(t, isTimeoutErr(err), "expected timeout-shaped error, got: %v", err)
	// Sanity: timeout should fire well before the server would have finished.
	assert.Less(t, elapsed, 400*time.Millisecond, "timeout fired too late: %v", elapsed)
}

func TestResolveTimeoutOption_Negative_DoesNotTimeOut(t *testing.T) {
	// The original bug: a negative value reached WithTimeoutSeconds(-1), a
	// negative deadline, and every request failed immediately with a timeout.
	// TestResolveTimeout_Mapping pins that a negative value maps to 0 (no
	// deadline); here the option must let a slow request complete.
	srv := startSlowServer(t, 300*time.Millisecond)

	for name, fields := range map[string][2]int{"seconds": {-1, 0}, "milliseconds": {0, -1}} {
		t.Run(name, func(t *testing.T) {
			opt := tls_client_cffi_src.ResolveTimeoutOption(fields[0], fields[1])
			elapsed, err := doWithTimeoutOption(t, opt, srv.URL)

			require.NoError(t, err, "expected the request to complete with the deadline disabled, elapsed=%v", elapsed)
			assert.GreaterOrEqual(t, elapsed, 250*time.Millisecond, "request returned suspiciously fast (%v); did the server actually wait?", elapsed)
		})
	}
}
