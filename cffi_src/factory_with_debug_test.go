package tls_client_cffi_src

import (
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin down getTlsClient's WithDebug handling. The fix has two
// observable consequences that we cover here:
//
//  1. Logger visibility: when requestInput.WithDebug is true, the constructed
//     tls_client.HttpClient must emit log output (the cffi caller wanted
//     diagnostic output — being silent defeats the flag).
//  2. Session cache: when WithDebug changes on a session, getTlsClient must
//     build a new client (otherwise the cached noop-logger client silently
//     wins and the flag has no effect), keep the session's cookie jar, and
//     reuse that client for following requests with the same WithDebug value.
//
// The test exercises both via the unexported getTlsClient. We trigger a
// well-known logger.Debug call by invoking client.GetCookies(u), which
// always emits "get cookies for url: ..." through c.logger.Debug, and we
// capture stdout to verify presence/absence.

// captureStdout swaps os.Stdout for an OS pipe, runs fn, restores stdout,
// and returns everything fn wrote to stdout. Multiple fmt.Printf calls
// inside fn are captured in order. The pipe is fully drained on a separate
// goroutine so a chatty fn can't deadlock by filling the pipe buffer.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	require.NoError(t, err, "os.Pipe")

	origStdout := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	var (
		mu      sync.Mutex
		readBuf strings.Builder
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				mu.Lock()
				readBuf.Write(buf[:n])
				mu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()

	fn()

	// Closing the writer ends the reader goroutine.
	_ = w.Close()
	<-done
	_ = r.Close()

	mu.Lock()
	defer mu.Unlock()
	return readBuf.String()
}

func cookiesUrl(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://example.test/with-debug-test")
	require.NoError(t, err)
	return u
}

// triggerLoggerCall hits a code path that calls c.logger.Debug — namely
// HttpClient.GetCookies, which logs "get cookies for url: %s". The actual
// returned cookies don't matter; we only care that the logger fired.
func triggerLoggerCall(t *testing.T, withDebug bool, sessionId string) string {
	t.Helper()

	input := RequestInput{
		TLSClientIdentifier: "chrome_124",
		WithDebug:           withDebug,
		FollowRedirects:     true,
		// Disable the cookie jar so we don't pull in network-style setup;
		// GetCookies still runs through c.logger.Debug.
		WithoutCookieJar: true,
	}

	withSession := sessionId != ""
	return captureStdout(t, func() {
		client, err := getTlsClient(input, sessionId, withSession)
		require.NoError(t, err, "getTlsClient")
		require.NotNil(t, client, "client must not be nil")

		// Drives c.logger.Debug("get cookies for url: ...")
		client.GetCookies(cookiesUrl(t))
	})
}

func TestGetTlsClient_WithDebugFalse_IsSilent(t *testing.T) {
	ClearSessionCache()

	out := triggerLoggerCall(t, false, "")
	assert.Empty(t, strings.TrimSpace(out), "WithDebug=false must not print to stdout; got %q", out)
}

func TestGetTlsClient_WithDebugTrue_EmitsDebugOutput(t *testing.T) {
	ClearSessionCache()

	out := triggerLoggerCall(t, true, "")
	// The exact message is fragile to upstream wording; assert on a stable
	// substring that uniquely identifies the GetCookies debug log.
	assert.Contains(t, out, "get cookies for url",
		"WithDebug=true must surface c.logger.Debug output; got %q", out)
}

func TestGetTlsClient_WithDebugTrue_AlsoEmitsWarnOutput(t *testing.T) {
	// The fix's primary intent: not just Debug-level, but Info / Warn /
	// Error must also reach stdout. With a noop inner logger (the previous
	// behaviour) the wrapper's Warn forwarded into a no-op and dropped.
	// GetCookies on a no-jar client emits "you did not setup a cookie jar"
	// at Warn level — perfect probe.
	ClearSessionCache()

	out := triggerLoggerCall(t, true, "")
	assert.Contains(t, out, "you did not setup a cookie jar",
		"WithDebug=true must surface c.logger.Warn output (not just Debug); got %q", out)
}

func TestGetTlsClient_WithDebug_RebuildsCachedNoopClient(t *testing.T) {
	// Regression: a sessionId first registered with WithDebug=false caches its
	// noop client. A later call with WithDebug=true on the same sessionId must
	// not silently reuse that client, otherwise the flag would be unobservable.
	ClearSessionCache()

	const sessionId = "rebuild-test"

	// 1) Prime the cache with a non-debug client.
	silent := triggerLoggerCall(t, false, sessionId)
	require.Empty(t, strings.TrimSpace(silent), "non-debug priming call should be silent; got %q", silent)

	// 2) Re-enter with WithDebug=true on the SAME sessionId.
	loud := triggerLoggerCall(t, true, sessionId)
	assert.Contains(t, loud, "get cookies for url",
		"WithDebug=true on a previously-cached session must rebuild the client and emit debug output; got %q", loud)
}

// sessionInput returns a RequestInput for a session with a cookie jar.
func sessionInput(withDebug bool) RequestInput {
	return RequestInput{
		TLSClientIdentifier: "chrome_150",
		WithDebug:           withDebug,
		FollowRedirects:     true,
	}
}

func getSessionClient(t *testing.T, sessionId string, withDebug bool) tls_client.HttpClient {
	t.Helper()
	var client tls_client.HttpClient
	captureStdout(t, func() {
		var err error
		client, err = getTlsClient(sessionInput(withDebug), sessionId, true)
		require.NoError(t, err, "getTlsClient")
	})
	return client
}

func TestGetTlsClient_WithDebugSwitch_KeepsSessionCookiesAndReusesClient(t *testing.T) {
	// The rebuild for a WithDebug change must not lose the session state: the
	// cookies stay, and as long as WithDebug does not change again the session
	// keeps using one client (no rebuild per request).
	ClearSessionCache()
	t.Cleanup(ClearSessionCache)

	const sessionId = "debug-switch-test"
	u := cookiesUrl(t)

	plain := getSessionClient(t, sessionId, false)
	plain.SetCookies(u, []*http.Cookie{{Name: "sid", Value: "abc"}})

	debug1 := getSessionClient(t, sessionId, true)
	assert.NotSame(t, plain, debug1, "switching WithDebug on must build a new client")
	assert.Same(t, plain.GetCookieJar(), debug1.GetCookieJar(), "the rebuilt client must keep the session's cookie jar")

	debug2 := getSessionClient(t, sessionId, true)
	assert.Same(t, debug1, debug2, "a second WithDebug=true request must reuse the cached debug client")

	plainAgain := getSessionClient(t, sessionId, false)
	assert.NotSame(t, debug2, plainAgain, "switching WithDebug off must build a new client")

	var names []string
	captureStdout(t, func() {
		for _, c := range plainAgain.GetCookies(u) {
			names = append(names, c.Name+"="+c.Value)
		}
	})
	assert.Equal(t, []string{"sid=abc"}, names, "cookies must survive both WithDebug switches")

	silent := captureStdout(t, func() { plainAgain.GetCookies(u) })
	assert.Empty(t, strings.TrimSpace(silent), "after switching WithDebug off the session client must be silent; got %q", silent)
}
