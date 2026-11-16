package tls_client_cffi_src

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/fhttp/http2/hpack"
	tls_client "github.com/bogdanfinn/tls-client"
)

const (
	msgPeerReset     = "reset by remote peer (RST_STREAM"
	msgAmbiguous     = "either the remote peer sent RST_STREAM, or the local transport rejected a malformed frame"
	msgLocalAbort    = "aborted by the local transport"
	msgGoAwayConnEnd = "connection closed by remote peer after GOAWAY"
)

func assertContainsAll(t *testing.T, msg string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(msg, want) {
			t.Errorf("message should contain %q, got: %q", want, msg)
		}
	}
}

func assertContainsNone(t *testing.T, msg string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if strings.Contains(msg, u) {
			t.Errorf("message should not contain %q, got: %q", u, msg)
		}
	}
}

// -----------------------------------------------------------------------------
// Unit tests: classification of hand-built errors.
// -----------------------------------------------------------------------------

func TestDescribeStreamReadError(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if got := describeStreamReadError(nil); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("cause-less INTERNAL_ERROR is a remote reset", func(t *testing.T) {
		// The error observed in a downstream proxy.
		orig := http2.StreamError{StreamID: 2985, Code: http2.ErrCodeInternal}
		got := describeStreamReadError(orig)
		msg := got.Error()

		assertContainsAll(t, msg, msgPeerReset, "INTERNAL_ERROR 0x2", orig.Error())
		assertContainsNone(t, msg, msgLocalAbort, msgAmbiguous)
		if !strings.HasSuffix(msg, orig.Error()) {
			t.Errorf("original error text should stay at the end, got: %q", msg)
		}

		var se http2.StreamError
		if !errors.As(got, &se) || se.Code != http2.ErrCodeInternal || se.StreamID != 2985 {
			t.Errorf("wrapped StreamError should stay recoverable via errors.As, got: %v", got)
		}
	})

	t.Run("cause-less CANCEL is a remote reset", func(t *testing.T) {
		msg := describeStreamReadError(http2.StreamError{StreamID: 5, Code: http2.ErrCodeCancel}).Error()
		assertContainsAll(t, msg, msgPeerReset, "CANCEL 0x8")
	})

	t.Run("cause-less PROTOCOL_ERROR is reported as ambiguous", func(t *testing.T) {
		// fhttp builds exactly this both for a peer RST_STREAM(PROTOCOL_ERROR)
		// and for protocol violations it detects itself.
		msg := describeStreamReadError(http2.StreamError{StreamID: 9, Code: http2.ErrCodeProtocol}).Error()
		assertContainsAll(t, msg, msgAmbiguous, "stream ID 9; PROTOCOL_ERROR")
		assertContainsNone(t, msg, msgPeerReset, msgLocalAbort)
	})

	t.Run("x/net errFromPeer cause is a remote reset", func(t *testing.T) {
		orig := http2.StreamError{StreamID: 11, Code: http2.ErrCodeProtocol, Cause: errors.New(errFromPeerText)}
		msg := describeStreamReadError(orig).Error()
		assertContainsAll(t, msg, msgPeerReset, "PROTOCOL_ERROR 0x1")
		assertContainsNone(t, msg, msgLocalAbort, msgAmbiguous)
	})

	t.Run("StreamError with a local cause is a local abort", func(t *testing.T) {
		orig := http2.StreamError{StreamID: 7, Code: http2.ErrCodeProtocol, Cause: errors.New("some framing fault")}
		msg := describeStreamReadError(orig).Error()
		// http2.StreamError has no Unwrap() for its Cause, so the cause is only
		// reachable through the message text.
		assertContainsAll(t, msg, msgLocalAbort, "PROTOCOL_ERROR 0x1", "some framing fault")
		assertContainsNone(t, msg, msgPeerReset, msgAmbiguous)
	})

	t.Run("StreamError wrapped in another error is still classified", func(t *testing.T) {
		orig := fmt.Errorf("read body: %w", http2.StreamError{StreamID: 3, Code: http2.ErrCodeInternal})
		msg := describeStreamReadError(orig).Error()
		assertContainsAll(t, msg, msgPeerReset, "read body: stream error: stream ID 3; INTERNAL_ERROR")
	})

	t.Run("GOAWAY is reported as a connection-wide close", func(t *testing.T) {
		orig := http2.GoAwayError{LastStreamID: 42, ErrCode: http2.ErrCodeEnhanceYourCalm, DebugData: "slow down"}
		got := describeStreamReadError(orig)
		assertContainsAll(t, got.Error(), msgGoAwayConnEnd, "ENHANCE_YOUR_CALM", "slow down", "LastStreamID=42")

		var ga http2.GoAwayError
		if !errors.As(got, &ga) || ga.ErrCode != http2.ErrCodeEnhanceYourCalm {
			t.Errorf("wrapped GoAwayError should stay recoverable via errors.As, got: %v", got)
		}
	})

	t.Run("unstructured errors pass through untouched", func(t *testing.T) {
		orig := fmt.Errorf("read tcp: connection reset by peer")
		if got := describeStreamReadError(orig); got != orig {
			t.Errorf("non-http2 error should be returned unchanged, got: %v", got)
		}
	})
}

// -----------------------------------------------------------------------------
// End-to-end tests: a real tls-client HTTP/2 connection to a local server that
// writes raw frames, read through StartStream / ReadStreamChunk. These pin the
// classification above against the actual fhttp transport, so an fhttp upgrade
// that changes which StreamError / Cause a body Read returns fails here.
// -----------------------------------------------------------------------------

// rawH2Conn is the server side of one HTTP/2 connection in the end-to-end tests.
type rawH2Conn struct {
	conn net.Conn
	fr   *http2.Framer
	hbuf bytes.Buffer
	henc *hpack.Encoder
}

func (c *rawH2Conn) headerBlock(kv ...string) []byte {
	c.hbuf.Reset()
	for i := 0; i+1 < len(kv); i += 2 {
		_ = c.henc.WriteField(hpack.HeaderField{Name: kv[i], Value: kv[i+1]})
	}
	return append([]byte(nil), c.hbuf.Bytes()...)
}

// startRawH2Server starts a TLS server that speaks HTTP/2 through a bare framer.
// For the first request it answers with response headers and one DATA frame,
// waits until the test calls release, and then runs act on that stream.
func startRawH2Server(t *testing.T, act func(c *rawH2Conn, streamID uint32)) (url string, release func()) {
	t.Helper()

	proceed := make(chan struct{})
	var once sync.Once
	release = func() { once.Do(func() { close(proceed) }) }

	ts := httptest.NewUnstartedServer(nil)
	ts.EnableHTTP2 = true
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	// A TLSNextProto entry for "h2" replaces net/http's own HTTP/2 server.
	ts.Config.TLSNextProto = map[string]func(*nethttp.Server, *tls.Conn, nethttp.Handler){
		"h2": func(_ *nethttp.Server, conn *tls.Conn, _ nethttp.Handler) {
			serveRawH2(conn, proceed, act)
		},
	}
	ts.StartTLS()

	// Cleanups run last-in first-out: unblock the handler, drop the
	// connections, then shut the server down.
	t.Cleanup(ts.Close)
	t.Cleanup(ts.CloseClientConnections)
	t.Cleanup(release)

	return ts.URL, release
}

func serveRawH2(conn net.Conn, proceed <-chan struct{}, act func(c *rawH2Conn, streamID uint32)) {
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}

	c := &rawH2Conn{conn: conn, fr: http2.NewFramer(conn, conn)}
	c.henc = hpack.NewEncoder(&c.hbuf)
	c.fr.AllowIllegalWrites = true // needed for the zero WINDOW_UPDATE case

	if err := c.fr.WriteSettings(); err != nil {
		return
	}

	handled := false
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = c.fr.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			if handled {
				continue
			}
			handled = true
			sid := f.StreamID
			_ = c.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      sid,
				BlockFragment: c.headerBlock(":status", "200", "content-type", "text/event-stream"),
				EndHeaders:    true,
			})
			_ = c.fr.WriteData(sid, false, []byte("data: hello\n\n"))
			<-proceed
			act(c, sid)
		}
	}
}

// readStreamErrorFrom sends a GET through tls-client, registers the response as
// a cffi stream, lets the server run its scenario, and returns the error text
// readStream reports.
func readStreamErrorFrom(t *testing.T, url string, release func(), streamId string) string {
	t.Helper()

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(15),
	)
	if err != nil {
		t.Fatalf("NewHttpClient: %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := fhttp.NewRequest(fhttp.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}

	StartStream(streamId, StartStreamParams{Response: resp, Cancel: cancel, BlockSize: 4096})
	t.Cleanup(func() { CancelStream(streamId) })

	// Only now let the server end the stream, so the failure surfaces in the
	// body read and not already in client.Do.
	release()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		out := ReadStreamChunk(streamId, 500)
		if out.Error != "" {
			return out.Error
		}
		if out.EOF {
			t.Fatalf("expected a read error, got EOF")
		}
	}
	t.Fatalf("no read error within the deadline")
	return ""
}

func TestDescribeStreamReadError_EndToEnd(t *testing.T) {
	tests := []struct {
		name      string
		act       func(c *rawH2Conn, streamID uint32)
		wants     []string
		unwanteds []string
	}{
		{
			name: "peer RST_STREAM INTERNAL_ERROR",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteRSTStream(sid, http2.ErrCodeInternal)
			},
			wants:     []string{msgPeerReset, "INTERNAL_ERROR 0x2", "; INTERNAL_ERROR"},
			unwanteds: []string{msgLocalAbort, msgAmbiguous},
		},
		{
			name: "peer RST_STREAM CANCEL",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteRSTStream(sid, http2.ErrCodeCancel)
			},
			wants:     []string{msgPeerReset, "CANCEL 0x8"},
			unwanteds: []string{msgLocalAbort, msgAmbiguous},
		},
		{
			name: "peer RST_STREAM PROTOCOL_ERROR is ambiguous",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteRSTStream(sid, http2.ErrCodeProtocol)
			},
			wants:     []string{msgAmbiguous, "; PROTOCOL_ERROR"},
			unwanteds: []string{msgPeerReset, msgLocalAbort},
		},
		{
			// fhttp rejects this locally and builds the same cause-less
			// PROTOCOL_ERROR as for a peer RST_STREAM(PROTOCOL_ERROR).
			name: "zero WINDOW_UPDATE rejected locally is ambiguous",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteWindowUpdate(sid, 0)
			},
			wants:     []string{msgAmbiguous, "; PROTOCOL_ERROR"},
			unwanteds: []string{msgPeerReset, msgLocalAbort},
		},
		{
			// Upper-case field names are invalid in HTTP/2; fhttp rejects the
			// trailer locally and sets the Cause.
			name: "invalid trailer rejected locally with a cause",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      sid,
					BlockFragment: c.headerBlock("X-Bad", "v"),
					EndStream:     true,
					EndHeaders:    true,
				})
			},
			wants:     []string{msgLocalAbort, "PROTOCOL_ERROR 0x1", `invalid header field name "X-Bad"`},
			unwanteds: []string{msgPeerReset, msgAmbiguous},
		},
		{
			name: "GOAWAY then connection close",
			act: func(c *rawH2Conn, sid uint32) {
				_ = c.fr.WriteGoAway(sid, http2.ErrCodeEnhanceYourCalm, []byte("slow down"))
				_ = c.conn.Close()
			},
			wants:     []string{msgGoAwayConnEnd, "ErrCode=ENHANCE_YOUR_CALM", `debug="slow down"`},
			unwanteds: []string{msgPeerReset, msgLocalAbort, msgAmbiguous},
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			url, release := startRawH2Server(t, tc.act)
			msg := readStreamErrorFrom(t, url, release, fmt.Sprintf("e2e-describe-%d", i))
			t.Logf("readStream error: %s", msg)
			assertContainsAll(t, msg, tc.wants...)
			assertContainsNone(t, msg, tc.unwanteds...)
		})
	}
}

func TestDescribeStreamReadError_BuildResponse(t *testing.T) {
	// The non-streaming request() path reads the body in BuildResponse and must
	// classify a failed read the same way readStream does.
	url, release := startRawH2Server(t, func(c *rawH2Conn, sid uint32) {
		_ = c.fr.WriteRSTStream(sid, http2.ErrCodeInternal)
	})

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
		tls_client.WithInsecureSkipVerify(),
		tls_client.WithTimeoutSeconds(15),
	)
	if err != nil {
		t.Fatalf("NewHttpClient: %v", err)
	}
	t.Cleanup(client.CloseIdleConnections)

	req, err := fhttp.NewRequest(fhttp.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}

	// Let the server reset the stream only now, so the failure surfaces while
	// BuildResponse reads the body.
	release()

	_, clientErr := BuildResponse("", false, resp, nil, RequestInput{})
	if clientErr == nil {
		t.Fatal("expected BuildResponse to fail")
	}
	msg := clientErr.Error()
	t.Logf("BuildResponse error: %s", msg)
	assertContainsAll(t, msg, msgPeerReset, "INTERNAL_ERROR 0x2", "; INTERNAL_ERROR")
}
