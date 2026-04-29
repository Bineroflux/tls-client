package tls_client_cffi_src

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover how a stream ends and is cleaned up: a backpressure abort
// must surface as an error (never as EOF), the pump must release the request as
// soon as the body has ended, abandoned streams must be removed, and
// ClearStreamCache must not leave pumps blocked. They live in the package so
// they can shorten backpressureTimeout and abandonedStreamTimeout.

func withStreamTimeouts(t *testing.T, backpressure, abandoned time.Duration) {
	t.Helper()
	oldBackpressure, oldAbandoned := backpressureTimeout.Load(), abandonedStreamTimeout.Load()
	backpressureTimeout.Store(backpressure)
	abandonedStreamTimeout.Store(abandoned)
	t.Cleanup(func() {
		backpressureTimeout.Store(oldBackpressure)
		abandonedStreamTimeout.Store(oldAbandoned)
	})
}

// closeSignalBody is a response body that reports when it was closed.
type closeSignalBody struct {
	io.Reader
	once   sync.Once
	closed chan struct{}
}

func newCloseSignalBody(data []byte) *closeSignalBody {
	return &closeSignalBody{Reader: bytes.NewReader(data), closed: make(chan struct{})}
}

func (b *closeSignalBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func lifecycleResp(body io.ReadCloser) *http.Response {
	u, _ := url.Parse("https://example.test/lifecycle")
	return &http.Response{
		Body:         body,
		Header:       http.Header{},
		StatusCode:   200,
		Proto:        "HTTP/1.1",
		Request:      &http.Request{URL: u},
		Uncompressed: true,
	}
}

// startLifecycleStream starts a stream over data and returns a channel that is
// closed when the stream's cancel func runs.
func startLifecycleStream(t *testing.T, id string, data []byte, blockSize int) (*StreamState, chan struct{}) {
	t.Helper()
	cancelled := make(chan struct{})
	var once sync.Once
	state := StartStream(id, StartStreamParams{
		Response:  lifecycleResp(io.NopCloser(bytes.NewReader(data))),
		Cancel:    func() { once.Do(func() { close(cancelled) }) },
		BlockSize: blockSize,
	})
	t.Cleanup(func() { CancelStream(id) })
	return state, cancelled
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not happen within 2s", what)
	}
}

func TestStream_BackpressureAbortIsReportedAsError(t *testing.T) {
	withStreamTimeouts(t, 50*time.Millisecond, time.Minute)

	const blockSize = 4
	total := (streamChannelCapacity + 10) * blockSize
	_, cancelled := startLifecycleStream(t, "backpressure-chunk", bytes.Repeat([]byte("x"), total), blockSize)

	// Do not read: the buffer fills up and the pump gives up after 50 ms. It must
	// release the request when it gives up.
	waitClosed(t, cancelled, "cancel after backpressure abort")

	got := 0
	for i := 0; i < streamChannelCapacity+20; i++ {
		out := ReadStreamChunk("backpressure-chunk", 1000)
		require.False(t, out.EOF, "a backpressure abort must never look like a complete body")
		require.False(t, out.Timeout, "unexpected timeout after the pump has ended")
		if out.Error != "" {
			assert.Contains(t, out.Error, "stream aborted")
			assert.Less(t, got, total, "the body is incomplete")
			_, ok := GetStream("backpressure-chunk")
			assert.False(t, ok, "stream must be removed after the abort was reported")
			return
		}
		b, err := base64.StdEncoding.DecodeString(out.Chunk)
		require.NoError(t, err)
		got += len(b)
	}
	t.Fatal("no error reported after the buffered chunks")
}

func TestStream_BackpressureAbortFailsReadStreamAll(t *testing.T) {
	withStreamTimeouts(t, 50*time.Millisecond, time.Minute)

	const blockSize = 4
	total := (streamChannelCapacity + 10) * blockSize
	_, cancelled := startLifecycleStream(t, "backpressure-all", bytes.Repeat([]byte("x"), total), blockSize)
	waitClosed(t, cancelled, "cancel after backpressure abort")

	resp, err := ReadStreamAll("backpressure-all")
	require.NotNil(t, err, "readStreamAll must fail instead of returning a truncated body")
	assert.Contains(t, err.Error(), "stream aborted")
	assert.Empty(t, resp.Body)
}

func TestStream_PumpReleasesRequestWhenBodyEnds(t *testing.T) {
	withStreamTimeouts(t, time.Minute, time.Minute)

	_, cancelled := startLifecycleStream(t, "release-on-eof", []byte("hello world"), 4)

	// Nobody reads, but the body is short and fits into the buffer: the pump
	// reaches EOF and must release the request (and a client without session)
	// right away instead of waiting for a reader.
	waitClosed(t, cancelled, "cancel after EOF")

	var buf bytes.Buffer
	for {
		out := ReadStreamChunk("release-on-eof", 1000)
		require.Empty(t, out.Error)
		b, err := base64.StdEncoding.DecodeString(out.Chunk)
		require.NoError(t, err)
		buf.Write(b)
		if out.EOF {
			break
		}
	}
	assert.Equal(t, "hello world", buf.String(), "buffered chunks must stay readable after the release")
}

func TestStream_AbandonedStreamIsRemoved(t *testing.T) {
	withStreamTimeouts(t, time.Minute, 100*time.Millisecond)

	startLifecycleStream(t, "abandoned", []byte("never read"), 4)

	require.Eventually(t, func() bool {
		_, ok := GetStream("abandoned")
		return !ok
	}, 2*time.Second, 20*time.Millisecond, "an ended stream that nobody reads must be removed")

	out := ReadStreamChunk("abandoned", 0)
	assert.Contains(t, out.Error, "unknown streamId")
}

func TestStream_ReadingKeepsEndedStreamAlive(t *testing.T) {
	withStreamTimeouts(t, time.Minute, 150*time.Millisecond)

	const payload = "abcdefghij"
	startLifecycleStream(t, "slow-reader", []byte(payload), 1)

	// Read one byte every 50 ms: the whole read takes longer than the abandon
	// timeout, but every read counts as activity, so the stream must survive.
	var buf strings.Builder
	for {
		time.Sleep(50 * time.Millisecond)
		out := ReadStreamChunk("slow-reader", 1000)
		require.Empty(t, out.Error, "a stream that is still being read must not be removed")
		b, err := base64.StdEncoding.DecodeString(out.Chunk)
		require.NoError(t, err)
		buf.Write(b)
		if out.EOF {
			break
		}
	}
	assert.Equal(t, payload, buf.String())
}

func TestStream_ClearStreamCacheUnblocksPump(t *testing.T) {
	withStreamTimeouts(t, time.Minute, time.Minute)

	const blockSize = 4
	body := newCloseSignalBody(bytes.Repeat([]byte("x"), (streamChannelCapacity+10)*blockSize))
	state := StartStream("clear-blocked", StartStreamParams{
		Response:  lifecycleResp(body),
		Cancel:    func() {},
		BlockSize: blockSize,
	})

	require.Eventually(t, func() bool { return len(state.Chunks) == streamChannelCapacity },
		2*time.Second, 10*time.Millisecond, "buffer should fill up")

	ClearStreamCache()

	// Without draining, the pump would stay blocked in sendChunk for the full
	// backpressureTimeout (here a minute) and only then close the body.
	waitClosed(t, body.closed, "body close after ClearStreamCache")
}
