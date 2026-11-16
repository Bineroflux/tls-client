package tls_client_cffi_src

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/google/uuid"
	"golang.org/x/net/html/charset"
)

// backpressureTimeout bounds how long the pump goroutine will block trying to
// hand off a chunk before giving up. It exists so a misbehaving caller (one
// that stops reading without calling cancelStream) cannot keep the underlying
// connection and goroutine alive indefinitely. A stream aborted this way ends
// with an error (see errBackpressure), never with EOF, because its body is
// incomplete. Atomic so tests can shorten it while pumps are running.
var backpressureTimeout = newAtomicDuration(60 * time.Second)

// abandonedStreamTimeout is how long a stream whose body has ended (EOF, read
// error or backpressure abort) stays registered without being read. After that
// it counts as abandoned: it is removed together with its buffered chunks, and a
// later readStream / readStreamAll reports an unknown streamId. Atomic so tests
// can shorten it while timers are running.
var abandonedStreamTimeout = newAtomicDuration(5 * time.Minute)

// atomicDuration is a time.Duration that can be read and written concurrently.
type atomicDuration struct{ ns atomic.Int64 }

func newAtomicDuration(d time.Duration) *atomicDuration {
	a := &atomicDuration{}
	a.Store(d)
	return a
}

func (a *atomicDuration) Load() time.Duration   { return time.Duration(a.ns.Load()) }
func (a *atomicDuration) Store(d time.Duration) { a.ns.Store(int64(d)) }

// errBackpressure ends a stream whose pump gave up because the caller did not
// read for backpressureTimeout while the chunk buffer was full.
func errBackpressure() error {
	return fmt.Errorf("stream aborted: the caller did not read for %s while %d chunks were buffered, so the body is incomplete", backpressureTimeout.Load(), streamChannelCapacity)
}

// defaultStreamBlockSize is the per-Read buffer size when StreamOutputBlockSize
// is not specified on the RequestInput.
const defaultStreamBlockSize = 4096

// streamChannelCapacity is the buffered capacity of the chunk channel between
// the pump goroutine and the readStream caller. Higher values smooth out short
// caller stalls; lower values keep memory bounded.
const streamChannelCapacity = 64

// StreamChunk is one item produced by the pump goroutine and consumed by
// readStream / readStreamAll. Exactly one of Data, EOF, or Err is meaningful.
type StreamChunk struct {
	Err  error
	Data []byte
	EOF  bool
}

// StreamState tracks one in-flight streaming response.
//
// Headers/status/cookies are captured at start time so readStreamAll can
// produce a complete Response envelope without the caller having to merge
// the requestStream envelope back in.
type StreamState struct {
	cancel      context.CancelFunc
	body        io.ReadCloser
	Chunks      chan StreamChunk
	Headers     http.Header
	Cookies     []*http.Cookie
	SessionId   string
	Proto       string
	Target      string
	ContentType string
	Status      int
	WithSession bool

	// IsByteResponse mirrors the original RequestInput so readStreamAll
	// formats the body the same way the non-streaming path would have.
	IsByteResponse bool

	closeOnce sync.Once

	// id is the streamId the state is registered under.
	id string
	// lastActivity is the UnixNano time of the last readStream / readStreamAll
	// call, used to detect abandoned streams.
	lastActivity atomic.Int64
}

// touch records a read so the stream does not count as abandoned.
func (s *StreamState) touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

// StartStreamParams bundles the inputs needed to register a streaming
// response. The caller is responsible for having already issued the request
// and obtained the response headers.
type StartStreamParams struct {
	Response       *http.Response
	Cookies        []*http.Cookie
	Cancel         context.CancelFunc
	SessionId      string
	WithSession    bool
	IsByteResponse bool
	BlockSize      int // <= 0 falls back to defaultStreamBlockSize
}

// StartStream wraps the response body with decompression (when applicable),
// constructs a StreamState, registers it under streamId, and spawns the pump
// goroutine. It returns the registered StreamState so the caller can build
// the requestStream envelope.
func StartStream(streamId string, p StartStreamParams) *StreamState {
	resp := p.Response

	body := resp.Body
	if !resp.Uncompressed {
		body = http.DecompressBodyByType(body, resp.Header.Get("Content-Encoding"))
	}

	target := ""
	if resp.Request != nil && resp.Request.URL != nil {
		target = resp.Request.URL.String()
	}

	state := &StreamState{
		cancel:         p.Cancel,
		body:           body,
		Chunks:         make(chan StreamChunk, streamChannelCapacity),
		Headers:        resp.Header,
		Cookies:        p.Cookies,
		SessionId:      p.SessionId,
		Proto:          resp.Proto,
		Target:         target,
		ContentType:    resp.Header.Get("Content-Type"),
		Status:         resp.StatusCode,
		WithSession:    p.WithSession,
		IsByteResponse: p.IsByteResponse,
		id:             streamId,
	}
	state.touch()

	RegisterStream(streamId, state)
	go pumpStream(state, p.BlockSize)
	return state
}

// Close is idempotent. It cancels the request context (which closes the
// underlying TCP/TLS connection and unblocks any in-flight body Read).
func (s *StreamState) Close() {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
}

var (
	streamsLock sync.Mutex
	streams     = make(map[string]*StreamState)
)

// RegisterStream stores a freshly created StreamState under streamId. The
// caller takes responsibility for spawning the pump goroutine.
func RegisterStream(streamId string, state *StreamState) {
	streamsLock.Lock()
	defer streamsLock.Unlock()
	streams[streamId] = state
}

// GetStream returns the StreamState for streamId, or (nil, false) if none.
func GetStream(streamId string) (*StreamState, bool) {
	streamsLock.Lock()
	defer streamsLock.Unlock()
	s, ok := streams[streamId]
	return s, ok
}

// removeStream deletes the registry entry for streamId and returns the
// previously stored StreamState. Callers should also invoke Close on the
// returned state to release the underlying connection.
func removeStream(streamId string) (*StreamState, bool) {
	streamsLock.Lock()
	defer streamsLock.Unlock()
	s, ok := streams[streamId]
	if ok {
		delete(streams, streamId)
	}
	return s, ok
}

// ClearStreamCache cancels and removes every registered stream. It is safe to
// call from destroyAll.
func ClearStreamCache() {
	streamsLock.Lock()
	toClose := make([]*StreamState, 0, len(streams))
	for _, s := range streams {
		toClose = append(toClose, s)
	}
	streams = make(map[string]*StreamState)
	streamsLock.Unlock()

	for _, s := range toClose {
		s.Close()
		// Like CancelStream: drain so a pump blocked in sendChunk ends promptly
		// instead of holding its buffers for up to backpressureTimeout.
		go drainChunks(s)
	}
}

// drainChunks discards the remaining chunks of a stream nobody will read.
func drainChunks(s *StreamState) {
	for range s.Chunks {
	}
}

// scheduleAbandonCheck removes the stream once nobody has read it for
// abandonedStreamTimeout. It is called when the pump has finished, so only the
// buffered chunks are left; a caller that is still reading keeps the stream
// alive because every read calls touch.
func scheduleAbandonCheck(state *StreamState) {
	var check func()
	check = func() {
		idle := time.Since(time.Unix(0, state.lastActivity.Load()))
		if timeout := abandonedStreamTimeout.Load(); idle < timeout {
			time.AfterFunc(timeout-idle, check)
			return
		}

		streamsLock.Lock()
		current, ok := streams[state.id]
		if ok && current == state {
			delete(streams, state.id)
		}
		streamsLock.Unlock()

		if ok && current == state {
			go drainChunks(state)
		}
	}
	time.AfterFunc(abandonedStreamTimeout.Load(), check)
}

// pumpStream reads from state.body in blockSize chunks and pushes them onto
// state.Chunks. It terminates on EOF, on read error, or when the consumer
// stalls for longer than backpressureTimeout. The chunk channel is closed
// before the goroutine returns.
//
// Every way out closes the state, so the request context is cancelled and a
// client without session is closed as soon as the body has ended, even if the
// caller never reads the rest. The chunks already buffered stay readable. A
// channel closed without a final EOF or error chunk means the pump gave up on
// backpressure; the readers report that as errBackpressure.
func pumpStream(state *StreamState, blockSize int) {
	defer func() {
		_ = state.body.Close()
		close(state.Chunks)
		state.Close()
		scheduleAbandonCheck(state)
	}()

	if blockSize <= 0 {
		blockSize = defaultStreamBlockSize
	}

	for {
		buf := make([]byte, blockSize)
		n, readErr := state.body.Read(buf)

		if n > 0 {
			if !sendChunk(state.Chunks, StreamChunk{Data: buf[:n]}) {
				return
			}
		}

		if readErr == io.EOF {
			sendChunk(state.Chunks, StreamChunk{EOF: true})
			return
		}
		if readErr != nil {
			sendChunk(state.Chunks, StreamChunk{Err: readErr})
			return
		}
	}
}

func sendChunk(ch chan<- StreamChunk, chunk StreamChunk) bool {
	select {
	case ch <- chunk:
		return true
	case <-time.After(backpressureTimeout.Load()):
		return false
	}
}

// BuildStreamStartResponse constructs the envelope returned by requestStream.
// The caller is expected to register the StreamState and spawn the pump after
// this returns.
func BuildStreamStartResponse(streamId string, state *StreamState) StreamStartResponse {
	response := Response{
		Id:           uuid.New().String(),
		Status:       state.Status,
		UsedProtocol: state.Proto,
		Body:         "",
		Headers:      state.Headers,
		Target:       state.Target,
		Cookies:      cookiesToMap(state.Cookies),
	}

	if state.WithSession {
		response.SessionId = state.SessionId
	}

	return StreamStartResponse{
		Response: response,
		StreamId: streamId,
	}
}

// StartRequestStream implements the requestStream cffi export. It sends the
// request described by input and registers its response as a stream as soon as
// the response headers have arrived; the body is read by the stream's pump.
// cookies are the request cookies (input.RequestCookies, converted by the
// caller). sessionId and withSession are returned for the error envelope.
//
// Like request(), it closes a client without session once it is done with it,
// so its HTTP/3 transports do not keep their UDP sockets open. Because the body
// outlives this call, that happens together with the stream (end of the body,
// cancelStream, destroyAll) or on any failure before the stream starts.
func StartRequestStream(input RequestInput, cookies []*http.Cookie) (StreamStartResponse, string, bool, *TLSClientError) {
	tlsClient, sessionId, withSession, clientErr := CreateClient(input)
	if clientErr != nil {
		return StreamStartResponse{}, sessionId, withSession, clientErr
	}

	// Cancellable context so cancelStream can release the in-flight read.
	ctx, cancelCtx := context.WithCancel(context.Background())
	cancel := cancelCtx
	if !withSession {
		cancel = func() {
			cancelCtx()
			tlsClient.Close()
		}
	}

	req, clientErr := BuildRequest(input)
	if clientErr != nil {
		cancel()
		return StreamStartResponse{}, sessionId, withSession, clientErr
	}
	req = req.WithContext(ctx)

	if tlsClient.GetCookieJar() != nil && len(cookies) > 0 {
		tlsClient.SetCookies(req.URL, cookies)
	} else {
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
	}

	resp, err := tlsClient.Do(req)
	if err != nil {
		cancel()
		return StreamStartResponse{}, sessionId, withSession, NewTLSClientError(fmt.Errorf("failed to do request: %w", err))
	}
	if resp == nil {
		cancel()
		return StreamStartResponse{}, sessionId, withSession, NewTLSClientError(fmt.Errorf("response is nil"))
	}

	blockSize := 0
	if input.StreamOutputBlockSize != nil {
		blockSize = *input.StreamOutputBlockSize
	}

	streamId := uuid.New().String()
	state := StartStream(streamId, StartStreamParams{
		Response:       resp,
		Cookies:        tlsClient.GetCookies(resp.Request.URL),
		Cancel:         cancel,
		SessionId:      sessionId,
		WithSession:    withSession,
		IsByteResponse: input.IsByteResponse,
		BlockSize:      blockSize,
	})

	return BuildStreamStartResponse(streamId, state), sessionId, withSession, nil
}

// ReadStreamChunk pulls the next chunk from the registry, applying timeoutMs
// semantics as documented on ReadStreamInput. On EOF or error it removes the
// stream from the registry and closes its underlying connection.
func ReadStreamChunk(streamId string, timeoutMs int) StreamChunkResponse {
	state, ok := GetStream(streamId)
	if !ok {
		return StreamChunkResponse{
			Id:       uuid.New().String(),
			StreamId: streamId,
			Error:    fmt.Sprintf("unknown streamId: %s", streamId),
		}
	}
	state.touch()
	defer state.touch()

	switch {
	case timeoutMs < 0:
		chunk, open := <-state.Chunks
		return finalizeChunk(streamId, state, chunk, open)
	case timeoutMs == 0:
		select {
		case chunk, open := <-state.Chunks:
			return finalizeChunk(streamId, state, chunk, open)
		default:
			return StreamChunkResponse{
				Id:       uuid.New().String(),
				StreamId: streamId,
				Timeout:  true,
			}
		}
	default:
		select {
		case chunk, open := <-state.Chunks:
			return finalizeChunk(streamId, state, chunk, open)
		case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
			return StreamChunkResponse{
				Id:       uuid.New().String(),
				StreamId: streamId,
				Timeout:  true,
			}
		}
	}
}

func finalizeChunk(streamId string, state *StreamState, chunk StreamChunk, open bool) StreamChunkResponse {
	if !open {
		// Channel was closed without a final EOF/Err chunk: the pump gave up
		// because the caller did not read for backpressureTimeout. The body is
		// incomplete, so this must not look like a normal EOF.
		_, _ = removeStream(streamId)
		state.Close()
		return StreamChunkResponse{
			Id:       uuid.New().String(),
			StreamId: streamId,
			Error:    errBackpressure().Error(),
		}
	}

	if chunk.Err != nil {
		_, _ = removeStream(streamId)
		state.Close()
		return StreamChunkResponse{
			Id:       uuid.New().String(),
			StreamId: streamId,
			Error:    chunk.Err.Error(),
		}
	}

	if chunk.EOF {
		_, _ = removeStream(streamId)
		state.Close()
		return StreamChunkResponse{
			Id:       uuid.New().String(),
			StreamId: streamId,
			EOF:      true,
		}
	}

	return StreamChunkResponse{
		Id:       uuid.New().String(),
		StreamId: streamId,
		Chunk:    base64.StdEncoding.EncodeToString(chunk.Data),
	}
}

// ReadStreamAll drains the rest of the body in one shot and returns a full
// Response envelope, formatted the same way BuildResponse would have for a
// non-streaming request (charset decoding for text bodies, base64 + MIME
// prefix for byte responses). After this returns, streamId is invalid.
func ReadStreamAll(streamId string) (Response, *TLSClientError) {
	state, ok := GetStream(streamId)
	if !ok {
		return Response{}, NewTLSClientError(fmt.Errorf("unknown streamId: %s", streamId))
	}

	var buf bytes.Buffer
	var streamErr error
	ended := false

	for chunk := range state.Chunks {
		state.touch()
		if chunk.Err != nil {
			streamErr = chunk.Err
			ended = true
			break
		}
		if len(chunk.Data) > 0 {
			buf.Write(chunk.Data)
		}
		if chunk.EOF {
			ended = true
			break
		}
	}
	if !ended {
		// The channel closed without EOF: backpressure abort, see finalizeChunk.
		streamErr = errBackpressure()
	}

	_, _ = removeStream(streamId)
	state.Close()

	if streamErr != nil {
		return Response{}, NewTLSClientError(streamErr)
	}

	bodyBytes := buf.Bytes()
	finalBody := ""

	if state.IsByteResponse {
		mimeType := http.DetectContentType(bodyBytes)
		finalBody = fmt.Sprintf("data:%s;base64,", mimeType) + base64.StdEncoding.EncodeToString(bodyBytes)
	} else if len(bodyBytes) > 0 {
		// Mirror the charset detection BuildResponse does for non-byte bodies.
		reader, err := charset.NewReader(bytes.NewReader(bodyBytes), state.ContentType)
		if err != nil {
			return Response{}, NewTLSClientError(err)
		}
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return Response{}, NewTLSClientError(err)
		}
		finalBody = string(decoded)
	}

	response := Response{
		Id:           uuid.New().String(),
		Status:       state.Status,
		UsedProtocol: state.Proto,
		Body:         finalBody,
		Headers:      state.Headers,
		Target:       state.Target,
		Cookies:      cookiesToMap(state.Cookies),
	}
	if state.WithSession {
		response.SessionId = state.SessionId
	}
	return response, nil
}

// CancelStream tears down the stream identified by streamId. It is idempotent:
// calling it after a natural EOF, after an error, or with an unknown streamId
// returns success without doing any work.
func CancelStream(streamId string) {
	state, ok := removeStream(streamId)
	if !ok {
		return
	}
	state.Close()
	// Drain any remaining chunks so the pump goroutine, which is blocked on
	// sendChunk, can terminate promptly.
	go drainChunks(state)
}
