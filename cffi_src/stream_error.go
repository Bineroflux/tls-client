package tls_client_cffi_src

import (
	"errors"
	"fmt"

	"github.com/bogdanfinn/fhttp/http2"
)

// errFromPeerText is the text of golang.org/x/net/http2's unexported errFromPeer
// sentinel. Current x/net versions set StreamError.Cause to it when the peer sent
// RST_STREAM. fhttp v0.7.3 still leaves Cause nil in that case; matching the text
// keeps the classification right if fhttp picks up the newer x/net behaviour.
const errFromPeerText = "received from peer"

// describeStreamReadError enriches an error returned by a body Read (a streamed
// read in pumpStream, or the full read in BuildResponse) so the consumer can tell
// WHY a stream ended abnormally, in particular whether the remote peer aborted it
// or the local http2 transport did.
//
// http2.StreamError.Error() renders as
//
//	stream error: stream ID 2985; INTERNAL_ERROR
//
// and omits the Cause when it is nil, so the message alone does not say who
// ended the stream. In fhttp v0.7.3 (github.com/bogdanfinn/fhttp/http2):
//
//   - The peer sent RST_STREAM: clientConnReadLoop.processResetStream builds
//     streamError(id, f.ErrCode) with no Cause, for any error code.
//   - The local transport rejected a frame from the peer: for some protocol
//     violations (DATA before HEADERS, DATA on a HEAD response, a zero
//     WINDOW_UPDATE increment, bad HEADERS padding) it also builds a StreamError
//     without Cause, always with PROTOCOL_ERROR. For others (invalid header
//     fields, bad pseudo headers) it sets Cause to the detail.
//
// So a cause-less StreamError with any code other than PROTOCOL_ERROR can only
// come from the peer's RST_STREAM. A cause-less PROTOCOL_ERROR is ambiguous, and a
// StreamError with a Cause was produced locally (unless the Cause is x/net's
// "received from peer" marker, see errFromPeerText). The end-to-end tests in
// stream_error_test.go pin this against the real transport, so an fhttp upgrade
// that changes it fails loudly.
//
// A GOAWAY followed by the connection closing (http2.GoAwayError) is reported as a
// connection-wide close so it is not mistaken for a per-stream reset.
//
// The original error is wrapped with %w, so its text stays at the end of the
// message and errors.Is / errors.As keep working. Anything that is not an http2
// stream or GOAWAY error (context cancellation, a net.OpError such as "connection
// reset by peer", io.ErrUnexpectedEOF, a decompressor fault, ...) is returned
// unchanged.
func describeStreamReadError(err error) error {
	if err == nil {
		return nil
	}

	var se http2.StreamError
	if errors.As(err, &se) {
		fromPeer := se.Cause != nil && se.Cause.Error() == errFromPeerText

		switch {
		case fromPeer || (se.Cause == nil && se.Code != http2.ErrCodeProtocol):
			return fmt.Errorf(
				"http2 stream reset by remote peer (RST_STREAM, code %s 0x%x); the remote side or an intermediary aborted this stream: %w",
				se.Code, uint32(se.Code), err)
		case se.Cause == nil:
			return fmt.Errorf(
				"http2 stream ended with PROTOCOL_ERROR and no further detail; either the remote peer sent RST_STREAM, or the local transport rejected a malformed frame from the peer: %w",
				err)
		default:
			return fmt.Errorf(
				"http2 stream aborted by the local transport (code %s 0x%x); it detected a protocol violation, typically malformed data from the peer: %w",
				se.Code, uint32(se.Code), err)
		}
	}

	var ga http2.GoAwayError
	if errors.As(err, &ga) {
		return fmt.Errorf(
			"http2 connection closed by remote peer after GOAWAY; this ends every stream on the connection, not just this one: %w",
			err)
	}

	return err
}
