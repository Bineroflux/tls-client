package tls_client_cffi_src

import (
	"encoding/json"
	"fmt"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

type TLSClientError struct {
	err error
}

func NewTLSClientError(err error) *TLSClientError {
	return &TLSClientError{
		err: err,
	}
}

func (e *TLSClientError) Error() string {
	return e.err.Error()
}

type DestroySessionInput struct {
	SessionId string `json:"sessionId"`
}

type DestroyOutput struct {
	Id      string `json:"id"`
	Success bool   `json:"success"`
}

type AddCookiesToSessionInput struct {
	SessionId string   `json:"sessionId"`
	Url       string   `json:"url"`
	Cookies   []Cookie `json:"cookies"`
}

type GetCookiesFromSessionInput struct {
	SessionId string `json:"sessionId"`
	Url       string `json:"url"`
}

type CookiesFromSessionOutput struct {
	Id      string   `json:"id"`
	Cookies []Cookie `json:"cookies"`
}

// RequestInput is the data a Python client can construct a client and request from.
//
// TimeoutSeconds / TimeoutMilliseconds: 0 means "use the default timeout" (30s),
// a positive value sets an explicit deadline, and a negative value disables the
// deadline entirely (required for long-lived SSE / streaming responses). Set at
// most one of the two fields: a request that sets both to non-zero values is
// rejected. See ResolveTimeout. For a session, the timeout is fixed when the
// session's client is created by its first request.
type RequestInput struct {
	CertificatePinningHosts     map[string][]string `json:"certificatePinningHosts"`
	CustomTlsClient             *CustomTlsClient    `json:"customTlsClient"`
	TransportOptions            *TransportOptions   `json:"transportOptions"`
	Headers                     map[string]string   `json:"headers"`
	DefaultHeaders              map[string][]string `json:"defaultHeaders"`
	ConnectHeaders              map[string][]string `json:"connectHeaders"`
	LocalAddress                *string             `json:"localAddress"`
	ServerNameOverwrite         *string             `json:"serverNameOverwrite"`
	ProxyUrl                    *string             `json:"proxyUrl"`
	RequestBody                 *string             `json:"requestBody"`
	RequestHostOverride         *string             `json:"requestHostOverride"`
	SessionId                   *string             `json:"sessionId"`
	StreamOutputBlockSize       *int                `json:"streamOutputBlockSize"`
	StreamOutputEOFSymbol       *string             `json:"streamOutputEOFSymbol"`
	StreamOutputPath            *string             `json:"streamOutputPath"`
	RequestMethod               string              `json:"requestMethod"`
	RequestUrl                  string              `json:"requestUrl"`
	TLSClientIdentifier         string              `json:"tlsClientIdentifier"`
	HeaderOrder                 []string            `json:"headerOrder"`
	RequestCookies              []Cookie            `json:"requestCookies"`
	TimeoutMilliseconds         int                 `json:"timeoutMilliseconds"`
	TimeoutSeconds              int                 `json:"timeoutSeconds"`
	CatchPanics                 bool                `json:"catchPanics"`
	FollowRedirects             bool                `json:"followRedirects"`
	ForceHttp1                  bool                `json:"forceHttp1"`
	DisableHttp3                bool                `json:"disableHttp3"`
	DisableSessionTickets       bool                `json:"disableSessionTickets"`
	WithProtocolRacing          bool                `json:"withProtocolRacing"`
	InsecureSkipVerify          bool                `json:"insecureSkipVerify"`
	IsByteRequest               bool                `json:"isByteRequest"`
	IsByteResponse              bool                `json:"isByteResponse"`
	IsRotatingProxy             bool                `json:"isRotatingProxy"`
	DisableIPV6                 bool                `json:"disableIPV6"`
	DisableIPV4                 bool                `json:"disableIPV4"`
	WithDebug                   bool                `json:"withDebug"`
	WithCustomCookieJar         bool                `json:"withCustomCookieJar"`
	WithoutCookieJar            bool                `json:"withoutCookieJar"`
	WithRandomTLSExtensionOrder bool                `json:"withRandomTLSExtensionOrder"`
}

// CustomTlsClient contains custom TLS specifications to construct a client from.
type CustomTlsClient struct {
	H2Settings                              map[string]uint32     `json:"h2Settings"`
	H2SettingsOrder                         []string              `json:"h2SettingsOrder"`
	H3Settings                              map[string]uint64     `json:"h3Settings"`
	H3SettingsOrder                         []string              `json:"h3SettingsOrder"`
	H3PseudoHeaderOrder                     []string              `json:"h3PseudoHeaderOrder"`
	HeaderPriority                          *PriorityParam        `json:"headerPriority"`
	CertCompressionAlgos                    []string              `json:"certCompressionAlgos"`
	Ja3String                               string                `json:"ja3String"`
	TrustAnchorsPayload                     string                `json:"trustAnchorsPayload"`
	KeyShareCurves                          []string              `json:"keyShareCurves"`
	ALPNProtocols                           []string              `json:"alpnProtocols"`
	ALPSProtocols                           []string              `json:"alpsProtocols"`
	ECHCandidatePayloads                    []uint16              `json:"ECHCandidatePayloads"`
	ECHCandidateCipherSuites                CandidateCipherSuites `json:"ECHCandidateCipherSuites"`
	PriorityFrames                          []PriorityFrames      `json:"priorityFrames"`
	PseudoHeaderOrder                       []string              `json:"pseudoHeaderOrder"`
	SupportedDelegatedCredentialsAlgorithms []string              `json:"supportedDelegatedCredentialsAlgorithms"`
	SupportedSignatureAlgorithms            []string              `json:"supportedSignatureAlgorithms"`
	SupportedVersions                       []string              `json:"supportedVersions"`
	ConnectionFlow                          uint32                `json:"connectionFlow"`
	RecordSizeLimit                         uint16                `json:"recordSizeLimit"`
	StreamId                                uint32                `json:"streamId"`
	H3PriorityParam                         uint32                `json:"h3PriorityParam"`
	H3SendGreaseFrames                      bool                  `json:"h3SendGreaseFrames"`
	AllowHttp                               bool                  `json:"allowHttp"`
}

type CandidateCipherSuites []CandidateCipherSuite

func (c CandidateCipherSuites) Translate() []tls_client.CandidateCipherSuites {
	suites := make([]tls_client.CandidateCipherSuites, len(c))
	for i, suite := range c {
		suites[i] = tls_client.CandidateCipherSuites{
			KdfId:  suite.KdfId,
			AeadId: suite.AeadId,
		}
	}

	return suites
}

type CandidateCipherSuite struct {
	KdfId  string `json:"kdfId"`
	AeadId string `json:"aeadId"`
}

// TransportOptions contains settings for the underlying http transport of the tls client
type TransportOptions struct {
	// IdleConnTimeout is the maximum amount of time an idle (keep-alive)
	// connection will remain idle before closing itself. Zero means no limit.
	IdleConnTimeout        *time.Duration `json:"idleConnTimeout"`
	MaxIdleConns           int            `json:"maxIdleConns"`
	MaxIdleConnsPerHost    int            `json:"maxIdleConnsPerHost"`
	MaxConnsPerHost        int            `json:"maxConnsPerHost"`
	MaxResponseHeaderBytes int64          `json:"maxResponseHeaderBytes"` // Zero means to use a default limit.
	WriteBufferSize        int            `json:"writeBufferSize"`        // If zero, a default (currently 4KB) is used.
	ReadBufferSize         int            `json:"readBufferSize"`         // If zero, a default (currently 4KB) is used.
	DisableKeepAlives      bool           `json:"disableKeepAlives"`
	DisableCompression     bool           `json:"disableCompression"`
	// ReadIdleTimeout sends an HTTP/2 health-check PING when no frame has been
	// received for this long. Zero disables it.
	ReadIdleTimeout time.Duration `json:"readIdleTimeout"`
	// PingTimeout closes the connection when that PING is not acknowledged in
	// time. Zero means 15 seconds.
	PingTimeout time.Duration `json:"pingTimeout"`
	// ResponseHeaderTimeout is the time to wait for the response headers after
	// the request has been written, over HTTP/1.1 and HTTP/2. Zero means no
	// timeout.
	ResponseHeaderTimeout time.Duration `json:"responseHeaderTimeout"`
}

type PriorityFrames struct {
	PriorityParam PriorityParam `json:"priorityParam"`
	StreamID      uint32        `json:"streamID"`
}

type PriorityParam struct {
	StreamDep uint32 `json:"streamDep"`
	Exclusive bool   `json:"exclusive"`
	Weight    uint8  `json:"weight"`
}

type Cookie struct {
	Expires  Timestamp `json:"expires"`
	Domain   string    `json:"domain"`
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Value    string    `json:"value"`
	MaxAge   int       `json:"maxAge"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"httpOnly"`
}

type Timestamp struct {
	time.Time
}

func (p *Timestamp) UnmarshalJSON(bytes []byte) error {
	var raw int64
	err := json.Unmarshal(bytes, &raw)
	if err != nil {
		return fmt.Errorf("error decoding timestamp: %w", err)
	}

	p.Time = time.Unix(raw, 0)

	return nil
}

func (p *Timestamp) MarshalJSON() ([]byte, error) {
	stamp := fmt.Sprintf("%d", p.Unix())
	return []byte(stamp), nil
}

// Response is the response that is sent back to the Python client.
type Response struct {
	Cookies      map[string]string   `json:"cookies"`
	Headers      map[string][]string `json:"headers"`
	Id           string              `json:"id"`
	Body         string              `json:"body"`
	SessionId    string              `json:"sessionId,omitempty"`
	Target       string              `json:"target"`
	UsedProtocol string              `json:"usedProtocol"`
	Status       int                 `json:"status"`
}

// WsConnectInput contains the parameters for establishing a WebSocket connection.
// Either SessionId (to reuse an existing TLS session) or TLSClientIdentifier / CustomTlsClient
// (to create an inline client) must be provided.
type WsConnectInput struct {
	SessionId                    *string           `json:"sessionId"`
	CustomTlsClient              *CustomTlsClient  `json:"customTlsClient"`
	ProxyUrl                     *string           `json:"proxyUrl"`
	ServerNameOverwrite          *string           `json:"serverNameOverwrite"`
	Url                          string            `json:"url"`
	TLSClientIdentifier          string            `json:"tlsClientIdentifier"`
	Headers                      map[string]string `json:"headers"`
	HeaderOrder                  []string          `json:"headerOrder"`
	HandshakeTimeoutMilliseconds int               `json:"handshakeTimeoutMilliseconds"`
	ReadBufferSize               int               `json:"readBufferSize"`
	WriteBufferSize              int               `json:"writeBufferSize"`
	InsecureSkipVerify           bool              `json:"insecureSkipVerify"`
	WithRandomTLSExtensionOrder  bool              `json:"withRandomTLSExtensionOrder"`
	DisableIPV6                  bool              `json:"disableIPV6"`
	DisableIPV4                  bool              `json:"disableIPV4"`
}

// WsConnectOutput is returned after a successful WebSocket handshake.
type WsConnectOutput struct {
	Id           string `json:"id"`
	ConnectionId string `json:"connectionId"`
	SessionId    string `json:"sessionId,omitempty"`
	Status       int    `json:"status"`
}

// WsReadInput contains the parameters for reading a single message from a WebSocket connection.
type WsReadInput struct {
	ConnectionId        string `json:"connectionId"`
	TimeoutMilliseconds int    `json:"timeoutMilliseconds"`
}

// WsReadOutput contains a message received from a WebSocket connection.
// MessageType 1 = text, 2 = binary (Data is base64-encoded for binary messages).
type WsReadOutput struct {
	Id           string `json:"id"`
	ConnectionId string `json:"connectionId"`
	MessageType  int    `json:"messageType"`
	Data         string `json:"data"`
}

// WsWriteInput contains the parameters for sending a message over a WebSocket connection.
// For binary messages (MessageType 2), Data must be base64-encoded.
// TimeoutMilliseconds > 0 bounds how long the write may block (peer not reading, dead path); a write
// that times out closes the connection. 0 = no deadline.
type WsWriteInput struct {
	ConnectionId        string `json:"connectionId"`
	Data                string `json:"data"`
	MessageType         int    `json:"messageType"`
	TimeoutMilliseconds int    `json:"timeoutMilliseconds"`
}

// WsWriteOutput is returned after sending a WebSocket message.
type WsWriteOutput struct {
	Id           string `json:"id"`
	ConnectionId string `json:"connectionId"`
	Success      bool   `json:"success"`
}

// WsCloseInput contains the parameters for closing a WebSocket connection.
type WsCloseInput struct {
	ConnectionId string `json:"connectionId"`
}

// WsCloseOutput is returned after closing a WebSocket connection.
type WsCloseOutput struct {
	Id      string `json:"id"`
	Success bool   `json:"success"`
}

// WsStatsInput contains the parameters for reading a WebSocket connection's diagnostics.
type WsStatsInput struct {
	ConnectionId string `json:"connectionId"`
}

// WsStatsOutput is a diagnostic snapshot of a WebSocket connection. Counters are application
// messages (not control frames). MsSince* are -1 when nothing was read / written yet.
type WsStatsOutput struct {
	Tcp                 *WsTcpInfo `json:"tcp,omitempty"`
	Id                  string     `json:"id"`
	ConnectionId        string     `json:"connectionId"`
	LocalAddr           string     `json:"localAddr"`
	RemoteAddr          string     `json:"remoteAddr"`
	AgeMs               int64      `json:"ageMs"`
	MessagesRead        int64      `json:"messagesRead"`
	MessagesWritten     int64      `json:"messagesWritten"`
	BytesRead           int64      `json:"bytesRead"`
	BytesWritten        int64      `json:"bytesWritten"`
	MsSinceLastRead     int64      `json:"msSinceLastRead"`
	MsSinceLastWrite    int64      `json:"msSinceLastWrite"`
	LastWriteDurationMs int64      `json:"lastWriteDurationMs"`
	MaxWriteDurationMs  int64      `json:"maxWriteDurationMs"`
	UnreadPending       bool       `json:"unreadPending"`
}

// WsTcpInfo is the kernel's view of the TCP socket (linux TCP_INFO). With a proxy this is the
// connection to the proxy. Growing Unacked / Retransmits with a stale MsSinceLastAckRecv means
// our bytes are not being acknowledged: the path is dead even though writes still "succeed".
type WsTcpInfo struct {
	State               uint8  `json:"state"` // 1 = ESTABLISHED
	Retransmits         uint8  `json:"retransmits"`
	Backoff             uint8  `json:"backoff"`
	RtoMs               uint32 `json:"rtoMs"`
	RttMs               uint32 `json:"rttMs"`
	Unacked             uint32 `json:"unacked"`
	Lost                uint32 `json:"lost"`
	TotalRetrans        uint32 `json:"totalRetrans"`
	NotsentBytes        uint32 `json:"notsentBytes"`
	MsSinceLastDataSent uint32 `json:"msSinceLastDataSent"`
	MsSinceLastDataRecv uint32 `json:"msSinceLastDataRecv"`
	MsSinceLastAckRecv  uint32 `json:"msSinceLastAckRecv"`
}

// ReadStreamInput is the input for the readStream cffi export.
//
// TimeoutMs:
//
//	< 0  block until the next chunk, EOF, or error
//	  0  non-blocking poll: returns Timeout=true immediately when no chunk is buffered
//	> 0  block up to TimeoutMs, then return Timeout=true if no chunk arrived
type ReadStreamInput struct {
	StreamId  string `json:"streamId"`
	TimeoutMs int    `json:"timeoutMs"`
}

// ReadStreamAllInput is the input for the readStreamAll cffi export.
type ReadStreamAllInput struct {
	StreamId string `json:"streamId"`
}

// CancelStreamInput is the input for the cancelStream cffi export.
type CancelStreamInput struct {
	StreamId string `json:"streamId"`
}

// StreamStartResponse is returned by requestStream. It carries the same fields
// as Response (status, headers, cookies, ...) with an empty Body and an
// additional StreamId. The caller uses StreamId for subsequent readStream /
// readStreamAll / cancelStream calls. Body is always empty here.
type StreamStartResponse struct {
	Response
	StreamId string `json:"streamId"`
}

// StreamChunkResponse is returned by readStream.
//
// Exactly one of EOF, Timeout, Error, or a non-empty Chunk is set on a
// successful call:
//   - Chunk (base64) holds the next slice of decompressed body bytes.
//   - EOF=true means the stream completed naturally; the StreamId is invalid
//     after this call.
//   - Timeout=true means no data was available within TimeoutMs; the stream
//     is still live and the caller may retry.
//   - Error holds a non-empty message when the underlying read failed, or when
//     the stream was aborted because the caller did not read for 60 s while
//     the chunk buffer was full (the body is incomplete then); the StreamId is
//     invalid after this call.
//
// A stream whose body has ended but that nobody reads for 5 minutes is removed;
// reading it later reports an unknown streamId.
type StreamChunkResponse struct {
	Id       string `json:"id"`
	StreamId string `json:"streamId"`
	Chunk    string `json:"chunk"`
	Error    string `json:"error,omitempty"`
	EOF      bool   `json:"eof"`
	Timeout  bool   `json:"timeout"`
}
