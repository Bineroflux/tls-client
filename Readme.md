# TLS-Client

### Preface

This TLS Client is built upon https://github.com/Carcraftz/fhttp and https://github.com/Carcraftz/utls (https://github.com/refraction-networking/utls). Big thanks to
all contributors so far. Sadly it seems that the original repositories from Carcraftz are not maintained anymore.

### What is TLS Fingerprinting?

Some people think it is enough to change the user-agent header of a request to let the server think that the client
requesting a resource is a specific browser.
Nowadays this is not enough, because the server might use a technique to detect the client browser which is called TLS
Fingerprinting.

Even though this article is about TLS Fingerprinting in NodeJS it well describes the technique in general.
https://httptoolkit.tech/blog/tls-fingerprinting-node-js/#how-does-tls-fingerprinting-work

### Why is this library needed?

With this library you are able to create a http client implementing an interface which is similar to golangs net/http
client interface.
This TLS Client allows you to specify the Client (Browser and Version) you want to use, when requesting a server.

### Features

- ✅ **HTTP/1.1, HTTP/2, HTTP/3** - Full protocol support with automatic negotiation
- ✅ **Protocol Racing** - Chrome-like "Happy Eyeballs" for HTTP/2 vs HTTP/3
- ✅ **TLS Fingerprinting** - Mimic Chrome, Firefox, Safari, and other browsers
- ✅ **HTTP/3 Fingerprinting** - Accurate QUIC/HTTP/3 fingerprints matching real browsers
- ✅ **WebSocket Support** - Maintain TLS fingerprinting over WebSocket connections
- ✅ **Custom Header Ordering** - Control the order of HTTP headers
- ✅ **Proxy Support** - HTTP and SOCKS5 proxies
- ✅ **Cookie Jar Management** - Built-in cookie handling
- ✅ **Certificate Pinning** - Enhanced security with custom certificate validation
- ✅ **Bandwidth Tracking** - Monitor upload/download bandwidth
- ✅ **Response Streaming** - Consume SSE, NDJSON, and chunked responses incrementally via cffi
- ✅ **Language Bindings** - Use from JavaScript (Node.js), Python, and C# via FFI

### Interface

The HTTP Client interface extends the base net/http Client with additional functionality:

```go
type HttpClient interface {
    GetCookies(u *url.URL) []*http.Cookie
    SetCookies(u *url.URL, cookies []*http.Cookie)
    SetCookieJar(jar http.CookieJar)
    GetCookieJar() http.CookieJar
    SetProxy(proxyUrl string) error
    GetProxy() string
    SetFollowRedirect(followRedirect bool)
    GetFollowRedirect() bool
    CloseIdleConnections()
    Do(req *http.Request) (*http.Response, error)
    Get(url string) (resp *http.Response, err error)
    Head(url string) (resp *http.Response, err error)
    Post(url, contentType string, body io.Reader) (resp *http.Response, err error)

    GetBandwidthTracker() bandwidth.BandwidthTracker
    GetDialer() proxy.ContextDialer
    GetTLSDialer() TLSDialerFunc
}
```

### Detailed Documentation

https://bogdanfinn.gitbook.io/open-source-oasis/

### Quick Usage Example

```go
package main

import (
	"fmt"
	"io"
	"log"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

func main() {
	jar := tls_client.NewCookieJar()
	options := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_150),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithCookieJar(jar), // create cookieJar instance and pass it as argument
	}

	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
	if err != nil {
		log.Println(err)
		return
	}

	req, err := http.NewRequest(http.MethodGet, "https://tls.peet.ws/api/all", nil)
	if err != nil {
		log.Println(err)
		return
	}

	req.Header = http.Header{
		"accept":                    {"*/*"},
		"accept-language":           {"de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"},
		"user-agent":                {"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"},
		http.HeaderOrderKey: {
			"accept",
			"accept-language",
			"user-agent",
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}

	defer resp.Body.Close()

	log.Println(fmt.Sprintf("status code: %d", resp.StatusCode))

	readBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return
	}

	log.Println(string(readBytes))
}
```

---

### Using the Library via CGo / Native Shared Library (cffi)

In addition to being imported as a Go module, tls-client can be compiled into a shared library (`.so` / `.dll` / `.dylib`) and called from any language that supports C FFI — Python (`ctypes`), Node.js (`ffi-napi` / `ffi-rs`), C#, Rust, etc.  
The shared library is built from `cffi_dist/` with `go build -buildmode=c-shared` (CGO enabled); see `cffi_dist/build.sh` for the per-platform commands.  
`cffi_dist` is a module of its own that builds against the tls-client version pinned in `cffi_dist/go.mod`, not against the checkout around it. To build the library from local changes to `cffi_src/` (e.g. before they are released), create a Go workspace that uses both modules — `go work init . ./cffi_dist` in the repository root, and do not commit the `go.work` file — and run the build in `cffi_dist/`.

The following exports are available:

| Export | Input | Description |
|---|---|---|
| `request` | `RequestInput` JSON | Send a request and receive the full response body in one call |
| `requestStream` | `RequestInput` JSON | Send a request and return as soon as the response **headers** arrive, together with a `streamId`; the body keeps streaming in the background |
| `readStream` | `{ "streamId", "timeoutMs" }` | Fetch the next body chunk of a live stream; `timeoutMs` controls how long to wait (see below) |
| `readStreamAll` | `{ "streamId" }` | Drain all remaining body bytes in one call and return a normal response envelope |
| `cancelStream` | `{ "streamId" }` | Abort a stream early and release its resources; idempotent, also safe after EOF or an error |
| `wsConnect` | `WsConnectInput` JSON (`url`, plus `sessionId` or `tlsClientIdentifier` / `customTlsClient`, ...) | Open a WebSocket connection with the same TLS fingerprint and return a `connectionId` |
| `wsRead` | `{ "connectionId", "timeoutMilliseconds" }` | Read the next message (`messageType` 1 = text, 2 = binary with base64 `data`); `0` waits indefinitely |
| `wsWrite` | `{ "connectionId", "data", "messageType", "timeoutMilliseconds" }` | Send a text or binary (base64) message |
| `wsClose` | `{ "connectionId" }` | Close a WebSocket connection |
| `wsStats` | `{ "connectionId" }` | Return diagnostic counters for a WebSocket connection |
| `destroySession` | `{ "sessionId" }` | Remove a named session and close its connections |
| `destroyAll` | none | Remove all sessions (closing their connections) and cancel all active streams |
| `getCookiesFromSession` | `{ "sessionId", "url" }` | Return cookies stored in a named session for a given URL |
| `addCookiesToSession` | `{ "sessionId", "url", "cookies" }` | Inject cookies into a named session for a given URL |
| `freeMemory` | envelope `id` as a plain C string (not JSON) | Release the memory of a returned envelope; returns nothing |

Every export except `freeMemory` returns a `char*` pointing to a JSON envelope that carries an `id`.  
The caller **must** call `freeMemory(envelope.id)` for every returned envelope to avoid leaks — after copying or parsing the string, because the pointer is invalid afterwards.  
If a call fails (invalid input JSON, the request cannot be sent, ...), the envelope has the normal response shape with `"status": 0` and the error message in `body`. This also applies to `requestStream` (the envelope then has no `streamId`), to `readStreamAll` and to the `ws*` exports (including a `wsRead` timeout). `readStream` instead reports read failures and unknown stream IDs in its `error` field (see below).

#### Request / Response JSON shape

`request` and `requestStream` take the same `RequestInput` shape. Key fields:

```json
{
  "requestMethod": "GET",
  "requestUrl": "https://example.com",
  "tlsClientIdentifier": "chrome_150",
  "sessionId": "my-session",
  "timeoutSeconds": 30,
  "followRedirects": true,
  "headers": { "accept": "*/*" },
  "headerOrder": ["accept"],
  "requestCookies": [],
  "isByteResponse": false,
  "streamOutputBlockSize": 4096
}
```

- `timeoutSeconds` / `timeoutMilliseconds`: `0` (or omitted) uses the default of 30 s, a positive value sets a deadline, and a **negative value** (e.g. `-1`) disables the deadline. Set at most one of the two fields: a request that sets both to non-zero values fails. The deadline covers the whole response including reading the body, so use a negative value for long-lived SSE / chunked streams, otherwise it fires mid-stream. With a `sessionId`, the timeout is fixed by the request that creates the session; later requests on that session cannot change it.
- `streamOutputBlockSize`: with `requestStream`, the maximum size in bytes of one chunk (default 4096).
- `isByteResponse`: with `requestStream`, this only affects `readStreamAll` (body returned as a `data:<mime>;base64,...` URL). `readStream` chunks are always base64-encoded.

#### Response Streaming

The four streaming exports let you consume Server-Sent Events, NDJSON feeds, or any other long-lived chunked response without buffering the entire body before returning.

**Flow:**

1. Call `requestStream`. It returns once the response headers are in, with the usual response envelope (`status`, `headers`, `cookies`, `target`, `usedProtocol`, an empty `body`) plus a `streamId`.
2. Loop calling `readStream` with `{ "streamId": "<id>", "timeoutMs": 5000 }` to fetch one chunk at a time.  
   `timeoutMs`: `0` (or omitted) polls without blocking, a positive value waits up to that many milliseconds, a negative value blocks until data, EOF or an error arrives.  
   Each chunk envelope has the shape `{ "id": "...", "streamId": "...", "chunk": "<base64>", "eof": false, "timeout": false }`, plus an `error` field only when a read failed. Exactly one of these is set:

   | Field | Meaning |
   |---|---|
   | `chunk` (non-empty) | The next slice of the body: decompressed raw bytes, base64-encoded, without charset conversion |
   | `timeout: true` | No data arrived within `timeoutMs`; the stream is still alive, call `readStream` again |
   | `eof: true` | The body is complete; the `streamId` is no longer valid |
   | `error` | Reading the body failed (e.g. the server reset the HTTP/2 stream); the `streamId` is no longer valid |

   When an HTTP/2 stream ends abnormally, the `error` text says which side ended it. The original transport error always stays at the end of the message:
   - `http2 stream reset by remote peer (RST_STREAM, code ...)`: the server, or a proxy / CDN in front of it, aborted the stream.
   - `http2 stream ended with PROTOCOL_ERROR and no further detail`: either the server sent `RST_STREAM(PROTOCOL_ERROR)` or tls-client rejected a malformed frame; the transport reports both the same way.
   - `http2 stream aborted by the local transport (code ...)`: tls-client rejected malformed data from the server, e.g. an invalid header field.
   - `http2 connection closed by remote peer after GOAWAY`: the server closed the whole connection.

   `readStreamAll` and `request` report a failed body read with the same texts in `body`. The peer-reset detection also recognizes the `received from peer` marker that newer `golang.org/x/net` versions set, by its text.

3. Call `cancelStream` in your `finally` block to release the connection, even on early exit.

Alternatively, call `readStreamAll` after `requestStream` (or after some `readStream` calls) to drain the rest of the body in one shot — useful when the response turns out not to be a stream after all. It returns the same envelope shape as `request`.

The Go side buffers up to 64 chunks per stream. If that buffer is full and the caller does not read for 60 seconds, the stream is torn down: after the chunks already buffered, `readStream` reports an `error` starting with `stream aborted`, and `readStreamAll` fails, because the body is incomplete. As soon as the body has ended, its connection is released; the buffered chunks stay readable. A stream whose body has ended but that is not read for 5 minutes is discarded, and later reads report an unknown `streamId`. So keep reading, or call `cancelStream`.

With `withDebug: true`, tls-client reads the whole body before `requestStream` returns, to log it. The response is then not streamed, so do not combine the two for long-lived streams.

**Python example (SSE / NDJSON):**

```python
import base64, codecs, ctypes, json

# Load the library built for your platform, e.g. tls-client-linux-ubuntu-amd64-<version>.so
lib = ctypes.cdll.LoadLibrary("./tls-client.so")

for fn in (lib.requestStream, lib.readStream, lib.readStreamAll, lib.cancelStream):
    fn.argtypes = [ctypes.c_char_p]
    fn.restype = ctypes.c_char_p   # ctypes copies the returned C string into Python bytes

lib.freeMemory.argtypes = [ctypes.c_char_p]
lib.freeMemory.restype = None      # freeMemory returns nothing

def call(fn, payload):
    raw = fn(json.dumps(payload).encode("utf-8"))
    envelope = json.loads(raw.decode("utf-8"))       # parse first ...
    lib.freeMemory(envelope["id"].encode("utf-8"))   # ... then release the C string
    return envelope

# 1. Start the stream
start = call(lib.requestStream, {
    "requestMethod": "GET",
    "requestUrl": "https://httpbin.org/stream/5",
    "tlsClientIdentifier": "chrome_150",
    "timeoutSeconds": -1,   # no deadline for long-lived streams
})
if start.get("status", 0) == 0:
    raise RuntimeError(f"requestStream failed: {start.get('body')}")
stream_id = start["streamId"]

# 2. Read chunks until EOF
decoder = codecs.getincrementaldecoder("utf-8")()  # a UTF-8 character may span two chunks
try:
    while True:
        chunk = call(lib.readStream, {"streamId": stream_id, "timeoutMs": 5000})
        if chunk.get("error"):
            raise RuntimeError(f"stream failed: {chunk['error']}")
        if chunk.get("timeout"):
            continue        # nothing yet, but the stream is still alive: poll again
        if chunk.get("chunk"):
            print(decoder.decode(base64.b64decode(chunk["chunk"])), end="", flush=True)
        if chunk.get("eof"):
            print(decoder.decode(b"", final=True), end="")
            break
finally:
    # 3. Always cancel to release the connection (idempotent, safe after EOF or an error)
    call(lib.cancelStream, {"streamId": stream_id})
```

A complete, commented Python example (including `readStreamAll`) is in `cffi_dist/example_python/example_stream.py`. The Node.js, TypeScript and C# examples in `cffi_dist/` only cover the non-streaming exports.

#### Decrypting the traffic with Wireshark

Set the environment variable `TLS_CLIENT_SSLKEYLOGFILE` to a file path before the process loads the library. The shared library then appends the TLS session secrets of every connection to that file in the NSS key log format, which Wireshark reads (Preferences → Protocols → TLS → (Pre)-Master-Secret log filename). The variable is read once, when the first client is created, and tls-client prints a warning to stderr while key logging is on. The generic `SSLKEYLOGFILE` that browsers and curl read is deliberately ignored, so a machine-wide setting for browser debugging does not make every application that uses tls-client write its secrets to disk; to capture both in one file, point both variables at the same path. Use this for debugging only: anyone with the file can decrypt the captured traffic.

---

### Questions?

Join my discord support server for free: https://discord.gg/7Ej9eJvHqk
No Support in DMs!


### Appreciate my work?

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/CaptainBarnius)

Or, if you prefer crypto:

- **ETH** `0x1Ef18abfE61372e49F08eD24B1055cbDD5d7e0Fc`
- **BTC** `bc1qkfqu5xvayqh55gwjtyannvyqzr4cax4eu3k2u6`
- **ADA** `addr1qxj5hg5xfq9l5r5ed7av7mzg0gy5xemn64lkna5cuu9e4yt0vk8st6zvmfuqjdz849drd7zgcdky4zrdvm603dzf4dgs5unend`
- **SOL** `7hYfiX4R5bEbggYY2JRZi2a3EdcEzQ6XbgZiHRiRHjau`

---

## 🛡️ Need Antibot Bypass?

<a href="https://hypersolutions.co/?utm_source=github&utm_medium=readme&utm_campaign=tls-client" target="_blank"><img src="https://raw.githubusercontent.com/bogdanfinn/tls-client/master/.github/assets/hypersolutions.jpg" height="47" width="149"></a>

TLS fingerprinting alone isn't enough for modern bot protection. **[Hyper Solutions](https://hypersolutions.co?utm_source=github&utm_medium=readme&utm_campaign=tls-client)** provides the missing piece - API endpoints that generate valid antibot tokens for:

**Akamai** • **DataDome** • **Kasada** • **Incapsula**

No browser automation. Just simple API calls that return the exact cookies and headers these systems require.

🚀 **[Get Your API Key](https://hypersolutions.co?utm_source=github&utm_medium=readme&utm_campaign=tls-client)** | 📖 **[Docs](https://docs.justhyped.dev)** | 💬 **[Discord](https://discord.gg/akamai)**

---

### Powered by
[![JetBrains logo.](https://resources.jetbrains.com/storage/products/company/brand/logos/jetbrains.svg)](https://jb.gg/OpenSource)