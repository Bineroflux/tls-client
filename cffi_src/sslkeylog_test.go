package tls_client_cffi_src

import (
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetSSLKeyLog makes the next sslKeyLogWriterFromEnv call read the environment
// again, and closes the file a previous call opened (Windows cannot remove an
// open file from t.TempDir).
func resetSSLKeyLog(t *testing.T) {
	t.Helper()
	reset := func() {
		if f, ok := sslKeyLogWriter.(*os.File); ok {
			_ = f.Close()
		}
		sslKeyLogOnce = sync.Once{}
		sslKeyLogWriter = nil
	}
	reset()
	t.Cleanup(reset)
}

func TestOpenSSLKeyLogFile_EmptyPathDisables(t *testing.T) {
	assert.Nil(t, openSSLKeyLogFile(""))
}

func TestOpenSSLKeyLogFile_UnopenablePathDisables(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-dir", "keys.log")
	assert.Nil(t, openSSLKeyLogFile(path))
}

func TestSSLKeyLogWriterFromEnv_IgnoresGenericSSLKEYLOGFILE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "browser-keys.log")
	resetSSLKeyLog(t) // after TempDir, so the file is closed before the directory is removed
	t.Setenv("SSLKEYLOGFILE", path)
	t.Setenv(sslKeyLogEnvVar, "")

	assert.Nil(t, sslKeyLogWriterFromEnv(), "the generic SSLKEYLOGFILE must not enable key logging")
	_, err := os.Stat(path)
	assert.True(t, os.IsNotExist(err), "no key log file may be created")
}

func TestSSLKeyLogWriterFromEnv_WritesSecretsOfARealHandshake(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tls-client-keys.log")
	resetSSLKeyLog(t) // after TempDir, so the file is closed before the directory is removed
	t.Setenv(sslKeyLogEnvVar, path)

	server := httptest.NewTLSServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	client, err := getTlsClient(RequestInput{
		TLSClientIdentifier: "chrome_150",
		InsecureSkipVerify:  true,
		FollowRedirects:     true,
	}, "keylog-test", false)
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Get(server.URL)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(content), "CLIENT_HANDSHAKE_TRAFFIC_SECRET") ||
		strings.Contains(string(content), "CLIENT_RANDOM"),
		"the key log must contain the secrets of the handshake, got %q", string(content))
}
