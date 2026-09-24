package integration

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"turboflare-transport/client"
	"turboflare-transport/proto"
	"turboflare-transport/server"
)

// startLocalEchoListener spins up a plain TCP server that echoes back
// whatever it receives -- standing in for "some real internet service"
// so this test doesn't depend on actual internet egress.
func startLocalEchoListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start local echo listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed, test cleanup
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().String()
}

func TestEndToEnd_ConnectAndForwardToRealTCP(t *testing.T) {
	echoAddr := startLocalEchoListener(t)

	serverPriv, err := proto.GenerateEphemeralKeypair()
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}

	tokens := server.NewTokenStore()
	const testToken = "test-provisioning-token"
	tokens.RegisterToken(testToken)

	srv := server.New(serverPriv, tokens)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := client.New(ts.URL, serverPriv.PublicKey(), 0xC0FFEE, testToken)

	if err := c.Open(); err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	// First payload on a fresh session is the CONNECT command.
	if err := c.Push([]byte(echoAddr)); err != nil {
		t.Fatalf("client.Push (CONNECT): %v", err)
	}

	confirmed := pollUntil(t, c, "OK CONNECTED", 2*time.Second)
	if !confirmed {
		t.Fatal("did not receive OK CONNECTED confirmation from server")
	}

	// Now push real data -- the server should forward it to the local
	// echo listener and relay the echoed response back.
	if err := c.Push([]byte("hello real internet")); err != nil {
		t.Fatalf("client.Push (data): %v", err)
	}

	got := pollUntilContains(t, c, "hello real internet", 2*time.Second)
	if !got {
		t.Fatal("did not receive forwarded+echoed payload back through the tunnel")
	}
}

func TestEndToEnd_ConnectToUnreachableTargetReportsError(t *testing.T) {
	serverPriv, _ := proto.GenerateEphemeralKeypair()
	tokens := server.NewTokenStore()
	const testToken = "unreachable-token"
	tokens.RegisterToken(testToken)

	srv := server.New(serverPriv, tokens)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := client.New(ts.URL, serverPriv.PublicKey(), 0xBAD1, testToken)
	if err := c.Open(); err != nil {
		t.Fatalf("client.Open: %v", err)
	}

	// Port 1 on localhost should reliably refuse the connection.
	if err := c.Push([]byte("127.0.0.1:1")); err != nil {
		t.Fatalf("client.Push (CONNECT): %v", err)
	}

	got := pollUntilContains(t, c, "ERROR", 3*time.Second)
	if !got {
		t.Fatal("expected an ERROR payload back for an unreachable target")
	}
}

func TestEndToEnd_SecondDeviceRejectedWhileTokenBound(t *testing.T) {
	serverPriv, _ := proto.GenerateEphemeralKeypair()
	tokens := server.NewTokenStore()
	const testToken = "shared-token"
	tokens.RegisterToken(testToken)

	srv := server.New(serverPriv, tokens)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceA := client.New(ts.URL, serverPriv.PublicKey(), 0x1111, testToken)
	if err := deviceA.Open(); err != nil {
		t.Fatalf("deviceA.Open: %v", err)
	}

	deviceB := client.New(ts.URL, serverPriv.PublicKey(), 0x2222, testToken)
	if err := deviceB.Open(); err == nil {
		t.Fatal("expected deviceB.Open to be rejected while token is bound to deviceA")
	}
}

func TestEndToEnd_RevokeAllowsNewDevice(t *testing.T) {
	serverPriv, _ := proto.GenerateEphemeralKeypair()
	tokens := server.NewTokenStore()
	const testToken = "revocable-token"
	tokens.RegisterToken(testToken)

	srv := server.New(serverPriv, tokens)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	deviceA := client.New(ts.URL, serverPriv.PublicKey(), 0xAAAA, testToken)
	if err := deviceA.Open(); err != nil {
		t.Fatalf("deviceA.Open: %v", err)
	}

	tokens.Revoke(testToken)

	deviceB := client.New(ts.URL, serverPriv.PublicKey(), 0xBBBB, testToken)
	if err := deviceB.Open(); err != nil {
		t.Fatalf("deviceB.Open after revoke should succeed: %v", err)
	}
}

func TestEndToEnd_ReconnectConfirmsKeyAndClosesGrace(t *testing.T) {
	serverPriv, _ := proto.GenerateEphemeralKeypair()
	tokens := server.NewTokenStore()
	const testToken = "reconnect-token"
	tokens.RegisterToken(testToken)

	srv := server.New(serverPriv, tokens)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	c := client.New(ts.URL, serverPriv.PublicKey(), 0xFEED, testToken)
	if err := c.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	originalConnID := c.Session.ConnectionID

	if err := c.Reconnect(); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if c.Session.ConnectionID != originalConnID {
		t.Fatalf("reconnect should reuse the same connection_id: got %d, want %d", c.Session.ConnectionID, originalConnID)
	}
	if st := c.Session.Reconnect.Status(); st.Active || !st.Confirmed {
		t.Fatalf("expected grace period to be confirmed-closed after successful reconnect, got %+v", st)
	}
}

// pollUntil polls Pull() repeatedly until a payload exactly matching
// want arrives, or the timeout expires.
func pollUntil(t *testing.T, c *client.Client, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		payloads, err := c.Pull()
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		for _, p := range payloads {
			if string(p) == want {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// pollUntilContains is like pollUntil but matches by substring, since
// forwarded TCP responses may arrive as multiple chunks.
func pollUntilContains(t *testing.T, c *client.Client, wantSubstr string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		payloads, err := c.Pull()
		if err != nil {
			t.Fatalf("Pull: %v", err)
		}
		for _, p := range payloads {
			if contains(string(p), wantSubstr) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
