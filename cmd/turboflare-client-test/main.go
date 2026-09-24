// Command turboflare-client-test is a manual, interactive-ish test
// harness for exercising the full protocol (handshake, CONNECT, real
// TCP relay, congestion control, polling) against a REAL deployed
// server through the REAL TurboFlare CDN -- not the in-process
// httptest.Server the automated integration tests use.
//
// Example:
//
//	go run ./cmd/turboflare-client-test \
//	    -base-url=https://pelevin-art.ru \
//	    -server-pub=bf88ebfa5312d8b1e7c8cdf656499e5b09dc33d0a1c8ef02f463004331c97d4d \
//	    -token=test-token-12345 \
//	    -target=example.com:80
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"turboflare-transport/client"
	"turboflare-transport/proto"
)

func main() {
	baseURL := flag.String("base-url", "https://pelevin-art.ru", "server base URL, through the CDN")
	serverPubHex := flag.String("server-pub", "", "server's static X25519 public key, hex-encoded (required)")
	token := flag.String("token", "", "provisioning token (required)")
	deviceIDHex := flag.String("device-id", "c0ffeec0ffee0001", "device_id, hex-encoded (any 8 bytes for a test run)")
	target := flag.String("target", "example.com:80", "host:port for the server to CONNECT to")
	httpRequest := flag.String("http-request", "", "raw HTTP request to send once connected (default: a simple GET to the target host)")
	pollDuration := flag.Duration("poll-duration", 8*time.Second, "how long to keep polling for a response after sending data")
	pollInterval := flag.Duration("poll-interval", 300*time.Millisecond, "delay between polls")
	flag.Parse()

	if *serverPubHex == "" || *token == "" {
		log.Fatal("both -server-pub and -token are required")
	}

	pubRaw, err := hex.DecodeString(*serverPubHex)
	if err != nil || len(pubRaw) != proto.X25519KeySize {
		log.Fatalf("invalid -server-pub: %v", err)
	}
	pub, err := proto.LoadX25519PublicKey(pubRaw)
	if err != nil {
		log.Fatalf("load server pubkey: %v", err)
	}

	deviceIDRaw, err := hex.DecodeString(*deviceIDHex)
	if err != nil || len(deviceIDRaw) != 8 {
		log.Fatalf("invalid -device-id (need 8 bytes hex): %v", err)
	}
	var deviceID uint64
	for _, b := range deviceIDRaw {
		deviceID = (deviceID << 8) | uint64(b)
	}

	req := *httpRequest
	if req == "" {
		host := strings.Split(*target, ":")[0]
		req = fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	}

	c := client.New(*baseURL, pub, deviceID, *token)

	fmt.Println("=== Step 1: handshake (Open) ===")
	t0 := time.Now()
	if err := c.Open(); err != nil {
		log.Fatalf("Open failed: %v", err)
	}
	fmt.Printf("OK, connection_id=%08x, rtt=%s\n\n", c.Session.ConnectionID, time.Since(t0))

	fmt.Printf("=== Step 2: CONNECT to %s ===\n", *target)
	if err := c.Push([]byte(*target)); err != nil {
		log.Fatalf("Push (CONNECT) failed: %v", err)
	}

	connected := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		payloads, err := c.Pull()
		if err != nil {
			log.Fatalf("Pull failed: %v", err)
		}
		for _, p := range payloads {
			s := string(p)
			fmt.Printf("  <- %q\n", s)
			if strings.HasPrefix(s, "OK CONNECTED") {
				connected = true
			}
			if strings.HasPrefix(s, "ERROR") {
				log.Fatalf("server reported error: %s", s)
			}
		}
		if connected {
			break
		}
		time.Sleep(*pollInterval)
	}
	if !connected {
		log.Fatal("timed out waiting for OK CONNECTED")
	}
	fmt.Println()

	fmt.Println("=== Step 3: send HTTP request through the tunnel ===")
	fmt.Printf("  -> %q\n\n", req)
	if err := c.Push([]byte(req)); err != nil {
		log.Fatalf("Push (data) failed: %v", err)
	}

	fmt.Println("=== Step 4: polling for the response ===")
	respDeadline := time.Now().Add(*pollDuration)
	var totalBytes int
	for time.Now().Before(respDeadline) {
		payloads, err := c.Pull()
		if err != nil {
			log.Fatalf("Pull failed: %v", err)
		}
		for _, p := range payloads {
			totalBytes += len(p)
			fmt.Printf("--- chunk (%d bytes) ---\n%s\n", len(p), string(p))
		}
		time.Sleep(*pollInterval)
	}

	fmt.Printf("\n=== Done. Total response bytes received: %d ===\n", totalBytes)
	fmt.Printf("Final congestion state: window=%d block_size=%d\n",
		c.Session.Congestion.CurrentWindow(), c.Session.Congestion.CurrentBlockSize())
}
