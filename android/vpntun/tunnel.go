// Package vpntun bridges a raw TUN file descriptor (from Android's
// VpnService.Builder.establish()) to our existing CONNECT-based
// transport protocol (client.Client, unchanged from the manual test
// harness in cmd/turboflare-client-test).
//
// Uses gVisor's netstack (gvisor.dev/gvisor/pkg/tcpip) as the userspace
// TCP/IP stack -- the same general approach used by Outline, Shadowsocks-
// Android, and most Android tun2socks-style VPN clients, rather than
// hand-parsing IP packets ourselves.
//
// BUILD NOTE: this package needs gvisor.dev/gvisor, which this
// environment could not fetch (no network). After adding it to the
// module:
//
//	go get gvisor.dev/gvisor@latest
//	go mod tidy
//
// verify the exact API surface against the version you get -- gVisor's
// tcpip package has shifted internal structure across releases; the
// shapes used below (fdbased.Options, stack.Options, tcp.NewForwarder,
// gonet.NewTCPConn) reflect a commonly-used stable surface but MUST be
// checked against your fetched version before this will compile cleanly
// (same spirit as the fingerprint/utlsclient HelloChrome_* version note).
//
// KNOWN LIMITATION (scope, not a bug): every intercepted TCP flow opens
// its OWN protocol session (its own X25519 handshake + CONNECT), reusing
// client.Client exactly as-is. This is simple and correct, but doesn't
// scale well -- a browser opening 20 connections does 20 handshakes.
// The wire format already carries a stream_id field for multiplexing
// many flows over one session (see proto/frame.go), but the SERVER side
// (server/server.go) only supports one outbound connection per session
// today. Multiplexed CONNECT is the natural next upgrade, not
// implemented here -- flagged rather than silently left as a surprise.
//
// UDP is mostly NOT handled -- general UDP packets arriving on the TUN
// interface are dropped. The one exception, added after real-device
// testing surfaced it as a hard blocker rather than a nice-to-have: DNS
// (UDP port 53) is intercepted and relayed as DNS-over-TCP (RFC 1035
// §4.2.2, supported by essentially every public resolver) through the
// SAME CONNECT-based TCP relay everything else uses -- one dedicated,
// persistent session opened once per tunnel lifetime (not one per
// query), serialized behind a mutex. This keeps every other UDP
// protocol (QUIC/HTTP3, WireGuard-in-app, game traffic, etc.) as a
// still-open limitation, but unblocks ordinary DNS resolution, which
// browsers and most apps need before anything else works at all.
package vpntun

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"turboflare-transport/client"
	"turboflare-transport/proto"
)

// DNSUpstream is the DNS-over-TCP resolver every tunnel relays queries
// to. Hardcoded to a well-known public resolver that reliably supports
// DNS-over-TCP -- not read from device DNS settings, since those are
// exactly what the TUN interface's own DNS config (see
// TurboflareVpnService.kt's addDnsServer call) is meant to override.
const DNSUpstream = "1.1.1.1:53"

const (
	nicID        tcpip.NICID = 1
	defaultMTU               = 1500
	tcpRecvBufSz             = 1 << 20
	tcpSendBufSz             = 1 << 20
)

// Config carries what every per-flow session needs to reach the
// TurboFlare server -- the exact same parameters client.New already
// takes, just bundled for reuse per flow.
type Config struct {
	BaseURL      string
	ServerPubHex string
	DeviceIDHex  string
	Token        string
}

// TunnelHandle controls a running tunnel; Stop() tears down the netstack
// and closes the TUN fd (ownership of which was transferred to this
// package by the caller via detachFd()).
type TunnelHandle struct {
	stack *stack.Stack
	wg    sync.WaitGroup
	dns   *dnsRelay
}

// Start builds the netstack over fd and begins relaying every
// intercepted TCP flow through the TurboFlare protocol. fd must be a
// valid, already-detached TUN file descriptor (see
// TurboflareVpnService.kt: ParcelFileDescriptor.detachFd()).
func Start(fd int, cfg Config) (*TunnelHandle, error) {
	linkEP, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: defaultMTU,
	})
	if err != nil {
		return nil, fmt.Errorf("vpntun: create fd-based endpoint: %w", err)
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if tcpipErr := s.CreateNIC(nicID, linkEP); tcpipErr != nil {
		return nil, fmt.Errorf("vpntun: create NIC: %v", tcpipErr)
	}

	// FIX (found via real-device testing): every UDP CreateEndpoint call
	// (used by both the TCP-CONNECT-style relay indirectly and directly
	// by the DNS UDP forwarder below) needs a LOCAL address to bind as
	// the connection's source when gVisor internally resolves a route
	// for the "connect" -- without one assigned to the NIC, that
	// resolution has nothing to pick, and gVisor surfaces this as
	// ECONNREFUSED on the endpoint (misleading error text, but that's
	// what it does) rather than a clearer "no local address" error.
	// nicAddr matches the address assigned via VpnService.Builder
	// .addAddress("10.0.0.2", 32) in TurboflareVpnService.kt -- the two
	// must stay in sync if either changes.
	nicAddr := tcpip.AddrFromSlice([]byte{10, 0, 0, 2})
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: nicAddr.WithPrefix(),
	}
	if tcpipErr := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		return nil, fmt.Errorf("vpntun: assign NIC address: %v", tcpipErr)
	}

	// The TUN device carries traffic for the whole device (or the
	// subset of apps selected for split tunnel, per VpnService's own
	// routing) -- promiscuous + spoofing mode lets the stack accept and
	// originate packets for addresses other than the NIC's own
	// configured address, which is required for acting as a router
	// rather than a single-host endpoint.
	_ = s.SetPromiscuousMode(nicID, true)
	_ = s.SetSpoofing(nicID, true)

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
	})

	h := &TunnelHandle{stack: s}

	dns, err := newDNSRelay(cfg)
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("vpntun: open DNS relay: %w", err)
	}
	h.dns = dns

	fwd := tcp.NewForwarder(s, tcpRecvBufSz, 1024, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		// NOTE (fixed after build error): older gVisor API split this
		// into CreatePassiveEndpoint(&wq) + a separate r.Complete(bool)
		// call. The version this project pins to (see
		// android/vpntun/README.md) merged these into one CreateEndpoint
		// call that performs the TCP three-way handshake internally --
		// there is no separate Complete() to call afterward.
		ep, epErr := r.CreateEndpoint(&wq)
		if epErr != nil {
			return
		}

		conn := gonet.NewTCPConn(&wq, ep)
		target := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			handleFlow(conn, target, cfg)
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		if id.LocalPort != 53 {
			return false // only DNS is relayed for UDP -- see package doc
		}

		var wq waiter.Queue
		ep, epErr := r.CreateEndpoint(&wq)
		if epErr != nil {
			return false
		}
		conn := gonet.NewUDPConn(&wq, ep)

		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			handleDNSFlow(conn, dns)
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return h, nil
}

// Stop tears down the stack, which closes the underlying TUN fd and
// unblocks any in-flight flows. Blocks until all per-flow goroutines
// have exited.
func (h *TunnelHandle) Stop() {
	h.stack.Close()
	h.wg.Wait()
	if h.dns != nil {
		h.dns.close()
	}
}

// handleFlow relays ONE intercepted TCP connection: opens its own
// protocol session (handshake + CONNECT to target), then pumps bytes
// both ways until either side closes. See the package doc's KNOWN
// LIMITATION note on why this is one-session-per-flow.
func handleFlow(conn *gonet.TCPConn, target string, cfg Config) {
	defer conn.Close()
	// A panic anywhere in this goroutine (e.g. writing to a connection
	// whose underlying netstack was torn down mid-flow by Stop()) would
	// otherwise crash the ENTIRE app process -- Go's default behavior
	// for an unrecovered panic in any goroutine, not just the main one.
	// Found via real-device testing: stopping and restarting the VPN
	// crashed the app, most likely because in-flight flow goroutines
	// from the OLD tunnel were still touching now-closed stack/endpoint
	// state when Stop() tore it down.
	defer func() {
		if r := recover(); r != nil {
			logf("vpntun: recovered panic in flow to %s: %v", target, r)
		}
	}()

	pubRaw, err := hex.DecodeString(cfg.ServerPubHex)
	if err != nil || len(pubRaw) != proto.X25519KeySize {
		logf("vpntun: invalid server pubkey config: %v", err)
		return
	}
	pub, err := proto.LoadX25519PublicKey(pubRaw)
	if err != nil {
		logf("vpntun: load server pubkey: %v", err)
		return
	}

	deviceIDRaw, err := hex.DecodeString(cfg.DeviceIDHex)
	if err != nil || len(deviceIDRaw) != 8 {
		logf("vpntun: invalid device_id config: %v", err)
		return
	}
	var deviceID uint64
	for _, b := range deviceIDRaw {
		deviceID = (deviceID << 8) | uint64(b)
	}

	c := client.New(cfg.BaseURL, pub, deviceID, cfg.Token)

	if err := c.Open(); err != nil {
		logf("vpntun: handshake failed for flow to %s: %v", target, err)
		return
	}

	if err := c.Push([]byte(target)); err != nil {
		logf("vpntun: CONNECT push failed for %s: %v", target, err)
		return
	}

	if !waitForConnected(c) {
		logf("vpntun: CONNECT to %s did not confirm", target)
		return
	}

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	// App -> tunnel: read from the local TCP connection (gVisor side,
	// i.e. bytes the on-device app sent) and push them through the
	// protocol.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("vpntun: recovered panic in app->tunnel pump: %v", r)
				closeDone()
			}
		}()
		buf := make([]byte, 16*1024) // matches the protocol's conservative target block size
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if pushErr := c.Push(buf[:n]); pushErr != nil {
					closeDone()
					return
				}
			}
			if err != nil {
				closeDone()
				return
			}
		}
	}()

	// Tunnel -> app: poll for responses and write them to the local
	// connection. Polling is the same model the manual test CLI and the
	// Android demo button already use -- no new mechanism here.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logf("vpntun: recovered panic in tunnel->app pump: %v", r)
				closeDone()
			}
		}()
		for {
			select {
			case <-done:
				return
			default:
			}
			payloads, err := c.Pull()
			if err != nil {
				closeDone()
				return
			}
			if len(payloads) == 0 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			for _, p := range payloads {
				if _, werr := conn.Write(p); werr != nil {
					closeDone()
					return
				}
			}
		}
	}()

	<-done
}

func waitForConnected(c *client.Client) bool {
	for i := 0; i < 50; i++ {
		payloads, err := c.Pull()
		if err != nil {
			return false
		}
		for _, p := range payloads {
			s := string(p)
			if len(s) >= 12 && s[:12] == "OK CONNECTED" {
				return true
			}
			if len(s) >= 5 && s[:5] == "ERROR" {
				return false
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

// -----------------------------------------------------------------------
// DNS relay: one persistent CONNECT session to DNSUpstream, reused for
// every DNS query from every app for the tunnel's whole lifetime.
// Queries are serialized (one in flight at a time) -- simple and
// correct, though it caps DNS throughput under heavy concurrent query
// load. A connection pool would remove that cap; not needed for
// personal use at the scale this prototype targets.
// -----------------------------------------------------------------------

type dnsRelay struct {
	mu  sync.Mutex
	c   *client.Client
	cfg Config
}

// openDNSSession performs the handshake + CONNECT for a fresh DNS relay
// TCP session. Factored out of newDNSRelay so reopen() (see resolve's
// error path below) can call it again without duplicating logic.
func openDNSSession(cfg Config) (*client.Client, error) {
	pubRaw, err := hex.DecodeString(cfg.ServerPubHex)
	if err != nil || len(pubRaw) != proto.X25519KeySize {
		return nil, fmt.Errorf("invalid server pubkey config: %w", err)
	}
	pub, err := proto.LoadX25519PublicKey(pubRaw)
	if err != nil {
		return nil, fmt.Errorf("load server pubkey: %w", err)
	}

	deviceIDRaw, err := hex.DecodeString(cfg.DeviceIDHex)
	if err != nil || len(deviceIDRaw) != 8 {
		return nil, fmt.Errorf("invalid device_id config: %w", err)
	}
	var deviceID uint64
	for _, b := range deviceIDRaw {
		deviceID = (deviceID << 8) | uint64(b)
	}

	c := client.New(cfg.BaseURL, pub, deviceID, cfg.Token)
	if err := c.Open(); err != nil {
		return nil, fmt.Errorf("dns relay handshake: %w", err)
	}
	if err := c.Push([]byte(DNSUpstream)); err != nil {
		return nil, fmt.Errorf("dns relay CONNECT: %w", err)
	}
	if !waitForConnected(c) {
		return nil, fmt.Errorf("dns relay CONNECT to %s did not confirm", DNSUpstream)
	}
	return c, nil
}

func newDNSRelay(cfg Config) (*dnsRelay, error) {
	c, err := openDNSSession(cfg)
	if err != nil {
		return nil, err
	}
	return &dnsRelay{c: c, cfg: cfg}, nil
}

// reopen discards the current (presumed corrupted/dead) session and
// establishes a fresh one. Caller must hold d.mu.
func (d *dnsRelay) reopen() {
	c, err := openDNSSession(d.cfg)
	if err != nil {
		logf("vpntun: DNS relay reopen failed: %v", err)
		return // keep the old (broken) session; next resolve() will retry reopening
	}
	d.c = c
	logf("vpntun: DNS relay session reopened")
}

// resolve sends one DNS message (raw wire-format query, WITHOUT the
// DNS-over-TCP 2-byte length prefix -- resolve adds it) and returns the
// matching response message (also with the prefix stripped).
//
// FIX (found via real-device testing): this session is persistent and
// shared across every DNS query for the tunnel's whole lifetime. If any
// single query times out (or otherwise errors) while the server had
// already queued bytes we never fully consumed, that leftover data
// permanently desyncs the length-prefix framing for every future query
// on the same session -- explains "works for a while, then breaks for
// good" rather than intermittent failures. On ANY error path here, the
// session is now unconditionally reopened before returning, so a single
// bad query costs one failed resolution instead of breaking DNS for the
// rest of the tunnel's life.
func (d *dnsRelay) resolve(query []byte, timeout time.Duration) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[0:2], uint16(len(query)))
	copy(framed[2:], query)

	if err := d.c.Push(framed); err != nil {
		d.reopen()
		return nil, fmt.Errorf("push DNS query: %w", err)
	}

	var buf []byte
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(buf) >= 2 {
			msgLen := int(binary.BigEndian.Uint16(buf[0:2]))
			if len(buf) >= 2+msgLen {
				return buf[2 : 2+msgLen], nil
			}
		}
		payloads, err := d.c.Pull()
		if err != nil {
			d.reopen()
			return nil, fmt.Errorf("pull DNS response: %w", err)
		}
		for _, p := range payloads {
			buf = append(buf, p...)
		}
		if len(payloads) == 0 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	// Timeout: the session may still have our query in flight, or
	// partial response bytes queued server-side -- either way, treat it
	// as corrupted and start clean rather than risk framing desync.
	d.reopen()
	return nil, fmt.Errorf("DNS relay timed out")
}

func (d *dnsRelay) close() {
	// client.Client has no explicit Close -- the underlying HTTP
	// connections are released by the standard library's transport as
	// the process/service tears down. Nothing else to release here.
}

// handleDNSFlow reads the triggering UDP datagram (one datagram = one
// DNS query, and -- since a standard OS UDP DNS client uses a fresh
// ephemeral source port per query -- the ONLY datagram this forwarder
// session will ever see) and relays it through the shared dnsRelay,
// writing the answer back as a single UDP datagram to the querying app.
//
// NOTE: an earlier attempt bypassed conn.Read() entirely via
// udp.ForwarderRequest.Packet(), which turned out not to exist in the
// gVisor version this project is pinned to (build error) -- reverted.
// The retry loop below is a pragmatic mitigation for the ECONNREFUSED
// seen on real devices: if it's a short-lived race right after
// CreateEndpoint (route/connect state not fully settled yet), a couple
// of quick retries should ride it out; if it's not transient, retrying
// costs only a few milliseconds before falling through to a real error.
func handleDNSFlow(conn *gonet.UDPConn, relay *dnsRelay) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			logf("vpntun: recovered panic in DNS flow: %v", r)
		}
	}()

	buf := make([]byte, 4096) // generously above typical DNS message sizes
	var query []byte
	var readErr error
	const maxAttempts = 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		n, err := conn.Read(buf)
		if err == nil {
			query = append([]byte(nil), buf[:n]...)
			readErr = nil
			if attempt > 0 {
				logf("vpntun: DNS UDP read succeeded on attempt %d/%d", attempt+1, maxAttempts)
			}
			break
		}
		readErr = err
		time.Sleep(30 * time.Millisecond)
	}
	if readErr != nil {
		logf("vpntun: DNS UDP read failed after %d attempts: %v", maxAttempts, readErr)
		return
	}

	resp, err := relay.resolve(query, 5*time.Second)
	if err != nil {
		logf("vpntun: DNS resolve failed: %v", err)
		return
	}
	if _, werr := conn.Write(resp); werr != nil {
		logf("vpntun: DNS UDP write error: %v", werr)
	}
}

// -----------------------------------------------------------------------
// In-app log buffer: mirrors every logf() call (used throughout this
// package instead of calling log.Printf directly) into a small ring
// buffer that the Android UI can poll and display, so debugging the
// tunnel doesn't require `adb logcat` every time. Still also writes to
// the standard log package, so logcat-based debugging keeps working too.
// -----------------------------------------------------------------------

var (
	logMu  sync.Mutex
	logBuf []string
)

const logBufCap = 500

func logf(format string, args ...interface{}) {
	line := fmt.Sprintf(format, args...)
	log.Print(line)

	logMu.Lock()
	logBuf = append(logBuf, line)
	if len(logBuf) > logBufCap {
		logBuf = logBuf[len(logBuf)-logBufCap:]
	}
	logMu.Unlock()
}

// DrainLogs returns every buffered log line (newline-joined) since the
// last call and clears the buffer. Exposed through gomobilebridge for
// the Android UI to poll periodically.
func DrainLogs() string {
	logMu.Lock()
	defer logMu.Unlock()
	if len(logBuf) == 0 {
		return ""
	}
	joined := ""
	for i, l := range logBuf {
		if i > 0 {
			joined += "\n"
		}
		joined += l
	}
	logBuf = logBuf[:0]
	return joined
}
