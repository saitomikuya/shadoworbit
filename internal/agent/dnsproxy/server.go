package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"snell-panel/internal/protocol"
)

const (
	maxEphemeralBindAttempts = 16
	defaultShutdownTimeout   = 5 * time.Second
)

type runningInstance struct {
	host      string
	port      int
	udpAddr   string
	tcpAddr   string
	udpSrv    *dns.Server
	tcpSrv    *dns.Server
	runCtx    context.Context
	runCancel context.CancelFunc
	wg        sync.WaitGroup
}

type sessionHandle struct {
	stoppedCh chan struct{}
}

// Server is a built-in miekg/dns loopback unlock dispatcher serving both UDP and TCP.
type Server struct {
	snap atomic.Pointer[runtimeState]
	inst atomic.Pointer[runningInstance]

	lifecycleMu sync.Mutex
	addrMu      sync.RWMutex
	running     bool
	active      *runningInstance
	session     *sessionHandle
}

// New constructs a validated dnsproxy Server. Note that ListenPort == 0 is
// preserved for OS-assigned ephemeral ports (use DefaultConfig() for port 1053).
func New(cfg Config) (*Server, error) {
	st, err := compileState(cfg, DefaultListenHost)
	if err != nil {
		return nil, err
	}
	s := &Server{}
	s.snap.Store(st)
	return s, nil
}

// Start binds paired UDP and TCP listeners and starts serving DNS requests until
// Stop is called or ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.running {
		return ErrAlreadyStarted
	}

	st := s.snap.Load()
	inst, err := s.startInstance(st.cfg.ListenHost, st.cfg.ListenPort)
	if err != nil {
		return err
	}

	sess := &sessionHandle{stoppedCh: make(chan struct{})}
	s.publishInstance(inst, sess)

	if ctx.Done() != nil {
		go func(watchCtx context.Context, targetSess *sessionHandle) {
			select {
			case <-watchCtx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
				defer cancel()
				_ = s.stopSession(shutdownCtx, targetSess)
			case <-targetSess.stoppedCh:
			}
		}(ctx, sess)
	}

	return nil
}

// Stop gracefully shuts down active UDP and TCP listeners and cancels in-flight
// upstream queries. Stop is idempotent.
func (s *Server) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.stopLocked(ctx)
}

func (s *Server) stopSession(ctx context.Context, target *sessionHandle) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if !s.running || s.session != target {
		return nil
	}
	return s.stopLocked(ctx)
}

func (s *Server) stopLocked(ctx context.Context) error {
	if !s.running {
		return nil
	}

	inst := s.active
	sess := s.session

	s.addrMu.Lock()
	s.running = false
	s.active = nil
	s.session = nil
	s.addrMu.Unlock()

	s.inst.Store(nil)
	if sess != nil {
		close(sess.stoppedCh)
	}
	return shutdownInstance(ctx, inst)
}

func (s *Server) publishInstance(inst *runningInstance, sess *sessionHandle) {
	s.addrMu.Lock()
	s.running = true
	s.active = inst
	if sess != nil {
		s.session = sess
	}
	s.addrMu.Unlock()
	s.inst.Store(inst)
}

// Addr returns the active TCP/UDP listener address ("host:port") when running,
// or "" when stopped.
func (s *Server) Addr() string {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if !s.running || s.active == nil {
		return ""
	}
	return s.active.tcpAddr
}

// UDPAddr returns the active UDP listener address ("host:port") when running,
// or "" when stopped.
func (s *Server) UDPAddr() string {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if !s.running || s.active == nil {
		return ""
	}
	return s.active.udpAddr
}

// TCPAddr returns the active TCP listener address ("host:port") when running,
// or "" when stopped.
func (s *Server) TCPAddr() string {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if !s.running || s.active == nil {
		return ""
	}
	return s.active.tcpAddr
}

// Port returns the active bound port (>0) when running, or 0 when stopped.
func (s *Server) Port() int {
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	if !s.running || s.active == nil {
		return 0
	}
	return s.active.port
}

// UpdateConfig validates and applies a new Config. When the server is running:
//   - If cfg.ListenPort == 0, the currently active port is preserved so hot-reloads
//     do not drop/rebind an ephemeral or configured listener.
//   - If ListenHost and effective ListenPort are unchanged, the snapshot is swapped
//     atomically via atomic.Pointer with zero listener interruption.
//   - Otherwise, listeners cleanly rebind with rollback on bind failure.
func (s *Server) UpdateConfig(cfg Config) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.updateConfigLocked(cfg)
}

func (s *Server) updateConfigLocked(cfg Config) error {
	prev := s.snap.Load()
	next, err := compileState(cfg, prev.cfg.ListenHost)
	if err != nil {
		return err
	}

	if !s.running || s.active == nil {
		s.snap.Store(next)
		return nil
	}

	curInst := s.active
	effectivePort := next.cfg.ListenPort
	if effectivePort == 0 {
		effectivePort = curInst.port
		next.cfg.ListenPort = prev.cfg.ListenPort
	}

	if next.cfg.ListenHost == curInst.host && effectivePort == curInst.port {
		s.snap.Store(next)
		return nil
	}

	// Port changed: bind and start new listeners before tearing down old ones.
	if effectivePort != curInst.port {
		newInst, err := s.startInstance(next.cfg.ListenHost, effectivePort)
		if err != nil {
			return err
		}
		s.snap.Store(next)
		s.publishInstance(newInst, nil)

		shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
		defer cancel()
		_ = shutdownInstance(shutdownCtx, curInst)
		return nil
	}

	// Host changed while keeping the same port: stop old listener first to avoid
	// address overlap (e.g. 127.0.0.1 <-> 0.0.0.0), then rebind with rollback.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), defaultShutdownTimeout)
	defer cancel()
	_ = shutdownInstance(shutdownCtx, curInst)

	newInst, err := s.startInstance(next.cfg.ListenHost, effectivePort)
	if err != nil {
		rbInst, rbErr := s.startInstance(curInst.host, curInst.port)
		if rbErr == nil {
			s.publishInstance(rbInst, nil)
			return fmt.Errorf("dnsproxy: rebind failed (%w); rolled back to %s", err, rbInst.tcpAddr)
		}
		s.addrMu.Lock()
		s.running = false
		s.active = nil
		if s.session != nil {
			close(s.session.stoppedCh)
			s.session = nil
		}
		s.addrMu.Unlock()
		s.inst.Store(nil)
		return fmt.Errorf("dnsproxy: rebind failed (%w) and rollback failed (%v)", err, rbErr)
	}

	s.snap.Store(next)
	s.publishInstance(newInst, nil)
	return nil
}

// ApplyProtocolConfig maps a Panel protocol.DNSConfig onto the server's Config
// and applies it via updateConfigLocked, preserving ListenHost and keeping the
// active/configured ListenPort when cfg.LocalPort <= 0.
func (s *Server) ApplyProtocolConfig(cfg protocol.DNSConfig) error {
	if cfg.LocalPort < 0 || cfg.LocalPort > 65535 {
		return fmt.Errorf("%w: local_port %d must be between 0 and 65535", ErrInvalidConfig, cfg.LocalPort)
	}

	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	cur := s.snap.Load().cfg

	host := cur.ListenHost
	if host == "" {
		host = DefaultListenHost
	}

	port := cur.ListenPort
	if cfg.LocalPort > 0 {
		port = cfg.LocalPort
	}

	upstream := strings.TrimSpace(cfg.UpstreamDNS)
	if upstream == "" {
		upstream = DefaultUpstreamDNS
	}

	next := Config{
		ListenHost:      host,
		ListenPort:      port,
		UnlockEnabled:   cfg.UnlockEnabled,
		UnlockServer:    cfg.UnlockServer,
		Rules:           slices.Clone(cfg.Rules),
		UpstreamDNS:     upstream,
		UpstreamTimeout: cur.UpstreamTimeout,
	}
	return s.updateConfigLocked(next)
}

func (s *Server) startInstance(host string, port int) (*runningInstance, error) {
	pc, ln, boundPort, err := bindPairedListeners(host, port)
	if err != nil {
		return nil, err
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		s.serveDNSWithContext(runCtx, w, r)
	})
	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})
	errCh := make(chan error, 2)

	var udpOnce, tcpOnce sync.Once
	udpSrv := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
		UDPSize:    dns.DefaultMsgSize,
		NotifyStartedFunc: func() {
			udpOnce.Do(func() { close(udpReady) })
		},
	}
	tcpSrv := &dns.Server{
		Listener: ln,
		Handler:  handler,
		NotifyStartedFunc: func() {
			tcpOnce.Do(func() { close(tcpReady) })
		},
	}

	inst := &runningInstance{
		host:      host,
		port:      boundPort,
		udpAddr:   pc.LocalAddr().String(),
		tcpAddr:   ln.Addr().String(),
		udpSrv:    udpSrv,
		tcpSrv:    tcpSrv,
		runCtx:    runCtx,
		runCancel: runCancel,
	}

	inst.wg.Add(2)
	go func() {
		defer inst.wg.Done()
		if err := udpSrv.ActivateAndServe(); err != nil {
			errCh <- fmt.Errorf("dnsproxy: udp server error: %w", err)
		}
	}()
	go func() {
		defer inst.wg.Done()
		if err := tcpSrv.ActivateAndServe(); err != nil {
			errCh <- fmt.Errorf("dnsproxy: tcp server error: %w", err)
		}
	}()

	udpDone, tcpDone := false, false
	for !udpDone || !tcpDone {
		select {
		case <-udpReady:
			udpDone = true
		case <-tcpReady:
			tcpDone = true
		case startErr := <-errCh:
			_ = pc.Close()
			_ = ln.Close()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = shutdownInstance(shutdownCtx, inst)
			cancel()
			return nil, startErr
		}
	}

	return inst, nil
}

func shutdownInstance(ctx context.Context, inst *runningInstance) error {
	if inst == nil {
		return nil
	}
	if inst.runCancel != nil {
		inst.runCancel()
	}

	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
	)
	shutdownOne := func(srv *dns.Server) {
		if srv == nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := srv.ShutdownContext(ctx); err != nil && !isNotStartedErr(err) {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	shutdownOne(inst.udpSrv)
	shutdownOne(inst.tcpSrv)
	wg.Wait()
	inst.wg.Wait()
	return errors.Join(errs...)
}

func isNotStartedErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "server not started")
}

func bindPairedListeners(host string, port int) (net.PacketConn, net.Listener, int, error) {
	if port > 0 {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("dnsproxy: bind udp %s: %w", addr, err)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			_ = pc.Close()
			return nil, nil, 0, fmt.Errorf("dnsproxy: bind tcp %s: %w", addr, err)
		}
		return pc, ln, port, nil
	}

	var lastErr error
	for attempt := 0; attempt < maxEphemeralBindAttempts; attempt++ {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, nil, 0, fmt.Errorf("dnsproxy: bind ephemeral udp on %s: %w", host, err)
		}
		udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
		if !ok || udpAddr.Port <= 0 {
			_ = pc.Close()
			return nil, nil, 0, errors.New("dnsproxy: unexpected udp local address")
		}
		boundPort := udpAddr.Port
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(boundPort)))
		if err != nil {
			lastErr = err
			_ = pc.Close()
			continue
		}
		return pc, ln, boundPort, nil
	}

	return nil, nil, 0, fmt.Errorf("dnsproxy: failed to bind paired ephemeral UDP+TCP port after %d attempts: %w", maxEphemeralBindAttempts, lastErr)
}

// ServeDNS implements dns.Handler. It evaluates MoeClub unlock rules, synthesizes
// immediate empty NODATA for AAAA/HTTPS/SVCB/ANY on matched unlock domains,
// routes matched domains exclusively to UnlockServer without upstream leakage,
// and forwards unmatched queries sequentially across UpstreamDNS.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.serveDNSWithContext(s.baseContext(), w, r)
}

func (s *Server) serveDNSWithContext(baseCtx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if r == nil {
		return
	}
	if baseCtx == nil {
		baseCtx = context.Background()
	}

	if len(r.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcodeFormatError(r)
		_ = w.WriteMsg(resp)
		return
	}

	if r.Opcode != dns.OpcodeQuery {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNotImplemented)
		_ = w.WriteMsg(resp)
		return
	}

	st := s.snap.Load()
	q := r.Question[0]
	isTCP := false
	if addr := w.RemoteAddr(); addr != nil && strings.HasPrefix(addr.Network(), "tcp") {
		isTCP = true
	}

	if st.unlockEnabled && st.matcher.MatchDomain(q.Name) {
		if isBlockedUnlockQtype(q.Qtype) {
			resp := buildEmptyNODATA(r)
			_ = w.WriteMsg(resp)
			return
		}
		if st.unlockServer != "" {
			if baseCtx.Err() != nil {
				writeServFail(w, r)
				return
			}
			resp, err := exchangeUpstream(baseCtx, r, st.unlockServer, isTCP, st.timeout)
			if err != nil || resp == nil {
				writeServFail(w, r)
				return
			}
			finalizeAndWrite(w, r, resp, isTCP)
			return
		}
	}

	var lastResp *dns.Msg
	for _, upstream := range st.upstreams {
		if baseCtx.Err() != nil {
			writeServFail(w, r)
			return
		}
		resp, err := exchangeUpstream(baseCtx, r, upstream, isTCP, st.timeout)
		if baseCtx.Err() != nil {
			writeServFail(w, r)
			return
		}
		if err != nil || resp == nil {
			continue
		}
		if !isFailoverRcode(resp.Rcode) {
			finalizeAndWrite(w, r, resp, isTCP)
			return
		}
		lastResp = resp
	}

	if lastResp != nil {
		finalizeAndWrite(w, r, lastResp, isTCP)
		return
	}
	writeServFail(w, r)
}

func (s *Server) baseContext() context.Context {
	if inst := s.inst.Load(); inst != nil && inst.runCtx != nil {
		return inst.runCtx
	}
	return context.Background()
}

func isBlockedUnlockQtype(qtype uint16) bool {
	switch qtype {
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeANY:
		return true
	default:
		return false
	}
}

func buildEmptyNODATA(r *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = nil
	resp.Ns = nil
	resp.Compress = true
	if opt := r.IsEdns0(); opt != nil {
		udpSize := opt.UDPSize()
		if udpSize < dns.MinMsgSize {
			udpSize = dns.MinMsgSize
		} else if udpSize > dns.DefaultMsgSize {
			udpSize = dns.DefaultMsgSize
		}
		resp.SetEdns0(udpSize, opt.Do())
	}
	return resp
}

func isFailoverRcode(rcode int) bool {
	switch rcode {
	case dns.RcodeServerFailure, dns.RcodeRefused, dns.RcodeNotImplemented, dns.RcodeFormatError:
		return true
	default:
		return false
	}
}

func exchangeOnce(ctx context.Context, c *dns.Client, req *dns.Msg, addr string) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := c.DialContext(ctx, addr)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	defer conn.Close()

	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	resp, _, err := c.ExchangeWithConnContext(ctx, req, conn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return resp, nil
}

func exchangeUpstream(parent context.Context, r *dns.Msg, addr string, isTCP bool, timeout time.Duration) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req := r.Copy()
	if isTCP {
		c := &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		}
		return exchangeOnce(ctx, c, req, addr)
	}

	udpClient := &dns.Client{
		Net:     "udp",
		UDPSize: dns.DefaultMsgSize,
		Timeout: timeout,
	}
	resp, err := exchangeOnce(ctx, udpClient, req, addr)
	if err == nil && resp != nil && resp.Truncated {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: timeout,
		}
		if tcpResp, tcpErr := exchangeOnce(ctx, tcpClient, r.Copy(), addr); tcpErr == nil && tcpResp != nil {
			return tcpResp, nil
		} else if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
	}
	return resp, err
}

func finalizeAndWrite(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg, isTCP bool) {
	resp.Id = req.Id
	resp.Compress = true
	if !isTCP {
		maxSize := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > maxSize {
			maxSize = int(opt.UDPSize())
		}
		resp.Truncate(maxSize)
	}
	_ = w.WriteMsg(resp)
}

func writeServFail(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(req, dns.RcodeServerFailure)
	resp.RecursionAvailable = true
	_ = w.WriteMsg(resp)
}
