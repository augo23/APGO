package overlaymobile

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/flynn/noise"
)

// applyRuntimeConfig mirrors the tail of the client's loadConfig: it sets the
// transport cipher, compression, and fills in defaults. Mobile builds its
// ClientConfig in-memory (no YAML file), so this runs those same normalizations.
func applyRuntimeConfig(cfg *ClientConfig) {
	compressionCfg.Enabled = cfg.Compression
	if cfg.MinAnnounceIntervalSeconds == 0 {
		cfg.MinAnnounceIntervalSeconds = 900
	}
	if cfg.TrackerMode == "" {
		cfg.TrackerMode = "bootstrap"
	}
	switch cfg.Cipher {
	case "", "chacha", "chacha20poly1305":
		noiseCipher = noise.CipherChaChaPoly
	case "aesgcm", "aes-gcm", "aes":
		noiseCipher = noise.CipherAESGCM
	}
	if cfg.TrackerMode == "passive" && cfg.MinAnnounceIntervalSeconds >= 900 {
		cfg.MinAnnounceIntervalSeconds = 30
	}
}

// Run starts the APGO overlay against an already-created tunnel (the OS-owned
// NEPacketTunnelFlow / VpnService fd, wrapped as an io.ReadWriteCloser of raw
// IPv4 packets) and blocks until stop is closed. It is the mobile analogue of
// client/main.go's main(): everything after TUN creation, with the tunnel
// injected instead of created, and shutdown driven by the stop channel instead
// of OS signals.
func run(tun io.ReadWriteCloser, cfg *ClientConfig, stop <-chan struct{}) error {
	applyRuntimeConfig(cfg)

	// An admin-signed network name/PSK rotation (compromise recovery) overrides
	// the config before we derive the info-hash or parse the PSK.
	applyNetConfigFile(cfg)

	overlayCIDR = cfg.OverlayCIDR
	pqEnabled = cfg.PostQuantum
	pqAuth = cfg.PQAuth
	ipv6Enabled = cfg.IPv6
	applyPolicyFile() // admin-signed network policy overrides the PQ default
	gConfigTrackers = cfg.Trackers
	gTrackerFile = cfg.TrackerListFile
	if gTrackerFile == "" {
		gTrackerFile = trackerFilePath()
	}

	// Trust the admin public key (from ADMIN_PUBLIC_KEY env, set by the bridge)
	// and load any persisted revocations before traffic starts.
	loadAdminPublicKey()

	if pf := os.Getenv("PROVISIONS_FILE"); pf != "" {
		provisions.load(pf)
	}
	if af := os.Getenv("APPROVALS_FILE"); af != "" {
		approvals.load(af)
	}
	loadSealedAdminKey()
	myFriendlyName = sanitizeName(cfg.FriendlyName)

	kp, err := loadOrCreateKey(cfg.NodePrivateKey)
	if err != nil {
		return err
	}
	psk, err := parsePSK(cfg.PSK)
	if err != nil {
		return err
	}
	gKP = kp
	gPSK = psk

	// Apply any persisted per-node PQ policy now that our static key is known.
	recomputeSelfPolicy()

	// Adopt any persisted admin-assigned overlay address / name for this node.
	adoptSelfProvisionAtStartup(cfg, kp.pub)
	if cfg.FriendlyName != "" {
		myFriendlyName = sanitizeName(cfg.FriendlyName)
	}

	// The overlay IP is chosen by the app (the OS tunnel is already configured
	// with it); derive from the key only if the app left it blank.
	if cfg.Tun.AddressCIDR == "" && cfg.OverlayCIDR != "" {
		if derived, derr := deriveOverlayIP(cfg.OverlayCIDR, kp.pub); derr == nil {
			cfg.Tun.AddressCIDR = derived
		}
	}
	if ip, _, perr := net.ParseCIDR(cfg.Tun.AddressCIDR); perr == nil && ip.To4() != nil {
		myOverlayIP = ip.To4().String()
	}

	tunIF = tun

	udpConn, port, err := udpListener(cfg.UDPListenPort)
	if err != nil {
		return err
	}
	myUDPPort = port

	GlobalSessions = NewSessionTable(udpConn)
	sessions = GlobalSessions
	GlobalConn = udpConn

	// Full-VPN outproxy: pick + track the fastest exit (a phone can't BE an exit).
	initExit(cfg)
	go exitSelectionLoop()

	passive := cfg.TrackerMode == "passive"

	// Decrypt path (UDP -> TUN)
	go func() {
		buf := make([]byte, 65535)
		var readErrs int
		for {
			n, raddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				// Intentional shutdown closed the socket — exit cleanly.
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Transient error (ICMP unreachable on recv, or a sleep/wake or
				// network transition). Don't kill the loop — that would leave the
				// client permanently deaf until restart. Keep reading with a short
				// backoff; the announce/keepalive loops re-punch once packets flow.
				readErrs++
				if readErrs <= 3 || readErrs%2000 == 0 {
					log.Printf("[transport] UDP read error (recovering, not fatal): %v", err)
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			readErrs = 0
			if n < 1 {
				continue
			}
			if dispatchSTUN(buf[:n]) {
				continue
			}
			if !isOverlayPacket(buf[0]) {
				continue
			}
			typ := buf[0]
			body := buf[1:n]

			if GlobalSessions.deliverPacket(raddr, typ, body, kp, psk) {
				continue
			}
			s := GlobalSessions.GetByAddr(raddr)
			if s == nil || !s.Established() {
				if typ == PktData && GlobalSessions.RoamData(raddr, body) {
					s = GlobalSessions.GetByAddr(raddr)
				}
				if s == nil || !s.Established() {
					continue
				}
			}
			pt, err := recvPacket(s, body)
			if err != nil {
				// Single failures are garbage/forgery/replay — never evict on
				// one. NoteDecryptFailure tears down only when everything has
				// failed for multiple keepalive intervals (key desync), forcing
				// a clean re-handshake instead of a minute-long blackhole.
				logDecryptError(raddr.String(), err)
				GlobalSessions.NoteDecryptFailure(raddr)
				continue
			}
			GlobalSessions.TouchLastSeen(raddr)
			// Post-quantum: peel the ML-KEM AEAD layer FIRST (once up we wrap all
			// frames on a direct session), so control + data dispatch correctly.
			if isPQPacket(pt) {
				if s := GlobalSessions.GetByAddr(raddr); s != nil {
					if inner, ok := pqUnwrap(s.peerStatic, pt); ok {
						pt = inner
					} else {
						continue
					}
				} else {
					continue
				}
			}
			if bytes.HasPrefix(pt, ctlMagic) {
				handleControl(pt[len(ctlMagic):], raddr)
				continue
			}

			// ADMISSION CONTROL — data path only; control frames above are
			// deliberately exempt so an unapproved peer can still learn the
			// admin key and its own approval (approvals.go). Past this point a
			// peer that is not admitted gets nothing: no TUN delivery, no relay
			// transit, no ipLearning entry. Mirrors client/main.go.
			// No-op when no admin key is set (admissionRequired() == false).
			if s := GlobalSessions.GetByAddr(raddr); s == nil || !admissionOK(s.peerStatic, "ingress") {
				continue
			}

			if len(pt) == 5 && pt[0] == 0x00 {
				srcIP := net.IPv4(pt[1], pt[2], pt[3], pt[4]).String()
				if srcIP == myOverlayIP {
					continue
				}
				ipLearning.Learn(srcIP, raddr)
				if s := GlobalSessions.GetByAddr(raddr); s != nil {
					setPeerOverlayIP(s.peerStatic, srcIP)
				}
				continue
			}
			if !isIPv4Packet(pt) {
				continue
			}
			if ifIP := extractIPv4Src(pt); ifIP != "" {
				ipLearning.Learn(ifIP, raddr)
			}
			if myOverlayIP != "" {
				if dst := extractIPv4Dst(pt); dst != "" && dst != myOverlayIP {
					if amExit && isInternetDst(dst) {
						tunIF.Write(pt)
						continue
					}
					// Relay transit for the RETURN path. When we relay an 'R'
					// frame, the destination learns "reach the sender via us"
					// and sends its replies back here as ORDINARY data frames
					// — but this branch used to just drop them, so relayed
					// connections passed exactly one packet and then went
					// dark. Forward one hop over a direct established
					// session, same rules as the 'R' handler: never to/from a
					// revoked node, and never back out the session it arrived
					// on (split horizon — no loops).
					if !isInternetDst(dst) &&
						!isOverlayIPRevoked(dst) && !isOverlayIPRevoked(extractIPv4Src(pt)) {
						if a := ipLearning.Lookup(dst); a != nil && a.String() != raddr.String() {
							// …and admitted: never relay onward into a pending
							// device. Mirrors client/main.go.
							if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "relay-return") {
								_ = sendPacket(GlobalConn, a, s, pt)
							}
						}
					}
					continue
				}
			}
			tunIF.Write(pt)
		}
	}()

	// Encrypt path (TUN -> UDP)
	go func() {
		pkt := make([]byte, 65535)
		for {
			n, err := tunIF.Read(pkt)
			if err != nil {
				return
			}
			ip := pkt[:n]

			// The overlay carries IPv4 only. In full-VPN mode the OS tunnel
			// also captures the IPv6 default route (to prevent v6 leaking past
			// the exit), so v6 packets arrive here constantly — drop them
			// immediately. Without this they fell through to the relay-flood
			// path below and got sprayed to every peer (pure waste).
			if n > 0 && ip[0]>>4 == 6 {
				continue
			}
			dst := extractIPv4Dst(ip)

			// Revoked peer: drop everything to its overlay IP (direct or relay).
			if dst != "" && isOverlayIPRevoked(dst) {
				continue
			}

			// Full-VPN mode: internet-bound packets go to the fastest exit node.
			if useExit && isInternetDst(dst) {
				if ea, es := currentExit(); ea != nil {
					_ = sendPacket(udpConn, ea, es, ip)
				}
				continue
			}

			if dst != "" {
				if a := ipLearning.Lookup(dst); a != nil {
					// Belt-and-braces admission check: the table can also be
					// seeded from provisions, so gate the send rather than
					// trust every writer. Mirrors client/main.go.
					if s := GlobalSessions.GetByAddr(a); s != nil && s.Established() && admissionOK(s.peerStatic, "egress") {
						// PQ wrapping (if enabled + ready) happens inside sendPacket.
						_ = sendPacket(udpConn, a, s, ip)
						continue
					}
					ipLearning.ForgetAddr(a)
				}
			}

			relayFrame := append(append(append([]byte{}, ctlMagic...), 'R'), ip...)

			var connectReq []byte
			if dst != "" && dst != myOverlayIP {
				if myCands := myConnectCandidates(); myCands != "" && shouldTryConnect(dst) {
					connectReq = buildConnectFrame('C', dst, myOverlayIP, myCands)
				}
			}

			for _, addr := range GlobalSessions.EstablishedAddrs() {
				// Broadcast of real payload to every direct peer — the easiest
				// place to leak data to a pending device. Admitted peers only.
				if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() && admissionOK(s.peerStatic, "egress-flood") {
					_ = sendPacket(udpConn, addr, s, ip)
					_ = sendPacket(udpConn, addr, s, relayFrame)
					if connectReq != nil {
						_ = sendPacket(udpConn, addr, s, connectReq)
					}
				}
			}
		}
	}()

	infoHash := deriveInfoHash(cfg.NetworkName)
	peerID := buildPeerID()
	log.Printf("info_hash=%x peer_id=%s udp_port=%d", infoHash, peerID, port)

	pub, err := fetchPublicEndpoint(udpConn, cfg.STUNServers, 10*time.Second)
	if err == nil {
		lastPublicIP = pub
		log.Printf("Public endpoint: %s", pub)
	} else {
		log.Printf("STUN failed: %v (fallback to local port %d)", err, port)
	}

	// NAT classification ALWAYS runs — see startNATProbing. The config flag now
	// only FORCES prediction on; probing turns it on by itself when it sees a
	// symmetric NAT, which is the case the phone could never diagnose before.
	portPredictionForced.Store(cfg.PortPrediction)
	portPredictionOn.Store(cfg.PortPrediction)
	startNATProbing(udpConn, cfg.STUNServers)

	mu.Lock()
	lastAnnounceTime = time.Now().Add(-time.Duration(cfg.MinAnnounceIntervalSeconds) * time.Second)
	mu.Unlock()

	go controllerHeartbeatLoop(cfg.ControllerURL, peerID)
	startLocalDiscovery(infoHash, port, kp, psk)

	for _, p := range cfg.StaticPeers {
		peer := p
		addKnownPeer(peer)
		go connectToPeer(peer, kp, psk)
	}
	go holePunchRetryLoop(kp, psk)

	GlobalSessions.SetSessionLostCallback(func(addr *net.UDPAddr) {
		ipLearning.ForgetAddr(addr)
		if !passive {
			return
		}
		go func() {
			pubNow, _ := fetchPublicEndpoint(udpConn, cfg.STUNServers, 8*time.Second)
			if pubNow == "" {
				mu.Lock()
				pubNow = lastPublicIP
				mu.Unlock()
			}
			announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pubNow, kp, psk, true)
		}()
	})

	go func() {
		ticker := time.NewTicker(gKeepaliveInterval)
		defer ticker.Stop()
		// Heavy admin-state frames re-flood every ~60 s; new peers get the full set
		// instantly via syncAdminStateTo on connect, and admin actions broadcast on
		// change. Short enough that name/IP changes propagate promptly.
		slowGossipEvery := int(time.Minute / gKeepaliveInterval)
		if slowGossipEvery < 1 {
			slowGossipEvery = 1
		}
		tickN := 0
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
			tickN++
			heavy := tickN%slowGossipEvery == 1
			// Rebuild the keepalive payload each tick (matches the desktop
			// client) so a live overlay-address change is reflected
			// immediately instead of advertising the stale IP forever.
			keepalive := []byte{0x00}
			if ip := net.ParseIP(myOverlayIP); ip != nil && ip.To4() != nil {
				keepalive = append(keepalive, ip.To4()...)
			}
			exitAd := buildExitAnnounce()
			var seed, sealed []byte
			if heavy {
				seed = buildAdminSeed()
				sealed = buildSealedKeyFrame()
			}
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				s := GlobalSessions.GetByAddr(addr)
				if s == nil || !s.Established() {
					continue
				}
				_ = sendPacket(GlobalConn, addr, s, keepalive)
				if seed != nil {
					_ = sendPacket(GlobalConn, addr, s, seed)
				}
				if sealed != nil {
					_ = sendPacket(GlobalConn, addr, s, sealed)
				}
				if exitAd != nil {
					_ = sendPacket(GlobalConn, addr, s, exitAd)
				}
				// PEX is per-recipient: same-site peers also get LAN endpoints.
				if pex := buildPeerExchangeFor(addr); pex != nil {
					_ = sendPacket(GlobalConn, addr, s, pex)
				}
				// Roster gossip: us + our direct peers, so every node keeps a
				// steady directory of the network (relay-only peers included).
				if roster := buildRosterFrame(); roster != nil {
					_ = sendPacket(GlobalConn, addr, s, roster)
				}
				if pqEnabled && pqInitiator(s.peerStatic) && !pqReady(s.peerStatic) {
					if offer := buildPQOffer(s.peerStatic); offer != nil {
						_ = sendPacket(GlobalConn, addr, s, offer)
					}
				}
				_ = sendPacket(GlobalConn, addr, s, buildPQStatus())
			}
			// Upgrade roster-known nodes without a direct session to direct
			// (relayed punch signaling; throttled per node inside).
			connectRosterNodes()
			if heavy {
				gossipNameAndProvisions()
				gossipRevocations()
				gossipApprovals()
				gossipNetConfig()
				gossipPolicy()
			}
		}
	}()

	// Fast post-quantum negotiation. The keepalive loop above only re-offers
	// every ~10s, so a single dropped (large) ML-KEM handshake packet — common
	// on constrained Wi-Fi paths — meant the "quantum-safe" lock took tens of
	// seconds to appear. This loop re-offers every ~1.5s until PQ is up (offers
	// are idempotent, so retransmits don't race with an in-flight reply), then
	// goes quiet. Negligible bandwidth: it only runs while a peer isn't PQ-ready.
	go func() {
		if !pqEnabled {
			return
		}
		t := time.NewTicker(1500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
			}
			for _, addr := range GlobalSessions.EstablishedAddrs() {
				s := GlobalSessions.GetByAddr(addr)
				if s == nil || !s.Established() || !pqInitiator(s.peerStatic) || pqReady(s.peerStatic) {
					continue
				}
				if offer := buildPQOffer(s.peerStatic); offer != nil {
					_ = sendPacket(GlobalConn, addr, s, offer)
				}
			}
		}
	}()

	announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pub, kp, psk, passive)
	announceRendezvous(cfg.RendezvousServers, infoHash, peerID, pub, kp, psk)
	mu.Lock()
	lastAnnounceTime = time.Now()
	mu.Unlock()

	const trackersPerTick = 3
	baseTick := time.Duration(cfg.MinAnnounceIntervalSeconds) * time.Second
	// Self-heal cadence: with ZERO established peers this node is an island —
	// poll fast until the first session forms, then relax to the base tick.
	isolationTick := 30 * time.Second
	if baseTick < isolationTick {
		isolationTick = baseTick
	}

	// Wake/resume detector. iOS suspends the tunnel extension when the device
	// sleeps (and Wi-Fi power-save silences it well before that); the
	// monotonic clock pauses with it, so the only reliable "we just resumed"
	// signal is a WALL-clock jump much larger than the probe interval. On
	// resume every NAT mapping and session is stale: drop them and
	// re-announce IMMEDIATELY, so the mesh — especially a LAN peer like a
	// Mac on the same Wi-Fi — reconnects in seconds instead of waiting out
	// keepalive staleness plus the next announce tick. The desktop client
	// has had this for laptop sleep; the phone, which suspends far more
	// often, was missing it — the "it just stops working for a while after
	// sitting idle" symptom.
	wakeCh := make(chan struct{}, 1)
	go func() {
		const probe = 15 * time.Second
		for {
			before := time.Now().Round(0) // .Round(0) strips monotonic → wall clock
			select {
			case <-stop:
				return
			case <-time.After(probe):
			}
			if gap := time.Now().Round(0).Sub(before); gap > probe+20*time.Second {
				log.Printf("[wake] resumed after ~%v suspended — forcing reconnect", gap.Round(time.Second))
				select {
				case wakeCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	for {
		wait := baseTick
		if len(GlobalSessions.EstablishedAddrs()) == 0 {
			wait = isolationTick
		}
		select {
		case <-stop:
			log.Println("shutdown requested")
			GlobalSessions.Close()
			udpConn.Close()
			return nil
		case <-wakeCh:
			// Resume from suspend: every session is stale — drop them all so
			// dead endpoints don't linger, then announce + reconnect NOW
			// (known LAN peers are re-dialed by the retry loop within
			// seconds; trackers re-learn our fresh NAT mapping).
			addrs := GlobalSessions.EstablishedAddrs()
			log.Printf("[wake] dropping %d stale session(s) and re-announcing", len(addrs))
			for _, addr := range addrs {
				GlobalSessions.Evict(addr)
				ipLearning.ForgetAddr(addr)
			}
			pubNow, perr := fetchPublicEndpoint(udpConn, cfg.STUNServers, 8*time.Second)
			if perr != nil {
				mu.Lock()
				pubNow = lastPublicIP
				mu.Unlock()
			}
			announceAndConnect(loadTrackerList(cfg), infoHash, peerID, port, pubNow, kp, psk, passive)
			announceRendezvous(cfg.RendezvousServers, infoHash, peerID, pubNow, kp, psk)
			mu.Lock()
			lastAnnounceTime = time.Now()
			if pubNow != "" {
				lastPublicIP = pubNow
			}
			mu.Unlock()
			continue
		case <-time.After(wait):
			pubNow, err := fetchPublicEndpoint(udpConn, cfg.STUNServers, 8*time.Second)
			if err != nil {
				mu.Lock()
				pubNow = lastPublicIP
				mu.Unlock()
			}
			isolated := len(GlobalSessions.EstablishedAddrs()) == 0
			mu.Lock()
			changed := pubNow != "" && pubNow != lastPublicIP
			staleRegistration := time.Since(lastAnnounceTime) > 25*time.Minute
			needHeal := isolated && time.Since(lastAnnounceTime) > 2*time.Minute
			mu.Unlock()

			if changed {
				ka := []byte{0x00}
				if ip := net.ParseIP(myOverlayIP); ip != nil && ip.To4() != nil {
					ka = append(ka, ip.To4()...)
				}
				for _, addr := range GlobalSessions.EstablishedAddrs() {
					if s := GlobalSessions.GetByAddr(addr); s != nil && s.Established() {
						_ = sendPacket(GlobalConn, addr, s, ka)
					}
				}
			}

			trackers := loadTrackerList(cfg)
			var subset []string
			fullAnnounce := changed || staleRegistration || needHeal
			if fullAnnounce || len(trackers) <= trackersPerTick {
				// Also takes the empty/tiny-list path: rotating over a list the
				// admin emptied out used to divide by zero and crash the loop.
				subset = trackers
			} else {
				trackerOffsetMu.Lock()
				off := trackerOffset % len(trackers)
				trackerOffset += trackersPerTick
				trackerOffsetMu.Unlock()
				for i := 0; i < trackersPerTick && i < len(trackers); i++ {
					subset = append(subset, trackers[(off+i)%len(trackers)])
				}
			}

			announceAndConnect(subset, infoHash, peerID, port, pubNow, kp, psk, passive)
			announceRendezvous(cfg.RendezvousServers, infoHash, peerID, pubNow, kp, psk)

			mu.Lock()
			if fullAnnounce {
				lastAnnounceTime = time.Now()
			}
			lastPublicIP = pubNow
			mu.Unlock()
		}
	}
}
