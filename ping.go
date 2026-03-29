package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/vpdotnet/wgnet"
)

func doPing(ctx context.Context, target string, count int, regionID string) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Generate WireGuard keys if needed
	if cfg.PrivateKey == "" || cfg.PublicKey == "" {
		privKey, pubKey, err := generateWireGuardKeyPair()
		if err != nil {
			return err
		}
		cfg.PrivateKey = privKey
		cfg.PublicKey = pubKey
		if err := saveConfig(cfg); err != nil {
			return err
		}
	}

	// Fetch server list
	serverList, err := fetchServerList(ctx, cfg.UseBeta)
	if err != nil {
		return err
	}

	// Find region
	var region *Region
	for i := range serverList.Regions {
		r := &serverList.Regions[i]
		if regionID != "" {
			if r.ID == regionID || r.Name == regionID {
				region = r
				break
			}
		} else if !r.Offline && r.AutoRegion {
			region = r
			break
		}
	}
	if region == nil {
		return fmt.Errorf("no suitable region found")
	}

	wgServers, ok := region.Servers["wg"]
	if !ok || len(wgServers) == 0 {
		return fmt.Errorf("no WireGuard servers in region %s", region.Name)
	}
	selectedServer := wgServers[0]

	// Get WireGuard port from server groups
	wgPort := 1337
	if groups, ok := serverList.Groups["wg"]; ok {
		for _, g := range groups {
			if len(g.Ports) > 0 {
				wgPort = g.Ports[0]
				break
			}
		}
	}

	// Register our public key with the server
	var regResult map[string]any
	err = auth.Apply(ctx, "VPN/Server/"+region.ID+":register", "POST", map[string]any{
		"public_key": cfg.PublicKey,
	}, &regResult)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	serverKeyStr := firstString(regResult, "server_key", "server_pubkey", "pubkey")
	if serverKeyStr == "" {
		return fmt.Errorf("no server key in response: %v", regResult)
	}

	peerIPStr := firstString(regResult, "peer_ip", "ip", "client_ip")
	if peerIPStr == "" {
		return fmt.Errorf("no peer IP in response: %v", regResult)
	}

	if p, ok := regResult["server_port"].(float64); ok && p > 0 {
		wgPort = int(p)
	}

	// Determine ping target
	if target == "" {
		target = firstString(regResult, "server_vip", "server_ip", "gateway")
		if target == "" {
			target = "10.0.0.1"
		}
	}

	targetIP := net.ParseIP(target).To4()
	if targetIP == nil {
		return fmt.Errorf("invalid target: %s", target)
	}

	peerIP := net.ParseIP(peerIPStr).To4()
	if peerIP == nil {
		return fmt.Errorf("invalid peer IP: %s", peerIPStr)
	}

	// Parse WireGuard keys
	var privKey wgnet.NoisePrivateKey
	privBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	copy(privKey[:], privBytes)

	var serverPubKey wgnet.NoisePublicKey
	serverKeyBytes, err := base64.StdEncoding.DecodeString(serverKeyStr)
	if err != nil {
		return fmt.Errorf("invalid server key: %w", err)
	}
	copy(serverPubKey[:], serverKeyBytes)

	// Create WireGuard handler and server
	handler, err := wgnet.NewHandler(wgnet.Config{PrivateKey: privKey})
	if err != nil {
		return fmt.Errorf("WireGuard init failed: %w", err)
	}
	handler.AddPeer(serverPubKey)

	pktCh := make(chan []byte, 16)
	connectedCh := make(chan struct{}, 1)

	srv, err := wgnet.NewServer(wgnet.ServerConfig{
		Handler: handler,
		OnPacket: func(data []byte, pk wgnet.NoisePublicKey, h *wgnet.Handler) {
			pkt := make([]byte, len(data))
			copy(pkt, data)
			select {
			case pktCh <- pkt:
			default:
			}
		},
		OnPeerConnected: func(pk wgnet.NoisePublicKey, h *wgnet.Handler) {
			select {
			case connectedCh <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		return fmt.Errorf("server init failed: %w", err)
	}
	defer srv.Close()

	// Open UDP socket and start serving
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return fmt.Errorf("UDP socket failed: %w", err)
	}
	defer conn.Close()

	go srv.Serve(conn)

	// Initiate WireGuard handshake
	serverAddr := &net.UDPAddr{
		IP:   net.ParseIP(selectedServer.IP),
		Port: wgPort,
	}
	fmt.Printf("Connecting to %s (%s:%d)...\n", region.Name, selectedServer.IP, wgPort)

	if err := srv.Connect(serverPubKey, serverAddr); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	select {
	case <-connectedCh:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("handshake timeout")
	}

	fmt.Printf("PING %s from %s via %s (%s)\n", targetIP, peerIP, region.Name, region.Country)

	// Signal handling for Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	icmpID := uint16(os.Getpid() & 0xffff)
	var sent, received int
	var totalRTT, minRTT, maxRTT time.Duration

	for seq := 0; count <= 0 || seq < count; seq++ {
		select {
		case <-sigCh:
			goto done
		default:
		}

		// Build and send ICMP echo request inside an IPv4 packet
		icmpPkt := buildICMPEchoRequest(icmpID, uint16(seq))
		ipPkt := buildIPv4Packet(peerIP, targetIP, 1, icmpPkt)

		sendTime := time.Now()
		if err := srv.Send(ipPkt, serverPubKey); err != nil {
			fmt.Printf("seq=%d send error: %v\n", seq, err)
			time.Sleep(time.Second)
			continue
		}
		sent++

		// Wait for ICMP echo reply
		replied := false
		timeout := time.After(2 * time.Second)
		for !replied {
			select {
			case pkt := <-pktCh:
				if isICMPEchoReply(pkt, icmpID, uint16(seq)) {
					rtt := time.Since(sendTime)
					received++
					totalRTT += rtt
					if minRTT == 0 || rtt < minRTT {
						minRTT = rtt
					}
					if rtt > maxRTT {
						maxRTT = rtt
					}

					replySize := len(pkt) - ipHeaderLen(pkt)
					srcIP := extractSrcIP(pkt)
					ttl := extractTTL(pkt)
					fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%s\n",
						replySize, srcIP, seq, ttl, rtt.Round(100*time.Microsecond))
					replied = true
				}
			case <-timeout:
				fmt.Printf("Request timeout for icmp_seq %d\n", seq)
				replied = true
			case <-sigCh:
				goto done
			}
		}

		// Wait 1s between pings
		if count <= 0 || seq < count-1 {
			select {
			case <-sigCh:
				goto done
			case <-time.After(time.Second):
			}
		}
	}

done:
	fmt.Printf("\n--- %s ping statistics ---\n", targetIP)
	if sent > 0 {
		loss := float64(sent-received) / float64(sent) * 100
		fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n", sent, received, loss)
	}
	if received > 0 {
		avg := totalRTT / time.Duration(received)
		fmt.Printf("rtt min/avg/max = %s/%s/%s\n",
			minRTT.Round(100*time.Microsecond),
			avg.Round(100*time.Microsecond),
			maxRTT.Round(100*time.Microsecond))
	}

	return nil
}

// firstString returns the first non-empty string value from a map for the given keys.
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// buildICMPEchoRequest creates an ICMP Echo Request packet (type 8, code 0).
func buildICMPEchoRequest(id, seq uint16) []byte {
	pkt := make([]byte, 64) // 8 byte header + 56 byte payload
	pkt[0] = 8              // Type: Echo Request
	pkt[1] = 0              // Code: 0
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	// Embed timestamp in payload for reference
	binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))
	// Compute and set checksum
	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// buildIPv4Packet creates a minimal IPv4 packet with the given payload.
func buildIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	totalLen := 20 + len(payload)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(os.Getpid()&0xffff)) // ID
	pkt[6] = 0x40 // Flags: Don't Fragment
	pkt[8] = 64   // TTL
	pkt[9] = protocol
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)

	// Compute IPv4 header checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	copy(pkt[20:], payload)
	return pkt
}

// isICMPEchoReply checks if an IPv4 packet contains an ICMP Echo Reply matching the expected ID and sequence.
func isICMPEchoReply(ipPkt []byte, expectedID, expectedSeq uint16) bool {
	if len(ipPkt) < 20 {
		return false
	}
	ihl := int(ipPkt[0]&0x0f) * 4
	if ipPkt[9] != 1 { // protocol != ICMP
		return false
	}
	if len(ipPkt) < ihl+8 {
		return false
	}
	icmp := ipPkt[ihl:]
	if icmp[0] != 0 { // type != Echo Reply
		return false
	}
	return binary.BigEndian.Uint16(icmp[4:6]) == expectedID &&
		binary.BigEndian.Uint16(icmp[6:8]) == expectedSeq
}

func extractSrcIP(ipPkt []byte) string {
	if len(ipPkt) < 20 {
		return "?"
	}
	return net.IPv4(ipPkt[12], ipPkt[13], ipPkt[14], ipPkt[15]).String()
}

func extractTTL(ipPkt []byte) int {
	if len(ipPkt) < 9 {
		return 0
	}
	return int(ipPkt[8])
}

func ipHeaderLen(ipPkt []byte) int {
	if len(ipPkt) < 1 {
		return 0
	}
	return int(ipPkt[0]&0x0f) * 4
}
