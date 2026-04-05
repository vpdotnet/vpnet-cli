package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/KarpelesLab/echeck"
	"github.com/vpdotnet/wgnet"
)

func doPing(ctx context.Context, target string, count int, regionID string, useBeta bool) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Generate ephemeral WireGuard keypair for this session
	privKeyB64, pubKeyB64, err := generateWireGuardKeyPair()
	if err != nil {
		return err
	}

	// Fetch server list and enclave list
	serverList, err := fetchServerList(ctx, useBeta || cfg.UseBeta)
	if err != nil {
		return err
	}

	enclaveList, err := fetchEnclaveList(ctx)
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

	// Register our public key with the server via direct HTTPS call
	regResult, err := registerWithServer(selectedServer.IP, pubKeyB64, auth.data.APIToken, enclaveList)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if regResult.ServerKey == "" {
		return fmt.Errorf("no server key in response")
	}

	peerIPStr := regResult.PeerIP
	if peerIPStr == "" {
		return fmt.Errorf("no peer IP in response")
	}

	if regResult.ServerPort > 0 {
		wgPort = regResult.ServerPort
	}

	serverKeyStr := regResult.ServerKey

	// Determine ping target (resolve after tunnel is up if it's a hostname)
	if target == "" {
		target = regResult.ServerVIP
		if target == "" {
			target = "10.0.0.1"
		}
	}

	peerIP := net.ParseIP(peerIPStr).To4()
	if peerIP == nil {
		return fmt.Errorf("invalid peer IP: %s", peerIPStr)
	}

	// Check if target is an IP or needs DNS resolution
	targetIP := net.ParseIP(target).To4()
	needsResolve := targetIP == nil

	// Parse WireGuard keys
	var privKey wgnet.NoisePrivateKey
	privBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
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

	// Resolve hostname via in-tunnel DNS if needed
	if needsResolve {
		if len(regResult.DNSServers) == 0 {
			return fmt.Errorf("cannot resolve %s: no DNS servers from server", target)
		}
		dnsServer := net.ParseIP(regResult.DNSServers[0]).To4()
		if dnsServer == nil {
			return fmt.Errorf("invalid DNS server: %s", regResult.DNSServers[0])
		}
		fmt.Printf("Resolving %s via %s...\n", target, dnsServer)
		resolved, err := resolveViaTunnel(srv, serverPubKey, peerIP, dnsServer, target, pktCh)
		if err != nil {
			return fmt.Errorf("DNS resolution failed: %w", err)
		}
		targetIP = resolved
		fmt.Printf("%s resolved to %s\n", target, targetIP)
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

// addKeyResponse is the JSON response from the server's /addKey endpoint.
type addKeyResponse struct {
	Status     string   `json:"status"`
	PeerIP     string   `json:"peer_ip"`
	PeerPubkey string   `json:"peer_pubkey"`
	ServerIP   string   `json:"server_ip"`
	ServerKey  string   `json:"server_key"`
	ServerPort int      `json:"server_port"`
	ServerVIP  string   `json:"server_vip"`
	DNSServers []string `json:"dns_servers"`
}

// registerWithServer connects to the WireGuard server on port 443,
// verifies the SGX certificate via echeck, and calls /addKey to register
// our public key and obtain connection parameters.
func registerWithServer(serverIP, pubKeyBase64, apiToken string, validEnclaves []EnclaveEntry) (*addKeyResponse, error) {
	// Decode base64 public key to hex
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	pubKeyHex := strings.ToUpper(hex.EncodeToString(pubKeyBytes))

	// Connect to server with TLS, verify CN=WG and SGX attestation via echeck
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("no certificates from server")
					}
					cert := cs.PeerCertificates[0]
					if cert.Subject.CommonName != "WG" {
						return fmt.Errorf("unexpected certificate CN=%q, expected WG", cert.Subject.CommonName)
					}
					// Verify SGX attestation
					quote, err := echeck.ExtractQuote(cert)
					if err != nil {
						return fmt.Errorf("SGX quote extraction failed: %w", err)
					}
					if err := echeck.VerifyQuote(cert, quote); err != nil {
						return fmt.Errorf("SGX quote verification failed: %w", err)
					}
					// Verify MRENCLAVE against known valid enclaves
					info := quote.GetQuoteInfo()
					mrEnclaveHex := hex.EncodeToString(info.MREnclave[:])
					matched := false
					for _, e := range validEnclaves {
						if e.MREnclave == mrEnclaveHex {
							matched = true
							break
						}
					}
					if !matched {
						return fmt.Errorf("SGX enclave MRENCLAVE %s not in valid enclave list", mrEnclaveHex)
					}
					return nil
				},
			},
		},
	}

	url := fmt.Sprintf("https://%s/addKey?pubkey=%s&pt=%s", serverIP, pubKeyHex, apiToken)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	var result addKeyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if result.Status != "OK" {
		return nil, fmt.Errorf("server returned status: %s", result.Status)
	}

	return &result, nil
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

// resolveViaTunnel sends a DNS A query through the WireGuard tunnel and returns the first IP.
func resolveViaTunnel(srv *wgnet.Server, serverPubKey wgnet.NoisePublicKey, srcIP, dnsServer net.IP, hostname string, pktCh chan []byte) (net.IP, error) {
	dnsID := uint16(os.Getpid() & 0xffff)
	query := buildDNSQuery(dnsID, hostname)
	udpPkt := buildUDPPacket(query, 12345, 53)
	ipPkt := buildIPv4Packet(srcIP, dnsServer, 17, udpPkt) // protocol 17 = UDP

	if err := srv.Send(ipPkt, serverPubKey); err != nil {
		return nil, fmt.Errorf("sending DNS query: %w", err)
	}

	timeout := time.After(5 * time.Second)
	for {
		select {
		case pkt := <-pktCh:
			ip := parseDNSResponse(pkt, dnsID)
			if ip != nil {
				return ip, nil
			}
		case <-timeout:
			return nil, fmt.Errorf("DNS resolution timeout for %s", hostname)
		}
	}
}

// buildDNSQuery builds a minimal DNS A record query.
func buildDNSQuery(id uint16, hostname string) []byte {
	var buf []byte

	// Header: ID, flags (standard query, recursion desired), QDCOUNT=1
	buf = binary.BigEndian.AppendUint16(buf, id)
	buf = binary.BigEndian.AppendUint16(buf, 0x0100) // RD=1
	buf = binary.BigEndian.AppendUint16(buf, 1)      // QDCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ANCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // NSCOUNT
	buf = binary.BigEndian.AppendUint16(buf, 0)      // ARCOUNT

	// Question: encode hostname as DNS labels
	for _, label := range strings.Split(hostname, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0) // root label

	buf = binary.BigEndian.AppendUint16(buf, 1) // QTYPE: A
	buf = binary.BigEndian.AppendUint16(buf, 1) // QCLASS: IN

	return buf
}

// buildUDPPacket wraps a payload in a UDP header.
func buildUDPPacket(payload []byte, srcPort, dstPort uint16) []byte {
	length := uint16(8 + len(payload))
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], length)
	// checksum = 0 (optional for IPv4 UDP)
	return append(hdr, payload...)
}

// parseDNSResponse extracts the first A record IP from a DNS response inside an IPv4/UDP packet.
func parseDNSResponse(ipPkt []byte, expectedID uint16) net.IP {
	if len(ipPkt) < 20 {
		return nil
	}
	ihl := int(ipPkt[0]&0x0f) * 4
	if ipPkt[9] != 17 { // not UDP
		return nil
	}
	if len(ipPkt) < ihl+8 {
		return nil
	}
	udp := ipPkt[ihl:]
	dns := udp[8:] // skip UDP header

	if len(dns) < 12 {
		return nil
	}

	id := binary.BigEndian.Uint16(dns[0:2])
	if id != expectedID {
		return nil
	}

	flags := binary.BigEndian.Uint16(dns[2:4])
	if flags&0x8000 == 0 { // not a response
		return nil
	}

	qdcount := binary.BigEndian.Uint16(dns[4:6])
	ancount := binary.BigEndian.Uint16(dns[6:8])

	// Skip questions
	off := 12
	for i := 0; i < int(qdcount); i++ {
		off = skipDNSName(dns, off)
		if off < 0 || off+4 > len(dns) {
			return nil
		}
		off += 4 // QTYPE + QCLASS
	}

	// Parse answers, look for first A record
	for i := 0; i < int(ancount); i++ {
		off = skipDNSName(dns, off)
		if off < 0 || off+10 > len(dns) {
			return nil
		}
		rtype := binary.BigEndian.Uint16(dns[off : off+2])
		rdlength := binary.BigEndian.Uint16(dns[off+8 : off+10])
		off += 10
		if off+int(rdlength) > len(dns) {
			return nil
		}
		if rtype == 1 && rdlength == 4 { // A record
			return net.IPv4(dns[off], dns[off+1], dns[off+2], dns[off+3]).To4()
		}
		off += int(rdlength)
	}

	return nil
}

// skipDNSName advances past a DNS name (handling compression pointers).
func skipDNSName(dns []byte, off int) int {
	for off < len(dns) {
		length := int(dns[off])
		if length == 0 {
			return off + 1
		}
		if length&0xC0 == 0xC0 { // compression pointer
			return off + 2
		}
		off += 1 + length
	}
	return -1
}
