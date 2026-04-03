package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"time"

	"github.com/KarpelesLab/slirp/vclient"
	"github.com/vpdotnet/wgnet"
)

func doWget(ctx context.Context, rawURL, output, regionID string, useBeta bool) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Generate ephemeral WireGuard keypair
	privKeyB64, pubKeyB64, err := generateWireGuardKeyPair()
	if err != nil {
		return err
	}

	// Fetch server list
	serverList, err := fetchServerList(ctx, useBeta || cfg.UseBeta)
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
	regResult, err := registerWithServer(selectedServer.IP, pubKeyB64, auth.data.APIToken)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if regResult.ServerPort > 0 {
		wgPort = regResult.ServerPort
	}

	peerIP := net.ParseIP(regResult.PeerIP).To4()
	if peerIP == nil {
		return fmt.Errorf("invalid peer IP: %s", regResult.PeerIP)
	}

	serverVIP := net.ParseIP(regResult.ServerVIP).To4()
	if serverVIP == nil {
		return fmt.Errorf("invalid server VIP: %s", regResult.ServerVIP)
	}

	var dnsServers []net.IP
	for _, s := range regResult.DNSServers {
		if ip := net.ParseIP(s).To4(); ip != nil {
			dnsServers = append(dnsServers, ip)
		}
	}

	// Parse WireGuard keys
	var privKey wgnet.NoisePrivateKey
	privBytes, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	copy(privKey[:], privBytes)

	var serverPubKey wgnet.NoisePublicKey
	serverKeyBytes, err := base64.StdEncoding.DecodeString(regResult.ServerKey)
	if err != nil {
		return fmt.Errorf("invalid server key: %w", err)
	}
	copy(serverPubKey[:], serverKeyBytes)

	// Create vclient - writer will be set after srv is ready
	vc := vclient.New(nil)
	defer vc.Close()

	// Create WireGuard handler and server
	handler, err := wgnet.NewHandler(wgnet.Config{PrivateKey: privKey})
	if err != nil {
		return fmt.Errorf("WireGuard init failed: %w", err)
	}
	handler.AddPeer(serverPubKey)

	connectedCh := make(chan struct{}, 1)

	srv, err := wgnet.NewServer(wgnet.ServerConfig{
		Handler: handler,
		OnPacket: func(data []byte, pk wgnet.NoisePublicKey, h *wgnet.Handler) {
			vc.HandlePacket(data)
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

	// Set the vclient writer to forward IP packets through WireGuard
	vc.SetWriter(func(packet []byte) error {
		return srv.Send(packet, serverPubKey)
	})

	// Configure vclient networking
	vc.SetIP(peerIP, net.CIDRMask(32, 32), serverVIP)
	vc.SetDNS(dnsServers)

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
	fmt.Fprintf(os.Stderr, "Connecting to %s (%s:%d)...\n", region.Name, selectedServer.IP, wgPort)

	if err := srv.Connect(serverPubKey, serverAddr); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}

	select {
	case <-connectedCh:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("handshake timeout")
	}

	fmt.Fprintf(os.Stderr, "Connected. Downloading %s...\n", rawURL)

	// Use vclient's HTTP client to download
	httpClient := vc.HTTPClient()
	resp, err := httpClient.Get(rawURL)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	fmt.Fprintf(os.Stderr, "HTTP %s\n", resp.Status)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %s", resp.Status)
	}

	// Determine output destination
	var w io.Writer
	if output == "-" || output == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	}

	// Default output filename from URL if not specified
	if output == "" {
		urlPath := resp.Request.URL.Path
		if base := path.Base(urlPath); base != "" && base != "." && base != "/" {
			f, err := os.Create(base)
			if err != nil {
				return fmt.Errorf("creating output file: %w", err)
			}
			defer f.Close()
			w = f
			output = base
		}
	}

	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	if output != "" && output != "-" {
		fmt.Fprintf(os.Stderr, "Saved %d bytes to %s\n", n, output)
	}

	return nil
}
