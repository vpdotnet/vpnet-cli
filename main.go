package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KarpelesLab/rest"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
)

const (
	serverListURL     = "https://serverlist.vp.net/vpninfo/servers/v6"
	serverListBetaURL = "https://serverlist.vp.net/vpninfo/servers-beta/v6"
	enclaveListURL    = "https://serverlist.vp.net/vpninfo/enclaves/v1"

	serverListPublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxSqleT52eqaEfBcgInai
J1y6p82WsnATs2pEMkw2m0COOP6/2DFrAZMtEHbbxdHsS2Rax6yqw7awFY+VAI9X
k6m52Rhr6l1mVFRXCu9vPU2T3qmgQyMFQ2TdK1ybMTDrKE/v3d53VCLIZEtQLi0u
/IiFFN7QqyQ7CJB3Pod6kHdbLa9Tw6LIWw5W0Lg1R7VKi7t+kEWirHDnhiJ8y3vO
cXdts1NiBsqlt66A/Y/pBkM1MCE8eQKkKDGxBeXCarkvtAvaTXl6o1hmivQh9UXo
L+aT0S9gNbB645fiEIfHGHrfMeUVeyUJTBt/BVErpETj0WbolM1whzw6CTT8q5zU
IefYNjpLdPo6ggl8OCcdy/2YBh/2vSQNOpeOJh6nw+K8t3CkkWbhbZv/KHkFP+mX
X9zhwqvNP9ZbwEunOlk3f4IgdCuydmgRkwHvwK4eEJW2dRvoC0RMd9LOJ2KHC4OT
gKyjNmubfEaFehGP04Oh9SJyvJPWNtzFg9pEQGnBtQOs3M/La4ePbRxHvoc14Mke
DvJb51JF7zSPw8aC4FpzmPfLCjlVNQh5QUe8NALVr4nHC5kgqD04Gm9mOW3moOUJ
Zd4P4lKaVpGDDGCcDQzLVtK6WK/jtAOsugf1RsBOrIidb6UVa16q32oiHmN1tXqS
G0/YY/gsigdiXvtD5nRn7uECAwEAAQ==
-----END PUBLIC KEY-----`
)

type Config struct {
	Token   string `json:"token,omitempty"`
	UseBeta bool   `json:"use_beta,omitempty"`
}

type ServerList struct {
	Groups  map[string][]ServerGroup `json:"groups"`
	Regions []Region                 `json:"regions"`
}

type ServerGroup struct {
	Name  string `json:"name"`
	Ports []int  `json:"ports"`
}

type Region struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	Country      string              `json:"country"`
	DNS          string              `json:"dns"`
	AutoRegion   bool                `json:"auto_region"`
	Geo          bool                `json:"geo"`
	Offline      bool                `json:"offline"`
	PortForward  bool                `json:"port_forward"`
	Servers      map[string][]Server `json:"servers"`
}

type Server struct {
	IP    string   `json:"ip"`
	CN    string   `json:"cn"`
	Cert  []string `json:"cert,omitempty"`
}

type EnclaveEntry struct {
	MREnclave string `json:"mr_enclave"`
	Status    string `json:"status"`
	Created   int64  `json:"created"`
}

func main() {
	rest.Host = "vp.net"

	var (
		connectCmd    = flag.NewFlagSet("connect", flag.ExitOnError)
		disconnectCmd = flag.NewFlagSet("disconnect", flag.ExitOnError)
		statusCmd     = flag.NewFlagSet("status", flag.ExitOnError)
		serversCmd    = flag.NewFlagSet("servers", flag.ExitOnError)
		loginCmd      = flag.NewFlagSet("login", flag.ExitOnError)
		logoutCmd     = flag.NewFlagSet("logout", flag.ExitOnError)
		accountCmd    = flag.NewFlagSet("account", flag.ExitOnError)
		pingCmd       = flag.NewFlagSet("ping", flag.ExitOnError)
		setKeyCmd     = flag.NewFlagSet("set-key", flag.ExitOnError)
		wgetCmd       = flag.NewFlagSet("wget", flag.ExitOnError)
	)

	connectToken := connectCmd.String("token", "", "Authentication token")
	serversBeta := serversCmd.Bool("beta", false, "List beta servers")
	loginUser := loginCmd.String("u", "", "Username (email)")
	loginAnon := loginCmd.Bool("anonymous", false, "Create anonymous account for crypto payments")
	loginEmailToken := loginCmd.Bool("token", false, "Use email token instead of password")
	pingCount := pingCmd.Int("c", 4, "Number of pings (0 = infinite)")
	pingRegion := pingCmd.String("region", "", "Region ID or name")
	pingBeta := pingCmd.Bool("beta", false, "Use beta servers")
	setKeyBeta := setKeyCmd.Bool("beta", false, "Use beta servers")
	wgetOutput := wgetCmd.String("o", "", "Output file (default: filename from URL, - for stdout)")
	wgetRegion := wgetCmd.String("region", "", "Region ID or name")
	wgetBeta := wgetCmd.Bool("beta", false, "Use beta servers")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()

	switch os.Args[1] {
	case "login":
		loginCmd.Parse(os.Args[2:])
		if err := doLogin(ctx, *loginUser, *loginAnon, *loginEmailToken); err != nil {
			log.Fatalf("Login failed: %v", err)
		}
	case "logout":
		logoutCmd.Parse(os.Args[2:])
		if err := doLogout(ctx); err != nil {
			log.Fatalf("Logout failed: %v", err)
		}
	case "account":
		accountCmd.Parse(os.Args[2:])
		if err := doAccount(ctx); err != nil {
			log.Fatalf("Account failed: %v", err)
		}
	case "order":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: vpnet-cli order PLAN [CRYPTO]")
		}
		payMethod := ""
		if len(os.Args) >= 4 {
			payMethod = os.Args[3]
		}
		if err := doOrder(ctx, os.Args[2], payMethod); err != nil {
			log.Fatalf("Order failed: %v", err)
		}
	case "set-email":
		if len(os.Args) < 3 {
			log.Fatalf("Usage: vpnet-cli set-email EMAIL")
		}
		if err := doSetEmail(ctx, os.Args[2]); err != nil {
			log.Fatalf("Set email failed: %v", err)
		}
	case "connect":
		connectCmd.Parse(os.Args[2:])
		if err := doConnect(ctx, *connectToken); err != nil {
			log.Fatalf("Connect failed: %v", err)
		}
	case "disconnect":
		disconnectCmd.Parse(os.Args[2:])
		if err := doDisconnect(ctx); err != nil {
			log.Fatalf("Disconnect failed: %v", err)
		}
	case "status":
		statusCmd.Parse(os.Args[2:])
		if err := doStatus(ctx); err != nil {
			log.Fatalf("Status failed: %v", err)
		}
	case "servers":
		serversCmd.Parse(os.Args[2:])
		if err := listServers(ctx, *serversBeta); err != nil {
			log.Fatalf("List servers failed: %v", err)
		}
	case "ping":
		pingCmd.Parse(os.Args[2:])
		target := ""
		if pingCmd.NArg() > 0 {
			target = pingCmd.Arg(0)
		}
		if err := doPing(ctx, target, *pingCount, *pingRegion, *pingBeta); err != nil {
			log.Fatalf("Ping failed: %v", err)
		}
	case "set-key":
		setKeyCmd.Parse(os.Args[2:])
		if setKeyCmd.NArg() < 2 {
			log.Fatalf("Usage: vpnet-cli set-key [-beta] <public-key> <region>")
		}
		if err := doSetKey(ctx, setKeyCmd.Arg(0), setKeyCmd.Arg(1), *setKeyBeta); err != nil {
			log.Fatalf("Set key failed: %v", err)
		}
	case "wget":
		wgetCmd.Parse(os.Args[2:])
		if wgetCmd.NArg() < 1 {
			log.Fatalf("Usage: vpnet-cli wget [-beta] [-region R] [-o FILE] URL")
		}
		if err := doWget(ctx, wgetCmd.Arg(0), *wgetOutput, *wgetRegion, *wgetBeta); err != nil {
			log.Fatalf("Download failed: %v", err)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("VP.NET CLI - WireGuard VPN Client")
	fmt.Println("\nUsage:")
	fmt.Println("  vpnet-cli login                    - Authenticate via OAuth2 (default)")
	fmt.Println("  vpnet-cli login -u EMAIL           - Authenticate with email/password")
	fmt.Println("  vpnet-cli login -u EMAIL --token   - Authenticate with email token")
	fmt.Println("  vpnet-cli login --anonymous        - Create anonymous account (crypto)")
	fmt.Println("  vpnet-cli logout                   - Invalidate token and log out")
	fmt.Println("  vpnet-cli account                  - Show account/subscription info")
	fmt.Println("  vpnet-cli order PLAN [CRYPTO]      - Create crypto payment order (1m, 1y, 3y)")
	fmt.Println("                                       CRYPTO: BTC, LTC, USDT@polygon, etc.")
	fmt.Println("  vpnet-cli set-email EMAIL          - Set email on anonymous account")
	fmt.Println("  vpnet-cli connect [--token TOKEN]  - Connect to VPN")
	fmt.Println("  vpnet-cli disconnect               - Disconnect from VPN")
	fmt.Println("  vpnet-cli status                   - Show connection status")
	fmt.Println("  vpnet-cli servers [--beta]         - List available servers")
	fmt.Println("  vpnet-cli ping [-c N] [-region R] [TARGET]")
	fmt.Println("                                     - Ping through VPN tunnel (no root needed)")
	fmt.Println("  vpnet-cli set-key [-beta] PUBKEY REGION")
	fmt.Println("                                     - Register WireGuard public key and output config")
	fmt.Println("  vpnet-cli wget [-beta] [-region R] [-o FILE] URL")
	fmt.Println("                                     - Download file through VPN tunnel")
}

func getConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config dir: %w", err)
	}

	vpnetDir := filepath.Join(configDir, "vpnet-cli")
	if err := os.MkdirAll(vpnetDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create config dir: %w", err)
	}

	return vpnetDir, nil
}

func loadConfig() (*Config, error) {
	configDir, err := getConfigDir()
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(configDir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

func saveConfig(cfg *Config) error {
	configDir, err := getConfigDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(configDir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func doLogin(ctx context.Context, username string, anonymous bool, emailToken bool) error {
	auth := &authInfo{}
	if err := auth.init(); err != nil {
		return err
	}

	switch {
	case anonymous:
		fmt.Println("Creating anonymous account...")
		if err := auth.loginAnonymous(); err != nil {
			return err
		}

	case username != "" && emailToken:
		// Email token login: server sends a code to the email
		fmt.Printf("Requesting login token for %s...\n", username)
		if err := auth.requestEmailToken(username); err != nil {
			return err
		}
		token := promptLine("Enter token from email: ")
		if token == "" {
			return fmt.Errorf("no token provided")
		}
		if err := auth.loginToken(token); err != nil {
			return err
		}

	case username != "":
		// Email + password login
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if err := auth.loginPassword(username, string(passwordBytes)); err != nil {
			return err
		}

	default:
		// OAuth2 login
		fmt.Println("Starting OAuth2 authentication...")
		if err := auth.loginOAuth2(); err != nil {
			return err
		}
	}

	if err := auth.save(); err != nil {
		return err
	}

	fmt.Println("Login successful! Token saved.")
	return nil
}

func doLogout(ctx context.Context) error {
	auth, err := loadAuth()
	if err != nil {
		fmt.Println("Not logged in.")
		return nil
	}

	if err := auth.logout(); err != nil {
		return err
	}

	fmt.Println("Logged out.")
	return nil
}

type vpnProduct struct {
	ID       string
	Name     string
	Lifetime string
	Price    string
}

// fetchProducts fetches VPN products and returns them indexed by lifetime alias
func fetchProducts(ctx context.Context) ([]vpnProduct, error) {
	products, err := listProducts(ctx)
	if err != nil {
		return nil, err
	}

	var result []vpnProduct
	for _, p := range products {
		id, _ := p["Catalog_Product__"].(string)
		name, _ := p["Basic.Name"].(string)
		lifetime, _ := p["Basic.ServiceLifetime"].(string)
		price := ""
		if prObj, ok := p["Price.Price"].(map[string]any); ok {
			if d, ok := prObj["display"].(string); ok {
				price = d
			}
		}
		if id == "" {
			continue
		}
		result = append(result, vpnProduct{
			ID:       id,
			Name:     name,
			Lifetime: lifetime,
			Price:    price,
		})
	}
	return result, nil
}

// lifetimeAliases maps user-friendly names to ServiceLifetime values
var lifetimeAliases = map[string]string{
	"1m":      "1m",
	"monthly": "1m",
	"1y":      "12m",
	"12m":     "12m",
	"yearly":  "12m",
	"3y":      "36m",
	"36m":     "36m",
}

func resolveProduct(ctx context.Context, input string) (*vpnProduct, error) {
	// Direct product ID
	if strings.HasPrefix(input, "cpr-") {
		return &vpnProduct{ID: input, Name: input}, nil
	}

	products, err := fetchProducts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch products: %w", err)
	}

	// Resolve alias to lifetime
	target := input
	if lt, ok := lifetimeAliases[strings.ToLower(input)]; ok {
		target = lt
	}

	for _, p := range products {
		if p.Lifetime == target {
			return &p, nil
		}
	}

	// Show available products
	fmt.Println("Available plans:")
	for _, p := range products {
		fmt.Printf("  %-4s  %s  %s\n", p.Lifetime, p.Price, p.Name)
	}
	return nil, fmt.Errorf("unknown plan %q", input)
}

type payOption struct {
	ID       string
	Symbol   string
	Chain    string
	Amount   string
	Addr     string
	Deadline time.Time
}

func matchPayOption(options []payOption, spec string) (int, error) {
	// Parse SYMBOL or SYMBOL@chain
	spec = strings.ToUpper(spec)
	symbol := spec
	chain := ""
	if i := strings.Index(spec, "@"); i >= 0 {
		symbol = spec[:i]
		chain = spec[i+1:]
	}

	var matches []int
	for i, opt := range options {
		if !strings.EqualFold(opt.Symbol, symbol) {
			continue
		}
		if chain != "" && !strings.EqualFold(opt.Chain, chain) {
			continue
		}
		matches = append(matches, i)
	}

	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return -1, fmt.Errorf("no payment method matching %q", spec)
	}
	// Ambiguous - show matching options
	fmt.Printf("Multiple matches for %q:\n", spec)
	for _, i := range matches {
		opt := options[i]
		fmt.Printf("  %s@%s  %s\n", opt.Symbol, strings.ToLower(opt.Chain), opt.Amount)
	}
	return -1, fmt.Errorf("specify chain, e.g. %s@%s", symbol, strings.ToLower(options[matches[0]].Chain))
}

func doOrder(ctx context.Context, product string, payMethod string) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login --anonymous' first")
	}

	p, err := resolveProduct(ctx, product)
	if err != nil {
		return err
	}

	label := p.Name
	if p.Price != "" {
		label += " (" + p.Price + ")"
	}
	fmt.Printf("Creating order for %s...\n", label)

	res, err := auth.createAnonOrder(ctx, p.ID)
	if err != nil {
		return err
	}

	checkoutID, _ := res["Crypto_Checkout__"].(string)
	if checkoutID == "" {
		return fmt.Errorf("no checkout ID in response")
	}

	// Fetch checkout to get payment options
	checkout, err := fetchCheckout(ctx, checkoutID)
	if err != nil {
		return fmt.Errorf("failed to fetch checkout: %w", err)
	}

	amounts, _ := checkout["Amount"].([]any)
	if len(amounts) == 0 {
		return fmt.Errorf("no payment methods available")
	}

	var options []payOption
	for _, a := range amounts {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		id, _ := am["Crypto_Checkout_Amount__"].(string)
		symbol := ""
		if tok, ok := am["Token"].(map[string]any); ok {
			symbol, _ = tok["Symbol"].(string)
		}
		chain := ""
		if ch, ok := am["Chain"].(map[string]any); ok {
			chain, _ = ch["Name"].(string)
		}
		amount := ""
		if af, ok := am["Amount_Full"].(map[string]any); ok {
			amount, _ = af["display"].(string)
		}
		addr := ""
		if pay, ok := am["Payment"].(map[string]any); ok {
			addr, _ = pay["to"].(string)
		}
		var deadline time.Time
		if dl, ok := am["Deadline"].(map[string]any); ok {
			if iso, ok := dl["iso"].(string); ok {
				deadline, _ = time.Parse("2006-01-02 15:04:05.000000", iso)
			}
		}
		if id != "" && addr != "" {
			options = append(options, payOption{id, symbol, chain, amount, addr, deadline})
		}
	}

	if len(options) == 0 {
		return fmt.Errorf("no payment options with addresses")
	}

	var selected payOption
	if payMethod != "" {
		idx, err := matchPayOption(options, payMethod)
		if err != nil {
			return err
		}
		selected = options[idx]
	} else {
		fmt.Println("\nAvailable payment methods:")
		for i, opt := range options {
			chainInfo := ""
			if opt.Chain != "" && opt.Chain != opt.Symbol {
				chainInfo = " (" + opt.Chain + ")"
			}
			fmt.Printf("  %2d) %-6s%-12s  %s\n", i+1, opt.Symbol, chainInfo, opt.Amount)
		}

		choice := promptLine("\nSelect payment method [1]: ")
		idx := 0
		if choice != "" {
			if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil || idx < 1 || idx > len(options) {
				return fmt.Errorf("invalid selection")
			}
			idx--
		}
		selected = options[idx]
	}

	// Activate the selected payment method
	activatedAmount, err := activateCheckoutAmount(ctx, selected.ID)
	if err != nil {
		return fmt.Errorf("failed to activate payment method: %w", err)
	}

	// Get deadline from activated amount response
	var deadline time.Time
	if dl, ok := activatedAmount["Deadline"].(map[string]any); ok {
		if iso, ok := dl["iso"].(string); ok {
			deadline, _ = time.Parse("2006-01-02 15:04:05.000000", iso)
		}
	}
	// Fall back to checkout-level deadline
	if deadline.IsZero() {
		co, err := fetchCheckout(ctx, checkoutID)
		if err == nil {
			if dl, ok := co["Deadline"].(map[string]any); ok {
				if iso, ok := dl["iso"].(string); ok {
					deadline, _ = time.Parse("2006-01-02 15:04:05.000000", iso)
				}
			}
		}
	}

	fmt.Printf("\nSend exactly %s to:\n", selected.Amount)
	fmt.Printf("  %s\n", selected.Addr)
	if !deadline.IsZero() {
		remaining := time.Until(deadline)
		if remaining > 0 {
			fmt.Printf("  Expires in: %s (at %s UTC)\n", remaining.Truncate(time.Second), deadline.Format("15:04:05"))
		}
	}

	// Poll for payment confirmation every 10s
	fmt.Println("\nWaiting for payment...")
	for {
		time.Sleep(10 * time.Second)
		co, err := fetchCheckout(ctx, checkoutID)
		if err != nil {
			continue
		}
		status, _ := co["Status"].(string)
		// Update deadline from checkout if we didn't have one
		if deadline.IsZero() {
			if dl, ok := co["Deadline"].(map[string]any); ok {
				if iso, ok := dl["iso"].(string); ok {
					deadline, _ = time.Parse("2006-01-02 15:04:05.000000", iso)
				}
			}
		}
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining > 0 {
				fmt.Printf("  Status: %s (expires in %s)\n", status, remaining.Truncate(time.Second))
			} else {
				fmt.Printf("  Status: %s (expired)\n", status)
			}
		} else {
			fmt.Printf("  Status: %s\n", status)
		}
		if status == "paid" {
			fmt.Println("\nPayment confirmed! Your VPN subscription is now active.")
			return nil
		}
		if status == "expired" {
			return fmt.Errorf("payment expired")
		}
	}
}

func doSetEmail(ctx context.Context, email string) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	if err := auth.setEmail(ctx, email); err != nil {
		return err
	}

	fmt.Printf("Email set to %s\n", email)
	return nil
}

func doAccount(ctx context.Context) error {
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	fmt.Printf("Auth method: %s\n", auth.data.Method)
	if auth.data.ExpiresAt != "" {
		fmt.Printf("Token expires: %s\n", auth.data.ExpiresAt)
	}

	if auth.data.Method == AuthVPNToken {
		info, err := auth.getAccountInfo(ctx)
		if err != nil {
			return fmt.Errorf("failed to get account info: %w", err)
		}

		if email, ok := info["email"].(string); ok && email != "" {
			fmt.Printf("Email: %s\n", email)
		}
		if plan, ok := info["plan"].(string); ok && plan != "" {
			fmt.Printf("Plan: %s\n", plan)
		}
		if active, ok := info["active"].(bool); ok {
			fmt.Printf("Active: %v\n", active)
		}
		if expired, ok := info["expired"].(bool); ok && expired {
			fmt.Println("Status: expired")
		}
		if days, ok := info["days_remaining"].(float64); ok {
			fmt.Printf("Days remaining: %.0f\n", days)
		}
		if renewURL, ok := info["renew_url"].(string); ok && renewURL != "" {
			if needsPay, ok := info["needs_payment"].(bool); ok && needsPay {
				fmt.Printf("Renew at: %s\n", renewURL)
			}
		}
	}

	return nil
}

func promptLine(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func doConnect(ctx context.Context, token string) error {
	// Load or create auth
	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first: %w", err)
	}

	// Load config
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Generate ephemeral WireGuard keypair for this session
	_, pubKeyB64, err := generateWireGuardKeyPair()
	if err != nil {
		return err
	}

	// Fetch server list and enclave list
	fmt.Println("Fetching server list...")
	serverList, err := fetchServerList(ctx, cfg.UseBeta)
	if err != nil {
		return err
	}

	enclaveList, err := fetchEnclaveList(ctx)
	if err != nil {
		return err
	}

	// Find a suitable server
	var selectedRegion *Region
	for i := range serverList.Regions {
		region := &serverList.Regions[i]
		if !region.Offline && region.AutoRegion {
			selectedRegion = region
			break
		}
	}

	if selectedRegion == nil {
		return fmt.Errorf("no available servers found")
	}

	fmt.Printf("Selected region: %s (%s)\n", selectedRegion.Name, selectedRegion.Country)

	// Get WireGuard servers from this region
	wgServers, ok := selectedRegion.Servers["wg"]
	if !ok || len(wgServers) == 0 {
		return fmt.Errorf("no WireGuard servers available in selected region")
	}

	selectedServer := wgServers[0]
	fmt.Printf("Connecting to server: %s\n", selectedServer.CN)

	// Register our public key with the server via direct HTTPS
	fmt.Println("Registering with server...")
	_, err = registerWithServer(selectedServer.IP, pubKeyB64, auth.data.APIToken, enclaveList)
	if err != nil {
		return fmt.Errorf("failed to register with server: %w", err)
	}

	fmt.Println("✓ Connected to VP.NET!")
	return nil
}

func doDisconnect(ctx context.Context) error {
	fmt.Println("Disconnecting from VP.NET...")
	return fmt.Errorf("not implemented yet")
}

func doStatus(ctx context.Context) error {
	fmt.Println("Checking VPN status...")
	return fmt.Errorf("not implemented yet")
}

func generateWireGuardKeyPair() (privateKey, publicKey string, err error) {
	// Generate a random private key
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Clamp the private key (WireGuard requirement)
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	// Generate the public key from the private key
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)

	// Encode keys to base64
	privateKey = base64.StdEncoding.EncodeToString(privKey[:])
	publicKey = base64.StdEncoding.EncodeToString(pubKey[:])

	return privateKey, publicKey, nil
}

func doSetKey(ctx context.Context, pubKeyB64, regionName string, useBeta bool) error {
	keyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(keyBytes) != 32 {
		return fmt.Errorf("invalid key length: got %d bytes, expected 32", len(keyBytes))
	}

	auth, err := loadAuth()
	if err != nil {
		return fmt.Errorf("not authenticated, please run 'vpnet-cli login' first")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}

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
		if r.ID == regionName || r.Name == regionName {
			region = r
			break
		}
	}
	if region == nil {
		return fmt.Errorf("region not found: %s", regionName)
	}

	wgServers, ok := region.Servers["wg"]
	if !ok || len(wgServers) == 0 {
		return fmt.Errorf("no WireGuard servers in region %s", region.Name)
	}
	selectedServer := wgServers[0]

	// Register public key with the server
	regResult, err := registerWithServer(selectedServer.IP, pubKeyB64, auth.data.APIToken, enclaveList)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Output WireGuard config
	fmt.Println("[Interface]")
	fmt.Printf("# PrivateKey = <your private key>\n")
	fmt.Printf("Address = %s/32\n", regResult.PeerIP)
	if len(regResult.DNSServers) > 0 {
		fmt.Printf("DNS = %s\n", strings.Join(regResult.DNSServers, ", "))
	}
	fmt.Println()
	fmt.Println("[Peer]")
	fmt.Printf("PublicKey = %s\n", regResult.ServerKey)
	fmt.Printf("Endpoint = %s:%d\n", regResult.ServerIP, regResult.ServerPort)
	fmt.Println("AllowedIPs = 0.0.0.0/0")

	return nil
}

func verifyServerListSignature(data, signature []byte) error {
	// Parse the public key
	block, _ := pem.Decode([]byte(serverListPublicKey))
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	// Hash the data
	hashed := sha256.Sum256(data)

	// Verify the signature
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

func fetchServerList(ctx context.Context, useBeta bool) (*ServerList, error) {
	url := serverListURL
	if useBeta {
		url = serverListBetaURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch servers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Split JSON data and signature
	lastBrace := bytes.LastIndexByte(body, '}')
	if lastBrace == -1 {
		return nil, fmt.Errorf("invalid response format: no JSON found")
	}

	jsonData := body[:lastBrace+1]
	sigBase64 := bytes.TrimSpace(body[lastBrace+1:])

	// Decode and verify signature
	signature, err := base64.StdEncoding.DecodeString(string(sigBase64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := verifyServerListSignature(jsonData, signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Parse JSON
	var serverList ServerList
	if err := json.Unmarshal(jsonData, &serverList); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &serverList, nil
}

func fetchEnclaveList(ctx context.Context) ([]EnclaveEntry, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", enclaveListURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch enclave list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enclave list returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Split JSON data and signature (JSON array ends with ']')
	lastBracket := bytes.LastIndexByte(body, ']')
	if lastBracket == -1 {
		return nil, fmt.Errorf("invalid enclave list format: no JSON array found")
	}

	jsonData := body[:lastBracket+1]
	sigBase64 := bytes.TrimSpace(body[lastBracket+1:])

	// Decode and verify signature
	signature, err := base64.StdEncoding.DecodeString(string(sigBase64))
	if err != nil {
		return nil, fmt.Errorf("failed to decode enclave list signature: %w", err)
	}

	if err := verifyServerListSignature(jsonData, signature); err != nil {
		return nil, fmt.Errorf("enclave list signature verification failed: %w", err)
	}

	// Parse JSON
	var entries []EnclaveEntry
	if err := json.Unmarshal(jsonData, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse enclave list: %w", err)
	}

	// Filter to valid enclaves only
	var valid []EnclaveEntry
	for _, e := range entries {
		if e.Status == "valid" {
			valid = append(valid, e)
		}
	}

	if len(valid) == 0 {
		return nil, fmt.Errorf("no valid enclaves in enclave list")
	}

	return valid, nil
}

func listServers(ctx context.Context, useBeta bool) error {
	url := serverListURL
	if useBeta {
		url = serverListBetaURL
	}

	fmt.Printf("Fetching server list from %s...\n", url)

	serverList, err := fetchServerList(ctx, useBeta)
	if err != nil {
		return err
	}

	fmt.Println("✓ Signature verified successfully")
	fmt.Println("\nAvailable regions:")

	for _, region := range serverList.Regions {
		status := "online"
		if region.Offline {
			status = "offline"
		}
		fmt.Printf("  - %s (%s) [%s]\n", region.Name, region.Country, status)
		if wgServers, ok := region.Servers["wg"]; ok && len(wgServers) > 0 {
			fmt.Printf("    WireGuard servers: %d\n", len(wgServers))
		}
	}

	return nil
}
