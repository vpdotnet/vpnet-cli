package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/KarpelesLab/rest"
)

// VP.NET OAuth2 client ID
const vpnetClientID = "oaap-wdeb2i-ee25-b6lj-rmqm-oe5b4qb4"

// AuthMethod represents how the user authenticated
type AuthMethod string

const (
	AuthOAuth2   AuthMethod = "oauth2"
	AuthVPNToken AuthMethod = "vpn_token"
)

// authData is the persisted authentication state
type authData struct {
	Method    AuthMethod  `json:"method"`
	OAuth2    *rest.Token `json:"oauth2,omitempty"`
	APIToken  string      `json:"api_token,omitempty"`
	ExpiresAt string      `json:"expires_at,omitempty"`
}

type authInfo struct {
	data     authData
	filepath string
}

func loadAuth() (*authInfo, error) {
	auth := &authInfo{}
	if err := auth.init(); err != nil {
		return nil, err
	}
	if err := auth.load(); err == nil {
		return auth, nil
	}
	return nil, os.ErrNotExist
}

func (auth *authInfo) init() error {
	cnf, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("failed to locate conf dir: %w", err)
	}
	cnf = filepath.Join(cnf, "vpnet-cli")
	os.MkdirAll(cnf, 0700)
	auth.filepath = filepath.Join(cnf, "auth.json")
	return nil
}

func (auth *authInfo) load() error {
	data, err := os.ReadFile(auth.filepath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &auth.data); err != nil {
		return err
	}
	if auth.data.OAuth2 != nil {
		auth.data.OAuth2.ClientID = vpnetClientID
	}
	return nil
}

func (auth *authInfo) save() error {
	data, err := json.MarshalIndent(auth.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(auth.filepath, data, 0600)
}

// loginOAuth2 performs the OAuth2 poll-based login flow
func (auth *authInfo) loginOAuth2() error {
	var res map[string]any
	err := rest.Apply(context.Background(), "OAuth2/App/"+vpnetClientID+":token_create", "POST", map[string]any{}, &res)
	if err != nil {
		return err
	}

	tok, ok := res["polltoken"].(string)
	if !ok {
		return fmt.Errorf("failed to fetch polltoken")
	}

	tokuri := url.QueryEscape("polltoken:" + tok)
	fulluri := fmt.Sprintf("https://vp.net/_rest/OAuth2:auth?response_type=code&client_id=%s&redirect_uri=%s&scope=profile", vpnetClientID, tokuri)
	if u, ok := res["xox"].(string); ok {
		fulluri = u
	}

	log.Printf("Please open this URL to authenticate:\n%s", fulluri)

	for {
		var pollRes map[string]any
		err := rest.Apply(context.Background(), "OAuth2/App/"+vpnetClientID+":token_poll", "POST", map[string]any{"polltoken": tok}, &pollRes)
		if err != nil {
			return err
		}

		v, ok := pollRes["response"]
		if !ok {
			time.Sleep(time.Second)
			continue
		}

		resp, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("invalid response from api")
		}

		code, ok := resp["code"].(string)
		if !ok {
			return fmt.Errorf("invalid response from api, no code")
		}

		log.Printf("Fetching authentication token...")

		httpresp, err := http.PostForm("https://vp.net/_special/rest/OAuth2:token", url.Values{
			"client_id":  {vpnetClientID},
			"grant_type": {"authorization_code"},
			"code":       {code},
		})
		if err != nil {
			return fmt.Errorf("while fetching token: %w", err)
		}
		defer httpresp.Body.Close()

		if httpresp.StatusCode != 200 {
			return fmt.Errorf("invalid status code from server: %s", httpresp.Status)
		}

		body, err := io.ReadAll(httpresp.Body)
		if err != nil {
			return fmt.Errorf("while reading token: %w", err)
		}

		var token rest.Token
		if err := json.Unmarshal(body, &token); err != nil {
			return fmt.Errorf("while decoding token: %w", err)
		}
		token.ClientID = vpnetClientID

		auth.data.Method = AuthOAuth2
		auth.data.OAuth2 = &token
		auth.data.APIToken = ""
		auth.data.ExpiresAt = ""

		log.Printf("Authentication successful!")
		return nil
	}
}

// loginPassword authenticates with email and password via the VPN API.
func (auth *authInfo) loginPassword(username, password string) error {
	var res struct {
		APIToken  string `json:"api_token"`
		ExpiresAt string `json:"expires_at"`
	}

	err := vpnAPICall(context.Background(), "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v5/api_token",
		"username": username,
		"password": password,
	}, "", &res)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if res.APIToken == "" {
		return fmt.Errorf("no api_token in response")
	}

	auth.data.Method = AuthVPNToken
	auth.data.APIToken = res.APIToken
	auth.data.ExpiresAt = res.ExpiresAt
	auth.data.OAuth2 = nil

	return nil
}

// requestEmailToken asks the server to send a login token to the given email address.
func (auth *authInfo) requestEmailToken(email string) error {
	return vpnAPICall(context.Background(), "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v5/request_token",
		"email":    email,
	}, "", nil)
}

// loginToken authenticates by consuming an email token.
func (auth *authInfo) loginToken(email, token string) error {
	var res struct {
		APIToken  string `json:"api_token"`
		ExpiresAt string `json:"expires_at"`
	}

	err := vpnAPICall(context.Background(), "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v5/api_token",
		"email":    email,
		"token":    token,
	}, "", &res)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	if res.APIToken == "" {
		return fmt.Errorf("no api_token in response")
	}

	auth.data.Method = AuthVPNToken
	auth.data.APIToken = res.APIToken
	auth.data.ExpiresAt = res.ExpiresAt
	auth.data.OAuth2 = nil

	return nil
}

// loginAnonymous creates a fully anonymous user with a VPN token via Network/VPN:anonToken
func (auth *authInfo) loginAnonymous() error {
	var res struct {
		Token string `json:"token"`
	}

	err := vpnAPICall(context.Background(), "Network/VPN:anonToken", "POST", map[string]any{}, "", &res)
	if err != nil {
		return fmt.Errorf("anonymous login failed: %w", err)
	}
	if res.Token == "" {
		return fmt.Errorf("no token in response")
	}

	auth.data.Method = AuthVPNToken
	auth.data.APIToken = res.Token
	auth.data.OAuth2 = nil

	return nil
}

// refreshToken refreshes the VPN API token
func (auth *authInfo) refreshToken() error {
	if auth.data.Method != AuthVPNToken {
		return nil // OAuth2 tokens auto-refresh via the rest library
	}

	var res struct {
		APIToken  string `json:"api_token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := auth.tokenAPICall(context.Background(), "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v5/refresh",
	}, &res); err != nil {
		return err
	}
	if res.APIToken != "" {
		auth.data.APIToken = res.APIToken
	}
	auth.data.ExpiresAt = res.ExpiresAt
	return auth.save()
}

// logout invalidates the current token and removes local auth
func (auth *authInfo) logout() error {
	if auth.data.Method == AuthVPNToken && auth.data.APIToken != "" {
		// Best-effort server-side expiration
		auth.tokenAPICall(context.Background(), "Network/VPN:apiV2", "POST", map[string]any{
			"resource": "client/v2/expire_token",
		}, nil)
	}
	return os.Remove(auth.filepath)
}

// Apply makes an authenticated REST API call using the appropriate auth method.
// For OAuth2, uses the rest library with Bearer auth.
// For VPN token, makes a direct HTTP call with Token auth header.
func (auth *authInfo) Apply(ctx context.Context, endpoint, method string, args map[string]any, target interface{}) error {
	switch auth.data.Method {
	case AuthOAuth2:
		if auth.data.OAuth2 == nil {
			return fmt.Errorf("no OAuth2 token available")
		}
		err := rest.Apply(auth.data.OAuth2.Use(ctx), endpoint, method, args, target)
		if err != nil {
			return err
		}
		auth.save()
		return nil
	case AuthVPNToken:
		return auth.tokenAPICall(ctx, endpoint, method, args, target)
	default:
		return fmt.Errorf("unknown auth method: %s", auth.data.Method)
	}
}

// tokenAPICall makes an authenticated VPN API call with the Token header
func (auth *authInfo) tokenAPICall(ctx context.Context, endpoint, method string, args map[string]any, target interface{}) error {
	return vpnAPICall(ctx, endpoint, method, args, "Token "+auth.data.APIToken, target)
}

// vpnAPICall makes a direct HTTP call to the REST API with optional auth.
// Used for endpoints that expect "Authorization: Token xxx" (not Bearer).
// Handles both raw responses (VPN API with setResponseFlag('raw')) and
// standard envelope responses {"result": "success", "data": X}.
func vpnAPICall(ctx context.Context, endpoint, method string, args map[string]any, authHeader string, target interface{}) error {
	apiURL := fmt.Sprintf("https://%s/_special/rest/%s", rest.Host, endpoint)

	var body io.Reader
	if args != nil && (method == "POST" || method == "PUT" || method == "PATCH") {
		data, err := json.Marshal(args)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, apiURL, body)
	if err != nil {
		return err
	}

	// For GET/DELETE, pass args as query parameters
	if args != nil && (method == "GET" || method == "DELETE") {
		q := req.URL.Query()
		for k, v := range args {
			q.Set(k, fmt.Sprint(v))
		}
		req.URL.RawQuery = q.Encode()
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Sec-ClientId", vpnetClientID)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response - handle both envelope and raw formats
	var envelope struct {
		Result string          `json:"result"`
		Data   json.RawMessage `json:"data"`
		Error  string          `json:"error"`
		Token  string          `json:"token"`
	}

	if err := json.Unmarshal(respBody, &envelope); err != nil {
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
		}
		// Not valid JSON at all
		return fmt.Errorf("invalid API response: %w", err)
	}

	// Check for standard error envelope
	if envelope.Result == "error" {
		return fmt.Errorf("API error [%s]: %s", envelope.Token, envelope.Error)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(respBody))
	}

	if target == nil {
		return nil
	}

	// If response has envelope with data, unmarshal from data field
	if envelope.Result == "success" && envelope.Data != nil {
		return json.Unmarshal(envelope.Data, target)
	}

	// Otherwise treat as raw response (e.g. VPN API endpoints with setResponseFlag('raw'))
	return json.Unmarshal(respBody, target)
}

// getVPNCredentials retrieves WireGuard auth credentials (vpn_secret1, vpn_secret2)
func (auth *authInfo) getVPNCredentials(ctx context.Context) (secret1, secret2 string, err error) {
	if auth.data.Method != AuthVPNToken {
		return "", "", fmt.Errorf("VPN credentials only available with token auth")
	}

	var res struct {
		VPNSecret1 string `json:"vpn_secret1"`
		VPNSecret2 string `json:"vpn_secret2"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := auth.tokenAPICall(ctx, "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v5/vpn_token",
	}, &res); err != nil {
		return "", "", err
	}

	return res.VPNSecret1, res.VPNSecret2, nil
}

// getAccountInfo retrieves account/subscription information
func (auth *authInfo) getAccountInfo(ctx context.Context) (map[string]any, error) {
	var res map[string]any
	if err := auth.tokenAPICall(ctx, "Network/VPN:apiV2", "GET", map[string]any{
		"resource": "client/v5/account",
	}, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// listProducts fetches available VPN products from the catalog
func listProducts(ctx context.Context) ([]map[string]any, error) {
	var res struct {
		Data []map[string]any `json:"data"`
	}
	err := vpnAPICall(ctx, "Catalog/Product:search", "GET", nil, "", &res)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// setEmail sets the email on an anonymous account that has no email yet
func (auth *authInfo) setEmail(ctx context.Context, email string) error {
	var res struct {
		Success bool `json:"success"`
	}
	return auth.tokenAPICall(ctx, "Network/VPN:apiV2", "POST", map[string]any{
		"resource": "client/v2/set_email",
		"email":    email,
	}, &res)
}

// createAnonOrder creates a crypto payment order for the given product
func (auth *authInfo) createAnonOrder(ctx context.Context, product string) (map[string]any, error) {
	if auth.data.Method != AuthVPNToken {
		return nil, fmt.Errorf("anonymous orders require VPN token auth")
	}

	var res map[string]any
	err := vpnAPICall(ctx, "Network/VPN:anonOrder", "POST", map[string]any{
		"product": product,
		"token":   auth.data.APIToken,
	}, "", &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// fetchCheckout fetches a crypto checkout by ID
func fetchCheckout(ctx context.Context, id string) (map[string]any, error) {
	var res map[string]any
	err := vpnAPICall(ctx, "Crypto/Checkout:fetch", "GET", map[string]any{
		"id": id,
	}, "", &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// activateCheckoutAmount selects a payment method for the checkout
func activateCheckoutAmount(ctx context.Context, amountID string) (map[string]any, error) {
	var res map[string]any
	err := vpnAPICall(ctx, "Crypto/Checkout:activateAmount", "POST", map[string]any{
		"amount_id": amountID,
	}, "", &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// submitCheckoutPayment marks a checkout as payment submitted
func submitCheckoutPayment(ctx context.Context, id string, txHash string) (map[string]any, error) {
	var res map[string]any
	args := map[string]any{"id": id}
	if txHash != "" {
		args["transaction"] = txHash
	}
	err := vpnAPICall(ctx, "Crypto/Checkout:submitPayment", "POST", args, "", &res)
	if err != nil {
		return nil, err
	}
	return res, nil
}
