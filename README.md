# vpnet-cli

Command-line client for the [VP.NET](https://vp.net) WireGuard VPN service.

## Features

- **Multiple authentication methods** -- OAuth2, email/password, email token, or anonymous accounts
- **Anonymous crypto payments** -- Subscribe with BTC, LTC, USDT, and more
- **Userspace WireGuard** -- No root access or kernel module required
- **Ping through VPN** -- Test connectivity and latency via the encrypted tunnel
- **In-tunnel DNS resolution** -- Resolve hostnames through the VPN tunnel
- **External WireGuard support** -- Register your own public key and get a WireGuard config
- **Server list with signature verification** -- RSA-signed server lists ensure authenticity

## Install

```sh
go install github.com/vpdotnet/vpnet-cli@latest
```

Or build from source:

```sh
git clone https://github.com/vpdotnet/vpnet-cli.git
cd vpnet-cli
go build
```

## Usage

### Authentication

```sh
# OAuth2 login (opens browser)
vpnet-cli login

# Email/password login
vpnet-cli login -u user@example.com

# Email token login (sends a code to your email)
vpnet-cli login -u user@example.com --token

# Create anonymous account (for crypto payments)
vpnet-cli login --anonymous
```

### Account & Subscription

```sh
# View account info
vpnet-cli account

# Set email on anonymous account
vpnet-cli set-email user@example.com

# Order a subscription with crypto (1m, 1y, or 3y)
vpnet-cli order 1y
vpnet-cli order 1m BTC
vpnet-cli order 3y USDT@polygon
```

### VPN Connection

```sh
# Connect to VPN
vpnet-cli connect

# Disconnect
vpnet-cli disconnect

# Check connection status
vpnet-cli status
```

### Ping

Test connectivity through the VPN tunnel without needing root access:

```sh
# Ping an IP (4 pings, auto-select region)
vpnet-cli ping 8.8.8.8

# Ping a hostname (resolved via in-tunnel DNS)
vpnet-cli ping google.com

# Ping via a specific region
vpnet-cli ping -region 'New York' 8.8.8.8

# Use beta servers
vpnet-cli ping -beta -region 'Los Angeles, California' 8.8.8.8

# Continuous ping
vpnet-cli ping -c 0 8.8.8.8
```

### Set Key

Register your own WireGuard public key with a server and get a config file:

```sh
# Register a key and output WireGuard config
vpnet-cli set-key <base64-pubkey> 'Amsterdam, Netherlands'

# With beta servers
vpnet-cli set-key -beta <base64-pubkey> 'Los Angeles, California'
```

### Server List

```sh
# List available servers
vpnet-cli servers

# Include beta servers
vpnet-cli servers --beta
```

## Configuration

Configuration is stored in `$XDG_CONFIG_HOME/vpnet-cli/` (typically `~/.config/vpnet-cli/`):

- `config.json` -- Preferences
- `auth.json` -- Authentication tokens

## License

[MIT](LICENSE) -- Copyright (c) 2025 VP.NET LLC
