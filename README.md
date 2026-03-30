# vpnet-cli

Command-line client for the [VP.NET](https://vp.net) WireGuard VPN service.

## Features

- **Multiple authentication methods** -- OAuth2, email/password, or anonymous accounts
- **Anonymous crypto payments** -- Subscribe with BTC, LTC, USDT, and more
- **Userspace WireGuard** -- No root access or kernel module required
- **Ping through VPN** -- Test connectivity and latency via the encrypted tunnel
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

# Email token login (sends a code to your email)
vpnet-cli login -u user@example.com

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
# Ping server (4 pings, auto-select region)
vpnet-cli ping

# Ping a specific target
vpnet-cli ping 8.8.8.8

# Continuous ping
vpnet-cli ping -c 0 10.0.0.1

# Ping via a specific region
vpnet-cli ping -region us-east
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

- `config.json` -- WireGuard keys and preferences
- `auth.json` -- Authentication tokens

## License

[MIT](LICENSE) -- Copyright (c) 2025 VP.NET LLC
