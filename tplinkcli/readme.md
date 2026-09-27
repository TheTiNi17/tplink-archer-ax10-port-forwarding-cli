# tplinkcli

> next time imma flash my own openwrt so i dont have to do this shit

A CLI + MCP tool for TP-Link Archer/AX routers, so you can manage the router from the terminal instead of the web UI. Reverse-engineered from the site's JS.

## Install

With [uv](https://docs.astral.sh/uv/), install it as a global tool - puts `tplink` and
`tplink-mcp` on your PATH:

```sh
uv tool install '.[mcp]'          # from a local checkout
# uv tool install 'tplinkcli[mcp]'  # once published to PyPI
```

Then put your credentials in `~/.config/tplink/.env`:

```sh
ROUTER_IP=192.168.0.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-router-password
```

Credentials are also read from environment variables, a project-local `.env`, or a file
pointed to by `$TPLINK_ENV` (precedence, low → high: user config → project `.env` →
`$TPLINK_ENV` → env vars → `--host/--password` flags).

## CLI

The router only allows **one admin session at a time**, so each `tplink <command>` logs
in, runs, and logs out, releasing the session for the web UI. For several commands in a
row, use the interactive session instead:

```sh
tplink                   # interactive session:
tplink> clients
tplink> raw status?form=internet --op read   # no quoting needed in here
tplink> exit           # logs out
```

One-shot commands:

```sh
tplink clients          # connected devices with IP + MAC
tplink status           # mode, WAN IP, uptime, CPU/mem, SSIDs
tplink wifi             # SSID + on/off per band (passwords hidden; --reveal-secrets)
tplink stats            # per-client wireless signal (dBm), PHY rate, band
tplink ports            # physical ethernet port link status
tplink dhcp             # DHCP leases
tplink watch clients|leases  # live poll: print join/leave/IP-change diffs (Ctrl-C to stop)
tplink dhcp-config      # DHCP server pool / lease time / DNS
tplink reservations     # DHCP address reservations
tplink syslog --level ERROR --limit 50   # system log (DHCP/SAE/DFS events)
tplink radio 5g         # radio settings for a band (channel, width, security)
tplink wifi-adv 5g      # advanced: WMM, beacon/DTIM/RTS, tx power, OFDMA, TWT, band steering
tplink firmware         # firmware/hardware version + cloud update check
tplink wan              # WAN/internet status (JSON)
tplink ipv6             # IPv6 WAN + LAN status
tplink session          # session age / login count
tplink dump -o snap.json # full-state snapshot (config-drift diffing)
tplink reboot           # reboot (asks to confirm; --yes to skip)

tplink raw 'status?form=client_status' --op load --json  # call any endpoint directly
```

Quote the `raw` path in your shell (the `?` is a glob) — not needed inside the interactive
session. Add `--json` to most commands for machine-readable output. 

## MCP server

Exposes the router to an AI agent — 24 tools including `get_syslog`, `get_client_stats`,
`get_dhcp_settings`/`set_dhcp_settings`, `list_reservations`/`add_reservation`,
`get_wifi_radio`/`set_wifi_channel`/`set_wifi_security`, `get_wps`/`set_wps`,
`get_guest_network`/`set_guest_network`, `session_info`, `list_endpoints`, and `raw_request`.
Wi-Fi passwords are redacted by default (`reveal_secrets=true` to opt in); radio-restarting
writes require `confirm=true`.

```sh
tplink-mcp
```

Example Claude Code config (credentials via `~/.config/tplink/.env` or inline `env`):

```json
{
  "mcpServers": {
    "tplink": {
      "command": "tplink-mcp",
      "env": { "ROUTER_IP": "192.168.0.1", "ROUTER_PASSWORD": "..." }
    }
  }
}
```

## Development

Work on the code from a checkout without installing globally:

```sh
uv sync --extra mcp    # dev tools (pytest) are in the default dependency group
uv run pytest -q       # crypto tests run offline (synthetic vectors only)
uv run tplink status   # run against the router without a global install

uv tool install --force '.[mcp]'   # reinstall the global tool after changes
```
