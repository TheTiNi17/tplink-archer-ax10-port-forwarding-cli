# tplink-archer-ax10-port-forwarding-cli

[Русская версия](README.ru.md)

CLI tool for managing port forwarding rules and UPnP on TP-Link Archer routers.

Two forms:
- Python script (Python 3.9+)
- Ready-made `.exe` (Windows)

## Problem

TP-Link web interface has no bulk toggle for port forwarding rules. With
many rules (games, servers, services), enabling or disabling them one by
one is slow. UPnP mappings are created automatically and there is no quick
way to list or disable them.

## Solution
## Tested on TP-Link Archer AX10 v1.0

Talks directly to the router's internal API:

- Enable / disable / toggle groups of port forwarding rules by name prefix.
- Control UPnP (on / off / status / toggle).
- List active UPnP mappings.

Works with any rule names.

## Commands

| Command | Description |
| `pf-tool portrules status [prefix]`                  | List rules (optional prefix filter) |
| `pf-tool portrules on` / `off` / `toggle [prefix]`   | Control matching rules |
| `pf-tool upnp status`                                | UPnP state |
| `pf-tool upnp on` / `off` / `toggle`                 | Control UPnP |
| `pf-tool upnp list`                                  | Active UPnP mappings |

If `prefix` is omitted, the command applies to all rules.

## Installation

### Option 1 — Windows `.exe`

1. Download `pf-tool.exe` from [Releases](../../releases).
2. Create `.env` next to it:

ROUTER_IP=192.168.0.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your_router_password

3. Run:
pf-tool.exe portrules status (example)

### Option 2 — Python script

1. Requirements: Python 3.9+, `requests`, `urllib3`, `pycryptodome`.

2. Run:
python pf.py portrules status

## Notes
Router allows only one admin session. Close the web interface before use.
.env must be placed next to the script or .exe.
The tool reads each rule before modifying it; unrelated fields are not overwritten.

## Acknowledgements
Built on tplinkcli by axo4xo (MIT) (https://github.com/axo4xo/tplinkcli).
tplinkcli/ is a frozen copy from 2026-09-27, included unchanged.
See tplinkcli/LICENSE.

## License
MIT. See LICENSE.
