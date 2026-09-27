"""MCP server exposing the router as tools for an AI agent.

Run with:  python -m tplinkcli.mcp_server     (reads .env / env for credentials)
Requires the optional dependency:  pip install "tplinkcli[mcp]"
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Optional

from .client import AuthError, TplinkClient, redact_secrets
from .config import Config

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The MCP SDK is not installed. Install it with: pip install 'tplinkcli[mcp]'"
    ) from exc

mcp = FastMCP("tplink-router")

_client: Optional[TplinkClient] = None
# The router permits one admin session; this lock serializes tool calls so a batch of
# concurrent calls can't race the lazy login / share the session unsafely.
_lock = threading.Lock()


def _get_client() -> TplinkClient:  # call with _lock held
    global _client
    if _client is None:
        cfg = Config.load()
        _client = TplinkClient(cfg.host, cfg.password, cfg.username, secure_hash=cfg.secure_hash)
        _client.login()
    return _client


def _call(fn):
    """Run a client method under the session lock, re-logging in once if it went stale."""
    global _client
    with _lock:
        try:
            return fn(_get_client())
        except AuthError:
            print("tplink-mcp: session expired/taken over — re-logging in and retrying", file=sys.stderr)
            if _client is not None:
                try:
                    _client.logout()
                finally:
                    _client.close()
            _client = None
            return fn(_get_client())


def _redact(obj: Any, reveal: bool) -> Any:
    """Mask Wi-Fi PSKs / passwords so they don't land in agent transcripts."""
    return redact_secrets(obj, reveal=reveal)


@mcp.tool()
def list_clients() -> dict[str, list[dict[str, Any]]]:
    """List devices currently connected to the router (wired, wireless, guest)."""
    return _call(lambda c: c.get_clients())


@mcp.tool()
def router_status(reveal_secrets: bool = False) -> dict[str, Any]:
    """Router overview: firmware/hardware version, operation mode, WAN IP, uptime,
    CPU/memory usage, SSIDs. Wi-Fi PSKs are redacted unless reveal_secrets=True.
    """
    data = _call(lambda c: {
        "firmware": c.get_firmware_info(),
        "sysmode": c.get_sysmode(),
        "status": c.get_status_all(),
    })
    return _redact(data, reveal_secrets)


@mcp.tool()
def get_firmware_info() -> dict[str, Any]:
    """Current firmware version, hardware version, and model."""
    return _call(lambda c: c.get_firmware_info())


@mcp.tool()
def check_firmware_update() -> dict[str, Any]:
    """Ask the TP-Link cloud whether a firmware update is available (update_number>0 = yes)."""
    return _call(lambda c: c.check_firmware_update())


@mcp.tool()
def wifi_info(reveal_secrets: bool = False) -> list[dict[str, Any]]:
    """SSID, security and on/off state per band. Passwords redacted unless reveal_secrets=True."""
    return _redact(_call(lambda c: c.get_wifi()), reveal_secrets)


@mcp.tool()
def dhcp_leases() -> list[dict[str, Any]]:
    """Current DHCP leases (hostname, IP, MAC, lease time)."""
    return _call(lambda c: c.get_dhcp_leases())


@mcp.tool()
def ethernet_ports() -> list[dict[str, Any]]:
    """Physical ethernet port link status (WAN/LAN, up/down, speed, duplex)."""
    return _call(lambda c: c.get_ethernet_ports())


@mcp.tool()
def set_wifi_band(band: str, enabled: bool) -> str:
    """Enable or disable a wireless band ('2g', '5g', '5g_2', '6g')."""
    _call(lambda c: c.set_wireless_enabled(band, enabled))
    return f"wireless {band} set to {'on' if enabled else 'off'}"


@mcp.tool()
def get_syslog(level: Optional[str] = None, log_type: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
    """System log (newest first): [{time, level, type, content}]. Shows DHCP DECLINE loops,
    SAE/WPA handshake failures, DFS radar events, session kicks, etc. Filter by level
    (INFO/WARNING/ERROR) and/or log_type (see the router's categories)."""
    return _call(lambda c: c.get_syslog(level=level, log_type=log_type, limit=limit))


@mcp.tool()
def get_dhcp_settings() -> dict[str, Any]:
    """DHCP server config: enable, pool ipaddr_start/end, leasetime (minutes), gateway, DNS."""
    return _call(lambda c: c.get_dhcp_settings())


@mcp.tool()
def set_dhcp_settings(
    leasetime: Optional[int] = None,
    ipaddr_start: Optional[str] = None,
    ipaddr_end: Optional[str] = None,
    gateway: Optional[str] = None,
    pri_dns: Optional[str] = None,
    snd_dns: Optional[str] = None,
    enable: Optional[bool] = None,
) -> Any:
    """Update DHCP server settings (only the given fields). Restarts the DHCP server;
    existing leases keep their IP until renewal. leasetime is in minutes."""
    changes: dict[str, Any] = {}
    if leasetime is not None:
        changes["leasetime"] = leasetime
    for k, v in (
        ("ipaddr_start", ipaddr_start),
        ("ipaddr_end", ipaddr_end),
        ("gateway", gateway),
        ("pri_dns", pri_dns),
        ("snd_dns", snd_dns),
    ):
        if v is not None:
            changes[k] = v
    if enable is not None:
        changes["enable"] = "on" if enable else "off"
    if not changes:
        return "refused: no DHCP settings provided; pass at least one field to change."
    return _call(lambda c: c.set_dhcp_settings(**changes))


@mcp.tool()
def list_reservations() -> list[dict[str, Any]]:
    """DHCP address reservations: [{mac, ip, comment, hostname, enable}]."""
    return _call(lambda c: c.list_reservations())


@mcp.tool()
def add_reservation(mac: str, ip: str, comment: str = "") -> Any:
    """Reserve an IP for a MAC (AA-BB-CC-DD-EE-FF). The correct fix for a device stuck in
    static-in-pool limbo — reserve it instead of relying on a static IP inside the pool."""
    return _call(lambda c: c.add_reservation(mac, ip, comment))


@mcp.tool()
def remove_reservation(mac: str) -> Any:
    """Delete the DHCP reservation for a MAC."""
    return _call(lambda c: c.remove_reservation(mac))


@mcp.tool()
def get_client_stats() -> list[dict[str, Any]]:
    """Per-client wireless stats for online clients: signal_dbm (RSSI), tx/rx_rate_kbps
    (negotiated PHY rate), band, online_seconds, packet counts. Turns "wifi is slow" into a
    one-call diagnosis (weak RSSI vs low PHY rate vs a specific band)."""
    return _call(lambda c: c.get_client_stats())


@mcp.tool()
def get_wifi_radio(band: str = "2g", reveal_secrets: bool = False) -> dict[str, Any]:
    """Full radio settings for a band ('2g','5g','5g_2','6g'): ssid, channel, htmode (width),
    encryption, txpower, mu_mimo, airtime_fairness. PSK redacted unless reveal_secrets=True."""
    return _redact(_call(lambda c: c.get_wifi_radio(band)), reveal_secrets)


@mcp.tool()
def set_wifi_channel(band: str, channel: str, htmode: Optional[str] = None, confirm: bool = False) -> str:
    """Set a band's channel (channel='auto' to auto-select) and optional width (htmode
    '20'/'40'/'80'). ⚠️ Restarts the radio: clients on that band drop for ~10 s; a DFS 5 GHz
    channel adds a ~60 s radar-scan quiet period. Requires confirm=True."""
    if not confirm:
        return "refused: this restarts the radio and drops clients ~10s (DFS +~60s). Call with confirm=True."
    _call(lambda c: c.set_wifi_channel(band, channel, htmode))
    return f"channel for {band} set to {channel}" + (f" @ {htmode}MHz" if htmode else "")


@mcp.tool()
def set_wifi_security(band: str, encryption: str, password: Optional[str] = None, confirm: bool = False) -> str:
    """Set a band's security mode / PSK. ⚠️ Restarts the radio and disconnects EVERY client on
    that band until they re-auth with the new settings. Requires confirm=True."""
    if not confirm:
        return "refused: this disconnects every client on the band until they re-auth. Call with confirm=True."
    _call(lambda c: c.set_wifi_security(band, encryption, password))
    return f"security for {band} updated"


@mcp.tool()
def get_wps() -> dict[str, Any]:
    """WPS global state ({wps: on/off})."""
    return _call(lambda c: c.get_wps())


@mcp.tool()
def set_wps(enabled: bool) -> str:
    """Enable or disable WPS globally."""
    _call(lambda c: c.set_wps(enabled))
    return f"wps set to {'on' if enabled else 'off'}"


@mcp.tool()
def get_guest_network(band: str = "2g", reveal_secrets: bool = False) -> dict[str, Any]:
    """Guest network config for a band. PSK redacted unless reveal_secrets=True."""
    return _redact(_call(lambda c: c.get_guest_network(band)), reveal_secrets)


@mcp.tool()
def set_guest_network(band: str, enabled: bool) -> str:
    """Turn a band's guest network on or off."""
    _call(lambda c: c.set_guest_network(band, enabled))
    return f"guest network {band} set to {'on' if enabled else 'off'}"


@mcp.tool()
def get_wireless_advanced(band: str = "2g") -> dict[str, Any]:
    """Advanced radio settings ("Additional Settings"): tx power, MU-MIMO, WMM, AP isolation,
    airtime fairness, short GI, beacon interval, DTIM, RTS/fragmentation threshold, group-key
    update, plus the Wi-Fi 6 toggles OFDMA, TWT (Target Wake Time — phone power-save), and
    Smart Connect band steering."""
    return _call(lambda c: c.get_wireless_advanced(band))


@mcp.tool()
def set_wireless_advanced(
    band: str,
    txpower: Optional[str] = None,
    mu_mimo: Optional[bool] = None,
    airtime_fairness: Optional[bool] = None,
    confirm: bool = False,
) -> str:
    """Set per-band tx power ('high'/'mid'/'low'), MU-MIMO, and/or airtime fairness.
    ⚠️ Restarts the radio; clients on the band drop briefly. Requires confirm=True."""
    if not confirm:
        return "refused: this restarts the radio and briefly drops clients. Call with confirm=True."
    _call(lambda c: c.set_wireless_advanced(band, txpower=txpower, mu_mimo=mu_mimo, airtime_fairness=airtime_fairness))
    return f"advanced wireless settings for {band} updated"


@mcp.tool()
def set_ofdma(enabled: bool, confirm: bool = False) -> str:
    """Enable/disable OFDMA (Wi-Fi 6). ⚠️ Restarts the radios; clients drop briefly. confirm=True."""
    if not confirm:
        return "refused: restarts the radios and briefly drops clients. Call with confirm=True."
    _call(lambda c: c.set_ofdma(enabled))
    return f"ofdma set to {'on' if enabled else 'off'}"


@mcp.tool()
def set_twt(enabled: bool, confirm: bool = False) -> str:
    """Enable/disable Target Wake Time (Wi-Fi 6 power-save; eases iOS/phone battery drain).
    ⚠️ Restarts the radios; clients drop briefly. Requires confirm=True."""
    if not confirm:
        return "refused: restarts the radios and briefly drops clients. Call with confirm=True."
    _call(lambda c: c.set_twt(enabled))
    return f"twt set to {'on' if enabled else 'off'}"


@mcp.tool()
def set_smart_connect(enabled: bool, confirm: bool = False) -> str:
    """Enable/disable Smart Connect band steering (single SSID across bands).
    ⚠️ Restarts the radios; clients drop briefly. Requires confirm=True."""
    if not confirm:
        return "refused: restarts the radios and briefly drops clients. Call with confirm=True."
    _call(lambda c: c.set_smart_connect(enabled))
    return f"smart_connect set to {'on' if enabled else 'off'}"


@mcp.tool()
def set_wireless_syspara(
    band: str,
    wmm: Optional[bool] = None,
    ap_isolation: Optional[bool] = None,
    beacon_interval: Optional[int] = None,
    dtim: Optional[int] = None,
    rts_threshold: Optional[int] = None,
    frag_threshold: Optional[int] = None,
    group_key_update: Optional[int] = None,
    confirm: bool = False,
) -> str:
    """Set the advanced radio parameters for a band — WMM, AP isolation, beacon interval,
    DTIM period, RTS/fragmentation threshold, group-key update interval. ⚠️ Restarts the
    radio; clients on the band drop briefly. Requires confirm=True."""
    if not confirm:
        return "refused: this restarts the radio and briefly drops clients. Call with confirm=True."
    _call(lambda c: c.set_wireless_syspara(
        band, wmm=wmm, ap_isolation=ap_isolation, beacon_interval=beacon_interval, dtim=dtim,
        rts_threshold=rts_threshold, frag_threshold=frag_threshold, group_key_update=group_key_update,
    ))
    return f"advanced radio parameters for {band} updated"


@mcp.tool()
def get_ipv6_status() -> dict[str, Any]:
    """IPv6 WAN + LAN status: connection type/enable, LAN address & prefix, DNS, assign type."""
    return _call(lambda c: c.get_ipv6_status())


@mcp.tool()
def session_info() -> dict[str, Any]:
    """Session observability: age_seconds, login_count, stok_prefix — lets you see the
    auto-recovery (re-login) happen instead of trusting it silently."""
    return _call(lambda c: c.session_info())


@mcp.tool()
def raw_request(form_path: str, operation: str = "read", params: Optional[dict[str, Any]] = None) -> Any:
    """Call any router endpoint, e.g. form_path='status?form=client_status', operation='load'.

    An escape hatch — many forms need a specific operation ('load'/'write'/... not 'read').
    Use list_endpoints() to discover valid form paths, operations, and shapes for this model.
    """
    return _call(lambda c: c.request(form_path, operation=operation, params=params))


@mcp.tool()
def list_endpoints(contains: Optional[str] = None) -> list[dict[str, Any]]:
    """Known API endpoints for raw_request: [{form_path, operations, purpose, read_safe}].
    Optionally filter to form paths/purposes containing a substring (e.g. 'dhcp', 'wireless')."""
    import json
    from pathlib import Path

    catalog = json.loads((Path(__file__).parent / "api_catalog.json").read_text())
    out = []
    for module in catalog:
        for e in module.get("endpoints", []):
            path = e["path"].replace("/admin/", "")
            if contains and contains.lower() not in (path + " " + e.get("purpose", "")).lower():
                continue
            out.append({
                "form_path": path,
                "operations": e.get("operations", []),
                "purpose": e.get("purpose", ""),
                "read_safe": e.get("read_safe", False),
            })
    return out


@mcp.tool()
def reboot_router(confirm: bool = False) -> str:
    """Reboot the router. Must be called with confirm=True to actually reboot."""
    if not confirm:
        return "refused: call again with confirm=True to reboot"
    _call(lambda c: c.reboot())
    return "reboot requested"


def main() -> None:
    # Self-signed router cert: silence the per-request warning at the app entry point.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    mcp.run()


if __name__ == "__main__":
    main()
