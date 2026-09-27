"""HTTP client for the TP-Link Archer/AX web API.

Implements the real login handshake (reverse-engineered from the router's web UI JS)
and the encrypted request/response envelope, then exposes typed helpers for
the useful features. Everything runs over the router's self-signed HTTPS.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Optional
from urllib.parse import urlencode

import requests
import urllib3

from .crypto import AesCipher, RsaCipher, TpEncryptor

# NOTE: Do not disable InsecureRequestWarning globally; callers may opt-in if desired.


class TplinkError(Exception):
    """A router call returned ``success: false`` or an unexpected response."""

    def __init__(self, message: str, errorcode: Optional[str] = None) -> None:
        super().__init__(message)
        self.errorcode = errorcode


class AuthError(TplinkError):
    """Login failed or the session is not (or no longer) valid."""


class TplinkClient:
    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        *,
        timeout: float = 10.0,
        verify_tls: bool = False,
        secure_hash: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self._password = password
        self.timeout = timeout
        self.verify_tls = verify_tls
        # Firmware with IS_RG_SEC uses SHA256(user+pass); Archer/AX uses MD5.
        self.secure_hash = secure_hash
        self.stok: str = ""
        self.encryptor: Optional[TpEncryptor] = None
        self._login_time: Optional[float] = None
        self._login_count = 0
        # The router has ONE session; serialize login()/request() so concurrent callers
        # (e.g. the MCP server fielding a batch of tool calls) can't corrupt it.
        self._lock = threading.RLock()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"https://{host}/webpages/index.html",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            }
        )

    # -- URL / transport ----------------------------------------------------

    def _url(self, path: str) -> str:
        # path starts with "/", e.g. "/login?form=auth" or "/admin/status?form=x"
        return f"https://{self.host}/cgi-bin/luci/;stok={self.stok}{path}"

    def _post(self, path: str, body: dict[str, str]) -> requests.Response:
        return self.session.post(
            self._url(path),
            data=body,
            timeout=self.timeout,
            verify=self.verify_tls,
        )

    def _post_plain(self, path: str, data: dict[str, str]) -> dict[str, Any]:
        """Unencrypted call (login handshake endpoints in the router's no-encrypt list)."""
        r = self._post(path, data)
        r.raise_for_status()
        payload = r.json()
        if not payload.get("success", False):
            raise AuthError(f"{path} failed: {payload}", str(payload.get("errorcode")))
        return payload.get("data", {})

    def _decode(self, payload: dict[str, Any]) -> dict[str, Any]:
        """A response is either plain JSON or {"data": "<base64>"} that we AES-decrypt.

        A dead session (expired, or taken over by the WebUI/another client — the router
        allows one admin at a time) answers with an empty ``data`` string. Surface that as
        an AuthError so callers can re-login, instead of crashing in the AES un-pad.
        """
        data = payload.get("data")
        if isinstance(data, str) and self.encryptor is not None:
            if data == "":
                raise AuthError("empty response — session expired or taken over by another admin")
            return json.loads(self.encryptor.decrypt_response(data))
        return payload

    # -- login --------------------------------------------------------------

    def login(self, force: bool = True) -> str:
        """Perform the full handshake and store the session token. Returns the stok.

        ``force`` retries with ``confirm=true`` if the router reports another active admin
        session (it allows only one), taking over that session — same as the web UI does.
        Serialized with the per-client lock.
        """
        with self._lock:
            return self._login(force)

    def _login(self, force: bool) -> str:
        # 1. RSA key that encrypts the password.
        keys = self._post_plain("/login?form=keys", {"operation": "read"})
        pw_n, pw_e = keys["password"]
        password_rsa = RsaCipher(pw_n, pw_e)

        # 2. RSA signing key + base sequence.
        auth = self._post_plain("/login?form=auth", {"operation": "read"})
        sign_n, sign_e = auth["key"]
        seq = int(auth["seq"])

        # 3. Fresh AES key/iv + login hash, assembled into the session encryptor.
        aes = AesCipher.generate()
        pw_hash = TpEncryptor.compute_hash(self.username, self._password, self.secure_hash)
        self.encryptor = TpEncryptor(aes, RsaCipher(sign_n, sign_e), pw_hash, seq)
        enc_password = password_rsa.encrypt(self._password)

        # 4. Submit the encrypted login (isLogin=True → sign embeds the AES key/iv).
        stok, decoded = self._submit_login(enc_password, confirm=False)
        if not stok and force and _is_conflict(decoded):
            stok, decoded = self._submit_login(enc_password, confirm=True)
        if not stok:
            raise AuthError(f"login failed: {decoded}", str(decoded.get("errorcode")))
        self.stok = stok
        self._login_time = time.time()
        self._login_count += 1
        return stok

    def _submit_login(self, enc_password: str, confirm: bool) -> tuple[str, dict[str, Any]]:
        body: dict[str, str] = {"operation": "login"}
        if confirm:
            body["confirm"] = "true"
        body["password"] = enc_password
        assert self.encryptor is not None
        req = self.encryptor.encrypt_request(urlencode(body), is_login=True)
        r = self._post("/login?form=login", req.as_form())
        r.raise_for_status()
        decoded = self._decode(r.json())
        return _find_stok(decoded), decoded

    # -- generic request ----------------------------------------------------

    def request(
        self,
        form_path: str,
        operation: str = "read",
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        """POST to /admin/<form_path> (e.g. "status?form=client_status") and return data.

        The plaintext body is a url-encoded form string beginning with ``operation=...``.
        Serialized with the per-client lock so concurrent callers (e.g. the MCP server
        handling a batch of tool calls) never race on the single session.
        """
        with self._lock:
            return self._request(form_path, operation, params)

    def _request(
        self,
        form_path: str,
        operation: str = "read",
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        if self.encryptor is None or not self.stok:
            raise AuthError("not logged in; call login() first")
        body = {"operation": operation}
        if params:
            body.update(params)
        req = self.encryptor.encrypt_request(urlencode(body), is_login=False)
        r = self._post(f"/admin/{form_path}", req.as_form())
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise TplinkError(f"{form_path}: HTTP {r.status_code}: {r.text[:120]!r}") from e
        if not r.text.strip():
            raise AuthError(f"{form_path}: empty response body (HTTP {r.status_code}) — session likely invalid")
        try:
            payload = r.json()
        except ValueError:
            raise TplinkError(f"{form_path}: non-JSON response (HTTP {r.status_code}): {r.text[:120]!r}")
        decoded = self._decode(payload)
        if not decoded.get("success", True):
            code = str(decoded.get("errorcode"))
            if code in {"-40401", "0", "timeout"} or "login" in code.lower():
                raise AuthError(f"session invalid ({code})", code)
            raise TplinkError(f"{form_path} failed: {decoded}", code)
        return decoded.get("data", decoded)

    # -- typed helpers (confirmed against the live device) ------------------

    def get_clients(self) -> dict[str, list[dict[str, Any]]]:
        """Connected devices split into wired / wireless host / wireless guest."""
        data = self.request("status?form=client_status", operation="load")
        return {
            "wired": data.get("access_devices_wired", []),
            "wireless": data.get("access_devices_wireless_host", []),
            "guest": data.get("access_devices_wireless_guest", []),
        }

    def get_wan_status(self) -> dict[str, Any]:
        return self.request("network?form=wan_ipv4_status")

    def get_ipv6_status(self) -> dict[str, Any]:
        """IPv6 WAN + LAN status: connection type/enable, LAN address & prefix, DNS, assign type."""
        return {
            "wan": self.request("network?form=wan_ipv6_status"),
            "lan": self.request("network?form=lan_ipv6"),
        }

    def get_sysmode(self) -> dict[str, Any]:
        return self.request("system?form=sysmode")

    def get_status_all(self) -> dict[str, Any]:
        """Big status blob: CPU/mem usage, uptime, WAN IP, per-band SSIDs, etc."""
        return self.request("status?form=all")

    def get_ethernet_ports(self) -> list[dict[str, Any]]:
        """Physical port list: name, WAN/LAN, link status, speed, duplex."""
        data = self.request("status?form=router")
        return data if isinstance(data, list) else data.get("ports", [])

    WIFI_BANDS = ("2g", "5g", "5g_2", "6g")

    def get_wireless(self, band: str) -> dict[str, Any]:
        """Host wireless settings for a band (ssid, psk_key, disabled, channel, ...)."""
        return self.request(f"wireless?form=wireless_{band}")

    def get_wifi(self) -> list[dict[str, Any]]:
        """SSID, password and on/off state for every wireless band the router has."""
        out: list[dict[str, Any]] = []
        for band in self.WIFI_BANDS:
            try:
                w = self.get_wireless(band)
            except TplinkError:
                continue
            if not w or not w.get("ssid"):
                continue
            out.append(
                {
                    "band": band,
                    "ssid": w.get("ssid"),
                    "password": w.get("psk_key") or w.get("key"),
                    "security": w.get("encryption"),
                    "enabled": w.get("disabled") not in ("on", True),
                    "hidden": w.get("hidden") == "on",
                    "channel": w.get("current_channel") or w.get("channel"),
                }
            )
        return out

    def get_dhcp_leases(self) -> list[dict[str, Any]]:
        data = self.request("dhcps?form=client", operation="load")
        return data if isinstance(data, list) else data.get("clients", [])

    # -- firmware -----------------------------------------------------------

    def get_firmware_info(self) -> dict[str, Any]:
        """Current firmware/hardware version and model (from firmware?form=upgrade read)."""
        return self.request("firmware?form=upgrade", operation="read")

    def check_firmware_update(self) -> dict[str, Any]:
        """Ask the TP-Link cloud whether a newer firmware is available."""
        return self.request("cloud_account?form=check_upgrade", operation="read")

    # -- syslog -------------------------------------------------------------

    def get_syslog(
        self, level: Optional[str] = None, log_type: Optional[str] = None, limit: Optional[int] = None
    ) -> list[dict[str, Any]]:
        """System log entries ``[{time, level, type, content}]`` (newest first).

        Optional client-side filter by ``level`` (INFO/WARNING/ERROR) and ``log_type``
        (see ``get_syslog_types``); ``limit`` caps the count.
        """
        entries = self.request("syslog?form=log", operation="load")
        if not isinstance(entries, list):
            entries = entries.get("log", []) if isinstance(entries, dict) else []
        if level:
            entries = [e for e in entries if str(e.get("level", "")).upper() == level.upper()]
        if log_type:
            entries = [e for e in entries if str(e.get("type", "")).upper() == log_type.upper()]
        return entries[:limit] if limit else entries

    def get_syslog_types(self) -> list[dict[str, Any]]:
        return self.request("syslog?form=types", operation="load")

    # -- DHCP server config + reservations ----------------------------------

    def get_dhcp_settings(self) -> dict[str, Any]:
        """DHCP server config: enable, ipaddr_start/end, leasetime (minutes), gateway, DNS."""
        return self.request("dhcps?form=setting")

    def set_dhcp_settings(self, **changes: Any) -> Any:
        """Update DHCP server settings (read-modify-write).

        Keys: ``enable`` (on/off), ``leasetime`` (minutes), ``ipaddr_start``, ``ipaddr_end``,
        ``gateway``, ``pri_dns``, ``snd_dns``, ``domain``. Restarts the DHCP server; existing
        leases keep their current IP until renewal.
        """
        current = self.get_dhcp_settings()
        current.update({k: str(v) for k, v in changes.items()})
        return self.request("dhcps?form=setting", operation="write", params=current)

    def list_reservations(self) -> list[dict[str, Any]]:
        """DHCP address reservations ``[{mac, ip, comment, hostname, enable}]``."""
        data = self.request("dhcps?form=reservation", operation="load")
        return data if isinstance(data, list) else data.get("reservations", [])

    def add_reservation(self, mac: str, ip: str, comment: str = "") -> Any:
        """Reserve ``ip`` for ``mac`` (operation add). ``mac`` as AA-BB-CC-DD-EE-FF."""
        return self.request(
            "dhcps?form=reservation",
            operation="add",
            params={"mac": mac, "ip": ip, "comment": comment, "enable": "on"},
        )

    def remove_reservation(self, mac: str) -> Any:
        """Delete the reservation for ``mac`` (operation remove)."""
        return self.request("dhcps?form=reservation", operation="remove", params={"mac": mac})

    # -- per-client wireless stats ------------------------------------------

    def get_client_stats(self) -> list[dict[str, Any]]:
        """Per-client wireless stats: RSSI (dBm), negotiated PHY rates, band, packets.

        Merges ``smart_network game_accelerator`` (signal + tx/rx rate) with
        ``wireless statistics`` (band + packet counts), keyed by MAC. Online clients only.
        """
        by_mac: dict[str, dict[str, Any]] = {}
        for d in self.request("smart_network?form=game_accelerator", operation="loadDevice"):
            if d.get("deviceTag") == "offline":
                continue
            by_mac[d["mac"]] = {
                "name": d.get("deviceName"),
                "mac": d.get("mac"),
                "signal_dbm": d.get("signal"),
                "tx_rate_kbps": d.get("txrate"),
                "rx_rate_kbps": d.get("rxrate"),
                "online_seconds": int(d.get("onlineTime") or 0),
            }
        for s in self.request("wireless?form=statistics", operation="load"):
            row = by_mac.setdefault(s["mac"], {"mac": s["mac"]})
            row["band"] = s.get("type")
            row["rx_packets"] = s.get("rxpkts")
            row["tx_packets"] = s.get("txpkts")
        return list(by_mac.values())

    # -- wireless radio (channel / security / advanced) ---------------------

    def get_wifi_radio(self, band: str) -> dict[str, Any]:
        """Full radio settings for a band: ssid, channel, htmode, encryption, txpower, etc."""
        form = f"wireless?form=wireless_{band}"
        try:
            return self.request(form, operation="read_spf")
        except TplinkError:
            # Some firmwares (notably 6 GHz) expose only `read` for this form.
            return self.request(form, operation="read")

    def set_wifi_channel(self, band: str, channel: Any, htmode: Optional[str] = None) -> Any:
        """Set the channel (and optionally HT/VHT width) for a band (read-modify-write).

        ⚠️ Restarts the radio: connected clients drop for ~10 s. A DFS 5 GHz channel adds a
        ~60 s radar-scan quiet period before the radio comes back. ``channel=auto`` lets the
        router pick. ``htmode`` e.g. "20"/"40"/"80"; see get_wifi_radio / wireless region.
        """
        spf = self.get_wifi_radio(band)
        spf["channel"] = str(channel)
        if htmode is not None:
            spf["htmode"] = str(htmode)
        return self.request(f"wireless?form=wireless_{band}", operation="write_spf", params=spf)

    def set_wifi_security(
        self, band: str, encryption: str, password: Optional[str] = None
    ) -> Any:
        """Set the security mode / password for a band (read-modify-write).

        ⚠️ Restarts the radio and disconnects every client on that band until they
        re-authenticate with the new settings. ``encryption`` is the router's mode string
        (e.g. as read back in get_wifi_radio); ``password`` sets the WPA/WPA2/WPA3 PSK.
        """
        spf = self.get_wifi_radio(band)
        spf["encryption"] = str(encryption)
        if password is not None:
            spf["psk_key"] = password
        return self.request(f"wireless?form=wireless_{band}", operation="write_spf", params=spf)

    # -- WPS / guest network ------------------------------------------------

    def get_wps(self) -> dict[str, Any]:
        return self.request("wireless?form=syspara_wps")

    def set_wps(self, enabled: bool) -> Any:
        """Enable/disable WPS globally (operation write)."""
        return self.request(
            "wireless?form=syspara_wps", operation="write", params={"wps": "on" if enabled else "off"}
        )

    def get_guest_network(self, band: str) -> dict[str, Any]:
        """Guest network config for a band (ssid, enable, encryption, psk, isolation)."""
        return self.request(f"wireless?form=guest_{band}")

    def set_guest_network(self, band: str, enabled: bool) -> Any:
        """Turn a band's guest network on/off (read-modify-write)."""
        cfg = self.get_guest_network(band)
        cfg["enable"] = "on" if enabled else "off"
        cfg["disabled"] = "off" if enabled else "on"
        return self.request(f"wireless?form=guest_{band}", operation="write", params=cfg)

    # -- advanced wireless (radio tuning + Wi-Fi 6 toggles) -----------------

    def get_wireless_advanced(self, band: str = "2g") -> dict[str, Any]:
        """Advanced radio settings for a band (the GUI's "Additional Settings"):

        per-band tx power / MU-MIMO (from write_spf), plus WMM, AP isolation, airtime
        fairness, short GI, beacon interval, DTIM, RTS/fragmentation threshold, and group-key
        update interval (from syspara), plus the global Wi-Fi 6 toggles OFDMA, TWT (Target
        Wake Time), and Smart Connect band steering.
        """
        spf = self.get_wifi_radio(band)
        sp = self.request(f"wireless?form=syspara_{band}", operation="read")
        return {
            "band": band,
            "txpower": spf.get("txpower"),
            "mu_mimo": spf.get("mu_mimo"),
            "airtime_fairness": sp.get("airtime_fairness"),
            "wmm": sp.get("wmm"),
            "ap_isolation": sp.get("isolate"),
            "short_gi": sp.get("shortgi"),
            "beacon_interval": sp.get("beacon_int"),
            "dtim": sp.get("dtim_period"),
            "rts_threshold": sp.get("rts"),
            "frag_threshold": sp.get("frag"),
            "group_key_update": sp.get("wpa_group_rekey"),
            "ofdma": self.request("wireless?form=ofdma").get("enable"),
            "twt": self.request("wireless?form=twt").get("enable"),
            "smart_connect": self.request("wireless?form=smart_connect").get("smart_enable"),
        }

    def set_wireless_syspara(
        self,
        band: str,
        wmm: Optional[bool] = None,
        ap_isolation: Optional[bool] = None,
        beacon_interval: Optional[int] = None,
        dtim: Optional[int] = None,
        rts_threshold: Optional[int] = None,
        frag_threshold: Optional[int] = None,
        group_key_update: Optional[int] = None,
    ) -> Any:
        """Set the advanced radio parameters — WMM, AP isolation, beacon interval, DTIM,
        RTS/fragmentation threshold, group-key update interval (read-modify-write on
        syspara). Restarts the radio; clients on the band drop briefly."""
        sp = self.request(f"wireless?form=syspara_{band}", operation="read")
        if wmm is not None:
            sp["wmm"] = "on" if wmm else "off"
        if ap_isolation is not None:
            sp["isolate"] = "on" if ap_isolation else "off"
        if beacon_interval is not None:
            sp["beacon_int"] = str(beacon_interval)
        if dtim is not None:
            sp["dtim_period"] = str(dtim)
        if rts_threshold is not None:
            sp["rts"] = str(rts_threshold)
        if frag_threshold is not None:
            sp["frag"] = str(frag_threshold)
        if group_key_update is not None:
            sp["wpa_group_rekey"] = str(group_key_update)
        return self.request(f"wireless?form=syspara_{band}", operation="write", params=sp)

    def set_wireless_advanced(
        self,
        band: str,
        txpower: Optional[str] = None,
        mu_mimo: Optional[bool] = None,
        airtime_fairness: Optional[bool] = None,
    ) -> Any:
        """Set per-band tx power ('high'/'mid'/'low'), MU-MIMO, airtime fairness
        (read-modify-write). Restarts the radio; clients on the band drop briefly."""
        spf = self.get_wifi_radio(band)
        if txpower is not None:
            spf["txpower"] = str(txpower)
        if mu_mimo is not None:
            spf["mu_mimo"] = "on" if mu_mimo else "off"
        if airtime_fairness is not None:
            spf["airtime_fairness"] = "on" if airtime_fairness else "off"
        return self.request(f"wireless?form=wireless_{band}", operation="write_spf", params=spf)

    def set_ofdma(self, enabled: bool) -> Any:
        """Enable/disable OFDMA (Wi-Fi 6 efficiency). Restarts the radios."""
        return self.request("wireless?form=ofdma", operation="write", params={"enable": "on" if enabled else "off"})

    def set_twt(self, enabled: bool) -> Any:
        """Enable/disable Target Wake Time (Wi-Fi 6 power-save; eases iOS/phone battery drain).
        Restarts the radios."""
        return self.request("wireless?form=twt", operation="write", params={"enable": "on" if enabled else "off"})

    def set_smart_connect(self, enabled: bool) -> Any:
        """Enable/disable Smart Connect band steering (one SSID across bands). Restarts radios."""
        return self.request(
            "wireless?form=smart_connect", operation="write", params={"smart_enable": "on" if enabled else "off"}
        )

    # -- session introspection / whole-state snapshot -----------------------

    def session_info(self) -> dict[str, Any]:
        """Observability for the auto-recovering session: age, login count, token prefix."""
        age = (time.time() - self._login_time) if self._login_time else None
        return {
            "logged_in": self.logged_in,
            "stok_prefix": self.stok[:8] if self.stok else None,
            "age_seconds": round(age, 1) if age is not None else None,
            "login_count": self._login_count,
        }

    def dump(self, reveal_secrets: bool = False) -> dict[str, Any]:
        """One full-state snapshot for config-drift / before-after diffing.

        Wi-Fi PSKs and WEP keys (in ``wifi``/``radios``) are redacted by default, since this
        is meant to be written to a file — pass ``reveal_secrets=True`` to include them.
        """
        radios: dict[str, Any] = {}
        for band in self.WIFI_BANDS:
            try:
                radios[band] = self.get_wifi_radio(band)
            except TplinkError:
                continue
        snapshot = {
            "sysmode": self.get_sysmode(),
            "status": self.get_status_all(),
            "clients": self.get_clients(),
            "client_stats": self.get_client_stats(),
            "wifi": self.get_wifi(),
            "radios": radios,
            "dhcp_settings": self.get_dhcp_settings(),
            "reservations": self.list_reservations(),
            "dhcp_leases": self.get_dhcp_leases(),
            "ethernet_ports": self.get_ethernet_ports(),
            "wps": self.get_wps(),
        }
        return redact_secrets(snapshot, reveal=reveal_secrets)

    def reboot(self) -> Any:
        """Reboot the router (operation write)."""
        return self.request("system?form=reboot", operation="write")

    def logout(self) -> None:
        """Release the admin session so another client (e.g. the WebUI) can log in.

        Best-effort: if the session is already gone, there is nothing to release.
        """
        with self._lock:
            if self.logged_in:
                try:
                    self.request("system?form=logout", operation="write")
                except Exception:
                    pass  # session may already be gone / router rebooting
            self.stok = ""
            self.encryptor = None

    @property
    def logged_in(self) -> bool:
        return bool(self.stok and self.encryptor is not None)

    def set_wireless_enabled(self, band: str, enabled: bool) -> Any:
        """Turn a wireless band's host network on or off (operation write)."""
        return self.request(
            f"wireless?form=wireless_{band}",
            operation="write",
            params={"disabled": "off" if enabled else "on"},
        )

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "TplinkClient":
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()
        self.close()


def _find_stok(decoded: dict[str, Any]) -> str:
    if "stok" in decoded:
        return str(decoded["stok"])
    data = decoded.get("data")
    if isinstance(data, dict) and "stok" in data:
        return str(data["stok"])
    return ""


def _is_conflict(decoded: dict[str, Any]) -> bool:
    """Whether a failed login was due to another active admin session (retry with confirm)."""
    blob = json.dumps(decoded).lower()
    return "conflict" in blob or "logined_user" in blob or "login_status" in blob


# Match only actual secret material — NOT mode/cipher enums like psk_version / psk_cipher /
# wpa_version / wep_type, which callers legitimately need (e.g. to verify WPA3 state).
_SECRET_KEY_HINTS = ("psk_key", "wpa_key", "wep_key", "password", "pwd")
_REDACTED = "***redacted*** (reveal_secrets=true to show)"


def redact_secrets(obj: Any, reveal: bool = False) -> Any:
    """Recursively mask Wi-Fi PSKs / passwords / WEP keys in a value.

    Used before anything lands in a file (``dump``) or an agent transcript (MCP tools).
    Pass ``reveal=True`` to return the value unchanged.
    """
    if reveal:
        return obj
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(h in k.lower() for h in _SECRET_KEY_HINTS) and isinstance(v, str) and v:
                out[k] = _REDACTED
            else:
                out[k] = redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    return obj
