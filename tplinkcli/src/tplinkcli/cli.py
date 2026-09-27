"""Command-line interface for the TP-Link router.

Run ``tplink`` with no command to open an interactive session: it logs in once, gives
you a ``tplink>`` prompt that reuses that single login, and logs out on ``exit``. Run
``tplink <command>`` for a one-shot call (log in, run it, log out) — this matters because
the router allows only one admin session at a time, so we hold it for as short as possible.

Examples:
    tplink                         # interactive session
    tplink clients                 # list connected devices
    tplink status
    tplink reboot --yes
    tplink raw 'status?form=client_status' --op load --json
"""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from typing import Any, Optional

from .client import AuthError, TplinkClient, TplinkError, redact_secrets
from .config import Config, ConfigError


def _print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: len(c) for c in columns}
    for r in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(r.get(c, ""))))
    print("  ".join(c.upper().ljust(widths[c]) for c in columns))
    print("  ".join("-" * widths[c] for c in columns))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))


# -- commands (each receives an already-logged-in client) -------------------

def cmd_login(client: TplinkClient, args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps({"stok": client.stok}))
    else:
        print(f"logged in; stok={client.stok}")
    return 0


def cmd_clients(client: TplinkClient, args: argparse.Namespace) -> int:
    groups = client.get_clients()
    if args.json:
        print(json.dumps(groups, indent=2))
        return 0
    rows = []
    for kind, items in (("wired", groups["wired"]), ("wifi", groups["wireless"]), ("guest", groups["guest"])):
        for it in items:
            rows.append(
                {
                    "type": it.get("wire_type", kind),
                    "hostname": it.get("hostname", ""),
                    "ip": it.get("ipaddr", ""),
                    "mac": it.get("macaddr", ""),
                }
            )
    print(f"{len(rows)} connected device(s):\n")
    _print_table(rows, ["type", "hostname", "ip", "mac"])
    return 0


def _fmt_uptime(seconds: Any) -> str:
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = [f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m", f"{s}s"]
    return " ".join(p for p in parts if p)


def cmd_status(client: TplinkClient, args: argparse.Namespace) -> int:
    mode = client.get_sysmode()
    alld = client.get_status_all()
    fw = client.get_firmware_info()
    if args.json:
        blob = {"firmware": fw, "sysmode": mode, "status": alld}
        print(json.dumps(redact_secrets(blob, reveal=args.reveal_secrets), indent=2))
        return 0
    print(f"model:     {fw.get('model', '?')} ({fw.get('hardware_version', '?')})")
    print(f"firmware:  {fw.get('firmware_version', '?')}")
    print(f"mode:      {mode.get('mode', '?')}")
    print(f"wan ip:    {alld.get('wan_ipv4_ipaddr', '?')}")
    print(f"uptime:    {_fmt_uptime(alld.get('wan_ipv4_uptime'))}")
    cpu = alld.get("cpu_usage")
    mem = alld.get("mem_usage")
    if cpu is not None:
        print(f"cpu:       {float(cpu) * 100:.0f}%")
    if mem is not None:
        print(f"memory:    {float(mem) * 100:.0f}%")
    ssid_2g = alld.get("wireless_2g_ssid")
    ssid_5g = alld.get("wireless_5g_ssid")
    if ssid_2g:
        print(f"2.4G SSID: {ssid_2g}")
    if ssid_5g:
        print(f"5G SSID:   {ssid_5g}")
    return 0


def cmd_wan(client: TplinkClient, args: argparse.Namespace) -> int:
    print(json.dumps(client.get_wan_status(), indent=2))
    return 0


def cmd_wifi(client: TplinkClient, args: argparse.Namespace) -> int:
    bands = client.get_wifi()
    reveal = args.reveal_secrets
    if args.json:
        print(json.dumps(redact_secrets(bands, reveal=reveal), indent=2))
        return 0
    rows = [
        {
            "band": b["band"],
            "ssid": b["ssid"],
            "password": (b["password"] or "") if reveal else "********",
            "state": "on" if b["enabled"] else "off",
            "security": b["security"] or "",
        }
        for b in bands
    ]
    _print_table(rows, ["band", "ssid", "password", "state", "security"])
    if not reveal:
        print("\n(passwords hidden — use --reveal-secrets to show)")
    return 0


def cmd_ports(client: TplinkClient, args: argparse.Namespace) -> int:
    ports = client.get_ethernet_ports()
    if args.json:
        print(json.dumps(ports, indent=2))
        return 0
    rows = [
        {
            "port": p.get("name", ""),
            "role": "WAN" if p.get("is_wan") else "LAN",
            "status": p.get("status", ""),
            "speed": p.get("speed", ""),
            "duplex": p.get("duplex", ""),
        }
        for p in ports
    ]
    _print_table(rows, ["port", "role", "status", "speed", "duplex"])
    return 0


def cmd_dhcp(client: TplinkClient, args: argparse.Namespace) -> int:
    leases = client.get_dhcp_leases()
    if args.json:
        print(json.dumps(leases, indent=2))
        return 0
    rows = [
        {
            "hostname": l.get("name", ""),
            "ip": l.get("ipaddr", ""),
            "mac": l.get("macaddr", ""),
            "lease": l.get("leasetime", ""),
        }
        for l in leases
    ]
    print(f"{len(rows)} DHCP lease(s):\n")
    _print_table(rows, ["hostname", "ip", "mac", "lease"])
    return 0


def cmd_reboot(client: TplinkClient, args: argparse.Namespace) -> int:
    if not args.yes:
        reply = input("Reboot the router now? [y/N] ").strip().lower()
        if reply not in {"y", "yes"}:
            print("aborted")
            return 1
    client.reboot()
    print("reboot requested")
    return 0


def cmd_raw(client: TplinkClient, args: argparse.Namespace) -> int:
    params: dict[str, str] = {}
    for kv in args.param or []:
        key, _, val = kv.partition("=")
        params[key] = val
    data = client.request(args.form_path, operation=args.op, params=params or None)
    print(json.dumps(data, indent=2))
    return 0


def cmd_syslog(client: TplinkClient, args: argparse.Namespace) -> int:
    entries = client.get_syslog(level=args.level, log_type=args.type, limit=args.limit)
    if args.json:
        print(json.dumps(entries, indent=2))
        return 0
    rows = [
        {"time": e.get("time", ""), "level": e.get("level", ""), "type": e.get("type", ""), "message": e.get("content", "")}
        for e in entries
    ]
    _print_table(rows, ["time", "level", "type", "message"])
    return 0


def cmd_stats(client: TplinkClient, args: argparse.Namespace) -> int:
    stats = client.get_client_stats()
    if args.json:
        print(json.dumps(stats, indent=2))
        return 0
    rows = [
        {
            "name": s.get("name", ""),
            "band": s.get("band", ""),
            "signal": f"{s['signal_dbm']} dBm" if s.get("signal_dbm") is not None else "",
            "tx": f"{s['tx_rate_kbps'] // 1000}M" if s.get("tx_rate_kbps") else "",
            "rx": f"{s['rx_rate_kbps'] // 1000}M" if s.get("rx_rate_kbps") else "",
            "online": _fmt_uptime(s.get("online_seconds")),
            "mac": s.get("mac", ""),
        }
        for s in stats
    ]
    _print_table(rows, ["name", "band", "signal", "tx", "rx", "online", "mac"])
    return 0


def cmd_reservations(client: TplinkClient, args: argparse.Namespace) -> int:
    res = client.list_reservations()
    if args.json:
        print(json.dumps(res, indent=2))
        return 0
    rows = [
        {"name": r.get("comment") or r.get("hostname", ""), "ip": r.get("ip", ""), "mac": r.get("mac", ""), "enabled": r.get("enable", "")}
        for r in res
    ]
    print(f"{len(rows)} reservation(s):\n")
    _print_table(rows, ["name", "ip", "mac", "enabled"])
    return 0


def cmd_dhcp_config(client: TplinkClient, args: argparse.Namespace) -> int:
    print(json.dumps(client.get_dhcp_settings(), indent=2))
    return 0


def cmd_radio(client: TplinkClient, args: argparse.Namespace) -> int:
    radio = client.get_wifi_radio(args.band)
    if args.json:
        print(json.dumps(redact_secrets(radio, reveal=args.reveal_secrets), indent=2))
        return 0
    keys = ["ssid", "channel", "current_channel", "htmode", "hwmode", "encryption", "txpower", "mu_mimo", "airtime_fairness", "hidden"]
    for k in keys:
        if k in radio:
            print(f"{k:18} {radio[k]}")
    return 0


def cmd_wifi_adv(client: TplinkClient, args: argparse.Namespace) -> int:
    adv = client.get_wireless_advanced(args.band)
    if args.json:
        print(json.dumps(adv, indent=2))
        return 0
    for k, v in adv.items():
        print(f"{k:18} {v}")
    return 0


def cmd_ipv6(client: TplinkClient, args: argparse.Namespace) -> int:
    print(json.dumps(client.get_ipv6_status(), indent=2))
    return 0


# target -> how to fetch, key by, label, render, and which fields count as a "change"
_WATCH_TARGETS = {
    "clients": {
        "fetch": lambda c: [
            {**d, "wire_type": d.get("wire_type") or ("wifi" if kind == "wireless" else kind)}
            for kind, grp in c.get_clients().items()
            for d in grp
        ],
        "key": lambda r: r.get("macaddr", ""),
        "label": lambda r: r.get("hostname") or "?",
        "cols": lambda r: f"{r.get('ipaddr',''):<15} {r.get('wire_type',''):<6} {r.get('macaddr','')}",
        "fields": ("ipaddr", "wire_type"),
    },
    "leases": {
        "fetch": lambda c: c.get_dhcp_leases(),
        "key": lambda r: r.get("macaddr", ""),
        "label": lambda r: r.get("name") or "?",
        "cols": lambda r: f"{r.get('ipaddr',''):<15} {r.get('leasetime',''):<10} {r.get('macaddr','')}",
        "fields": ("ipaddr",),
    },
}


def cmd_watch(client: TplinkClient, args: argparse.Namespace) -> int:
    import time

    cfg = _WATCH_TARGETS[args.target]
    interval = max(2, args.interval)

    def line(sign: str, event: str, item: dict[str, Any], extra: str = "") -> None:
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {sign} {event:<7} {cfg['label'](item):<20} {cfg['cols'](item)}{extra}")

    print(f"watching {args.target} every {interval}s — Ctrl-C to stop\n")
    prev: dict[str, dict[str, Any]] = {}
    first = True
    try:
        while True:
            try:
                items = cfg["fetch"](client)
            except AuthError:
                print("  (session expired — re-logging in)", file=sys.stderr)
                client.login()
                items = cfg["fetch"](client)
            cur = {}
            for r in items:
                k = cfg["key"](r)
                if k:
                    cur[k] = r
            for k, item in cur.items():
                if k not in prev:
                    line("+", "present" if first else "join", item)
                else:
                    changed = [f for f in cfg["fields"] if prev[k].get(f) != item.get(f)]
                    if changed:
                        old = ", ".join(f"{f}: {prev[k].get(f)}->{item.get(f)}" for f in changed)
                        line("~", "change", item, extra=f"   ({old})")
            for k, item in prev.items():
                if k not in cur:
                    line("-", "leave", item)
            prev = cur
            first = False
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


def cmd_firmware(client: TplinkClient, args: argparse.Namespace) -> int:
    fw = client.get_firmware_info()
    update = client.check_firmware_update()
    if args.json:
        print(json.dumps({"current": fw, "update": update}, indent=2))
        return 0
    print(f"model:    {fw.get('model', '?')} ({fw.get('hardware_version', '?')})")
    print(f"firmware: {fw.get('firmware_version', '?')}")
    n = str(update.get("update_number", "0"))
    print(f"updates:  {'up to date' if n in ('0', '') else n + ' available'}")
    return 0


def cmd_session(client: TplinkClient, args: argparse.Namespace) -> int:
    print(json.dumps(client.session_info(), indent=2))
    return 0


def cmd_dump(client: TplinkClient, args: argparse.Namespace) -> int:
    snapshot = client.dump(reveal_secrets=args.reveal_secrets)
    text = json.dumps(snapshot, indent=2)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"wrote full-state snapshot to {args.output}")
    else:
        print(text)
    return 0


# -- parser -----------------------------------------------------------------

def _register_commands(sub: "argparse._SubParsersAction") -> None:
    def add(name: str, fn, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
        sp.add_argument("--json", action="store_true", help="output raw JSON")
        return sp

    add("login", cmd_login, "log in and print the session token")
    add("clients", cmd_clients, "list connected devices")
    status = add("status", cmd_status, "router + WAN overview")
    status.add_argument("--reveal-secrets", action="store_true", help="show Wi-Fi PSKs (hidden by default)")
    add("wan", cmd_wan, "WAN/internet status (JSON)")
    add("ipv6", cmd_ipv6, "IPv6 WAN + LAN status")
    wifi = add("wifi", cmd_wifi, "list SSIDs and on/off state per band (passwords hidden)")
    wifi.add_argument("--reveal-secrets", action="store_true", help="show Wi-Fi passwords (hidden by default)")
    add("ports", cmd_ports, "physical ethernet port link status")
    add("dhcp", cmd_dhcp, "DHCP lease list")
    watch = add("watch", cmd_watch, "poll clients|leases and print join/leave/change diffs")
    watch.add_argument("target", nargs="?", default="clients", choices=["clients", "leases"])
    watch.add_argument("-n", "--interval", type=int, default=5, help="poll seconds (min 2)")
    reboot = add("reboot", cmd_reboot, "reboot the router")
    reboot.add_argument("--yes", action="store_true", help="skip confirmation")
    raw = add("raw", cmd_raw, "call any endpoint: raw <module?form=x>")
    raw.add_argument("form_path", help='e.g. "status?form=client_status"')
    raw.add_argument("--op", default="read", help="operation (read/load/write/...)")
    raw.add_argument("--param", action="append", help="extra body param k=v (repeatable)")

    syslog = add("syslog", cmd_syslog, "system log (filter by --level/--type)")
    syslog.add_argument("--level", help="INFO / WARNING / ERROR")
    syslog.add_argument("--type", help="log category (see router)")
    syslog.add_argument("--limit", type=int, help="max entries")
    add("stats", cmd_stats, "per-client wireless stats (signal, PHY rate, band)")
    add("reservations", cmd_reservations, "DHCP address reservations")
    add("dhcp-config", cmd_dhcp_config, "DHCP server config (pool, lease time, DNS)")
    radio = add("radio", cmd_radio, "wireless radio settings for a band")
    radio.add_argument("band", nargs="?", default="2g", help="2g / 5g / 5g_2 / 6g (default 2g)")
    radio.add_argument("--reveal-secrets", action="store_true", help="show PSK in --json (hidden by default)")
    wifiadv = add("wifi-adv", cmd_wifi_adv, "advanced wireless: tx power, MU-MIMO, OFDMA, TWT")
    wifiadv.add_argument("band", nargs="?", default="2g", help="2g / 5g / 5g_2 / 6g (default 2g)")
    add("firmware", cmd_firmware, "firmware/hardware version + cloud update check")
    add("session", cmd_session, "session age / login count (recovery observability)")
    dump = add("dump", cmd_dump, "full-state JSON snapshot (config-drift diffing)")
    dump.add_argument("-o", "--output", help="write snapshot to a file instead of stdout")
    dump.add_argument("--reveal-secrets", action="store_true", help="include Wi-Fi passwords (redacted by default)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tplink", description="Control a TP-Link Archer/AX router from the CLI.")
    p.add_argument("--host", help="router IP/host (default: ROUTER_IP from .env)")
    p.add_argument("--username", help="login username (default: admin)")
    p.add_argument("--password", help="login password (default: ROUTER_PASSWORD from .env)")
    # subcommand optional: no command opens the interactive session.
    _register_commands(p.add_subparsers(dest="command", required=False))
    return p


def build_repl_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="", add_help=False)
    _register_commands(p.add_subparsers(dest="command"))
    return p


# -- session dispatch / REPL ------------------------------------------------

def _dispatch(client: TplinkClient, args: argparse.Namespace) -> int:
    """Run one command, re-logging in once if the session was taken over mid-use."""
    try:
        return args.func(client, args)
    except AuthError:
        print("session was taken over — re-logging in...", file=sys.stderr)
        client.login()
        return args.func(client, args)


def run_repl(client: TplinkClient) -> int:
    parser = build_repl_parser()
    print("tplink interactive session — type a command, `help`, or `exit`.")
    while True:
        try:
            line = input("tplink> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            continue
        if not line:
            continue
        if line in {"exit", "quit", "logout", "q"}:
            break
        if line in {"help", "?"}:
            parser.print_help()
            continue
        try:
            tokens = shlex.split(line)
        except ValueError as e:
            print(f"parse error: {e}", file=sys.stderr)
            continue
        try:
            args = parser.parse_args(tokens)
        except SystemExit:
            continue  # argparse already reported the bad command / printed help
        if not getattr(args, "func", None):
            continue
        try:
            _dispatch(client, args)
        except TplinkError as e:
            print(f"error: {e}", file=sys.stderr)
        except Exception as e:  # keep the session alive on any single-command failure
            print(f"error: {e}", file=sys.stderr)
    return 0


def _silence_tls_warnings() -> None:
    # The router uses a self-signed cert, so verify_tls is off by default. Silence the
    # per-request InsecureRequestWarning here at the app entry point (not in the library).
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main(argv: Optional[list[str]] = None) -> int:
    _silence_tls_warnings()
    args = build_parser().parse_args(argv)
    try:
        cfg = Config.load(host=args.host, username=args.username, password=args.password)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    client = TplinkClient(cfg.host, cfg.password, cfg.username, secure_hash=cfg.secure_hash)
    try:
        client.login()
    except AuthError as e:
        print(f"auth error: {e}", file=sys.stderr)
        return 3
    except (TplinkError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        if not args.command:
            return run_repl(client)
        return _dispatch(client, args)
    except AuthError as e:
        print(f"auth error: {e}", file=sys.stderr)
        return 3
    except TplinkError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        # Best-effort cleanup; must survive an impatient second Ctrl-C (e.g. during `watch`).
        try:
            client.logout()  # release the single admin session for the WebUI / next run
        except (Exception, KeyboardInterrupt):
            pass
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
