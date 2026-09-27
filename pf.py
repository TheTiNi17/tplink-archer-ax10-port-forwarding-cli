#!/usr/bin/env python3
import sys
import os

# --- Determine paths: works both as script and as .exe ---------------------
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = sys._MEIPASS
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR

for base in (APP_DIR, BUNDLE_DIR):
    candidate = os.path.join(base, "tplinkcli", "src")
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)
        break
else:
    candidate = os.path.join(BUNDLE_DIR, "src")
    if os.path.isdir(candidate):
        sys.path.insert(0, candidate)

import json
from pathlib import Path
import urllib3
from tplinkcli.client import TplinkClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Config -----------------------------------------------------------------

def load_env():
    """Load .env from script dir, then ~/.config/tplink/.env. Returns path or None."""
    candidates = [
        Path(APP_DIR) / ".env",
        Path.home() / ".config" / "tplink" / ".env",
    ]
    for path in candidates:
        if path.is_file():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip()
            return str(path)
    return None


# --- Helpers ----------------------------------------------------------------

def matches_prefix(name, prefix):
    """Case-insensitive prefix match. Empty prefix matches everything."""
    return not prefix or name.lower().startswith(prefix.lower())


def print_table(headers, rows):
    """Aligned table with dynamic column widths. rows: list of tuples."""
    if not rows:
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*[str(c) for c in row]))


# --- Port forwarding rules --------------------------------------------------

def get_rules(client):
    return client.request("nat?form=vs", operation="load")


def set_rule_enable(client, rule, enable_state):
    old_json = json.dumps(rule)
    new_rule = rule.copy()
    new_rule["enable"] = enable_state
    new_json = json.dumps(new_rule)
    params = {"key": rule["name"], "old": old_json, "new": new_json}
    client.request("nat?form=vs", operation="update", params=params)


def cmd_portrules(client, sub, prefix=""):
    try:
        rules = get_rules(client)
    except Exception as e:
        print(f"Failed to read rules: {e}", file=sys.stderr)
        return 1

    if sub == "status":
        rows = []
        for rule in rules:
            if not matches_prefix(rule["name"], prefix):
                continue
            rows.append((
                rule["name"],
                rule["external_port"],
                rule["internal_port"],
                rule["protocol"],
                rule["enable"],
                rule["ipaddr"],
            ))
        if not rows:
            print("No matching rules found.")
            return 0
        print_table(
            ["Name", "External", "Internal", "Protocol", "State", "IP"],
            rows,
        )
        return 0

    if sub not in ("on", "off", "toggle"):
        print("Invalid action. Use status, on, off or toggle.", file=sys.stderr)
        return 1

    changed = 0
    for rule in rules:
        if not matches_prefix(rule["name"], prefix):
            continue

        if sub == "on":
            target = "on"
        elif sub == "off":
            target = "off"
        else:
            target = "off" if rule["enable"] == "on" else "on"

        if rule["enable"] == target:
            continue

        try:
            set_rule_enable(client, rule, target)
            print(f"Rule '{rule['name']}' -> {target}")
            changed += 1
        except Exception as e:
            print(f"Failed to update '{rule['name']}': {e}", file=sys.stderr)

    if changed == 0:
        print("No rules to change.")
    else:
        print(f"Rules changed: {changed}")
    return 0


# --- UPnP -------------------------------------------------------------------

def get_upnp_state(client):
    result = client.request("upnp?form=enable", operation="read")
    if isinstance(result, dict):
        return result.get("enable", "?")
    return str(result)


def set_upnp_state(client, state):
    client.request("upnp?form=enable", operation="write", params={"enable": state})


def list_upnp_mappings(client):
    try:
        result = client.request("upnp?form=service", operation="load")
    except Exception:
        result = client.request("upnp?form=service", operation="read")

    if isinstance(result, dict):
        for key in ("service", "list", "data", "rules"):
            if key in result and isinstance(result[key], list):
                return result[key]
        return [result]
    if isinstance(result, list):
        return result
    return []


def cmd_upnp(client, sub):
    try:
        current = get_upnp_state(client)
    except Exception as e:
        print(f"Failed to read UPnP state: {e}", file=sys.stderr)
        return 1

    if sub in ("list", "show"):
        try:
            mappings = list_upnp_mappings(client)
        except Exception as e:
            print(f"Failed to read UPnP mappings: {e}", file=sys.stderr)
            return 1

        if not mappings:
            print("No active UPnP mappings.")
            return 0

        rows = []
        for m in mappings:
            rows.append((
                str(m.get("description", m.get("desc", ""))),
                str(m.get("name", "")),
                str(m.get("ipaddr", "")),
                str(m.get("external_port", "")),
                str(m.get("internal_port", "")),
                str(m.get("protocol", "")),
            ))
        print_table(
            ["Description", "Name", "IP", "External", "Internal", "Protocol"],
            rows,
        )
        return 0

    if sub == "status":
        print(f"UPnP: {current}")
        return 0

    if sub == "toggle":
        target = "off" if current == "on" else "on"
    elif sub in ("on", "off"):
        target = sub
    else:
        print("Usage: pf-tool upnp {on|off|status|toggle|list}", file=sys.stderr)
        return 1

    if current == target:
        print(f"UPnP already {target}")
        return 0

    try:
        set_upnp_state(client, target)
        print(f"UPnP -> {target}")
        return 0
    except Exception as e:
        print(f"Failed to change UPnP state: {e}", file=sys.stderr)
        return 1


# --- Usage ------------------------------------------------------------------

def print_usage():
    prog = os.path.basename(sys.argv[0]) or "pf-tool"
    print("Usage:")
    print(f"  {prog} portrules {{status|on|off|toggle}} [prefix]  # port forwarding rules")
    print(f"  {prog} upnp      {{on|off|status|toggle|list}}     # UPnP service")
    print()
    print("Examples:")
    print(f"  {prog} portrules status            # all rules")
    print(f"  {prog} portrules status GTA        # rules with prefix GTA (case-insensitive)")
    print(f"  {prog} portrules on GTA            # enable all GTA rules")
    print(f"  {prog} portrules off GTA           # disable all GTA rules")
    print(f"  {prog} portrules toggle GTA        # invert state of GTA rules")
    print(f"  {prog} upnp on                     # enable UPnP")
    print(f"  {prog} upnp off                    # disable UPnP")
    print(f"  {prog} upnp status                 # current UPnP state")
    print(f"  {prog} upnp toggle                 # invert UPnP state")
    print(f"  {prog} upnp list                   # active UPnP mappings")


# --- main -------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print_usage()
        return 1

    env_path = load_env()
    if env_path is None:
        print("Error: .env not found.", file=sys.stderr)
        print("Place .env next to the script, or at ~/.config/tplink/.env", file=sys.stderr)
        return 1

    host = os.getenv("ROUTER_IP", "192.168.0.1")
    username = os.getenv("ROUTER_USERNAME", "admin")
    password = os.getenv("ROUTER_PASSWORD")
    secure_hash = os.getenv("ROUTER_SECURE_HASH", "").lower() in {"1", "true", "yes"}

    if not password:
        print("Error: ROUTER_PASSWORD is not set in .env", file=sys.stderr)
        return 1

    client = TplinkClient(host, password, username=username, secure_hash=secure_hash)
    try:
        try:
            client.login()
        except Exception as e:
            print(f"Router login failed: {e}", file=sys.stderr)
            return 1

        action = sys.argv[1].lower()

        if action == "portrules":
            sub = sys.argv[2].lower() if len(sys.argv) > 2 else "status"
            prefix = sys.argv[3] if len(sys.argv) > 3 else ""
            return cmd_portrules(client, sub, prefix)

        if action == "upnp":
            sub = sys.argv[2].lower() if len(sys.argv) > 2 else "status"
            return cmd_upnp(client, sub)

        print(f"Unknown command: {action}", file=sys.stderr)
        print_usage()
        return 1
    finally:
        try:
            client.logout()
        except Exception:
            pass
        client.close()


if __name__ == "__main__":
    sys.exit(main())