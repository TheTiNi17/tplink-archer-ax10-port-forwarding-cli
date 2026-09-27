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
import urllib3
from tplinkcli.client import TplinkClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_env(path):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()
        return True
    return False


env_path = os.path.join(APP_DIR, ".env")
if not load_env(env_path):
    print(f"Error: .env file not found at {env_path}")
    print("Place .env next to the executable.")
    sys.exit(1)

host = os.getenv("ROUTER_IP", "192.168.0.1")
username = os.getenv("ROUTER_USERNAME", "admin")
password = os.getenv("ROUTER_PASSWORD")

if not password:
    print("Error: ROUTER_PASSWORD is not set in .env")
    sys.exit(1)

client = TplinkClient(host, password, username=username)
try:
    client.login()
except Exception as e:
    print(f"Router login failed: {e}")
    sys.exit(1)


# --- Port forwarding rules -------------------------------------------------

def get_rules():
    return client.request("nat?form=vs", operation="load")


def set_rule_enable(rule, enable_state):
    old_json = json.dumps(rule)
    new_rule = rule.copy()
    new_rule["enable"] = enable_state
    new_json = json.dumps(new_rule)
    params = {"key": rule["name"], "old": old_json, "new": new_json}
    client.request("nat?form=vs", operation="update", params=params)


def cmd_portrules(sub, prefix=""):
    """sub = status|on|off|toggle, prefix = filter by name start."""
    try:
        rules = get_rules()
    except Exception as e:
        print(f"Failed to read rules: {e}")
        sys.exit(1)

    if sub == "status":
        print(f"{'Name':<25} {'External':<15} {'Internal':<15} "
              f"{'Protocol':<10} {'State':<6} {'IP':<15}")
        print("-" * 95)
        found = False
        for rule in rules:
            if prefix and not rule["name"].startswith(prefix):
                continue
            found = True
            print(f"{rule['name']:<25} {rule['external_port']:<15} "
                  f"{rule['internal_port']:<15} {rule['protocol']:<10} "
                  f"{rule['enable']:<6} {rule['ipaddr']:<15}")
        if not found:
            print("No matching rules found.")
        return

    if sub not in ("on", "off", "toggle"):
        print("Invalid action. Use status, on, off or toggle.")
        sys.exit(1)

    changed = 0
    for rule in rules:
        if prefix and not rule["name"].startswith(prefix):
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
            set_rule_enable(rule, target)
            print(f"Rule '{rule['name']}' -> {target}")
            changed += 1
        except Exception as e:
            print(f"Failed to update '{rule['name']}': {e}")

    if changed == 0:
        print("No rules to change.")
    else:
        print(f"Rules changed: {changed}")


# --- UPnP ------------------------------------------------------------------

def get_upnp_state():
    result = client.request("upnp?form=enable", operation="read")
    if isinstance(result, dict):
        return result.get("enable", "?")
    return str(result)


def set_upnp_state(state):
    client.request("upnp?form=enable", operation="write", params={"enable": state})


def list_upnp_mappings():
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


def cmd_upnp(sub):
    try:
        current = get_upnp_state()
    except Exception as e:
        print(f"Failed to read UPnP state: {e}")
        sys.exit(1)

    if sub in ("list", "show"):
        try:
            mappings = list_upnp_mappings()
        except Exception as e:
            print(f"Failed to read UPnP mappings: {e}")
            sys.exit(1)

        if not mappings:
            print("No active UPnP mappings.")
            return

        print(f"{'Description':<25} {'Name':<20} {'IP':<15} "
              f"{'External':<15} {'Internal':<15} {'Protocol':<10}")
        print("-" * 100)
        for m in mappings:
            desc = str(m.get("description", m.get("desc", "")))[:24]
            name = str(m.get("name", ""))[:19]
            ip = str(m.get("ipaddr", ""))[:14]
            ext = str(m.get("external_port", ""))[:14]
            intr = str(m.get("internal_port", ""))[:14]
            proto = str(m.get("protocol", ""))[:9]
            print(f"{desc:<25} {name:<20} {ip:<15} {ext:<15} {intr:<15} {proto:<10}")
        return

    if sub == "status":
        print(f"UPnP: {current}")
        return

    if sub == "toggle":
        target = "off" if current == "on" else "on"
    elif sub in ("on", "off"):
        target = sub
    else:
        print("Usage: pf-tool upnp {on|off|status|toggle|list}")
        sys.exit(1)

    if current == target:
        print(f"UPnP already {target}")
        return

    try:
        set_upnp_state(target)
        print(f"UPnP -> {target}")
    except Exception as e:
        print(f"Failed to change UPnP state: {e}")
        sys.exit(1)


# --- Usage -----------------------------------------------------------------

def print_usage():
    print("Usage:")
    print("  pf-tool portrules {status|on|off|toggle} [prefix]  # port forwarding rules")
    print("  pf-tool upnp      {on|off|status|toggle|list}     # UPnP service")
    print()
    print("Examples:")
    print("  pf-tool portrules status            # all rules")
    print("  pf-tool portrules status GTA        # rules with prefix GTA")
    print("  pf-tool portrules on GTA            # enable all GTA rules")
    print("  pf-tool portrules off GTA           # disable all GTA rules")
    print("  pf-tool portrules toggle GTA        # invert state of GTA rules")
    print("  pf-tool upnp on                     # enable UPnP")
    print("  pf-tool upnp off                    # disable UPnP")
    print("  pf-tool upnp status                 # current UPnP state")
    print("  pf-tool upnp toggle                 # invert UPnP state")
    print("  pf-tool upnp list                   # active UPnP mappings")


# --- main ------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    action = sys.argv[1].lower()

    if action == "portrules":
        sub = sys.argv[2].lower() if len(sys.argv) > 2 else "status"
        prefix = sys.argv[3] if len(sys.argv) > 3 else ""
        cmd_portrules(sub, prefix)
        return

    if action == "upnp":
        sub = sys.argv[2].lower() if len(sys.argv) > 2 else "status"
        cmd_upnp(sub)
        return

    print(f"Unknown command: {action}")
    print_usage()
    sys.exit(1)


if __name__ == "__main__":
    main()