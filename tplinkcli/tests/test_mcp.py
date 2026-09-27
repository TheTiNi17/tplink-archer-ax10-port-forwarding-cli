"""MCP tool-logic tests that need no device (redaction, catalog, confirm-gating)."""

import pytest

mcp_server = pytest.importorskip("tplinkcli.mcp_server")


def test_redact_masks_secret_keys():
    data = {
        "ssid": "MyNet",
        "psk_key": "hunter2",
        "nested": {"wpa_key": "s2", "channel": "6"},
        "clients": [{"password": "p", "name": "x"}],
    }
    red = mcp_server._redact(data, reveal=False)
    assert red["ssid"] == "MyNet"
    assert red["nested"]["channel"] == "6"
    assert "redact" in red["psk_key"]
    assert "redact" in red["nested"]["wpa_key"]
    assert "redact" in red["clients"][0]["password"]
    assert red["clients"][0]["name"] == "x"


def test_redact_reveal_is_passthrough():
    data = {"psk_key": "hunter2"}
    assert mcp_server._redact(data, reveal=True) == data


def test_list_endpoints_filters_by_substring():
    eps = mcp_server.list_endpoints(contains="dhcp")
    assert eps
    assert all("dhcp" in (e["form_path"] + " " + e["purpose"]).lower() for e in eps)
    assert all({"form_path", "operations", "purpose", "read_safe"} <= e.keys() for e in eps)


def test_disruptive_writes_require_confirm():
    # These must NOT touch the network without confirm=True.
    assert "confirm=True" in mcp_server.set_wifi_channel("2g", "6")
    assert "confirm=True" in mcp_server.set_wifi_security("2g", "psk_sae")
    assert "confirm=True" in mcp_server.reboot_router()
    assert "confirm=True" in mcp_server.set_wireless_advanced("2g", txpower="low")
    assert "confirm=True" in mcp_server.set_ofdma(False)
    assert "confirm=True" in mcp_server.set_twt(True)
    assert "confirm=True" in mcp_server.set_smart_connect(True)
    assert "confirm=True" in mcp_server.set_wireless_syspara("2g", dtim=3)
