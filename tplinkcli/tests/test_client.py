"""Client behaviour tests that need no device (session/error handling)."""

import pytest

from tplinkcli.client import AuthError, TplinkClient
from tplinkcli.crypto import AesCipher, RsaCipher, TpEncryptor

_SYNTH_RSA_N = (
    "BB9BB6DF468AD909C870894219D5EBCFCA64BDB61C331E3327C0C7F22CA51C1C"
    "33E871F500C47294283151FD159391E2EA5D78997840E5CAC2AAC92F8C41FC39"
)


def _session_client() -> TplinkClient:
    c = TplinkClient("192.0.2.1", password="x")  # TEST-NET-1, never dialed in these tests
    c.stok = "0" * 32
    c.encryptor = TpEncryptor(
        AesCipher("1234567890123456", "6543210987654321"),
        RsaCipher(_SYNTH_RSA_N, "010001"),
        "0" * 32,
        1,
    )
    return c


def test_empty_data_raises_autherror_not_unpad_crash():
    # A dead/taken-over session answers with empty data; must surface as AuthError so
    # callers re-login, not crash in AES un-pad (the reported raw_request bug).
    c = _session_client()
    with pytest.raises(AuthError):
        c._decode({"data": ""})


def test_decode_passes_through_plain_error_envelope():
    c = _session_client()
    payload = {"success": False, "errorcode": "no such callback"}
    assert c._decode(payload) == payload


def test_request_without_login_raises_autherror():
    c = TplinkClient("192.0.2.1", password="x")
    with pytest.raises(AuthError):
        c.request("status?form=client_status")


def test_logout_without_session_is_noop():
    c = TplinkClient("192.0.2.1", password="x")
    c.logout()  # no session -> no network call, just clears state
    assert not c.logged_in


def test_redact_secrets_masks_dump_fields():
    # dump() writes to a file, so wifi passwords + radio psk/wep keys must be masked.
    from tplinkcli.client import redact_secrets

    data = {
        "wifi": [{"ssid": "Net", "password": "hunter2"}],
        "radios": {
            "2g": {
                "channel": "6",
                "psk_key": "k",
                "wep_key1": "w",
                # mode/cipher enums — NOT secrets; callers need them (WPA3 verification)
                "psk_version": "sae_transition",
                "psk_cipher": "aes",
                "wpa_version": "auto",
                "wep_type1": "64",
            }
        },
    }
    red = redact_secrets(data)
    assert red["wifi"][0]["ssid"] == "Net"
    assert red["radios"]["2g"]["channel"] == "6"
    assert "redact" in red["wifi"][0]["password"]
    assert "redact" in red["radios"]["2g"]["psk_key"]
    assert "redact" in red["radios"]["2g"]["wep_key1"]
    # enums must pass through untouched
    assert red["radios"]["2g"]["psk_version"] == "sae_transition"
    assert red["radios"]["2g"]["psk_cipher"] == "aes"
    assert red["radios"]["2g"]["wpa_version"] == "auto"
    assert red["radios"]["2g"]["wep_type1"] == "64"
    assert redact_secrets(data, reveal=True) == data


def test_concurrent_requests_are_serialized():
    # Concurrent callers (the MCP batch bug) must not overlap on the single session.
    import concurrent.futures as cf
    import threading
    import time

    c = _session_client()
    guard = threading.Lock()
    state = {"active": 0, "max": 0}

    class FakeResp:
        status_code = 200
        text = '{"success": true, "data": {"ok": 1}}'

        def raise_for_status(self):
            pass

        def json(self):
            return {"success": True, "data": {"ok": 1}}

    def fake_post(path, body):
        with guard:
            state["active"] += 1
            state["max"] = max(state["max"], state["active"])
        time.sleep(0.02)
        with guard:
            state["active"] -= 1
        return FakeResp()

    c._post = fake_post  # type: ignore[assignment]
    with cf.ThreadPoolExecutor(max_workers=5) as ex:
        for f in [ex.submit(c.request, "status?form=x") for _ in range(5)]:
            f.result()
    assert state["max"] == 1  # the per-client lock kept them one-at-a-time
