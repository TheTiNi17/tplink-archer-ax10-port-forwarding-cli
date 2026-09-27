"""Crypto tests using synthetic vectors only (no data from any real device).

The AES known-answer vector was produced independently with
``openssl enc -aes-128-cbc`` on made-up key/iv/plaintext, so it cross-checks our
CryptoJS-style output against a reference AES implementation.
"""

import hashlib

from tplinkcli.crypto import AesCipher, RsaCipher, TpEncryptor

# Made-up 16-char key/iv (the router uses random numeric strings of this shape).
_KEY, _IV = "1234567890123456", "6543210987654321"
# openssl: printf 'operation=read' | openssl enc -aes-128-cbc -K <hex(key)> -iv <hex(iv)> -a
_KAT_PLAINTEXT, _KAT_CIPHERTEXT = "operation=read", "oQqKW5GCl0amLOvltfa+yg=="
# Throwaway 512-bit modulus from `openssl genrsa 512` — not any real device key.
_SYNTH_RSA_N = (
    "BB9BB6DF468AD909C870894219D5EBCFCA64BDB61C331E3327C0C7F22CA51C1C"
    "33E871F500C47294283151FD159391E2EA5D78997840E5CAC2AAC92F8C41FC39"
)


def test_aes_roundtrip():
    aes = AesCipher.generate()
    assert len(aes.key) == 16 and aes.key.isdigit()
    assert len(aes.iv) == 16 and aes.iv.isdigit()
    plaintext = "operation=login&password=deadBEEF00"
    assert aes.decrypt(aes.encrypt(plaintext)) == plaintext


def test_aes_matches_openssl_vector():
    # Byte-for-byte match against openssl's AES-128-CBC/PKCS7 output.
    assert AesCipher(_KEY, _IV).encrypt(_KAT_PLAINTEXT) == _KAT_CIPHERTEXT


def test_aes_decrypts_reference_vector():
    assert AesCipher(_KEY, _IV).decrypt(_KAT_CIPHERTEXT) == _KAT_PLAINTEXT


def test_hash_md5():
    # setHash("admin", pwd) with IS_RG_SEC false == MD5(user + pwd).
    assert TpEncryptor.compute_hash("admin", "secret") == hashlib.md5(b"adminsecret").hexdigest()


def test_hash_sha256():
    assert TpEncryptor.compute_hash("admin", "secret", rg_sec=True) == hashlib.sha256(
        b"adminsecret"
    ).hexdigest()


def test_signature_shape():
    # 512-bit RSA => each block is 128 hex chars; a short sign string is one block.
    enc = TpEncryptor(AesCipher.generate(), RsaCipher(_SYNTH_RSA_N, "010001"), "0" * 32, 12345)
    req = enc.encrypt_request("operation=read", is_login=False)
    assert len(req.sign) == 128
    assert req.data  # non-empty base64


def test_signature_login_variant_spans_more_blocks():
    # The login sign plaintext embeds k=&i=, so it needs a second RSA block (256 hex).
    enc = TpEncryptor(AesCipher(_KEY, _IV), RsaCipher(_SYNTH_RSA_N, "010001"), "0" * 32, 12345)
    login = enc.encrypt_request("operation=login&password=x", is_login=True)
    normal = enc.encrypt_request("operation=read", is_login=False)
    assert len(login.sign) == 256
    assert len(normal.sign) == 128
