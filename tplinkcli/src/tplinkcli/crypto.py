"""Client-side crypto for TP-Link Archer/AX web API.

Faithful port of the router's ``tpEncrypt.js`` + ``encrypt.js``.

The scheme, per request:

* ``data`` = base64( AES-128-CBC / PKCS7 ) of a url-encoded form string. The AES
  key and IV are each a 16-character random *numeric* string used as 16 UTF-8 bytes.
* ``sign`` = RSA (PKCS#1 v1.5, 512-bit, hex) of a short signature string, encrypted
  in 53-byte chunks with the hex outputs concatenated:
    - normal request: ``h=<hash>&s=<seq + len(data)>``
    - login request:  ``k=<key>&i=<iv>&h=<hash>&s=<seq + len(data)>``
* ``hash`` = MD5("admin" + password)  (SHA256 when the firmware sets IS_RG_SEC).
* ``seq``  = base sequence issued by ``/login?form=auth``; every request signs
  ``seq + len(data)`` off that same base (this firmware does not increment it).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

# Max PKCS#1 v1.5 plaintext for a 512-bit key is 64 - 11 = 53 bytes; the JS chunks
# the signature string at 53 characters to match.
_RSA_CHUNK = 53


def _random_digits(length: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


class AesCipher:
    """AES-128-CBC / PKCS7 with 16-char numeric string key & IV (as CryptoJS uses)."""

    def __init__(self, key: str, iv: str) -> None:
        self.key = key
        self.iv = iv

    @classmethod
    def generate(cls) -> "AesCipher":
        return cls(_random_digits(16), _random_digits(16))

    def _cipher(self) -> "AES":
        return AES.new(self.key.encode("utf-8"), AES.MODE_CBC, self.iv.encode("utf-8"))

    def encrypt(self, plaintext: str) -> str:
        ct = self._cipher().encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
        return base64.b64encode(ct).decode("ascii")

    def decrypt(self, b64: str) -> str:
        pt = unpad(self._cipher().decrypt(base64.b64decode(b64)), AES.block_size)
        return pt.decode("utf-8")

    def key_string(self) -> str:
        return f"k={self.key}&i={self.iv}"


class RsaCipher:
    """RSA PKCS#1 v1.5 public-key encryption; hex in, hex out, fixed to modulus width."""

    def __init__(self, n_hex: str, e_hex: str) -> None:
        self.n_hex = n_hex
        self.e_hex = e_hex
        self._key = RSA.construct((int(n_hex, 16), int(e_hex, 16)))
        self._cipher = PKCS1_v1_5.new(self._key)
        self._hex_width = (self._key.size_in_bytes()) * 2  # 128 for a 512-bit key

    def encrypt(self, plaintext: str) -> str:
        block = self._cipher.encrypt(plaintext.encode("utf-8"))
        return block.hex().rjust(self._hex_width, "0")

    def encrypt_chunked(self, plaintext: str) -> str:
        out = []
        for off in range(0, len(plaintext), _RSA_CHUNK):
            out.append(self.encrypt(plaintext[off : off + _RSA_CHUNK]))
        return "".join(out)


@dataclass
class EncryptedRequest:
    sign: str
    data: str

    def as_form(self) -> dict[str, str]:
        return {"sign": self.sign, "data": self.data}


class TpEncryptor:
    """Ties together the AES data cipher, the RSA signing key, the login hash and seq."""

    def __init__(
        self,
        aes: AesCipher,
        sign_rsa: RsaCipher,
        password_hash: str,
        seq: int,
    ) -> None:
        self.aes = aes
        self.sign_rsa = sign_rsa
        self.hash = password_hash
        self.seq = int(seq)

    @staticmethod
    def compute_hash(username: str, password: str, rg_sec: bool = False) -> str:
        data = (username + password).encode("utf-8")
        return (hashlib.sha256(data) if rg_sec else hashlib.md5(data)).hexdigest()

    def _signature(self, s_value: int, is_login: bool) -> str:
        if is_login:
            plain = f"{self.aes.key_string()}&h={self.hash}&s={s_value}"
        else:
            plain = f"h={self.hash}&s={s_value}"
        return self.sign_rsa.encrypt_chunked(plain)

    def encrypt_request(self, plaintext: str, is_login: bool = False) -> EncryptedRequest:
        data = self.aes.encrypt(plaintext)
        sign = self._signature(self.seq + len(data), is_login)
        return EncryptedRequest(sign=sign, data=data)

    def decrypt_response(self, b64: str) -> str:
        return self.aes.decrypt(b64)
