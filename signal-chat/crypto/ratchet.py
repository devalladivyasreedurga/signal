"""
Double Ratchet — per-message AES-256-GCM encryption with forward secrecy.
Uses dh.py for DH ratchet; cryptography lib only for AES-256-GCM and HKDF.
"""
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .dh import DHKeyPair


_KDF_RK_INFO = b"UIC-Signal-RatchetRoot-v1"
_KDF_CK_INFO = b"UIC-Signal-RatchetChain-v1"
_MAX_SKIP = 100


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 64) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    out = _hkdf(dh_out, salt=root_key, info=_KDF_RK_INFO, length=64)
    return out[:32], out[32:]  # new_root_key, chain_key


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    out = _hkdf(chain_key, salt=b"\x00" * 32, info=_KDF_CK_INFO, length=64)
    return out[:32], out[32:]  # new_chain_key, message_key


def _encrypt(mk: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(mk).encrypt(nonce, plaintext, aad)
    return nonce + ct


def _decrypt(mk: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(mk).decrypt(ciphertext[:12], ciphertext[12:], aad)


class RatchetSession:
    """
    One Double Ratchet session between two parties.
    The 'initiator' flag distinguishes who sends first.

    For the receiver (initiator=False), pass their SPK DHKeyPair as
    `my_initial_keypair` so the first recv chain is derived correctly via
    DH(bob_spk_priv, alice_ratchet_pub).
    """

    def __init__(
        self,
        shared_key: bytes,
        their_ratchet_pub: int | None,
        initiator: bool,
        my_initial_keypair: DHKeyPair | None = None,
    ):
        self.root_key = shared_key
        self.sending_chain_key: bytes | None = None
        self.recv_chain_key: bytes | None = None
        # Sender uses a fresh ratchet key; receiver may reuse their SPK
        self.send_ratchet = my_initial_keypair if (not initiator and my_initial_keypair) else DHKeyPair()
        self.recv_ratchet_pub: int | None = their_ratchet_pub
        self.send_msg_num = 0
        self.recv_msg_num = 0
        self.prev_send_count = 0
        self.skipped: dict[tuple[int, int], bytes] = {}  # (pub, n) -> mk
        self.initiator = initiator

        if initiator and their_ratchet_pub is not None:
            # Sender: derive sending chain from DH(alice_ratchet, bob_spk)
            self.root_key, self.sending_chain_key = _kdf_rk(
                self.root_key,
                self.send_ratchet.dh(their_ratchet_pub),
            )
        elif not initiator and their_ratchet_pub is not None and my_initial_keypair is not None:
            # Receiver: derive recv chain from DH(bob_spk, alice_ratchet)
            self.root_key, self.recv_chain_key = _kdf_rk(
                self.root_key,
                my_initial_keypair.dh(their_ratchet_pub),
            )

    def encrypt(self, plaintext: str) -> dict:
        if self.sending_chain_key is None:
            raise RuntimeError("Sending chain not initialised")
        self.sending_chain_key, mk = _kdf_ck(self.sending_chain_key)
        header = {
            "dh": self.send_ratchet.public_key,
            "pn": self.prev_send_count,
            "n": self.send_msg_num,
        }
        self.send_msg_num += 1
        aad = json.dumps(header, sort_keys=True).encode()
        ct = _encrypt(mk, plaintext.encode(), aad)
        return {"header": header, "ciphertext": ct.hex()}

    def decrypt(self, message: dict) -> str:
        header = message["header"]
        ct = bytes.fromhex(message["ciphertext"])
        dh_pub = header["dh"]
        n = header["n"]
        pn = header["pn"]

        # Check skipped message keys first
        skip_key = (dh_pub, n)
        if skip_key in self.skipped:
            mk = self.skipped.pop(skip_key)
            aad = json.dumps(header, sort_keys=True).encode()
            return _decrypt(mk, ct, aad).decode()

        # DH ratchet step if public key changed
        if dh_pub != self.recv_ratchet_pub:
            self._skip_message_keys(pn)
            self._dh_ratchet(dh_pub)

        self._skip_message_keys(n)
        self.recv_chain_key, mk = _kdf_ck(self.recv_chain_key)
        self.recv_msg_num += 1
        aad = json.dumps(header, sort_keys=True).encode()
        return _decrypt(mk, ct, aad).decode()

    def _skip_message_keys(self, until: int):
        if self.recv_msg_num + _MAX_SKIP < until:
            raise RuntimeError("Too many skipped messages")
        while self.recv_chain_key and self.recv_msg_num < until:
            self.recv_chain_key, mk = _kdf_ck(self.recv_chain_key)
            self.skipped[(self.recv_ratchet_pub, self.recv_msg_num)] = mk
            self.recv_msg_num += 1

    def _dh_ratchet(self, their_pub: int):
        self.prev_send_count = self.send_msg_num
        self.send_msg_num = 0
        self.recv_msg_num = 0
        self.recv_ratchet_pub = their_pub
        self.root_key, self.recv_chain_key = _kdf_rk(
            self.root_key, self.send_ratchet.dh(their_pub)
        )
        self.send_ratchet = DHKeyPair()
        self.root_key, self.sending_chain_key = _kdf_rk(
            self.root_key, self.send_ratchet.dh(their_pub)
        )

    def get_ratchet_public(self) -> int:
        return self.send_ratchet.public_key
