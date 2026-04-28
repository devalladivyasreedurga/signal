"""
X3DH (Extended Triple Diffie-Hellman) key agreement.
Uses dh.py for all DH operations; cryptography lib only for HKDF.
"""
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from .dh import DHKeyPair


_INFO = b"UIC-Signal-X3DH-v1"
_F = b"\xff" * 32  # X3DH spec padding


def _hkdf(ikm: bytes, length: int = 32, salt: bytes = b"\x00" * 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=_INFO,
    ).derive(ikm)


class X3DHBundle:
    """A full prekey bundle for a single user."""

    def __init__(self):
        self.ik = DHKeyPair()          # identity key (long-term)
        self.spk = DHKeyPair()         # signed prekey
        self.opk = DHKeyPair()         # one-time prekey

    def public_bundle(self) -> dict:
        return {
            "ik_pub": self.ik.public_key,
            "spk_pub": self.spk.public_key,
            "opk_pub": self.opk.public_key,
        }


def x3dh_sender(
    sender_ik: DHKeyPair,
    recipient_bundle: dict,
) -> tuple[bytes, int, int, int]:
    """
    Sender-side X3DH.
    Returns (shared_key_32_bytes, ek_pub, sender_ik_pub, opk_pub_used).
    """
    ek = DHKeyPair()  # ephemeral key

    rik = recipient_bundle["ik_pub"]
    rspk = recipient_bundle["spk_pub"]
    ropk = recipient_bundle["opk_pub"]

    dh1 = sender_ik.dh(rspk)
    dh2 = ek.dh(rik)
    dh3 = ek.dh(rspk)
    dh4 = ek.dh(ropk)

    km = _F + dh1 + dh2 + dh3 + dh4
    sk = _hkdf(km)
    return sk, ek.public_key, sender_ik.public_key, ropk


def x3dh_receiver(
    receiver_bundle: X3DHBundle,
    sender_ik_pub: int,
    ek_pub: int,
) -> bytes:
    """
    Receiver-side X3DH — reconstructs the same shared key.
    """
    dh1 = receiver_bundle.spk.dh(sender_ik_pub)
    dh2 = receiver_bundle.ik.dh(ek_pub)
    dh3 = receiver_bundle.spk.dh(ek_pub)
    dh4 = receiver_bundle.opk.dh(ek_pub)

    km = _F + dh1 + dh2 + dh3 + dh4
    return _hkdf(km)
