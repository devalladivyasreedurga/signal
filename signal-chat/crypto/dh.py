# Diffie-Hellman using RFC 3526 Group 14 (2048-bit MODP)
# Square-and-multiply modular exponentiation — no crypto library used

P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""),
    16,
)
G = 2


def _pow_mod(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation."""
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def generate_private_key() -> int:
    import os
    return int.from_bytes(os.urandom(32), "big") % (P - 2) + 2


def generate_public_key(private_key: int) -> int:
    return _pow_mod(G, private_key, P)


def compute_shared_secret(their_public: int, my_private: int) -> int:
    return _pow_mod(their_public, my_private, P)


def shared_secret_bytes(their_public: int, my_private: int) -> bytes:
    secret = compute_shared_secret(their_public, my_private)
    return secret.to_bytes(256, "big")


class DHKeyPair:
    def __init__(self, private_key: int | None = None):
        self.private_key = private_key if private_key is not None else generate_private_key()
        self.public_key = generate_public_key(self.private_key)

    def dh(self, their_public: int) -> bytes:
        return shared_secret_bytes(their_public, self.private_key)

    def public_bytes(self) -> bytes:
        return self.public_key.to_bytes(256, "big")

    @staticmethod
    def public_from_bytes(b: bytes) -> int:
        return int.from_bytes(b, "big")
