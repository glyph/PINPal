
from __future__ import annotations

from dataclasses import dataclass
from hashlib import scrypt
from secrets import SystemRandom, token_bytes
from time import time

oldDefaultScryptParams = {
    "n": str(0x4000),
    "r": str(8),
    "p": str(1),
    "maxmem": str(64 * 1024 * 1024),
}

sysrand = SystemRandom()

@dataclass
class SCryptParameters:
    """
    Keyword parameters for L{scrypt}.
    """

    r: int
    p: int
    n: int
    maxmem: int

    def kdf(self, *, salt: bytes, password: bytes) -> bytes:
        return scrypt(
            password, salt=salt, r=self.r, p=self.p, n=self.n, maxmem=self.maxmem
        )

    @classmethod
    def fromjson(cls, json: dict[str, str]) -> SCryptParameters:
        """
        Load SCrypt parameters from some serialized JSON objects.
        """
        return cls(
            r=int(json["r"]),
            p=int(json["p"]),
            n=int(json["n"]),
            maxmem=int(json["maxmem"]),
        )

    def tojson(self) -> dict[str, str]:
        """
        Convert SCrypt parameters to JSON.
        """
        return {
            "r": str(self.r),
            "p": str(self.p),
            "n": str(self.n),
            "maxmem": str(self.maxmem),
        }


determined: SCryptParameters | None = None


def determineScryptParameters(times: int = 10) -> SCryptParameters:
    """
    Determine an ideal value for `n` and `maxmem`, per U{this comment,
    <https://go-review.googlesource.com/c/crypto/+/67070/3/scrypt/scrypt.go#223>}

    'consider setting N to the highest power of 2 you can derive within 100
    milliseconds'
    """
    global determined
    if determined is not None:
        return determined
    salt = token_bytes(16)
    password = token_bytes(16)
    r = 8
    p = 1
    nPower = 13
    n = 1 << nPower

    while True:
        then = time()
        previousN = n
        n = 1 << nPower
        # documented in Node, but not Python, apparently: “It is an error when
        # (approximately) 128 * N * r > maxmem. Default: 32 * 1024 * 1024.”
        # https://nodejs.org/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options
        maxmem = 128 * n * r * 2
        # '* 2' added on the end here because we stil seem to bump into memory
        # issues when set to exactly 128*n*r
        for _ in range(times):
            scrypt(salt=salt, password=password, r=r, p=p, n=n, maxmem=maxmem)

        now = time()
        if ((now - then) / times) > 0.1:
            determined = SCryptParameters(r=r, p=p, n=previousN, maxmem=maxmem)
            return determined
        nPower += 1
