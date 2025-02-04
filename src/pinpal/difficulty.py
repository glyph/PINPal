from __future__ import annotations

from dataclasses import dataclass
from functools import cache
from hashlib import scrypt
from secrets import SystemRandom, token_bytes
from time import time
from typing import Callable

oldDefaultScryptParams = {
    "n": str(0x4000),
    "r": str(8),
    "p": str(1),
    "maxmem": str(64 * 1024 * 1024),
}

sysrand = SystemRandom()


THE_ONLY_VALUE_FOR_R = 8
THE_ONLY_VALUE_FOR_P = 1
ONE_HUNDRED_MILLISECONDS = 0.1


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
    def forNPower(
        cls, nPower: int, r: int = THE_ONLY_VALUE_FOR_R, p: int = THE_ONLY_VALUE_FOR_P
    ) -> SCryptParameters:
        n = 1 << nPower
        return cls(
            r=r,
            p=p,
            n=n,
            maxmem=_maxmemFor(n=n, r=THE_ONLY_VALUE_FOR_R),
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


def _maxmemFor(n: int, r: int = THE_ONLY_VALUE_FOR_R) -> int:
    # documented in Node, but not Python, apparently: “It is an error when
    # (approximately) 128 * N * r > maxmem. Default: 32 * 1024 * 1024.”
    # https://nodejs.org/api/crypto.html#cryptoscryptsyncpassword-salt-keylen-options

    # '* 2' added on the end here because we stil seem to bump into memory
    # issues when set to exactly 128*n*r
    return 128 * n * r * 2


@cache
def determineScryptParameters(
    times: int = 3, nPower: int = 13, debug: Callable[[str], None] = lambda _: None
) -> SCryptParameters:
    """
    Determine an ideal value for `n` and `maxmem`, per U{this comment,
    <https://go-review.googlesource.com/c/crypto/+/67070/3/scrypt/scrypt.go#223>}

    'consider setting N to the highest power of 2 you can derive within 100
    milliseconds'

    @param times: the number of invocations of scrypt() to average to get a
        stable timing for its execution.
    """
    salt = token_bytes(16)
    password = token_bytes(16)

    while True:
        then = time()
        candidate = SCryptParameters.forNPower(nPower)
        nPower += 1
        nextCandidate = SCryptParameters.forNPower(nPower)
        for _ in range(times):
            nextCandidate.kdf(salt=salt, password=password)
        now = time()
        avgTime = (now - then) / times
        debug(f"tested candidate {nPower} at {avgTime}/sec")
        if avgTime > ONE_HUNDRED_MILLISECONDS:
            return candidate


if __name__ == "__main__":
    print(determineScryptParameters(debug=print))
