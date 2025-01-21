from typing import Protocol

from .difficulty import SCryptParameters

class UserPrompter(Protocol):
    async def promptUser(
        self,
        *,
        nextTime: float,
        label: str,
        kdf: SCryptParameters,
        salt: bytes,
        key: bytes,
        separator: str,
        knownTokens: list[str],
        totalTokens: int,
        hiddenTokens: int,
        forgottenChar: str = "•",
        hiddenChar: str = "°",
        attempts: int = 4,
    ) -> bool | None:
        ...
