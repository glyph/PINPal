from __future__ import annotations

from dataclasses import dataclass, field
from secrets import token_bytes
from time import time
from typing import TYPE_CHECKING, Any, Sequence
from uuid import uuid4

from pinpal.uiboundary import UserPrompter

from .difficulty import (SCryptParameters, determineScryptParameters,
                         oldDefaultScryptParams, sysrand)
from .txtui import promptUser

if TYPE_CHECKING:
    from .app import MemChange


@dataclass
class Memorization:
    """
    A PIN or password whose memorization is in progress
    """

    id: str
    """
    A durable identifier for this memorization; generated on-demand the first
    time it is accessed; never changed thereafter.
    """

    label: str
    """
    The name of this new PIN.
    """

    remainingTokens: list[str]
    """
    The digits or words we haven't memorized yet.
    """

    tokensMemorized: int
    """
    The number of digits or words the user has already memorized.
    """

    successCount: int
    """
    How many times in a row the user has succeeded at success.
    """

    separator: str
    """
    The separator between characters.
    """

    salt: bytes
    """
    Salt for deriving the correct hash.
    """

    key: bytes
    """
    The result of hashing the password being memorized.
    """

    entryTimes: list[tuple[float, bool]]

    kdf: SCryptParameters

    dirty: bool
    """
    Does this memorization need to be saved?  (Currently only used during
    loading to determine if IDs were generated.)
    """
    _changeCallback: MemChange = field(default=lambda me: None)

    def whenMemorizationChanges(self, newCallback: MemChange) -> None:
        self._changeCallback = newCallback

    @property
    def done(self) -> bool:
        return len(self.remainingTokens) == 0

    @classmethod
    def new(
        cls,
        label: str,
        tokens: Sequence[str] = "1234567890",
        length: int = 6,
        separator: str = "",
    ) -> Memorization:
        """
        create a new password to memorize
        """
        remainingTokens = [sysrand.choice(tokens) for _ in range(length)]
        salt = token_bytes(16)
        kdf = determineScryptParameters()
        password = separator.join(remainingTokens).encode("utf-8")
        key = kdf.kdf(salt=salt, password=password)
        return Memorization(
            label=label,
            remainingTokens=remainingTokens,
            tokensMemorized=0,
            successCount=0,
            separator=separator,
            salt=salt,
            key=key,
            kdf=kdf,
            entryTimes=[],
            id=str(uuid4()),
            dirty=False,
        )

    def string(self) -> str:
        groupSeparator = "/"
        placeholderChar = "•"
        placeholder: str = placeholderChar * 4 if self.separator else placeholderChar
        allTokens = self.remainingTokens + (self.tokensMemorized * [placeholder])
        allTokens.insert(
            (len(self.remainingTokens) + self.tokensMemorized) // 2, groupSeparator
        )
        return self.separator.join(allTokens)

    async def prompt(self, prompter: UserPrompter) -> bool:
        correct = await promptUser(
            prompter,
            nextTime=self.nextPromptTime(),
            label=self.label,
            kdf=self.kdf,
            salt=self.salt,
            key=self.key,
            separator=self.separator,
            knownTokens=self.remainingTokens,
            totalTokens=len(self.remainingTokens) + self.tokensMemorized,
            hiddenTokens=0,
        )
        if correct is None:
            return False
        self.entryTimes.append((time(), correct))
        self._changeCallback(self)
        if correct:
            SUCCESS_THRESHOLD = 5
            self.successCount += 1
            await prompter.tellUser(
                f"✅ Yay, correct {self.successCount}/{SUCCESS_THRESHOLD} times"
            )
            if self.successCount >= SUCCESS_THRESHOLD and self.remainingTokens:
                self.tokensMemorized += 1
                self.remainingTokens.pop(-1)
                await prompter.tellUser("🎉 Level Up! 🎊")
                self.successCount = 0
            return True
        else:
            self.successCount = 0
            print("❌ Oops, try again")
            return False

    def tojson(self) -> dict[str, object]:
        """
        convert to json-serializable dict
        """
        return {
            "id": self.id,
            "label": self.label,
            "remainingTokens": self.remainingTokens,
            "tokensMemorized": self.tokensMemorized,
            "successCount": self.successCount,
            "separator": self.separator,
            "salt": self.salt.hex(),
            "key": self.key.hex(),
            "entryTimes": self.entryTimes,
            "kdf": self.kdf.tojson(),
        }

    @classmethod
    def fromjson(cls, data: dict[str, Any]) -> Memorization:
        """
        convert from json-serializable dict
        """
        if "id" in data:
            idval = data["id"]
            dirty = False
        else:
            idval = str(uuid4())
            dirty = True
        return Memorization(
            id=idval,
            label=data["label"],
            remainingTokens=data["remainingTokens"],
            tokensMemorized=data["tokensMemorized"],
            successCount=data["successCount"],
            separator=data["separator"],
            salt=bytes.fromhex(data["salt"]),
            key=bytes.fromhex(data["key"]),
            entryTimes=data["entryTimes"],
            kdf=SCryptParameters.fromjson(data.get("kdf", oldDefaultScryptParams)),
            dirty=dirty,
        )

    def nextPromptTime(self) -> float:
        """
        When should we next prompt the user?
        """
        if not self.entryTimes:
            # I've never guessed; let's guess right now.
            return time()
        timestamp, correct = self.entryTimes[-1]
        if not correct:
            return time()
        # need to delay. want to memorize a password in around 3 days or so. 6
        # digits, 5 correct guesses per digit necessary.  30 guesses minimum.
        return timestamp + min(86400, (90 * (2**self.successCount)))
