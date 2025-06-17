# -*- test-case-name: pinpal.test.test_mem2 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from secrets import token_bytes
from time import time as _globalTime
from typing import TYPE_CHECKING, Any, Callable, Sequence
from uuid import uuid4

from pinpal.uiboundary import UserPrompter

from .difficulty import (SCryptParameters, determineScryptParameters,
                         oldDefaultScryptParams)
from .difficulty import sysrand as _sysrand
from .txtui import promptUser, show

if TYPE_CHECKING:
    from .app import MemChange


@dataclass
class TokenInfo:
    tokens: Callable[[], Sequence[str]]
    separator: str
    retokenize: Callable[[str], Sequence[str]]


def horsephrase_tokens() -> Sequence[str]:
    from horsephrase.__main__ import words

    return words


class TokenType(Enum):
    numbers = TokenInfo(lambda: "0123456789", ", ", lambda x: list(x))
    words = TokenInfo(horsephrase_tokens, " ", lambda x: x.split(" "))


@dataclass
class UserGuess:
    """
    A user guessed the passphrase.
    """

    correct: bool
    """
    Was the user correct in their guess?
    """
    timestamp: float
    """
    What time was this done at?
    """
    length: int
    """
    How many tokens long was the thing they needed to guess?
    """

    def tojson(self) -> dict[str, object]:
        return {
            "correct": self.correct,
            "timestamp": self.timestamp,
            "length": str(self.length),
        }

    @classmethod
    def fromjson(cls, data: dict[str, Any]) -> UserGuess:
        return cls(
            correct=data["correct"],
            timestamp=data["timestamp"],
            length=int(data["length"]),
        )


@dataclass
class Memorization2:
    """
    Memorization stratetgy v2.0:

        - upon creation, remember what kind of secret we're generating, how
          many tokens we're targeting, and generate a single token.

        - when the user gets the guess correct N times, generate a new token,
          and save the hash of the new secret.

        - when the length of the secret gets over maxKnown tokens, forget the
          first token in the sequence.
    """

    id: str
    """
    A durable identifier for this memorization; generated on-demand the first
    time it is accessed; never changed thereafter.
    """

    label: str
    """
    The name of this new token we're generating.
    """

    targetTokenCount: int
    """
    The number of tokens we are ultimately hoping to generate.
    """

    knownTokens: list[str]
    """
    The list of tokens that the user is in the process of memorizing, that
    pinpal is storing in plaintext in order to prompt the user each time.
    """

    generatedCount: int
    """
    The total number of tokens generated so far by this memorization, including
    both plaintext-stored and already-forgotten tokens.
    """

    salt: bytes
    """
    Randomized salt for deriving the key. (16 random token bytes.)
    """

    key: bytes
    """
    The output of the KDF of all tokens generated so far (both plaintext-stored
    and already-forgotten).
    """

    tokenType: TokenType
    """
    The type of tokens being generated (i.e.: numbers L{TokenType.numbers} for
    a short PIN, words L{TokenType.words} for a passphrase).
    """

    guesses: list[UserGuess]
    """
    A record of all the user's guesses, both successful and unsuccessful.
    """

    maxKnown: int
    """
    The maximum number of tokens we can have stored in plaintext.
    """

    kdf: SCryptParameters
    """
    The parameters for the KDF.
    """

    dirty: bool
    """
    Does this memorization need to be saved?  (Currently only used during
    loading to determine if IDs were generated.)
    """

    _time: Callable[[], float] = field(default=_globalTime)
    """
    The source of wall-clock time as a POSIX timestamp.
    """

    _choice: Callable[[Sequence[str]], str] = _sysrand.choice
    """
    The source of randomness.  Really should only be specified by tests;
    otherwise determinism (i.e. predictability) is deeply undesirable.
    """

    _changeCallback: MemChange = field(default=lambda me: None)

    def whenMemorizationChanges(self, newCallback: MemChange) -> None:
        self._changeCallback = newCallback

    @property
    def done(self) -> bool:
        """
        Have we generated every token that we are going to generate, and
        forgotten all plaintext tokens, storing only the metadata and KDF
        output?
        """
        return (self.generatedCount == self.targetTokenCount) and (
            0 == len(self.knownTokens)
        )

    def tojson(self) -> dict[str, object]:
        """
        convert to json-serializable dict
        """
        return {
            "id": self.id,
            "label": self.label,
            "targetTokenCount": str(self.targetTokenCount),
            "knownTokens": self.knownTokens,
            "generatedCount": str(self.generatedCount),
            "salt": self.salt.hex(),
            "key": self.key.hex(),
            "tokenType": self.tokenType.name,
            "guesses": [each.tojson() for each in self.guesses],
            "maxKnown": str(self.maxKnown),
            "kdf": self.kdf.tojson(),
        }

    @classmethod
    def fromjson(cls, data: dict[str, Any]) -> Memorization2:
        """
        convert from json-serializable dict
        """
        if "id" in data:
            idval = data["id"]
            dirty = False
        else:
            idval = str(uuid4())
            dirty = True
        return cls(
            id=idval,
            label=data["label"],
            targetTokenCount=int(data["targetTokenCount"]),
            knownTokens=data["knownTokens"],
            generatedCount=int(data["generatedCount"]),
            salt=bytes.fromhex(data["salt"]),
            key=bytes.fromhex(data["key"]),
            tokenType=TokenType[data["tokenType"]],
            guesses=[UserGuess.fromjson(each) for each in data["guesses"]],
            maxKnown=int(data["maxKnown"]),
            kdf=SCryptParameters.fromjson(data.get("kdf", oldDefaultScryptParams)),
            dirty=dirty,
        )

    @classmethod
    async def new(cls, label: str, prompter: UserPrompter) -> Memorization2:
        """
        Create a new passphrase to memorize.
        """
        self = cls(
            id=str(uuid4()),
            label=label,
            targetTokenCount=5,
            knownTokens=[],
            generatedCount=0,
            salt=b"",
            key=b"",
            tokenType=TokenType.words,
            guesses=[],
            maxKnown=3,
            kdf=determineScryptParameters(),
            dirty=False,
        )
        await self.generateOne(prompter)
        return self

    def string(self) -> str:
        return show(
            self.tokenType.value.separator,
            self.knownTokens,
            self.generatedCount,
            0 if not self.knownTokens else 1 if self.correctGuessCount() >= 2 else 0,
        )

    def nextPromptTime(self) -> float:
        """
        The time (in epoch seconds) at which the next prompt to the user ought
        to be displayed.
        """
        if not self.guesses:
            return self._time()
        else:
            return self.guesses[-1].timestamp + min(
                86400, (90 * (1.4 ** self.correctGuessCount()))
            )

    def correctThreshold(self) -> int:
        """
        How many guesses do we need to get correct in order to move on to the
        next token?
        """
        return (self.generatedCount) * 2

    def correctGuessCount(self) -> int:
        """
        Compute the number of continuous correct guesses at the current length
        of the password.
        """
        result = 0
        for each in reversed(self.guesses):
            if each.correct and each.length == self.generatedCount:
                result += 1
            else:
                return result
        return result

    async def generateOne(self, prompter: UserPrompter) -> None:
        """
        Generate one additional token.
        """
        chosen = self._choice(self.tokenType.value.tokens())
        if self.generatedCount > self.maxKnown:
            # we no longer remember the entire passphrase, but the key has to
            # represent the entire passphrase.
            wholePassphrase = await prompter.askForPassword(
                "enter password to confirm",
                show(
                    self.tokenType.value.separator,
                    self.knownTokens + [chosen],
                    self.generatedCount + 1,
                    0,
                ),
            )
            if wholePassphrase is None:
                await prompter.tellUser("No password provided.")
                return
            tokens = self.tokenType.value.retokenize(wholePassphrase)
            newTokenMismatch = tokens[-1] != chosen
            oldTokenMismatch = (
                self.kdf.kdf(
                    salt=self.salt,
                    password=self.tokenType.value.separator.join(tokens[:-1]).encode(
                        "utf-8"
                    ),
                )
                != self.key
            )
            if newTokenMismatch or oldTokenMismatch:
                print("passphrase incorrect")
                return
        else:
            wholePassphrase = self.tokenType.value.separator.join(
                [*self.knownTokens, chosen]
            )
        # commit!
        self.generatedCount += 1
        self.knownTokens.append(chosen)
        if len(self.knownTokens) > self.maxKnown:
            self.knownTokens.pop(0)
        self.salt = token_bytes(16)
        self.key = self.kdf.kdf(
            salt=self.salt, password=wholePassphrase.encode("utf-8")
        )

    async def prompt(self, prompter: UserPrompter) -> bool:
        correct = await promptUser(
            prompter,
            nextTime=self.nextPromptTime(),
            label=self.label,
            kdf=self.kdf,
            salt=self.salt,
            key=self.key,
            separator=self.tokenType.value.separator,
            knownTokens=self.knownTokens,
            totalTokens=self.generatedCount,
            hiddenTokens=(
                0 if not self.knownTokens else 1 if self.correctGuessCount() >= 2 else 0
            ),
        )
        if correct is None:
            return False
        self.guesses.append(
            UserGuess(
                correct=correct, timestamp=self._time(), length=self.generatedCount
            )
        )
        self._changeCallback(self)
        if correct:
            guessesToGo = self.correctThreshold() - self.correctGuessCount()
            if guessesToGo > 0:
                await prompter.tellUser(
                    f"{guessesToGo} correct entries to go before leveling up"
                )
                return correct
            if not self.knownTokens:
                await prompter.tellUser("keep practicing!")
                return correct
            if self.generatedCount < self.targetTokenCount:
                await prompter.tellUser("leveling up")
                await self.generateOne(prompter)
            else:
                await prompter.tellUser("forgetting some more")
                del self.knownTokens[0]
        else:
            await prompter.tellUser("passphrase incorrect")
        return correct
