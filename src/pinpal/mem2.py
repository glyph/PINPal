from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Sequence
from time import time
from getpass import getpass
from secrets import token_bytes

from .difficulty import SCryptParameters, oldDefaultScryptParams, determineScryptParameters, sysrand
from .txtui import show, promptUser


class TokenType(Enum):
    tokens: Callable[[], Sequence[str]]
    separator: str
    retokenize: Callable[[str], Sequence[str]]

    numbers = "numbers"
    words = "words"


TokenType.numbers.tokens = lambda: "0123456789"
TokenType.numbers.separator = ""
TokenType.numbers.retokenize = lambda x: list(x)


def horsephrase_tokens() -> Sequence[str]:
    from horsephrase.__main__ import words

    return words


TokenType.words.tokens = horsephrase_tokens
TokenType.words.separator = " "
TokenType.words.retokenize = lambda x: x.split(" ")


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
    The tokens currently known to and stored by PinPal itself.
    """

    generatedCount: int
    """
    The number of tokens generated and stored in C{self.key}.
    """

    salt: bytes
    """
    Salt for deriving the key.
    """

    key: bytes
    """
    The encrypted partial portion of the thing being memorized.
    """

    tokenType: TokenType
    """
    The type of tokens being generated.
    """

    guesses: list[UserGuess]
    """
    Every time the user has guessed.
    """

    maxKnown: int
    """
    The maximum number of tokens we can have stored.
    """

    kdf: SCryptParameters
    """
    The parameters for the KDF.
    """

    def tojson(self) -> dict[str, object]:
        """
        convert to json-serializable dict
        """
        return {
            "label": self.label,
            "targetTokenCount": str(self.targetTokenCount),
            "knownTokens": self.knownTokens,
            "generatedCount": str(self.generatedCount),
            "salt": self.salt.hex(),
            "key": self.key.hex(),
            "tokenType": self.tokenType.value,
            "guesses": [each.tojson() for each in self.guesses],
            "maxKnown": str(self.maxKnown),
            "kdf": self.kdf.tojson(),
        }

    @classmethod
    def fromjson(cls, data: dict[str, Any]) -> Memorization2:
        """
        convert from json-serializable dict
        """
        return cls(
            label=data["label"],
            targetTokenCount=int(data["targetTokenCount"]),
            knownTokens=data["knownTokens"],
            generatedCount=int(data["generatedCount"]),
            salt=bytes.fromhex(data["salt"]),
            key=bytes.fromhex(data["key"]),
            tokenType=TokenType(data["tokenType"]),
            guesses=[UserGuess.fromjson(each) for each in data["guesses"]],
            maxKnown=int(data["maxKnown"]),
            kdf=SCryptParameters.fromjson(data.get("kdf", oldDefaultScryptParams)),
        )

    @classmethod
    def new(cls, label: str) -> Memorization2:
        """
        Create a new passphrase to memorize.
        """
        self = cls(
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
        )
        self.generateOne()
        return self

    def string(self) -> str:
        return show(self.tokenType.separator, self.knownTokens, self.generatedCount)

    def nextPromptTime(self) -> float:
        """
        The time for the next prompt
        """
        if not self.guesses:
            return time()
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
        """ """
        result = 0
        for each in reversed(self.guesses):
            if each.correct and each.length == self.generatedCount:
                result += 1
            else:
                return result
        return result

    def generateOne(self) -> None:
        """
        Generate one additional token.
        """
        chosen = sysrand.choice(self.tokenType.tokens())
        if self.generatedCount > self.maxKnown:
            # we no longer remember the entire passphrase, but the key has to
            # represent the entire passphrase.
            wholePassphrase = getpass(
                "enter correctly to confirm: "
                + show(
                    self.tokenType.separator,
                    self.knownTokens + [chosen],
                    self.generatedCount + 1,
                )
                + ": "
            )
            tokens = self.tokenType.retokenize(wholePassphrase)
            newTokenMismatch = tokens[-1] != chosen
            oldTokenMismatch = (
                self.kdf.kdf(
                    salt=self.salt,
                    password=self.tokenType.separator.join(tokens[:-1]).encode("utf-8"),
                )
                != self.key
            )
            if newTokenMismatch or oldTokenMismatch:
                print("passphrase incorrect")
                return
        else:
            wholePassphrase = self.tokenType.separator.join([*self.knownTokens, chosen])
        # commit!
        self.generatedCount += 1
        self.knownTokens.append(chosen)
        if len(self.knownTokens) > self.maxKnown:
            self.knownTokens.pop(0)
        self.salt = token_bytes(16)
        self.key = self.kdf.kdf(
            salt=self.salt, password=wholePassphrase.encode("utf-8")
        )

    def prompt(self) -> bool:
        correct = promptUser(
            nextTime=self.nextPromptTime(),
            label=self.label,
            reminder=self.string(),
            kdf=self.kdf,
            salt=self.salt,
            key=self.key,
        )
        if correct is None:
            return False
        self.guesses.append(
            UserGuess(correct=correct, timestamp=time(), length=self.generatedCount)
        )
        if correct:
            print("yay")
            guessesToGo = self.correctThreshold() - self.correctGuessCount()
            if guessesToGo > 0:
                print(guessesToGo, "correct entries to go before leveling up")
                return correct
            if not self.knownTokens:
                print("keep practicing!")
                return correct
            if self.generatedCount < self.targetTokenCount:
                print("leveling up")
                self.generateOne()
            else:
                print("forgetting some more")
                del self.knownTokens[0]
        else:
            print("too bad")
        return correct
