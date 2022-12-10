"""
PINPal: a tool for helping you memorize PINs
"""


from __future__ import annotations

__version__ = "0.0.1"

from dataclasses import dataclass
from enum import Enum
from getpass import getpass
from hashlib import scrypt
from json import dumps, loads
from os import urandom
from os.path import exists, expanduser
from random import SystemRandom
from time import time
from typing import Any, Callable, Sequence

from keyring import get_password, set_password


r = SystemRandom()


def kdf(*, salt: bytes, password: bytes) -> bytes:
    "scrypt with good defaults"
    return scrypt(password, salt=salt, n=0x4000, r=8, p=1)


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


def show(
    separator: str, knownTokens: list[str], totalTokens: int, placeholderChar: str = "•"
) -> str:
    placeholder: str = placeholderChar * 4 if separator else placeholderChar
    allTokens = ((totalTokens - len(knownTokens)) * [placeholder]) + knownTokens
    return separator.join(allTokens)


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
            return self.guesses[-1].timestamp + min(86400, (90 * (1.4**self.correctGuessCount())))

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
        chosen = r.choice(self.tokenType.tokens())
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
                kdf(
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
        self.salt = urandom(16)
        self.key = kdf(salt=self.salt, password=wholePassphrase.encode("utf-8"))

    def prompt(self) -> bool:
        remaining = self.nextPromptTime() - time()
        if remaining > 0:
            print(
                "next reminder for", repr(self.label), "in", int(remaining), "seconds"
            )
            return False
        userInput = getpass(f"\n\n\n{self.label} (reminder: {self.string()}): ")
        correct = kdf(salt=self.salt, password=userInput.encode("utf-8")) == self.key
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


@dataclass
class Memorization:
    """
    A PIN or password whose memorization is in progress
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
        remainingTokens = [r.choice(tokens) for _ in range(length)]
        salt = urandom(16)
        key = kdf(salt=salt, password=separator.join(remainingTokens).encode("utf-8"))
        return Memorization(
            label=label,
            remainingTokens=remainingTokens,
            tokensMemorized=0,
            successCount=0,
            separator=separator,
            salt=salt,
            key=key,
            entryTimes=[],
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

    def prompt(self) -> bool:
        remaining = self.nextPromptTime() - time()
        if remaining > 0:
            print(
                "next reminder for", repr(self.label), "in", int(remaining), "seconds"
            )
            return False
        userInput = getpass(f"\n\n\n{self.label} (reminder: {self.string()}): ")
        timestamp = time()
        correct = kdf(salt=self.salt, password=userInput.encode("utf-8")) == self.key
        self.entryTimes.append((timestamp, correct))
        if correct:
            SUCCESS_THRESHOLD = 5
            self.successCount += 1
            print(f"✅ Yay, correct {self.successCount}/{SUCCESS_THRESHOLD} times")
            if self.successCount >= SUCCESS_THRESHOLD and self.remainingTokens:
                self.tokensMemorized += 1
                self.remainingTokens.pop(-1)
                print("🎉 Level Up! 🎊")
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
            "label": self.label,
            "remainingTokens": self.remainingTokens,
            "tokensMemorized": self.tokensMemorized,
            "successCount": self.successCount,
            "separator": self.separator,
            "salt": self.salt.hex(),
            "key": self.key.hex(),
            "entryTimes": self.entryTimes,
        }

    @classmethod
    def fromjson(cls, data: dict[str, Any]) -> Memorization:
        """
        convert from json-serializable dict
        """
        return Memorization(
            label=data["label"],
            remainingTokens=data["remainingTokens"],
            tokensMemorized=data["tokensMemorized"],
            successCount=data["successCount"],
            separator=data["separator"],
            salt=bytes.fromhex(data["salt"]),
            key=bytes.fromhex(data["key"]),
            entryTimes=data["entryTimes"],
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


timecache = expanduser("~/.pinpal-timestamp")


@dataclass
class PinPalApp:
    memorizations: list[Memorization | Memorization2]

    def save(self) -> None:
        """
        Write it all out to somewhere persistent.
        """
        with open(timecache, "w") as f:
            f.write(
                str(
                    min([each.nextPromptTime() for each in self.memorizations])
                    if self.memorizations
                    else 0
                )
            )
        set_password(
            "pinpal", "storage", dumps([each.tojson() for each in self.memorizations])
        )

    @classmethod
    def load(cls) -> PinPalApp | None:
        """
        Load it from somewhere persistent.
        """
        stored = get_password("pinpal", "storage")
        if stored is None:
            return None
        self = PinPalApp([load(each) for each in loads(stored)])
        return self

def load(x: dict[str, object]) -> Memorization | Memorization2:
    if "targetTokenCount" in x:
        return Memorization2.fromjson(x)
    else:
        return Memorization.fromjson(x)

def main() -> None:
    """
    Run the tool.
    """
    from sys import argv, exit, stdout

    if len(argv) > 1 and argv[1] == "check":
        if exists(timecache):
            with open(timecache) as f:
                needsCheckAt = float(f.read())
            if needsCheckAt < time():
                stdout.write(" 📌 Time To Run PinPal 📌")
        exit(0)
    if len(argv) > 1 and argv[1] == "test":
        testing: Memorization2|Memorization = Memorization2.new("testing")
        while True:
            testing = load(loads(dumps(testing.tojson())))
            testing.prompt()
    if len(argv) > 1 and argv[1] == "clear":
        app: PinPalApp | None = PinPalApp([])
    else:
        app = PinPalApp.load()
        if app is None:
            app = PinPalApp([])
    assert app is not None
    if len(argv) > 1 and argv[1] == "new":
        newLabel = input("What do you want to call this new PIN?")
        m = Memorization2.new(newLabel)
        app.memorizations.append(m)
    else:
        for each in app.memorizations:
            each.prompt()
    app.save()


if __name__ == "__main__":
    main()
