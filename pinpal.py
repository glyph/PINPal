from __future__ import annotations

from dataclasses import dataclass
from getpass import getpass
from hashlib import scrypt
from random import SystemRandom
from os import urandom
from os.path import expanduser, exists
from time import time
from typing import Sequence, Any
from keyring import get_password, set_password
from json import dumps, loads

r = SystemRandom()


def kdf(*, salt: bytes, password: bytes) -> bytes:
    "scrypt with good defaults"
    return scrypt(password, salt=salt, n=0x4000, r=8, p=1)


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
        cls, label: str, tokens: Sequence[str] = "1234567890", length: int = 6, separator: str = ""
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
        allTokens.insert((len(self.remainingTokens) + self.tokensMemorized)//2, groupSeparator)
        return self.separator.join(allTokens)

    def prompt(self) -> bool:
        remaining = self.nextPromptTime() - time()
        if remaining > 0:
            print("next reminder for", repr(self.label), "in", int(remaining), "seconds")
            return False
        userInput = getpass(f"\n\n\n{self.label} (reminder: {self.string()}) + : ")
        timestamp = time()
        correct = kdf(salt=self.salt, password=userInput.encode("utf-8")) == self.key
        self.entryTimes.append((timestamp, correct))
        if correct:
            self.successCount += 1
            print("Yay, password correct", self.successCount, "times")
            SUCCESS_THRESHOLD = 5
            if self.successCount >= SUCCESS_THRESHOLD and self.remainingTokens:
                self.tokensMemorized += 1
                self.remainingTokens.pop(-1)
                print("dropping a token!")
                self.successCount = 0
            else:
                print("keep it up!")
            return True
        else:
            self.successCount = 0
            print("Oops, try again")
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
            label=data['label'],
            remainingTokens=data['remainingTokens'],
            tokensMemorized=data['tokensMemorized'],
            successCount=data['successCount'],
            separator=data['separator'],
            salt=bytes.fromhex(data['salt']),
            key=bytes.fromhex(data['key']),
            entryTimes=data['entryTimes'],
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
        return (timestamp + (90 * (2 ** self.successCount)))


timecache = expanduser("~/.pinpal-timestamp")

@dataclass
class PinPalApp:
    memorizations: list[Memorization]

    def save(self) -> None:
        """
        Write it all out to somewhere persistent.
        """
        with open(timecache, "w") as f:
            f.write(str(min([each.nextPromptTime() for each in self.memorizations]) if self.memorizations else 0))
        set_password("pinpal", "storage", dumps([each.tojson() for each in self.memorizations]))

    @classmethod
    def load(cls) -> PinPalApp | None:
        """
        Load it from somewhere persistent.
        """
        stored = get_password("pinpal", "storage")
        if stored is None:
            return None
        self = PinPalApp([Memorization.fromjson(each) for each in loads(stored)])
        return self


if __name__ == "__main__":
    from sys import argv, exit, stdout
    if len(argv) > 1 and argv[1] == 'check':
        if exists(timecache):
            with open(timecache) as f:
                needsCheckAt = float(f.read())
            if needsCheckAt < time():
                stdout.write(' 📌 Time To Run PinPal 📌')
        exit(0)

    if len(argv) > 1 and argv[1] == 'clear':
        app: PinPalApp | None = PinPalApp([])
    else:
        app = PinPalApp.load()
        if app is None:
            app = PinPalApp([])
    assert app is not None
    if len(argv) > 1 and argv[1] == 'new':
        newLabel = input("What do you want to call this new PIN?")
        m = Memorization.new(newLabel)
        app.memorizations.append(m)
    else:
        for each in app.memorizations:
            each.prompt()
    app.save()
