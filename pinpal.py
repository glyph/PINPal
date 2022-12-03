from __future__ import annotations
from dataclasses import dataclass
from getpass import getpass
from hashlib import scrypt
from random import SystemRandom
from os import urandom

r = SystemRandom()

def kdf(*, salt: bytes, password: bytes) -> bytes:
    "scrypt with good defaults"
    return scrypt(password, salt=salt, n=0x4000, r=8, p=1)

@dataclass
class Memorization:
    """
    A PIN or password whose memorization is in progress
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
    The derived key.
    """

    @classmethod
    def new(cls, tokens: str="1234567890", length: int=3, separator: str="") -> Memorization:
        """
        create a new password to memorize
        """
        remainingTokens = [r.choice(tokens) for _ in range(length)]
        salt = urandom(16)
        key = kdf(salt=salt, password=separator.join(remainingTokens).encode("utf-8"))
        return Memorization(
            remainingTokens=remainingTokens,
            tokensMemorized=0,
            successCount=0,
            separator=separator,
            salt=salt,
            key=key,
        )

    def string(self) -> str:
        placeholderChar = "•"
        placeholder: str = placeholderChar * 4 if self.separator else placeholderChar
        return self.separator.join(
            self.remainingTokens + (self.tokensMemorized * [placeholder])
        )

    def prompt(self) -> bool:
        print("Complete the PIN")
        userInput = getpass('"' + self.string() + '": ')
        if kdf(salt=self.salt, password=userInput.encode("utf-8")) == self.key:
            self.successCount += 1
            print("Yay, password correct", self.successCount, "times")
            SUCCESS_THRESHOLD = 3
            if self.successCount >= SUCCESS_THRESHOLD:
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


@dataclass
class PinPalApp:
    memorizations: list[Memorization]

if __name__ == '__main__':
    m = Memorization.new()
    while m.remainingTokens:
        m.prompt()
