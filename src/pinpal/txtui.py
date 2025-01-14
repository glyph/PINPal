# -*- test-case-name: pinpal.test.test_txtui -*-
from .difficulty import SCryptParameters
from time import time
from getpass import getpass


def promptUser(
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
    """
    Prompt the user.
    """

    remaining = nextTime - time()
    if remaining > 0:
        print("next reminder for", label, "in", int(remaining), "seconds")
        return None
    attempt = ""
    for repetition in range(attempts):
        reshow = show(
            separator,
            knownTokens,
            totalTokens,
            hiddenTokens,
            forgottenChar,
            hiddenChar,
        )
        userInput = getpass(f"\n\n\n{label} (reminder: {reshow}){attempt}: ")
        attempt = f" (attempt {repetition + 2}/{attempts})"
        if kdf.kdf(salt=salt, password=userInput.encode("utf-8")) == key:
            return True
        hiddenTokens = 0
    return False


def show(
    separator: str,
    knownTokens: list[str],
    totalTokens: int,
    hiddenTokens: int,
    forgottenChar: str = "•",
    hiddenChar: str = "°",
) -> str:
    """
    Show a partially-obscured passphrase based on a list of tokens that are
    still stored in plaintext, a total number of tokens, and a placeholder.
    """

    # TODO: placeholder styling ought to be the responsibility of TokenType,
    # with •••• being TokenType.words and • being TokenType.numbers.
    def inflate(ch: str) -> str:
        return ch * 4 if separator else ch

    forgottenPlaceholder: str = inflate(forgottenChar)
    hiddenPlaceholder: str = inflate(hiddenChar)
    allTokens = (
        ((totalTokens - len(knownTokens)) * [forgottenPlaceholder])
        + ([hiddenPlaceholder] * hiddenTokens)
        + knownTokens[hiddenTokens:]
    )
    return separator.join(allTokens)
