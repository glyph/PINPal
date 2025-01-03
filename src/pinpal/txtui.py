from .difficulty import SCryptParameters
from time import time
from getpass import getpass


def promptUser(
    *,
    nextTime: float,
    label: str,
    reminder: str,
    kdf: SCryptParameters,
    salt: bytes,
    key: bytes,
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
        userInput = getpass(f"\n\n\n{label} (reminder: {reminder}){attempt}: ")
        attempt = f" (attempt {repetition + 2}/{attempts})"
        if kdf.kdf(salt=salt, password=userInput.encode("utf-8")) == key:
            return True
    return False


def show(
    separator: str, knownTokens: list[str], totalTokens: int, placeholderChar: str = "•"
) -> str:
    placeholder: str = placeholderChar * 4 if separator else placeholderChar
    allTokens = ((totalTokens - len(knownTokens)) * [placeholder]) + knownTokens
    return separator.join(allTokens)
