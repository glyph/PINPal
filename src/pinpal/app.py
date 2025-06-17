from __future__ import annotations

from dataclasses import dataclass, field
from json import dumps, loads
from os import environ
from os.path import expanduser
from typing import Callable, Sequence, TypeAlias

from keyring import get_keyring
from keyring.backend import KeyringBackend

from .mem1 import Memorization
from .mem2 import Memorization2

timecache = expanduser("~/.pinpal-timestamp")

DEFAULT_SERVICE_NAME = environ.get("PINPAL_KEYRING", "pinpal")
DEFAULT_KEYRING = get_keyring()

MemChange: TypeAlias = "Callable[[Memorization | Memorization2], None]"

@dataclass
class PinPalApp:
    _memorizations: list[Memorization2 | Memorization]
    keyringServiceName: str
    backend: KeyringBackend
    _memChangeCB: MemChange = field(default=lambda me: None)

    @property
    def memorizations(self) -> Sequence[Memorization2 | Memorization]:
        return self._memorizations

    def whenMemorizationChanges(self, changeCallback: MemChange) -> None:
        """
        Call the given callback when any memorization changes, passing it in to
        said callback.
        """
        self._memChangeCB = changeCallback
        for memorization in self.memorizations:
            memorization.whenMemorizationChanges(changeCallback)

    def addMemorization(self, memorization: Memorization2 | Memorization) -> None:
        self._memorizations.append(memorization)
        memorization.whenMemorizationChanges(self._memChangeCB)

    def removeMemorizationAtIndex(self, idx: int) -> None:
        del self._memorizations[idx]

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
        self.backend.set_password(
            self.keyringServiceName,
            "storage",
            dumps([each.tojson() for each in self.memorizations]),
        )

    @classmethod
    def new(
        cls, keyringServiceName: str = DEFAULT_SERVICE_NAME, backend=DEFAULT_KEYRING
    ) -> PinPalApp:
        """
        Construct a new, blank PinPalApp
        """
        return cls([], keyringServiceName, backend)

    @classmethod
    def load(
        cls, keyringServiceName: str = DEFAULT_SERVICE_NAME, backend=DEFAULT_KEYRING
    ) -> PinPalApp | None:
        """
        Load it from somewhere persistent.
        """
        stored = backend.get_password(keyringServiceName, "storage")
        if stored is None:
            return None
        self = PinPalApp(
            [loadSomeMemorization(each) for each in loads(stored)],
            keyringServiceName,
            backend,
        )
        if any(memorization.dirty for memorization in self.memorizations):
            self.save()
        return self


def loadSomeMemorization(x: dict[str, object]) -> Memorization | Memorization2:
    if "targetTokenCount" in x:
        return Memorization2.fromjson(x)
    else:
        return Memorization.fromjson(x)
