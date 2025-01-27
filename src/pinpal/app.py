from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads
from os import environ
from os.path import expanduser

from keyring import get_keyring
from keyring.backend import KeyringBackend

from .mem1 import Memorization
from .mem2 import Memorization2

timecache = expanduser("~/.pinpal-timestamp")

DEFAULT_SERVICE_NAME = environ.get("PINPAL_KEYRING", "pinpal")


@dataclass
class PinPalApp:
    memorizations: list[Memorization | Memorization2]
    keyringServiceName: str
    backend: KeyringBackend

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
        cls, keyringServiceName: str = DEFAULT_SERVICE_NAME, backend=get_keyring()
    ) -> PinPalApp:
        """
        Construct a new, blank PinPalApp
        """
        return cls([], keyringServiceName, backend)

    @classmethod
    def load(
        cls, keyringServiceName: str = DEFAULT_SERVICE_NAME, backend=get_keyring()
    ) -> PinPalApp | None:
        """
        Load it from somewhere persistent.
        """
        stored = backend.get_password(keyringServiceName, "storage")
        if stored is None:
            return None
        self = PinPalApp(
            [load(each) for each in loads(stored)], keyringServiceName, backend
        )
        return self


def load(x: dict[str, object]) -> Memorization | Memorization2:
    if "targetTokenCount" in x:
        return Memorization2.fromjson(x)
    else:
        return Memorization.fromjson(x)
