
from __future__ import annotations

from dataclasses import dataclass
from json import dumps, loads

from os.path import expanduser

from keyring import get_password, set_password

from .mem1 import Memorization
from .mem2 import Memorization2


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


