from os.path import exists
from time import time

from .app import load, timecache, PinPalApp
from .mem1 import Memorization
from .mem2 import Memorization2


def doSelfTest() -> None:
    from json import dumps, loads
    testing: Memorization2 | Memorization = Memorization2.new("testing")
    while True:
        testing = load(loads(dumps(testing.tojson())))
        testing.prompt()


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
                stdout.write(" 📌⏰")
        exit(0)

    subCommand = None if len(argv) < 2 else argv[1]

    if subCommand == "test":
        doSelfTest()

    app = (
        PinPalApp([])
        if (subCommand == "clear") or (maybeApp := PinPalApp.load()) is None
        else maybeApp
    )

    if subCommand == "new":
        newLabel = input("What do you want to call this new PIN?")
        m = Memorization2.new(newLabel)
        app.memorizations.append(m)

    elif subCommand == "list":
        for idx, mem in enumerate(app.memorizations):
            print(f"{idx}: {mem.label} {'done' if mem.done else 'in-progress'}")

    elif subCommand == "drop":
        for idx, mem in enumerate(app.memorizations):
            print(f"{idx}: {mem.label}")
        dropnum = input("Which number do you want to drop? ")
        dropidx = int(dropnum)
        if (input(f"Dropping {mem.label}, OK?")) == "yes":
            del app.memorizations[dropidx]
            print("OK, dropped.")

    else:
        for each in app.memorizations:
            each.prompt()
    app.save()


