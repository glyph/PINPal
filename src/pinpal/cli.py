from os.path import exists
from time import time

from twisted.internet.defer import Deferred

from .app import PinPalApp, loadSomeMemorization, timecache
from .mem1 import Memorization
from .mem2 import Memorization2
from .txtui import TerminalUserPrompter


async def doSelfTest(p: TerminalUserPrompter) -> None:
    from json import dumps, loads

    testing: Memorization2 | Memorization = await Memorization2.new("testing", p)
    while True:
        testing = loadSomeMemorization(loads(dumps(testing.tojson())))
        await testing.prompt(p)


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

    prompter = TerminalUserPrompter()

    async def _() -> None:
        if subCommand == "test":
            await doSelfTest(prompter)

        app = (
            PinPalApp.new()
            if (subCommand == "clear") or (maybeApp := PinPalApp.load()) is None
            else maybeApp
        )

        if subCommand == "new":
            newLabel = input("What do you want to call this new PIN?")
            m = await Memorization2.new(newLabel, prompter)
            app.addMemorization(m)

        elif subCommand == "list":
            for idx, mem in enumerate(app.memorizations):
                await prompter.tellUser(f"{idx}: {mem.label} {'done' if mem.done else 'in-progress'}")

        elif subCommand == "drop":
            for idx, mem in enumerate(app.memorizations):
                await prompter.tellUser(f"{idx}: {mem.label}")
            dropnum = input("Which number do you want to drop? ")
            dropidx = int(dropnum)
            if (input(f"Dropping {mem.label}, OK?")) == "yes":
                app.removeMemorizationAtIndex(dropidx)
                await prompter.tellUser("OK, dropped.")

        else:

            for each in app.memorizations:
                await each.prompt(prompter)

        app.save()

    # Note: this is async, but synchronous; more correct would be to run the
    # reactor, but we don't really need to yet for the CLI.
    Deferred.fromCoroutine(_())
