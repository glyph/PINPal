from __future__ import annotations

from time import time

from AppKit import NSApplication, NSNib, NSTableColumn, NSTableView
from Foundation import NSObject
from objc import IBAction, IBOutlet, object_property
from quickmacapp import Status, answer, getpass, mainpoint
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime

from .app import DEFAULT_SERVICE_NAME, PinPalApp
from .difficulty import SCryptParameters
from .mem2 import Memorization2
from .txtui import show


class MacUserPrompter:
    async def promptUser(
        self,
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
        remaining = nextTime - time()
        if remaining > 0:
            await answer(f"next reminder for {label} in {int(remaining)} seconds")
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
            userInput = await getpass(f"{label} (reminder: {reshow}){attempt}: ")
            if userInput is None:
                return False
            attempt = f" (attempt {repetition + 2}/{attempts})"
            if kdf.kdf(salt=salt, password=userInput.encode("utf-8")) == key:
                return True
        return False


class MemorizationDataSource(NSObject):
    pinPalApp: PinPalApp = object_property()
    selectedRow: NSObject | None = object_property()
    appOwner: PINPalAppOwner
    appOwner = IBOutlet()

    def awakeFromNib(self) -> None:
        self.pinPalApp = self.appOwner.pinPalApp

    def tableViewSelectionDidChange_(self, notification: NSObject) -> None:
        selectedRowIndexes = notification.object().selectedRowIndexes()
        if selectedRowIndexes.count() == 0:
            self.selectedRow = None
        else:
            self.selectedRow = self.tableView_objectValueForTableColumn_row_(
                None, None, selectedRowIndexes.firstIndex()
            )

    def numberOfRowsInTableView_(
        self,
        tableView: NSTableView,
    ) -> int:
        return len(self.pinPalApp.memorizations)

    def tableView_objectValueForTableColumn_row_(
        self,
        tableView: NSTableView,
        column: NSTableColumn,
        row: int,
    ) -> object:
        item = self.pinPalApp.memorizations[row]
        return {
            "label": item.label,
            "guesses": (
                len(item.guesses)
                if isinstance(item, Memorization2)
                else item.successCount
            ),
        }

    @IBAction
    def rehearsal_(self, sender: NSObject) -> None:
        macPrompter = MacUserPrompter()
        async def rehearse() -> None:
            for mem in self.pinPalApp.memorizations:
                await mem.prompt(macPrompter)
        Deferred.fromCoroutine(rehearse())


class PINPalAppOwner(NSObject):
    """
    NIB owner for the application.
    """

    pinPalApp: PinPalApp

    def initWithApp_(self, pinPalApp: PinPalApp) -> PINPalAppOwner:
        self.pinPalApp = pinPalApp
        return self.init()


def maybeTestMain(reactor: IReactorTime, testMode: bool) -> None:
    """
    Run oldMain by default so I can keep using the app while I'm working on a
    radical refactor of the object model in newMain.
    """
    status = Status("🔑🦃🗝")

    serviceName = (
        DEFAULT_SERVICE_NAME if not testMode else f"testing.{DEFAULT_SERVICE_NAME}"
    )

    loaded = PinPalApp.load(serviceName)
    if loaded is None:
        loaded = PinPalApp.new(serviceName)

    owner = PINPalAppOwner.alloc().initWithApp_(loaded)

    def sayHello() -> None:
        # Deferred.fromCoroutine(answer("hi"))
        nibInstance = NSNib.alloc().initWithNibNamed_bundle_("PINList.nib", None)
        nibInstance.instantiateWithOwner_topLevelObjects_(owner, None)

    def bye() -> None:
        NSApplication.sharedApplication().terminate_(owner)

    sayHello()
    status.menu(
        [
            # ("Hello World", sayHello),
            ("Quit", bye),
        ]
    )


@mainpoint()
def main(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, False)


@mainpoint()
def testMain(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, True)
