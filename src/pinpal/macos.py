from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

from AppKit import NSApplication, NSNib, NSTableColumn, NSTableView
from datetype import aware
from Foundation import NSObject
from fritter.drivers.datetimes import guessLocalZone
from objc import IBAction, IBOutlet, object_property
from quickmacapp import Status, answer, getpass, mainpoint
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime

from .app import DEFAULT_SERVICE_NAME, PinPalApp
from .mem2 import Memorization2


class MacUserPrompter:

    async def askForPassword(self, question: str, reminder: str) -> str | None:
        return await getpass(question, reminder)

    async def tellUser(self, message: str) -> None:
        await answer(message)


class MemorizationDataSource(NSObject):
    pinPalApp: PinPalApp = object_property()
    selectedRow: NSObject | None = object_property()
    appOwner: PINPalAppOwner
    appOwner = IBOutlet()
    tableView: NSTableView
    tableView = IBOutlet()

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
        zone = guessLocalZone()
        dt = aware(datetime.fromtimestamp(item.nextPromptTime(), zone), ZoneInfo)
        return {
            "label": item.label,
            "guesses": str(
                item.correctGuessCount()
                if isinstance(item, Memorization2)
                else item.successCount
            ),
            "nextPromptTime": dt.isoformat(),
        }

    @IBAction
    def rehearsal_(self, sender: NSObject) -> None:
        macPrompter = MacUserPrompter()

        async def rehearse() -> None:
            for mem in self.pinPalApp.memorizations:
                await mem.prompt(macPrompter)
            self.pinPalApp.save()
            self.tableView.reloadData()

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
    Run main() normally, but if in a test-mode build, run testMain instead.
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
