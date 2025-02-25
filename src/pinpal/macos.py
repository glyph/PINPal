from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from AppKit import NSApplication, NSNib, NSTableColumn, NSTableView, NSEvent, NSMenu
from datetype import aware
from Foundation import NSObject
from fritter.drivers.datetimes import guessLocalZone
from objc import IBAction, IBOutlet, object_property, super
from quickmacapp import Status, answer, ask, choose, getpass, mainpoint
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
    selectedMemorization: Memorization2 | None = object_property()
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
            self.selectedMemorization = None
        else:
            it = self.tableView_objectValueForTableColumn_row_(
                None, None, selectedRowIndexes.firstIndex()
            )
            self.selectedRow = it
            self.selectedMemorization = it["memorization"]

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
    ) -> dict[str, Any]:
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
            "nextPromptTime": dt.replace(microsecond=0, tzinfo=None).isoformat(sep=' '),
            "memorization": item,
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

    @IBAction
    def newMemorization_(self, sender: NSObject) -> None:
        macPrompter = MacUserPrompter()

        async def _() -> None:
            self.pinPalApp.memorizations.append(
                await Memorization2.new(
                    await ask("What is the label for your new memorization?"),
                    macPrompter,
                )
            )
            self.tableView.reloadData()
            self.pinPalApp.save()

        Deferred.fromCoroutine(_())

    @IBAction
    def removeMemorization_(self, sender: NSObject) -> None:

        async def _() -> None:
            mem = self.selectedMemorization
            assert mem is not None, "you have to select a memorization"
            doIt = await choose(
                [(False, "Nevermind"), (True, "Yes, Delete")],
                "Really delete this memorization?",
                f"“{mem.label}”",
            )
            if doIt:
                self.pinPalApp.memorizations.remove(mem)
                self.tableView.reloadData()

        Deferred.fromCoroutine(_())


class PINPalAppOwner(NSObject):
    """
    NIB owner for the application.
    """

    pinPalApp: PinPalApp

    sparkleUpdaterController: NSObject
    sparkleUpdaterController = IBOutlet()

    def initWithApp_(self, pinPalApp: PinPalApp) -> PINPalAppOwner:
        self.pinPalApp = pinPalApp
        return self.init()


class PINPalMacApplication(NSApplication):
    mainMenu: NSMenu
    mainMenu = IBOutlet()

    statusMenu: NSMenu
    statusMenu = IBOutlet()

    def sendEvent_(self, event: NSEvent) -> None:
        for menu in [self.statusMenu, self.myMenu]:
            handled = menu.performKeyEquivalent_(event)
            if handled:
                return
        super().sendEvent_(event)


def maybeTestMain(reactor: IReactorTime, testMode: bool) -> None:
    """
    Run main() normally, but if in a test-mode build, run testMain instead.
    """
    app: PINPalMacApplication = PINPalMacApplication.sharedApplication()

    serviceName = (
        DEFAULT_SERVICE_NAME if not testMode else f"testing.{DEFAULT_SERVICE_NAME}"
    )

    loaded = PinPalApp.load(serviceName)

    if loaded is None:
        loaded = PinPalApp.new(serviceName)

    owner: PINPalAppOwner = PINPalAppOwner.alloc().initWithApp_(loaded)

    app.mainMenu = (
        NSNib.alloc()
        .initWithNibNamed_bundle_("MainMenu.nib", None)
        .instantiateWithOwner_topLevelObjects_(app, None)
    )

    status = Status("🔑🦃🗝")
    def sayHello() -> None:
        # Deferred.fromCoroutine(answer("hi"))
        nibInstance = NSNib.alloc().initWithNibNamed_bundle_("PINList.nib", None)
        nibInstance.instantiateWithOwner_topLevelObjects_(owner, None)

    def bye() -> None:
        app.terminate_(owner)

    def checkForUpdates() -> None:
        owner.sparkleUpdaterController.checkForUpdates_(app)

    sayHello()
    status.menu(
        [
            # ("Hello World", sayHello),
            ("CFU", checkForUpdates),
            ("Quit", bye),
        ]
    )
    app.statusMenu = status.item.menu()


@mainpoint()
def main(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, False)


@mainpoint()
def testMain(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, True)
