from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from AppKit import (
    NSApplication,
    NSApplicationActivationPolicyRegular,
    NSEvent,
    NSImage,
    NSMenu,
    NSNib,
    NSTableColumn,
    NSTableView,
    NSWindow,
)
from ServiceManagement import (
    SMAppService,
    SMAppServiceStatusEnabled,
    SMAppServiceStatusRequiresApproval,
)

from datetype import DateTime, aware
from Foundation import NSBundle, NSIndexSet, NSLog, NSObject
from fritter.drivers.datetimes import guessLocalZone
from objc import IBAction, IBOutlet, loadBundle, object_property, super
from quickmacapp import (
    Status,
    ItemState,
    answer,
    ask,
    choose,
    dockIconWhenVisible,
    getpass,
    mainpoint,
)
from quickmacapp.notifications import configureNotifications, response, Notifier
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime
from twisted.logger import Logger

from .app import DEFAULT_SERVICE_NAME, PinPalApp
from .mem1 import Memorization
from .mem2 import Memorization2

log = Logger()


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
        self.appOwner.memoDataSource = self

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

    def numberOfRowsInTableView_(self, tableView: NSTableView) -> int:
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
            "nextPromptTime": dt.replace(microsecond=0, tzinfo=None).isoformat(sep=" "),
            "memorization": item,
        }

    def _changedSomeData(self) -> None:
        """
        I changed the list.  Save the app's storage, reload the UI view in the
        table.
        """
        self.pinPalApp.save()
        self.tableView.reloadData()

    @IBAction
    def rehearsal_(self, sender: NSObject) -> None:
        macPrompter = MacUserPrompter()

        async def rehearse() -> None:
            for mem in self.pinPalApp.memorizations:
                await mem.prompt(macPrompter)
            self._changedSomeData()

        Deferred.fromCoroutine(rehearse())

    @IBAction
    def newMemorization_(self, sender: NSObject) -> None:
        macPrompter = MacUserPrompter()

        async def _() -> None:
            self.pinPalApp.addMemorization(
                it := await Memorization2.new(
                    await ask("What is the label for your new memorization?"),
                    macPrompter,
                )
            )
            self._changedSomeData()
            now = aware(datetime.now(zone), ZoneInfo)
            await self.appOwner.notifyForOneMemo(now, it)

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
                self.pinPalApp.removeMemorizationAtIndex(
                    self.pinPalApp.memorizations.index(mem)
                )
                self._changedSomeData()
                self.appOwner.notifier.undeliver(TimeToRehearse(mem, self))

        Deferred.fromCoroutine(_())


# TODO: react to timezone changes
zone = guessLocalZone()


class PINPalAppOwner(NSObject):
    """
    NIB owner for the application.
    """

    pinPalApp: PinPalApp

    mainWindow: NSWindow
    mainWindow = IBOutlet()

    sparkleUpdaterController: NSObject
    sparkleUpdaterController = IBOutlet()

    memoDataSource: MemorizationDataSource = object_property()
    notifier: Notifier[TimeToRehearse] = object_property()

    def initWithApp_(self, pinPalApp: PinPalApp) -> PINPalAppOwner:
        self.pinPalApp = pinPalApp
        return self.init()

    async def notifyForOneMemo(
        self, now: DateTime[ZoneInfo], memorization: Memorization | Memorization2
    ):
        """
        Update the OS user notification state for a single memorization.
        """
        try:
            when = aware(
                datetime.fromtimestamp(memorization.nextPromptTime(), zone), ZoneInfo
            )
            if when > now:
                self.notifier.undeliver(
                    TimeToRehearse(memorization, self.memoDataSource)
                )
                NSLog(
                    "Scheduling <%@> reminder notification at <%@>",
                    memorization.label,
                    str(when),
                )
                await self.notifier.notifyAt(
                    when,
                    TimeToRehearse(memorization, self.memoDataSource),
                    "PINPal Rehearsal Time",
                    f"Continue memorizing “{memorization.label}”.",
                )
            else:
                NSLog(
                    "Not touching <%@> reminder notification from the past at <%@>",
                    memorization.label,
                    when,
                )
        except BaseException:
            log.failure("while updating notification state")

    async def doNotificationSetup(self) -> None:
        async with configureNotifications() as n:
            self.notifier = n.add(
                TimeToRehearse,
                RehearseNotificationTranslator(self.pinPalApp, self.memoDataSource),
            )

        @self.pinPalApp.whenMemorizationChanges
        def changecb(memo: Memorization | Memorization2) -> None:
            Deferred.fromCoroutine(
                self.notifyForOneMemo(aware(datetime.now(zone), ZoneInfo), memo)
            )

        now = aware(datetime.now(zone), ZoneInfo)
        for memorization in self.pinPalApp.memorizations:
            await self.notifyForOneMemo(now, memorization)


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


@dataclass
class TimeToRehearse:
    """
    Notification category for it being time to rehearse a particular
    memorization.
    """

    memorization: Memorization | Memorization2
    source: MemorizationDataSource

    @response.default()
    async def defaulted(self) -> None:
        from AppKit import NSApp

        NSApp().activate()
        desiredIndex = next(
            (
                index
                for (index, memorization) in enumerate(
                    self.source.appOwner.pinPalApp.memorizations
                )
                if memorization == self.memorization
            ),
            None,
        )
        if desiredIndex is not None:
            self.source.tableView.selectRowIndexes_byExtendingSelection_(
                NSIndexSet.indexSetWithIndex_(desiredIndex), False
            )


@dataclass
class RehearseNotificationTranslator:
    """
    Translate L{TimeToRehearse} notifications.
    """

    app: PinPalApp
    source: MemorizationDataSource

    def fromNotification(
        self, notificationID: str, userData: dict[str, list[str]]
    ) -> TimeToRehearse:
        memoID = notificationID.split(".")[1]
        memo = next((each for each in self.app.memorizations if each.id == memoID))
        # TODO: what should we do if the referenced memorization no longer exists?
        return TimeToRehearse(memo, self.source)

    def toNotification(
        self, notification: TimeToRehearse
    ) -> tuple[str, dict[str, list[str]]]:
        return (f"rehearse.{notification.memorization.id}", {})


def loadIncludedFramework(frameworkName: str) -> bool:
    """
    Dynamically load the given framework from the application's bundle.

    @return: True if the framework loaded, False otherwise.
    """
    try:
        loadBundle(
            frameworkName,
            {},
            bundle_path=NSBundle.mainBundle().privateFrameworksPath()
            + f"/{frameworkName}.framework",
        )
    except ImportError as ie:
        NSLog("Could not load %@ framework: %@", frameworkName, ie)
        return False
    else:
        return True


def createMainWindow(owner: PINPalAppOwner, app: PINPalMacApplication) -> None:
    """
    Create the main window once we have already initialized the owner and the
    shared application.
    """
    nibInstance = NSNib.alloc().initWithNibNamed_bundle_("PINList.nib", None)
    nibInstance.instantiateWithOwner_topLevelObjects_(owner, None)
    dockIconWhenVisible(owner.mainWindow, hideIconOnOtherSpaces=False)
    owner.mainWindow.makeMainWindow()
    owner.mainWindow.makeKeyWindow()
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
    app.activate()


def maybeTestMain(reactor: IReactorTime, testMode: bool) -> None:
    """
    Run main() normally, but if in a test-mode build, run testMain instead.
    """
    # Ensure that the Sparkle framework is loaded before nib deserialization,
    # so that the update controller can be instantiated by the nib machinery.
    didLoadSparkle = loadIncludedFramework("Sparkle")
    app: PINPalMacApplication = PINPalMacApplication.sharedApplication()
    myAppService = SMAppService.mainAppService()
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
        .instantiateWithOwner_topLevelObjects_(owner, None)
    )
    (statusicon := NSImage.imageNamed_("statusicon.png")).setTemplate_(True)
    # a 'template' icon is one that is abstract black-only line-art that can
    # adapt to dark/light mode
    status = Status(image=statusicon)

    def bye() -> None:
        app.terminate_(owner)

    def checkForUpdates() -> None:
        owner.sparkleUpdaterController.checkForUpdates_(app)

    def toggleLaunchOnLogin() -> ItemState:
        nowOn = myAppService.status() in {
            SMAppServiceStatusEnabled,
            SMAppServiceStatusRequiresApproval,
        }
        if nowOn:
            didUnregister, err = myAppService.unregisterAndReturnError_(None)
            NSLog("unregistered app service launch; got %@ %@", didUnregister, err)
            nowOn = not didUnregister
        else:
            didRegister, err = myAppService.registerAndReturnError_(None)
            NSLog("registered app service launch; got %@ %@", didRegister, err)
            nowOn = didRegister
        return ItemState(checked=nowOn)

    createMainWindow(owner, app)
    status.menu(
        [
            # ("Hello World", sayHello),
            (
                "Check for updates…",
                checkForUpdates,
                ItemState(enabled=didLoadSparkle, key=""),
            ),
            (
                "Launch on Login",
                toggleLaunchOnLogin,
                ItemState(
                    checked=myAppService.status() == SMAppServiceStatusEnabled, key=""
                ),
            ),
            ("Quit", bye),
        ]
    )
    app.statusMenu = status.item.menu()
    Deferred.fromCoroutine(owner.doNotificationSetup())


@mainpoint()
def main(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, False)


@mainpoint()
def testMain(reactor: IReactorTime) -> None:
    maybeTestMain(reactor, True)
