from objc import object_property
from AppKit import NSApplication, NSNib, NSTableView, NSTableColumn
from Foundation import NSObject
from quickmacapp import Status, mainpoint  # , answer

# from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime

from .app import PinPalApp
from .mem2 import Memorization2


class MemorizationDataSource(NSObject):
    pinPalApp: PinPalApp = object_property()
    selectedRow: NSObject = object_property()

    def awakeFromNib(self) -> None:
        loaded = PinPalApp.load()
        if loaded is None:
            loaded = PinPalApp([])
        self.pinPalApp = loaded

    def tableViewSelectionDidChange_(self, notification: NSObject) -> None:
        self.selectedRow = self.tableView_objectValueForTableColumn_row_(
            None, None, notification.object().selectedRowIndexes().firstIndex()
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


class PINPalAppOwner(NSObject):
    """
    NIB owner for the application.
    """


@mainpoint()
def main(reactor: IReactorTime) -> None:
    """
    Run oldMain by default so I can keep using the app while I'm working on a
    radical refactor of the object model in newMain.
    """
    status = Status("🔑🦃🗝")

    owner = PINPalAppOwner.alloc().init()

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
