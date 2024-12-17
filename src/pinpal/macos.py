
from AppKit import NSApplication, NSNib
from Foundation import NSObject
from quickmacapp import Status, answer, mainpoint
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime


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
        Deferred.fromCoroutine(answer("hi"))
        nibInstance = NSNib.alloc().initWithNibNamed_bundle_(
            "PINList.nib", None
        )
        nibInstance.instantiateWithOwner_topLevelObjects_(owner, None)

    def bye() -> None:
        NSApplication.sharedApplication().terminate_(owner)

    status.menu(
        [
            ("Hello World", sayHello),
            ("Quit", bye),
        ]
    )
