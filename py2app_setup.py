"""
To build the macOS application::

    $ python py2app_setup.py py2app
"""
from os.path import expanduser
from setuptools import setup

APP = [f"PINPalMac/{MODE}PINPal.py"]
DATA_FILES = [
    "PINPalMac/MainMenu.xib",
    "PINPalMac/PINList.xib",
    "statusicon.png",
]

# must be synced with version in ./getsparkle
SPARKLE_VERSION = "2.6.4"

OPTIONS = {
    "plist": {
        "LSUIElement": True,
        "NSRequiresAquaSystemAppearance": False,
        "CFBundleIdentifier": f"im.glyph.and.this.is.{MODE}pinpal",
        "CFBundleName": f"{MODE}PINPal",
        "SUPublicEDKey": "e4lwY+RAzYj1jgwjAqq6fIQJHpZVh/O2Od9aYSpY3CI=",
        "SUFeedURL": "https://www.glyph.im/apps/pinpal/updates/appcast.xml",
    },
    "iconfile": f"{MODE}icon.icns",
    "app": APP,
    "frameworks": [
        expanduser(
            f"~/.local/firstparty/sparkle-project.org/Sparkle-{SPARKLE_VERSION}/Sparkle.framework"
        ),
    ],
    "dylib_excludes": [
        "/Library/Frameworks/Python.framework/Versions/3.13/Frameworks/Tcl.framework",
        "/Library/Frameworks/Python.framework/Versions/3.13/Frameworks/Tk.framework",
    ],
}

setup(
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
)
