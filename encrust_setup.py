from pathlib import Path

from encrust.api import AppDescription, SparkleData
macFiles = Path("PINPalMac")
description = AppDescription(
    bundleID="im.glyph.and.this.is.pinpal",
    bundleName="PINPal",
    icnsFile=Path("icon.icns"),
    mainPythonScript=macFiles / "PINPal.pyw",
    dataFiles=[Path("statusicon.png"), *macFiles.glob("*.xib")],
    dockIconAtStart=True,
    sparkleData=SparkleData.withConfig(
        sparkleVersion="2.7.0",
        publicEDKey="e4lwY+RAzYj1jgwjAqq6fIQJHpZVh/O2Od9aYSpY3CI=",
        feedURL="https://www.glyph.im/apps/pinpal/updates/appcast.xml",
        keychainAccount="im.glyph.and.this.is.my.sparkle.key",
        localUpdatesFolder=(
            Path.home() / "Storage" / "Sparkle" / "PINPal" / "Releases"
        ),
        remoteHost="public.glyph.im",
        remotePath="/site/www.glyph.im/apps/pinpal/updates/",
    ),
).varyBundleForTesting()
