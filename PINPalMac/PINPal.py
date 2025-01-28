import OpenSSL.SSL as _
import service_identity as _
import _cffi_backend as _

# entrypoints declared from keyring, even the ones we don't need
import keyring.backends.kwallet as _
import keyring.backends.SecretService as _
import keyring.backends.Windows as _
import keyring.backends.chainer as _
import keyring.backends.libsecret as _
import keyring.backends.macOS as _

from pinpal.macos import main

main.runMain()
