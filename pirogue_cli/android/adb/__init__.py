import logging
import os
from typing import Optional

from adb_shell.adb_device import AdbDeviceUsb, AdbDevice
from adb_shell.auth.keygen import keygen, write_public_keyfile
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from usb1 import USBErrorAccess, USBErrorBusy


ADB_KEY_PATH = os.path.expanduser("~/.android/adbkey")
ADB_PUB_KEY_PATH = os.path.expanduser("~/.android/adbkey.pub")
log = logging.getLogger(__name__)


def _check_adb_keys():
    if not os.path.isdir(os.path.dirname(ADB_KEY_PATH)):
        os.makedirs(os.path.dirname(ADB_KEY_PATH))

    if not os.path.exists(ADB_KEY_PATH):
        keygen(ADB_KEY_PATH)

    if not os.path.exists(ADB_PUB_KEY_PATH):
        write_public_keyfile(ADB_KEY_PATH, ADB_PUB_KEY_PATH)


def adb_connect() -> Optional[AdbDevice]:
    _check_adb_keys()
    with open(ADB_KEY_PATH, "rb") as handle:
        priv_key = handle.read()
    with open(ADB_PUB_KEY_PATH, "rb") as handle:
        pub_key = handle.read()

    signer = PythonRSASigner(pub_key, priv_key)
    try:
        device = AdbDeviceUsb()
        device.connect(rsa_keys=[signer], auth_timeout_s=5)
        return device
    except (USBErrorBusy, USBErrorAccess):
        log.critical("Device is busy, maybe run `adb kill-server` and try again.")
    except Exception as e:
        log.critical("No device found. Make sure it is connected and unlocked.")
    return None
