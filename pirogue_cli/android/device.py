import logging
import sys
from tempfile import NamedTemporaryFile

from adb_shell.adb_device import AdbDevice

from pirogue_cli.android.adb import adb_connect
from pirogue_cli.frida.server import download_frida_server

FRIDA_SERVER_NAME = 'fryda-server'
FRIDA_SERVER_INSTALL_DIR = f'/data/local/tmp/{FRIDA_SERVER_NAME}'
log = logging.getLogger(__name__)


class AndroidDevice:
    adb_device: AdbDevice

    def __init__(self):
        self.__connect()

    def __connect(self):
        log.info('⚡ Connecting to the USB device...')
        self.adb_device = adb_connect()
        if not self.adb_device:
            log.error('⚠️Unable to connect to your Android device')
            sys.exit(-1)
        log.info(f'⚡ Connected to {self.adb_device._local_id}...')
        self.adb_device.root()

    def get_architecture(self):
        cpu = self.get_property('ro.product.cpu.abi')
        if "arm64" in cpu:
            return "arm64"
        if "x86_64" in cpu:
            return "x86_64"
        if "arm" in cpu:
            return "arm"
        if "x86" in cpu:
            return "x86"
        return ""

    def get_property(self, key: str) -> str:
        value = self.adb_device.shell(f'getprop {key}', read_timeout_s=200.0)
        return value

    def install_latest_frida_server(self):
        log.info(f'⚡ Installing the latest version of frida-server as {FRIDA_SERVER_NAME}...')
        with NamedTemporaryFile(mode='wb') as frida_server:
            download_frida_server(self.get_architecture(), frida_server.name)
            frida_server.seek(0)
            self.adb_device.push(frida_server.name, FRIDA_SERVER_INSTALL_DIR)
            log.info('⚡ Latest version of frida-server successfully installed...')
