import logging
import subprocess
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile

from pirogue_cli.frida.server import FridaServer

log = logging.getLogger(__name__)


class AndroidDevice:

    def __init__(self):
        self.frida_server_name = 'frydaxx-server'
        self.frida_server_install_dir = f'/data/local/tmp/{self.frida_server_name}'
        self.__connect()
        self._check_frida_server_installed()

    def __connect(self):
        log.info('⚡ Connecting to the USB device...')
        self.__adb_root()
        log.info(f'⚡ Connected...')

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

    def __adb_root(self):
        try:
            output = subprocess.check_output(
                'adb root',
                shell=True,
                stderr=subprocess.PIPE)
            return output
        except CalledProcessError as e:
            raise e

    def __adb_shell(self, command):
        output = subprocess.check_output(
            f'adb shell {command}',
            shell=True,
            stderr=subprocess.PIPE)
        return output.decode('utf-8')

    def __adb_shell_no_wait(self, command):
        try:
            subprocess.Popen(f'adb shell {command}', shell=True)
        except CalledProcessError as e:
            raise e

    def __adb_push(self, local_file, to):
        try:
            subprocess.check_call(
                f'adb push {local_file} {to}',
                shell=True,
                stderr=subprocess.PIPE)
        except CalledProcessError as e:
            raise e

    def get_property(self, key: str) -> str:
        value = self.__adb_shell(f'getprop {key}')
        return value

    def _check_frida_server_running(self):
        try:
            value = self.__adb_shell(f'ps -A | grep {self.frida_server_name}')
            value = value.strip()
            return bool(value)
        except CalledProcessError:
            return False

    def _check_frida_server_installed(self):
        try:
            self.__adb_shell(f'ls {self.frida_server_install_dir}')
        except CalledProcessError:
            self.install_latest_frida_server()

    def start_frida_server(self):
        if self._check_frida_server_running():
            log.info(f'⚡ Frida server is already running...')
        else:
            log.info(f'⚡ Starting Frida server...')
            self.__adb_shell_no_wait(f'{self.frida_server_install_dir} && sleep 2147483647 &')

    def stop_frida_server(self):
        log.info(f'⚡ Stopping Frida server...')
        self.__adb_shell(f'pkill {self.frida_server_name}')

    def install_latest_frida_server(self):
        log.info(f'⚡ Installing the latest version of frida-server as {self.frida_server_name}...')
        with NamedTemporaryFile(mode='wb') as frida_server:
            FridaServer.download_frida_server(self.get_architecture(), frida_server.name, 'android')
            frida_server.seek(0)
            self.__adb_push(frida_server.name, self.frida_server_install_dir)
            self.__adb_shell(f'chmod +x {self.frida_server_install_dir}')
            log.info('⚡ Latest version of frida-server successfully installed...')
