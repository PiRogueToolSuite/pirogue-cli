import logging
import subprocess
import time
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile

from pirogue_cli.frida.server import FridaServer
from pirogue_cli.system.apt import get_install_packages

log = logging.getLogger(__name__)


class AndroidDevice:

    def __init__(self):
        self.frida_server_name = 'frydaxx-server'
        self.frida_server_install_dir = f'/data/local/tmp/{self.frida_server_name}'
        self.has_adb_root = False
        self.requires_su = False
        self.rooted = False
        self.is_rooted()
        self._check_frida_server_installed()
        self.__connect()

    def __connect(self):
        log.info('⚡ Connecting to the USB device...')
        if not self.rooted:
            raise Exception('Your Android device must be rooted')
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

    def is_rooted(self):
        try:
            output = subprocess.check_output(
                'adb root',
                shell=True,
                stderr=subprocess.PIPE, )
            self.has_adb_root = True
            if (
                'adbd cannot run as root in production builds' in output.decode()
                # This happens when root is disabled in developer options
                or 'ADB Root access is disabled' in output.decode()
            ):
                self.has_adb_root = False
                try:
                    time.sleep(1)
                    # Check whether root escalation is possible through su.
                    subprocess.check_call(
                        'adb shell su -c "echo 1"',
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, )
                    self.requires_su = True
                except CalledProcessError as e:
                    pass
        except CalledProcessError as e:
            pass
        self.rooted = self.has_adb_root or self.requires_su
        return self.rooted

    def __adb_shell(self, command):
        if self.requires_su:
            command = f'su -c "{command}"'
        output = subprocess.check_output(
            f'adb shell {command}',
            shell=True,
            stderr=subprocess.PIPE)
        return output.decode('utf-8')

    def __adb_shell_no_wait(self, command):
        try:
            if self.requires_su:
                command = f'su -c "{command}"'
            subprocess.Popen(f'adb shell {command}', shell=True)
        except CalledProcessError as e:
            raise e

    def __adb_push(self, local_file, to):
        try:
            subprocess.check_call(
                f'adb push {local_file} {to}',
                shell=True,
                stdout=subprocess.PIPE,
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
            frida_server_version = self.get_frida_server_version()
            frida_client_version = self.get_frida_client_version()
            if frida_server_version != frida_client_version:
                self.install_latest_frida_server()

        except CalledProcessError:
            self.install_latest_frida_server()

    def get_frida_server_version(self):
        try:
            return self.__adb_shell(f'{self.frida_server_install_dir} --version').strip()
        except:
            return '0.0.0'

    def get_frida_client_version(self):
        frida_package = get_install_packages('frida')
        if len(frida_package) != 1:
            log.warning(
                'Unable to get the version of Frida installed on the PiRogue, defaulting to latest version.'
            )
            return None
        frida_version = frida_package[0].get('version')
        if '~pirogue' in frida_version:
            frida_version = frida_version[0:frida_version.find('~')]
        return frida_version

    def start_frida_server(self):
        if self._check_frida_server_running():
            log.info(f'⚡ Frida server is already running...')
        else:
            log.info(f'⚡ Starting Frida server...')
            self.__adb_shell_no_wait(f'{self.frida_server_install_dir} && sleep 2147483647 &')

    def stop_frida_server(self):
        log.info(f'⚡ Stopping Frida server...')
        try:
            self.__adb_shell(f'pkill {self.frida_server_name}')
        except Exception as e:
            log.error(e)

    def install_latest_frida_server(self):
        frida_client_version = self.get_frida_client_version()
        log.info(f'⚡ Installing the matching version of frida-server as {self.frida_server_name}...')
        with NamedTemporaryFile(mode='wb') as frida_server:
            FridaServer.download_frida_server(self.get_architecture(), frida_server.name, 'android', frida_client_version)
            frida_server.seek(0)
            self.__adb_push(frida_server.name, self.frida_server_install_dir)
            self.__adb_shell(f'chmod +x {self.frida_server_install_dir}')
            log.info('⚡ Matching version of frida-server successfully installed...')
