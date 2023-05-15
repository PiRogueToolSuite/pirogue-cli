import logging
import time

import pkg_resources
from frida_tools.application import ConsoleApplication

from pirogue_cli.frida.capture_manager import CaptureManager

PWD = pkg_resources.resource_filename('pirogue_cli', 'frida-scripts')
log = logging.getLogger(__name__)


class FridaApplication(ConsoleApplication):
    SESSION_ID_LENGTH = 32
    MASTER_KEY_LENGTH = 48

    def __init__(self):
        self.capture_manager: CaptureManager
        super(FridaApplication, self).__init__()

    def _add_options(self, parser):
        parser.add_argument(
            '--capture-command',
            help=(
                'Specify directly a capture command instead of building it from interface. '
                'Useful for remote capture over SSH. Example: '
                'ssh root@openwrt "tcpdump -U -n -w - -i wlan0 \'host PHONE_IP\'"'
            )
        )
        parser.add_argument('-o', '--output', help='The output directory')
        parser.add_argument('-i', '--iface', help='The network interface to capture', default=None)

    def _initialize(self, parser, options, args):
        self.capture_manager = CaptureManager(options.output, iface=options.iface)
        self.capture_manager.start_capture(capture_cmd=options.capture_command)

    def _needs_target(self):
        return True

    def _start(self):
        self._output_files = {}
        self._update_status('Attached')

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._session_cache = set()

        self._script = self._session.create_script(self.capture_manager.get_agent_script())
        self._script.on('message', on_message)

        self._update_status('Loading script...')
        self._script.load()
        self._update_status('Loaded script')
        api = self._script.exports
        api.socket_trace()
        api.log_ssl_keys()
        try:
            api.log_aes_info()
        except Exception:
            pass
        api.log_ad_ids()
        api.no_root()
        self._update_status('Loaded script')
        self._resume()
        time.sleep(1)

    def _usage(self):
        return ''

    def save_data(self):
        self.capture_manager.stop_capture()

    def _on_message(self, message, data):
        if message['type'] == 'send':
            if message.get('payload'):
                self.capture_manager.capture_data(message.get('payload'))
                return
