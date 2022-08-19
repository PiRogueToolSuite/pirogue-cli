import glob
import json
import logging
import os
import time

import pkg_resources
from frida_tools.application import ConsoleApplication

from pirogue_cli.android.device import AndroidDevice
from pirogue_cli.config.config import Configuration
from pirogue_cli.network.packet_capture import TcpDump

PWD = pkg_resources.resource_filename('pirogue_cli', 'frida-scripts')
log = logging.getLogger(__name__)


class FridaApplication(ConsoleApplication):
    SESSION_ID_LENGTH = 32
    MASTER_KEY_LENGTH = 48

    def __init__(self):

        super(FridaApplication, self).__init__()

    def _add_options(self, parser):
        configuration = Configuration()
        current_configuration = configuration.get_currently_applied_configuration()
        default_iface = 'wlan0'
        if current_configuration:
            default_iface = current_configuration.settings.get('WLAN_IFACE')
        parser.add_argument('-o', '--output', help='The output directory')
        parser.add_argument('-i', '--iface', help='The network interface to capture', default=default_iface)

    def _initialize(self, parser, options, args):
        if not os.path.exists(options.output):
            os.makedirs(options.output)
        self.output_dir = options.output
        self._output_files = {}
        self.iface = options.iface
        self.tcp_dump = TcpDump(
            interface=self.iface,
            output_dir=self.output_dir,
            pcap_file_name='traffic.pcap'
        )
        self.device = AndroidDevice()
        self.device.start_frida_server()
        self.tcp_dump.start_capture()
        # time.sleep(1)

    def _usage(self):
        return 'usage: %%prog [options] target'

    def _needs_target(self):
        return True

    @staticmethod
    def _agent():
        js_files = glob.glob(f'{PWD}/*.js', recursive=True)
        js_script = ''
        for js_file in js_files:
            with open(js_file, mode='r') as f:
                js_script += f.read()
        return js_script

    def _start(self):
        self._output_files = {}
        self._update_status('Attached')

        def on_message(message, data):
            self._reactor.schedule(lambda: self._on_message(message, data))

        self._session_cache = set()

        self._script = self._session.create_script(self._agent())
        self._script.on('message', on_message)

        self._update_status('Loading script...')
        self._script.load()
        self._update_status('Loaded script')
        api = self._script.exports
        api.log_ssl_keys()
        api.log_aes_info()
        self._update_status('Loaded script')
        self._resume()
        time.sleep(1)

    def save_data(self):
        for filename, elt in self._output_files.items():
            if len(elt) == 0:
                continue
            data_type = elt[0].get('data_type')
            with open(f'{self.output_dir}/{filename}', mode='w') as out:
                if data_type == 'json':
                    json.dump(elt, out, indent=2)
                else:
                    for record in elt:
                        data = record.get('data')
                        out.write(f'{data}\n')

    def _acc_data(self, data):
        output_file = data.get('dump')
        if output_file not in self._output_files:
            self._output_files[output_file] = []
        self._output_files[output_file].append(data)

    def _on_message(self, message, data):
        if message['type'] == 'send':
            if message.get('payload'):
                self._acc_data(message.get('payload'))
                return
