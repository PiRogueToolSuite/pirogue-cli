import glob
import json
import logging
import os

import pkg_resources

from pirogue_cli.android.device import AndroidDevice
from pirogue_cli.config.config import Configuration
from pirogue_cli.network.packet_capture import TcpDump

PWD = pkg_resources.resource_filename('pirogue_cli', 'frida-scripts')
log = logging.getLogger(__name__)


class CaptureManager:
    def __init__(self, output_dir, iface=None):
        self.output_dir = output_dir
        self._output_files = {}
        self.tcp_dump = None
        self.device = None
        self._js_script = None
        default_iface = 'wlan0'
        try:
            configuration = Configuration()
            self.current_configuration = configuration.get_currently_applied_configuration()
            default_iface = self.current_configuration.settings.get('WLAN_IFACE')
        except:
            log.warning('Could not load configuration - skipping.')
            self.current_configuration = None
        if iface:
            self.iface = iface
        else:
            self.iface = default_iface

    def start_capture(self, capture_cmd=None):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.tcp_dump = TcpDump(
            interface=self.iface,
            output_dir=self.output_dir,
            pcap_file_name='traffic.pcap',
            capture_cmd=capture_cmd
        )
        self.device = AndroidDevice()
        self.device.start_frida_server()
        self.tcp_dump.start_capture()

    def get_agent_script(self, extra_scripts_dir=None):
        if self._js_script:
            return self._js_script

        js_files = glob.glob(f'{PWD}/*.js', recursive=True)
        if extra_scripts_dir:
            js_files.extend(glob.glob(f'{extra_scripts_dir}/*.js', recursive=True))

        self._js_script = ''
        for js_file in js_files:
            with open(js_file, mode='r') as f:
                self._js_script += f.read()

        return self._js_script

    def capture_data(self, data):
        output_file = data.get('dump')
        if output_file not in self._output_files:
            self._output_files[output_file] = []
        self._output_files[output_file].append(data)

    def save_data_files(self):
        log.info('Saving data captured by Frida')
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

    def stop_capture(self):
        self.save_data_files()
        self.device.stop_frida_server()
        self.tcp_dump.stop_capture()
