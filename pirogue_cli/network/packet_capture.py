import logging
import os
import signal
import subprocess
import time

log = logging.getLogger(__name__)


class TcpDump:
    __slots__ = (
        'interface',
        'capture_cmd',
        'pcap_file_name',
        'output_dir',
        'process'
    )

    def __init__(self, interface: str, output_dir: str, pcap_file_name: str):
        self.interface = interface
        self.pcap_file_name = pcap_file_name
        if not self.pcap_file_name.endswith('.pcap'):
            self.pcap_file_name += '.pcap'
        self.output_dir = output_dir
        self.process = None
        self.capture_cmd = f'tcpdump -U -i {self.interface} -w {output_dir}/{pcap_file_name}'

    def start_capture(self):
        log.info(f'⚡ Starting network interception...')
        try:
            self.process = subprocess.Popen(
                self.capture_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
        except Exception as e:
            print(e)
            self.stop_capture()
            raise e

    def stop_capture(self):
        log.info(f'⚡ Stopping network interception...')
        try:
            self.process.send_signal(signal.SIGINT)
            time.sleep(1)
            os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            self.process.kill()
        except:
            pass
