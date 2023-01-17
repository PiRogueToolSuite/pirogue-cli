import logging
import os
import signal
import subprocess
import time
from typing import Optional

log = logging.getLogger(__name__)


class TcpDump:
    __slots__ = (
        'interface',
        'capture_cmd',
        'pcap_file_name',
        'output_dir',
        'process',
        'has_user_provided_cmd'
    )

    def __init__(self, interface: str, output_dir: str, pcap_file_name: str, capture_cmd: Optional[str]):
        if capture_cmd:
            self.capture_cmd = capture_cmd
            self.has_user_provided_cmd = True
        else:
            self.interface = interface
            self.capture_cmd = f'tcpdump -U -w - -i {self.interface}'
            self.has_user_provided_cmd = False
        self.pcap_file_name = pcap_file_name
        if not self.pcap_file_name.endswith('.pcap'):
            self.pcap_file_name += '.pcap'
        self.output_dir = output_dir
        self.process = None

    @staticmethod
    def __check_user_rights():
        try:
            subprocess.check_call(
                'tcpdump -c 1',
                timeout=1,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError:
            raise Exception("""You do not have the permission to dump network traffic. Re-run with sudo.\n
                Or, run the following command to grant your user the right to capture network traffic:\n
                sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump""")
        except Exception:
            pass

    def start_capture(self):
        log.info(f'⚡ Starting network interception...')
        if not self.has_user_provided_cmd:
            TcpDump.__check_user_rights()
        try:
            self.process = subprocess.Popen(
                self.capture_cmd,
                shell=True,
                stdout=open(f'{self.output_dir}/{self.pcap_file_name}', 'w'),
                stderr=subprocess.PIPE,
            )
        except Exception as e:
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
