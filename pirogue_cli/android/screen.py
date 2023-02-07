import logging
import os
import time
import signal
import subprocess


log = logging.getLogger(__name__)


class ScreenRecorder:
    def __init__(self, output_dir) -> None:
        self.output_dir = output_dir
        self.process = None

    def start_recording(self):
        log.info(f'⚡ Starting screen recording...')
        capture_cmd = f'scrcpy -t --max-size=1024 --max-fps=15 --bit-rate=2M --record={self.output_dir}/screen.mp4 -N'
        try:
            self.process = subprocess.Popen(
                capture_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except Exception as e:
            self.stop_recording()
            raise e

    def stop_recording(self):
        log.info(f'⚡ Stopping screen recording...')
        try:
            self.process.send_signal(signal.SIGINT)
            time.sleep(1)
            os.killpg(os.getpgid(self.process.pid), signal.SIGINT)
            self.process.kill()
        except:
            pass