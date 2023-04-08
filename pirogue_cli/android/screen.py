import logging
import time

from pirogue_cli.android.device import AndroidDevice

log = logging.getLogger(__name__)


class ScreenRecorder:
    device_path = '/data/local/tmp/screen.mp4'
    def __init__(self, device: AndroidDevice, output_dir) -> None:
        self.device: AndroidDevice = device
        self.output_dir = output_dir
        self.process = None

    def start_recording(self):
        log.info('⚡ Starting screen recording...')
        capture_cmd = f'screenrecord --bugreport --size 1280x720 --bit-rate 2000000 {self.device_path}'
        # capture_cmd = f'scrcpy -t --max-size=1024 --max-fps=15 --bit-rate=2M --record={self.output_dir}/screen.mp4 -N -n'
        try:
            self.device.adb_shell_no_wait(capture_cmd)
        except Exception as e:
            self.stop_recording()
            raise e

    def stop_recording(self):
        log.info(f'⚡ Stopping screen recording...')
        try:
            self.device.adb_shell('pkill -SIGINT screenrecord')
        except Exception as e:
            log.error(e)
        time.sleep(1)
        try:
            log.info(f'⚡ Retrieving the screencast from the device...')
            self.device.adb_pull(self.device_path, f'{self.output_dir}/screen.mp4')
        except Exception as e:
            log.error(e)
        try:
            self.device.adb_shell(f'rm -f {self.device_path}')
        except:
            pass
