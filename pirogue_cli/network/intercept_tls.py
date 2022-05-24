import logging

from rich.console import Console
from rich.logging import RichHandler

from pirogue_cli.android.device import AndroidDevice
from pirogue_cli.frida.application import FridaApplication

LOG_FORMAT = '[%(name)s] %(message)s'
logging.basicConfig(level='INFO', format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format='%X')])
console = Console()


def start_interception():
    device = AndroidDevice()
    device.start_frida_server()
    app = FridaApplication()
    try:
        app.run()
    except KeyboardInterrupt as k:
        # Have to handle something?
        pass
    finally:
        app.save_data()
        app.tcp_dump.stop_capture()
        device.stop_frida_server()
