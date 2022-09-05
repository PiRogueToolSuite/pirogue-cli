import logging

from rich.console import Console
from rich.logging import RichHandler

from pirogue_cli.frida.application import FridaApplication

LOG_FORMAT = '[%(name)s] %(message)s'
logging.basicConfig(level='INFO', format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format='%X')])
console = Console()
log = logging.getLogger(__name__)


def start_interception():
    app = None
    try:
        app = FridaApplication()
        app.run()
    except KeyboardInterrupt as k:
        # Have to handle something?
        pass
    except Exception as e:
        log.error(e)
    finally:
        if app:
            app.save_data()
            app.tcp_dump.stop_capture()
            app.device.stop_frida_server()


if __name__ == '__main__':
    start_interception()
    