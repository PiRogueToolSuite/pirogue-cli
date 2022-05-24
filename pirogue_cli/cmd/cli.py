import argparse
import logging

from rich.console import Console
from rich.logging import RichHandler

LOG_FORMAT = "[%(name)s] %(message)s"
logging.basicConfig(level="INFO", format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format="%X")])
console = Console()


def __install_frida():
    from pirogue_cli.android.device import AndroidDevice
    device = AndroidDevice()
    device.install_latest_frida_server()


def main():
    arg_parser = argparse.ArgumentParser(prog="pirogue", description="PiRogue CLI")
    subparsers = arg_parser.add_subparsers(dest="func")

    status_group = subparsers.add_parser("status", help="Get PiRogue status")

    android_group = subparsers.add_parser("android", help="Interact with connected Android device")
    android_group.add_argument("action", type=str, help="", nargs="?",
                               choices="install-frida")

    args = arg_parser.parse_args()
    if not args.func:
        arg_parser.print_help()

    if args.func == 'status':
        from pirogue_cli.status import print_full_status
        print_full_status(console)
    elif args.func == 'android':
        android_route = {
            "install-frida": __install_frida
        }
        android_route.get(args.action, __install_frida)()


if __name__ == '__main__':
    console = Console()
    main()
