import argparse
import logging

from rich.console import Console
from rich.logging import RichHandler

LOG_FORMAT = '[%(name)s] %(message)s'
logging.basicConfig(level='INFO', format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format='%X')])
console = Console()


def __install_frida():
    from pirogue_cli.android.device import AndroidDevice
    device = AndroidDevice()
    device.install_latest_frida_server()


def __start_frida():
    from pirogue_cli.android.device import AndroidDevice
    device = AndroidDevice()
    device.start_frida_server()


def __stop_frida():
    from pirogue_cli.android.device import AndroidDevice
    device = AndroidDevice()
    device.stop_frida_server()


def main():
    arg_parser = argparse.ArgumentParser(prog='pirogue', description='PiRogue CLI')
    subparsers = arg_parser.add_subparsers(dest='func')
    # Status
    status_group = subparsers.add_parser('status', help='Get PiRogue status')
    # Android
    android_group = subparsers.add_parser('android', help='Interact with a connected Android device')
    android_group.add_argument('action', type=str, help='Interact with Android device connected to the PiRogue',
                               nargs='?',
                               choices=['install-frida', 'start-frida', 'stop-frida'])
    # Config
    config_group = subparsers.add_parser('config', help='Manage PiRogue configuration')
    config_subparsers = config_group.add_subparsers(dest='config_func')

    show_group = config_subparsers.add_parser('show', help='Show configuration')
    edit_group = config_subparsers.add_parser('edit', help='Edit the current configuration file')
    apply_group = config_subparsers.add_parser('apply', help='Apply configuration')
    backups_group = config_subparsers.add_parser('backups', help='Show configuration backups')
    revert_group = config_subparsers.add_parser('restore', help='Restore configuration from a previous version')

    apply_group.add_argument('--no_prompt', help='Apply the configuration without asking for confirmation', action='store_true', default=True)
    show_group.add_argument('--raw', help='Show configuration in format that can be sourced', action='store_true', default=False)

    args = arg_parser.parse_args()
    if not args.func:
        arg_parser.print_help()
        return

    if args.func == 'status':
        from pirogue_cli.status.status_panel import print_pirogue_status
        print_pirogue_status()
    elif args.func == 'config':
        from pirogue_cli.config.config_manager import show_current_configuration, show_backups, revert_backup, apply, edit_config
        if args.config_func == 'apply':
            apply(prompt=args.no_prompt)
        elif args.config_func == 'show':
            show_current_configuration(raw=args.raw)
        elif args.config_func == 'backups':
            show_backups()
        elif args.config_func == 'restore':
            revert_backup()
        elif args.config_func == 'edit':
            edit_config()
    elif args.func == 'android':
        android_route = {
            'install-frida': __install_frida,
            'start-frida': __start_frida,
            'stop-frida': __stop_frida,
        }
        android_route.get(args.action, __install_frida)()


if __name__ == '__main__':
    main()
