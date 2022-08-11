import os.path
import time
from typing import List, Optional, Tuple

from rich.console import Console

from pirogue_cli.status.internal.systemd import Systemd, Unit
from pirogue_cli.system.apt import print_packages

suricata_rule_file = '/var/lib/suricata/rules/suricata.rules'
support = 'Find support at https://piroguetoolsuite.github.io/'


def check_suricata_rules() -> Tuple[bool, Optional[str], int]:
    try:
        last_update = time.ctime(os.path.getmtime(suricata_rule_file))
        size = os.path.getsize(suricata_rule_file)
        return True, last_update, size
    except:
        return False, None, 0


def print_suricata_status(console: Console):
    exists, last_update, size = check_suricata_rules()
    console.print('[bold]:gear: PiRogue Suricata rules[/bold]')
    if not exists:
        console.print(
            f'\t:red_circle: Suricata rules file located at {suricata_rule_file} does not exist. {support}')
    if exists and size < 1:
        console.print(
            f'\t:red_circle: Suricata rules file located at {suricata_rule_file} is empty. {support}')
    if exists and size > 10:
        console.print(f'\t:green_circle: Suricata rules file has been updated on {last_update}')


def print_services_status(console: Console, title: str, units: List[str]):
    systemd = Systemd()
    console.print(f'[bold]:gear: {title}[/bold]')
    for unit_name in units:
        unit = systemd.get_unit_by_name(unit_name)
        if not unit:
            console.print(f'\t:red_circle: the service {unit_name} was not found, ')
        elif not unit.is_running:
            console.print(f'\t:red_circle: {unit.unit} is not running. {support}')
        else:
            console.print(f'\t:green_circle: {unit.unit} is running properly')


def print_pirogue_db_status(console: Console):
    units = [
        'influxdb.service',
    ]
    print_services_status(console, 'PiRogue database', units)


def print_full_status(console: Console):
    print_packages(console, 'PiRogue packages', 'pirogue*')
    print_services_status(console, 'PiRogue dashboard', ['influxdb.service', 'grafana-server.service'])
    print_services_status(console, 'PiRogue network', ['hostapd.service', 'dnsmasq.service', 'dhcpcd.service'])
    print_services_status(console, 'PiRogue DPI', ['pirogue-flow-inspector.service', 'pirogue-flow-inspector@*.service'])  # ToDo switch to pirogue-flow-inspector@iface
    print_services_status(console, 'PiRogue screen', ['pirogue-screen-st7789-240x240.service'])
    print_services_status(console, 'PiRogue maintenance', ['pirogue-maintenance.timer'])
    print_services_status(console, 'PiRogue Suricata', ['suricata.service', 'pirogue-eve-collector.service'])
    print_suricata_status(console)
