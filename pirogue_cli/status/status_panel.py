from datetime import datetime

import psutil
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

from pirogue_cli.config.config import Configuration
from pirogue_cli.config.config_manager import __make_config_panel
from pirogue_cli.status import Systemd, check_suricata_rules, suricata_rule_file
from pirogue_cli.system.apt import get_install_packages


def make_layout() -> Layout:
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main"),
    )
    layout["main"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1)
    )
    return layout


def make_current_configuration_panel():
    new_configuration = Configuration()
    new_configuration.read()
    current_configuration = new_configuration.get_currently_applied_configuration()
    current_configuration_panel = None
    if current_configuration:
        current_configuration_panel = Panel(__make_config_panel(current_configuration.settings),
                                            border_style="medium_purple1",
                                            title_align='left',
                                            title='Configuration currently applied')
    else:
        current_configuration_panel = Panel('[red]No configuration currently applied',
                                            border_style="medium_purple1",
                                            title_align='left',
                                            title='Configuration currently applied')
    return current_configuration_panel


def make_packages_panel():
    table = Table.grid(padding=(0, 2))
    table.add_column('Installed', justify='center')
    table.add_column('Package')
    table.add_column('Version')
    for p in get_install_packages('pirogue*'):
        table.add_row(*p.values())
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title_align='left',
        title="PiRogue system packages",
        border_style="medium_purple1",
    )
    return panel


def get_service_status(unit_name: str):
    systemd = Systemd()
    unit = systemd.get_unit_by_name(unit_name)
    if not unit:
        return f'[red]{unit_name} was not found[/red]'
    elif not unit.is_running:
        return f'[red]{unit.unit} is not running[/red]'
    else:
        return f'[green]{unit.unit} is running properly[/green]'


def make_ap_panel() -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="medium_purple1", justify="right")
    table.add_column(style="white", justify="left")
    table.add_row(
        'Access point manager', get_service_status('hostapd.service')
    )
    table.add_row(
        'DHCP server', get_service_status('dnsmasq.service')
    )
    table.add_row(
        'DHCP client', get_service_status('dhcpcd.service')
    )
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title_align='left',
        title="Access point",
        border_style="medium_purple1",
    )
    return panel


def get_suricata_rules_status():
    exists, last_update, size = check_suricata_rules()
    if not exists:
        return f'[red]Suricata rules file located at {suricata_rule_file} does not exist[/red]'
    if exists and size < 1:
        return f'[red]Suricata rules file located at {suricata_rule_file} is empty[/red]'
    if exists and size > 10:
        return f'[green]Suricata rules file has been updated on {last_update}[/green]'


def make_net_panel() -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="medium_purple1", justify="right")
    table.add_column(style="white", justify="left")
    table.add_row(
        'Flow inspector (DPI)', get_service_status('pirogue-flow-inspector@*.service')
    )
    table.add_row(
        'Alarm collector', get_service_status('pirogue-eve-collector.service')
    )
    table.add_row(
        'Suricata', get_service_status('suricata.service')
    )
    table.add_row(
        'Detection rules', get_suricata_rules_status()
    )
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title_align='left',
        title="Network traffic analysis",
        border_style="medium_purple1",
    )
    return panel


def make_dashboard_panel() -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="medium_purple1", justify="right")
    table.add_column(style="white", justify="left")
    table.add_row(
        'Database', get_service_status('influxdb.service')
    )
    table.add_row(
        'Dashboard', get_service_status('grafana-server.service')
    )
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title="Network traffic dashboard",
        title_align='left',
        border_style="medium_purple1",
    )
    return panel


def make_maintenance_panel() -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="medium_purple1", justify="right")
    table.add_column(style="white", justify="left")
    table.add_row(
        'Daily maintenance', get_service_status('pirogue-maintenance.timer')
    )
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title="PiRogue maintenance",
        title_align='left',
        border_style="medium_purple1",
    )
    return panel


def make_system_status_panel() -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="medium_purple1", justify="right")
    table.add_column(style="white", justify="left")
    ram_usage = psutil.virtual_memory()
    ram_percent = ram_usage[2]
    disk_usage = psutil.disk_usage('/')
    disk_percent = disk_usage[3]
    table.add_row(
        'RAM usage',
        f'{ram_percent}%',
    )
    table.add_row(
        'Disk usage',
        f'{disk_percent}%',
    )
    panel = Panel(
        table,
        box=box.ROUNDED,
        padding=(1, 2),
        title_align='left',
        title="System",
        border_style="medium_purple1",
    )
    return panel


class Header:
    def __rich__(self) -> Panel:
        grid = Table.grid(expand=True)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right")
        grid.add_row(
            "PiRogue status",
            datetime.now().ctime().replace(":", "[blink]:[/]"),
        )
        return Panel(grid, style="white on medium_purple3")


def print_pirogue_status():
    right_grid = Table.grid(expand=True)
    right_grid.add_column()
    right_grid.add_row(make_system_status_panel())
    right_grid.add_row(make_current_configuration_panel())
    right_grid.add_row(make_packages_panel())
    left_grid = Table.grid(expand=True)
    left_grid.add_column()
    left_grid.add_row(make_ap_panel())
    left_grid.add_row(make_net_panel())
    left_grid.add_row(make_dashboard_panel())
    left_grid.add_row(make_maintenance_panel())
    console = Console()
    layout = make_layout()
    layout["header"].update(Header())
    layout["right"].update(right_grid)
    layout["left"].update(left_grid)
    console.print(layout)

