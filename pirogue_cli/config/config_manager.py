import sys

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.prompt import Prompt
from rich.table import Table

from pirogue_cli.config.config import Configuration

prefix = ''


def __make_config_panel(configuration: dict):
    config_table = Table.grid(padding=(0, 2))
    config_table.add_column(style="medium_purple1", justify="right")
    config_table.add_column(no_wrap=True)
    for k, v in configuration.items():
        config_table.add_row(
            k,
            v,
        )
    return Align.center(
        Align.center(config_table),
        vertical="middle",
    )


def show_configurations(console):
    new_configuration = Configuration(prefix=prefix)
    new_configuration.read()
    current_configuration = new_configuration.get_currently_applied_configuration()
    new_configuration_panel = Panel(__make_config_panel(new_configuration.settings),
                                        border_style="green",
                                        title='Configuration to be applied')
    if current_configuration:
        current_configuration_panel = Panel(__make_config_panel(current_configuration.settings),
                                            border_style="medium_purple1",
                                            title='Configuration currently applied')
    else:
        current_configuration_panel = Panel('[red]No configuration currently applied',
                                            border_style="medium_purple1",
                                            title='Configuration currently applied')
    columns = Columns([new_configuration_panel, current_configuration_panel], padding=1)
    console.print(columns)
    return new_configuration


def show_current_configuration(raw=False):
    new_configuration = Configuration(prefix=prefix)
    new_configuration.read()
    current_configuration = new_configuration.get_currently_applied_configuration()
    if raw:
        if current_configuration:
            current_configuration.show()
            sys.exit(0)
        else:
            print()
            sys.exit(1)
    else:
        console = Console()
        if current_configuration:
            current_configuration_panel = Panel(__make_config_panel(current_configuration.settings),
                                                border_style="medium_purple1",
                                                title='Configuration currently applied')
        else:
            current_configuration_panel = Panel('[red]No configuration currently applied',
                                                border_style="medium_purple1",
                                                title='Configuration currently applied')
        console.print(Columns([current_configuration_panel]))
        return new_configuration


def has_currently_applied_configuration():
    new_configuration = Configuration(prefix=prefix)
    new_configuration.read()
    current_configuration = new_configuration.get_currently_applied_configuration()
    if current_configuration is None:
        return -1
    else:
        return 0


def show_backups():
    new_configuration = Configuration(prefix=prefix)
    new_configuration.read()
    backups = new_configuration.list_backups()
    backup_table = Table.grid(padding=(0, 2))
    backup_table.add_column(style="medium_purple1", justify="right")
    backup_table.add_column(no_wrap=True)
    for backup in backups:
        if backup.is_currently_applied:
            backup_table.add_row(
                f'[white bold]>> [/white bold]{backup.id}',
                backup.path,
            )
        else:
            backup_table.add_row(
                f'{backup.id}',
                backup.path,
            )
        backup_table.add_row(
            '',
            f'Currently applied: {backup.is_currently_applied}',
        )
        backup_table.add_row(
            '',
            f'Created on: {backup.creation_date}',
        )
    message_panel = Panel(
        Align.center(backup_table),
        box=box.ROUNDED,
        padding=(1, 2),
        title="List of configuration backups",
        border_style="medium_purple1",
    )
    console = Console()
    console.print(message_panel)
    return new_configuration


def revert_backup():
    new_configuration = show_backups()
    backup_id = Prompt.ask('Enter the backup ID (i.e. 1659977118376167)')
    new_configuration.restore(backup_id)


def apply(prompt=False):
    console = Console()
    new_configuration = show_configurations(console)
    status = new_configuration.status()
    is_dirty = status.get('is_dirty')
    if not is_dirty:
        console.print('[green]There is no changes to be applied :)[/green]')
    if prompt and is_dirty:
        confirm = Confirm.ask('Apply the new configuration?', default=False)
        if confirm:
            new_configuration.apply()
            # print('new_configuration.apply()')
    elif not prompt and is_dirty:
        new_configuration.apply()
        # print('new_configuration.apply()')
