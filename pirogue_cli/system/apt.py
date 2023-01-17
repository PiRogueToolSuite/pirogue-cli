import logging
import subprocess
import shutil
from typing import List

from rich.console import Console
from rich.table import Table

log = logging.getLogger(__name__)


def get_install_packages(pattern: str) -> List[dict]:
    if shutil.which('dpkg-query') is None:
        # Not running on Raspbian/Ubuntu/Debian
        return []

    cmd = 'dpkg-query --showformat=\'${Status}\t${Package}\t${Version}\t${Homepage}\n\' -W "%s"' % pattern
    packages = []
    try:
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
        for line in output.splitlines():
            status, package, version, homepage = line.split('\t')
            if 'ok installed' in status or 'install ok half-configured' in status:
                packages.append({
                    'installed': '[green]:heavy_check_mark:[/green]',
                    'package': package,
                    'version': version,
                })
        return packages
    except Exception as e:
        log.error(e)
        return []


def print_packages(console: Console, title: str, pattern: str):
    table = Table()
    table.add_column('Installed', justify='center')
    table.add_column('Package')
    table.add_column('Version')
    for p in get_install_packages(pattern):
        table.add_row(*p.values())
    console.print(table)

