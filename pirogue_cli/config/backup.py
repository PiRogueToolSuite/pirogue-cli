import logging
import os
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from pirogue_cli.config.formats.kv_pair import KeyValuePairParser
from pirogue_cli.config.handlers.dhcpcd import DhcpcdConfigurationHandler
from pirogue_cli.config.handlers.dnsmasq import DnsmasqConfigurationHandler
from pirogue_cli.config.handlers.flow_inspector import FlowInspectorConfigurationHandler
from pirogue_cli.config.handlers.grafana import GrafanaConfigurationHandler
from pirogue_cli.config.handlers.hostapd import HostapdConfigurationHandler
from pirogue_cli.config.handlers.iptables import IptablesConfigurationHandler
from pirogue_cli.config.handlers.suricata import SuricataConfigurationHandler

LOG_FORMAT = '[%(name)s] %(message)s'
logging.basicConfig(level='INFO', format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format='%X')])
console = Console()
log = logging.getLogger(__name__)


class ConfigurationFromBackup:

    def __init__(self, backup_path: str):
        self.settings: Optional[dict] = None
        self.path = backup_path
        self.id = int(os.path.basename(backup_path).replace('.current', ''))
        self.creation_date = datetime.fromtimestamp(self.id/(1000*1000))
        self.is_currently_applied = '.current' in backup_path
        self.configuration_file_path = f'{backup_path}/pirogue.env'
        self.configuration_parser = KeyValuePairParser(self.configuration_file_path)
        self.read()
        self.configuration_handlers = [
            DhcpcdConfigurationHandler(self),
            GrafanaConfigurationHandler(self),
            DnsmasqConfigurationHandler(self),
            HostapdConfigurationHandler(self),
            SuricataConfigurationHandler(self),
            IptablesConfigurationHandler(self),
            FlowInspectorConfigurationHandler(self),
            #  etc.
        ]

    def read(self):
        # log.info(f'Reading configuration from file {self.configuration_file_path}')
        self.settings = self.configuration_parser.read()

    def show(self):
        for k, v in self.settings.items():
            print(f'{k}={v}')

    def apply(self):
        applied = []
        for handler in self.configuration_handlers:
            try:
                log.info(f'Applying configuration to {handler.service_name}.')
                applied.append(handler)
                handler.apply_configuration()
                log.info(f'Configuration successfully applied to {handler.service_name}.')
            except Exception as e:
                log.error(f'An error occurred during {handler.service_name} configuration.')
                log.error(e)
                log.error(f'Reverting ...')
                for r_handler in applied:
                    r_handler.revert()
                if self.is_currently_applied:
                    # Delete the .current prefix
                    os.rename(self.path, self.path.replace('.current', ''))
                    self.is_currently_applied = False
                return
