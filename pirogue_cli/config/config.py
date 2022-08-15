import logging
import os
import time
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from pirogue_cli.config.backup import ConfigurationFromBackup
from pirogue_cli.config.formats.kv_pair import KeyValuePairParser
from pirogue_cli.config.network import NetworkSetup

LOG_FORMAT = '[%(name)s] %(message)s'
logging.basicConfig(level='INFO', format=LOG_FORMAT, handlers=[
    RichHandler(show_path=False, log_time_format='%X')])
console = Console()
log = logging.getLogger(__name__)


class Configuration:
    ALLOWED_KEYWORDS = {
        'WIFI_NETWORK_NAME': {
            'description': '',
        },
        'WIFI_NETWORK_KEY': {
            'description': '',
        },
        'WIFI_COUNTRY_CODE': {
            'description': '',
        },
        'WLAN_IFACE': {
            'description': '',
        },
        'ETH_IFACE': {
            'description': '',
        },
        'DASHBOARD_PASSWORD': {
            'description': '',
        },
    }

    def __init__(self, prefix=''):
        self.settings: Optional[dict] = None
        self.id = int(time.time_ns() / 1000)
        self.configuration_folder_path = f'{prefix}/var/lib/pirogue/config'
        self.configuration_backup_path = f'{prefix}/var/lib/pirogue/config/backups'
        self.configuration_file_path = f'{self.configuration_folder_path}/pirogue.env'
        self.configuration_parser = KeyValuePairParser(self.configuration_file_path)
        self.init()

    def read(self):
        self.settings = self.configuration_parser.read()

    def apply(self):
        if not self.validate():
            return
        configuration_to_be_applied = self.backup(set_current=True)
        configuration_to_be_applied.apply()

    def restore(self, backup_id=0):
        backup_id = int(backup_id)
        found = False
        backups = self.list_backups()
        for backup in backups:
            if backup_id == backup.id:
                found = True
                backup.apply()
                break
        if not found:
            log.error(f'Configuration backup {backup_id} not found.')

    def init(self):
        if not self.exists():
            Configuration.__create_folder(self.configuration_folder_path)
            Configuration.__create_folder(self.configuration_backup_path)
            self.__generate_defaults()

    def exists(self):
        return os.path.isfile(self.configuration_file_path) and os.path.isdir(self.configuration_backup_path)

    def backup(self, set_current=False) -> ConfigurationFromBackup:
        current_backup_folder = f'{self.configuration_backup_path}/{self.id}'
        if set_current:
            current_backup_folder = f'{current_backup_folder}.current'
            for backup_folder in Configuration.__list_folders(self.configuration_backup_path):
                if '.current' in backup_folder:
                    os.rename(backup_folder, backup_folder.replace('.current', ''))
        Configuration.__create_folder(current_backup_folder)
        self.configuration_parser.write_to(f'{current_backup_folder}/pirogue.env')
        return ConfigurationFromBackup(current_backup_folder)

    def list_backups(self):
        backups = []
        for backup_folder in Configuration.__list_folders(self.configuration_backup_path):
            backups.append(ConfigurationFromBackup(backup_folder))
        return backups

    def status(self):
        current_configuration = self.get_currently_applied_configuration()
        status = {
            'is_dirty': False,
            'identical_entry_values': [],
            'different_entry_values': [],
            'new_entries': [],
            'missing_entries': [],
        }
        if current_configuration:
            for n_k, n_v in self.settings.items():
                if n_k in current_configuration.settings:
                    c_v = current_configuration.settings.get(n_k)
                    if n_v == c_v:
                        status['identical_entry_values'].append({
                            'entry': n_k,
                            'old_value': c_v,
                            'new_value': n_v,
                        })
                    else:
                        status['different_entry_values'].append({
                            'entry': n_k,
                            'old_value': c_v,
                            'new_value': n_v,
                        })
                        status['is_dirty'] = True
                else:
                    status['new_entries'].append({
                        'entry': n_k,
                        'old_value': '',
                        'new_value': n_v,
                    })
                    status['is_dirty'] = True
            for c_k, c_v in current_configuration.settings.items():
                if c_k not in self.settings:
                    status['missing_entries'].append({
                        'entry': c_k,
                        'old_value': c_v,
                        'new_value': '',
                    })
                    status['is_dirty'] = True
        else:
            status['is_dirty'] = True
        return status

    def get_currently_applied_configuration(self):
        for backup in self.list_backups():
            if backup.is_currently_applied:
                return backup
        return None

    @staticmethod
    def __list_folders(path):
        folders = []
        for f in os.listdir(path):
            tmp_path = os.path.join(path, f)
            if os.path.isdir(tmp_path):
                folders.append(tmp_path)
        return folders

    def __generate_defaults(self):
        # Gets the default gateway
        default_gateway_interface_name = 'eth0'
        default_gateway = NetworkSetup.get_default_gateway_interface()
        if default_gateway:
            default_gateway_interface_name = default_gateway.name
        # Gets the wireless interface
        preferred_wireless_interface_name = 'wlan0'
        wireless_interfaces = NetworkSetup.get_wireless_interfaces()
        if wireless_interfaces:
            preferred_wireless_interface_name = wireless_interfaces[0].name
        config = {
            'WIFI_NETWORK_NAME': 'PiRogue1',
            'WIFI_NETWORK_KEY': 'superlongkey',
            'WIFI_COUNTRY_CODE': 'FR',
            'WLAN_IFACE': preferred_wireless_interface_name,
            'ETH_IFACE': default_gateway_interface_name,
            'DASHBOARD_PASSWORD': 'PiRogue',
        }
        self.configuration_parser.set_from_dict(config)
        self.configuration_parser.write()

    def show(self):
        for k, v in self.settings.items():
            print(f'{k}={v}')

    def validate(self):
        is_valid = True
        if not self.settings:
            self.read()
        for k, v in self.settings.items():
            if k not in Configuration.ALLOWED_KEYWORDS:
                log.error(f'Unsupported option found: "{k}"')
                is_valid = False
            if not v:
                log.error(f'Empty value for the option "{k}" found. Either set a value or remove the option.')
                is_valid = False
        return is_valid

    @staticmethod
    def __create_folder(folder_path):
        os.makedirs(folder_path, exist_ok=True)


if __name__ == '__main__':
    c = Configuration(prefix='.')
    c.init()
    c.read()
    c.validate()
    c.show()
    c.list_backups()
    c.backup(set_current=True)
    for b in c.list_backups():
        b.show()
