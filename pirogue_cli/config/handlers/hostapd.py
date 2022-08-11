import shutil
import subprocess

import pkg_resources

from pirogue_cli.config.formats.kv_pair import KeyValuePairParser

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class HostapdConfigurationHandler:
    backup_file_name = 'hostapd.conf'
    configuration_file = '/etc/hostapd/hostapd.conf'
    preserved_values = []
    post_configuration_commands = [
        'systemctl restart hostapd.service'
    ]
    backup_suffix = '.old'
    service_name = 'hostapd'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup
        self.parser = KeyValuePairParser(self.configuration_file)

    def revert(self):
        shutil.copy(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', self.configuration_file)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name}', ignore_errors=True)
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        shutil.copy(self.configuration_file, f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}')
        # Apply changes
        self.parser.set_key('interface', self.backup.settings.get('WLAN_INTERFACE'))
        self.parser.set_key('country_code', self.backup.settings.get('WIFI_COUNTRY_CODE'))
        self.parser.set_key('ssid', self.backup.settings.get('WIFI_NETWORK_NAME'))
        self.parser.set_key('wpa_passphrase', self.backup.settings.get('WIFI_NETWORK_KEY'))
        # Generate new configuration file in the backup directory
        self.parser.write_to(f'{self.backup.path}/{self.backup_file_name}')
        # Generate new configuration file on FS
        self.parser.write()
        # Restart the service
        if self.parser.dirty:
            for command in self.post_configuration_commands:
                subprocess.check_call(command, shell=True)
