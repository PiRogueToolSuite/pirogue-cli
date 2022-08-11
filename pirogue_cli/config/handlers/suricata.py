import shutil
import subprocess

import pkg_resources

from pirogue_cli.config.formats.yaml import YamlParser

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class SuricataConfigurationHandler:
    backup_file_name = 'suricata.yaml'
    configuration_file = '/etc/suricata/suricata.yaml'
    preserved_value = 'default'
    post_configuration_commands = [
        'systemctl restart suricata.service'
    ]
    backup_suffix = '.old'
    service_name = 'suricata'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup
        self.parser = YamlParser(self.configuration_file, preserve_value=self.preserved_value)

    def revert(self):
        shutil.copy(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', self.configuration_file)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name}', ignore_errors=True)
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        shutil.copy(self.configuration_file, f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}')
        # Apply changes
        self.parser.set_key(('af-packet', 'interface'), self.backup.settings.get('WLAN_INTERFACE'))
        # Generate new configuration file in the backup directory
        self.parser.write_to(f'{self.backup.path}/{self.backup_file_name}')
        # Generate new configuration file on FS
        self.parser.write()
        # Restart the service
        if self.parser.dirty:
            for command in self.post_configuration_commands:
                subprocess.check_call(command, shell=True)
