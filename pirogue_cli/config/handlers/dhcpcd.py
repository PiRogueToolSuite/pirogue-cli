import shutil
import subprocess

import pkg_resources

from pirogue_cli.config.formats.template import Template

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class DhcpcdConfigurationHandler:
    backup_file_name = 'dhcpcd.conf'
    configuration_file = '/etc/dhcpcd.conf'
    preserved_values = []
    post_configuration_commands = [
        'systemctl restart dhcpcd.service'
    ]
    template_file = f'{PWD}/dhcpcd.conf'
    backup_suffix = '.old'
    service_name = 'dhcpcd'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup
        self.parser = Template(self.template_file)

    def revert(self):
        shutil.copy(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', self.configuration_file)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name}', ignore_errors=True)
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        shutil.copy(self.configuration_file, f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}')
        # Generate new configuration file in the backup directory
        self.parser.generate(f'{self.backup.path}/{self.backup_file_name}', self.backup.settings)
        # Generate new configuration file on FS
        self.parser.generate(f'{self.configuration_file}', self.backup.settings)
        # Restart the service
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)
