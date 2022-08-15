import shutil
import subprocess

import pkg_resources
import semver

from pirogue_cli.config.formats.template import Template
from pirogue_cli.config.formats.yaml import YamlParser
from pirogue_cli.system.apt import get_install_packages

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

    target_package = 'pirogue-eve-collector'
    minimum_package_version = '1.0.5'
    package_config_file_template = '/usr/share/pirogue/suricata/suricata.yaml'
    reconfigure_package = False

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup

        # Check if pirogue specific package is installed
        package_info = get_install_packages(self.target_package)
        package_version = '0.0.1'
        if package_info and len(package_info) == 1:
            package_info = package_info[0]
            package_version = package_info.get('version')

        # If the package version is greater or equal than the minimum one
        if semver.compare(package_version, self.minimum_package_version) > -1:
            self.reconfigure_package = True
            self.parser = Template(self.package_config_file_template)
        # Else modify the service configuration file inplace
        else:
            self.parser = YamlParser(self.configuration_file, preserve_value=self.preserved_value)

    def revert(self):
        shutil.copy(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', self.configuration_file)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name}', ignore_errors=True)
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        shutil.copy(self.configuration_file, f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}')
        if self.reconfigure_package:
            # Generate new configuration file in the backup directory
            self.parser.generate(f'{self.backup.path}/{self.backup_file_name}', self.backup.settings)
            # Generate new configuration file on FS
            self.parser.generate(f'{self.configuration_file}', self.backup.settings)
        else:
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
