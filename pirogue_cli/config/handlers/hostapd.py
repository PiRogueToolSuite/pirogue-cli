import shutil
import subprocess
import os
import pkg_resources
import semver

from pirogue_cli.config.formats.kv_pair import KeyValuePairParser
from pirogue_cli.config.formats.template import Template
from pirogue_cli.system.apt import get_install_packages

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

    target_package = 'pirogue-ap'
    minimum_package_version = '1.0.2'
    package_config_file_template = '/usr/share/pirogue/ap/hostapd.conf'
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
            self.parser = KeyValuePairParser(self.configuration_file)

    def is_applicable(self):
        return os.path.isfile(self.configuration_file) and os.path.isfile(self.package_config_file_template)

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
            self.parser.set_key('interface', self.backup.settings.get('WLAN_IFACE'))
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
