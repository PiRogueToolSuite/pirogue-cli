import shutil
import subprocess
import os

import pkg_resources
import semver

from pirogue_cli.config.formats.template import Template
from pirogue_cli.system.apt import get_install_packages

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class NftablesConfigurationHandler:
    backup_file_name = 'nftables-pirogue.conf'
    template_file = f'{PWD}/iptables_rules'
    configuration_file = '/etc/nftables-pirogue.conf'
    preserved_values = []
    post_configuration_commands = [
        'systemctl restart nftables.service',
    ]
    backup_suffix = '.old'
    service_name = 'nftables'

    target_package = 'pirogue-ap'
    minimum_package_version = '1.1.0'
    package_config_file_template = '/usr/share/pirogue/ap/nftables-pirogue.conf'
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
            # Migrate to new way to manage configuration
            migrated = self.__migrate(self.configuration_file, self.template_file)
            if not migrated and not migrated_v6:
                # Apply changes
                config_lines = self.__get_generated_configuration_lines()
                self.__generate_rule_file(f'{self.configuration_file}', f'{self.backup.path}/{self.backup_file_name}', config_lines)
                self.__generate_rule_file(f'{self.configuration_file}', f'{self.configuration_file}', config_lines)

        # Restart the service
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    @staticmethod
    def __generate_line(line: str, config: dict):
        for k, v in config.items():
            if k in line:
                line = line.replace(k, v)
        return line

    @staticmethod
    def __get_line_id(line):
        if 'PTS[' in line and '] MANAGED' in line:
            return int(line[line.find('PTS[') + 4:line.find('] MANAGED')])
        return -1

    def __get_generated_configuration_lines(self):
        configuration_lines = {}
        with open(self.template_file) as template:
            for line in template.readlines():
                line_id = NftablesConfigurationHandler.__get_line_id(line)
                if line_id > -1:
                    new_line = NftablesConfigurationHandler.__generate_line(line, self.backup.settings)
                    configuration_lines[line_id] = new_line
        return configuration_lines

    def __generate_rule_file(self, source: str, destination: str, configuration_lines: dict):
        original_lines = open(source, mode='r').readlines()
        with open(destination, mode='w') as output:
            for line in original_lines:
                line_id = NftablesConfigurationHandler.__get_line_id(line)
                if line_id > -1:
                    output.write(configuration_lines.get(line_id))
                else:
                    output.write(line)

    def __migrate(self, config_file, template_file):
        require_migration = False
        with open(config_file, mode='r') as config:
            if '] MANAGED' not in config.read():
                require_migration = True
        if require_migration:
            generator = Template(template_file)
            generator.generate(config_file, self.backup.settings)
        return require_migration
