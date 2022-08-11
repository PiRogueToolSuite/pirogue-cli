import shutil
import subprocess

import pkg_resources

from pirogue_cli.config.formats.template import Template

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class IptablesConfigurationHandler:
    backup_file_name_v4 = 'rules.v4'
    backup_file_name_v6 = 'rules.v6'
    template_file = f'{PWD}/iptables_rules'
    configuration_file_v4 = '/etc/iptables/rules.v4'
    configuration_file_v6 = '/etc/iptables/rules.v6'
    preserved_values = []
    post_configuration_commands = [
        f'iptables-restore < {configuration_file_v4}',
        f'ip6tables-restore < {configuration_file_v6}',
    ]
    backup_suffix = '.old'
    service_name = 'iptables'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup

    def revert(self):
        shutil.copy(f'{self.backup.path}/{self.backup_file_name_v4}{self.backup_suffix}', self.configuration_file_v4)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name_v4}', ignore_errors=True)
        shutil.copy(f'{self.backup.path}/{self.backup_file_name_v6}{self.backup_suffix}', self.configuration_file_v6)
        shutil.rmtree(f'{self.backup.path}/{self.backup_file_name_v6}', ignore_errors=True)
        for command in self.post_configuration_commands:
            subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        shutil.copy(self.configuration_file_v4, f'{self.backup.path}/{self.backup_file_name_v4}{self.backup_suffix}')
        shutil.copy(self.configuration_file_v6, f'{self.backup.path}/{self.backup_file_name_v6}{self.backup_suffix}')

        # Migrate to new way to manage configuration
        migrated_v4 = self.__migrate(self.configuration_file_v4, self.template_file)
        migrated_v6 = self.__migrate(self.configuration_file_v6, self.template_file)
        if not migrated_v4 and not migrated_v6:
            # Apply changes
            config_lines = self.__get_generated_configuration_lines()
            self.__generate_rule_file(f'{self.configuration_file_v4}', f'{self.backup.path}/{self.backup_file_name_v4}', config_lines)
            self.__generate_rule_file(f'{self.configuration_file_v6}', f'{self.backup.path}/{self.backup_file_name_v6}', config_lines)
            self.__generate_rule_file(f'{self.configuration_file_v4}', f'{self.configuration_file_v4}', config_lines)
            self.__generate_rule_file(f'{self.configuration_file_v6}', f'{self.configuration_file_v6}', config_lines)

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
                line_id = IptablesConfigurationHandler.__get_line_id(line)
                if line_id > -1:
                    new_line = IptablesConfigurationHandler.__generate_line(line, self.backup.settings)
                    configuration_lines[line_id] = new_line
        return configuration_lines

    def __generate_rule_file(self, source: str, destination: str, configuration_lines: dict):
        original_lines = open(source, mode='r').readlines()
        with open(destination, mode='w') as output:
            for line in original_lines:
                line_id = IptablesConfigurationHandler.__get_line_id(line)
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
