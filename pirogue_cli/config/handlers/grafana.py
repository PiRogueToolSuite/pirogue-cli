import subprocess

import pkg_resources
from pirogue_cli.system.apt import get_install_packages

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class GrafanaConfigurationHandler:
    backup_file_name = None
    configuration_file = None
    preserved_values = []
    post_configuration_commands = [
    ]
    template_file = None
    backup_suffix = None
    target_package = 'grafana'
    service_name = 'Grafana'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup

    def is_applicable(self):
        return bool(get_install_packages(self.target_package))

    def revert(self):
        pass

    def apply_configuration(self):
        # Apply configuration
        grafana_password = self.backup.settings.get('DASHBOARD_PASSWORD')
        command = f'grafana-cli admin reset-admin-password {grafana_password}'
        subprocess.check_call(command, shell=True)
        print('!! Grafana configuration cannot be reverted !!')
