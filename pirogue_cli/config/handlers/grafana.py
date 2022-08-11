import subprocess

import pkg_resources

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class GrafanaConfigurationHandler:
    backup_file_name = None
    configuration_file = None
    preserved_values = []
    post_configuration_commands = [
    ]
    template_file = None
    backup_suffix = None
    service_name = 'Grafana'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup

    def revert(self):
        pass

    def apply_configuration(self):
        # Apply configuration
        grafana_password = self.backup.settings.get('DASHBOARD_PASSWORD')
        command = f'grafana-cli admin reset-admin-password {grafana_password}'
        subprocess.check_call(command, shell=True)
        print('!! Grafana configuration cannot be reverted !!')
