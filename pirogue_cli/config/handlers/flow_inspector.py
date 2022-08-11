import subprocess

import pkg_resources

from pirogue_cli.status import Systemd

PWD = pkg_resources.resource_filename('pirogue_cli', 'config-files')


class FlowInspectorConfigurationHandler:
    backup_file_name = 'flow-inspector.conf'
    configuration_file = None
    preserved_values = []
    post_configuration_commands = [
    ]
    template_file = None
    backup_suffix = '.old'
    service_name = 'PiRogue flow inspector'
    systemd_unit_name = 'pirogue-flow-inspector@*.service'
    systemd_unit_name_pattern = lambda x: f'pirogue-flow-inspector@{x}.service'

    def __init__(self, backup: 'ConfigurationFromBackup'):
        self.backup: 'ConfigurationFromBackup' = backup
        self.systemd = Systemd()

    def revert(self):
        previous_unit = open(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', mode='r').read().strip()
        current_unit = self.systemd.get_unit_by_name(self.systemd_unit_name)
        if current_unit and current_unit != previous_unit:
            self.__systemd_switch_to(current_unit, previous_unit)

    def __systemd_switch_to(self, old_unit, new_unit):
        command = f'systemctl enable --now {new_unit}'
        subprocess.check_call(command, shell=True)
        command = f'systemctl disable {old_unit}'
        subprocess.check_call(command, shell=True)
        command = f'systemctl stop {old_unit}'
        subprocess.check_call(command, shell=True)

    def apply_configuration(self):
        # Backup current configuration file
        old_unit = self.systemd.get_unit_by_name(self.systemd_unit_name)
        if old_unit:
            with open(f'{self.backup.path}/{self.backup_file_name}{self.backup_suffix}', mode='w') as backup_file:
                backup_file.write(old_unit.unit)
        wlan = self.backup.settings.get('WLAN_IFACE')
        new_unit_name = f'pirogue-flow-inspector@{wlan}.service'
        if new_unit_name != old_unit.unit:
            # Apply configuration
            self.__systemd_switch_to(old_unit.unit, new_unit_name)
