import subprocess


class Commander:
    def __init__(self, mappings, service_name):
        self.changes = []
        self.data = {}
        self.service_name = service_name
        self.mappings = mappings
        self.dirty = True

    def set_key(self, key, value):
        if value and key in self.mappings.values():
            key_to_change = None
            for k, v in self.mappings.items():
                if v == key:
                    key_to_change = k
            if key_to_change:
                old_value = 'unavailable'
                self.data[key_to_change] = value
                self.changes.append((old_value, value))

    def get_data(self):
        return self.data

    def dry_run(self):
        print(f'Modifications to be applied for {self.service_name}:')
        for k, v in self.data.items():
            command = self.mappings.get(k)(v)
            print(f'  {command}')

    def write(self, overrides=None):
        for k, v in self.data.items():
            command = self.mappings.get(k)(v)
            if command:
                # print(f'>>> {command}')
                subprocess.check_call(command, shell=True)


if __name__ == '__main__':
    mappings = {
        'dashboard-password': lambda passwd: f'grafana-cli admin reset-admin-password {passwd}',
    }
    kv = Commander(mappings, 'Toto')
    kv.set_key('dashboard-password', 'PiRogue34')
    kv.set_key('wifi-password', 'PiRogue34')
    kv.dry_run()
    kv.write()
