import os.path
from configparser import ConfigParser


class IniParser:
    def __init__(self, file_path, delimiter='=', comment_prefix='#', preserve_value=None):
        self.file_path = file_path
        self.delimiter = delimiter
        self.comment_prefix = comment_prefix
        self.preserve_value = preserve_value
        self.data = ConfigParser()
        self.changes = []
        if os.path.exists(file_path):
            self.read()

    def read(self):
        self.data.read(self.file_path)

    def get_data(self):
        if not self.data.sections():
            self.read()

        tmp = {}
        for s, e in self.data.items():
            for k, v in e.items():
                tmp[f'{s}>{k}'] = v
        return tmp

    def set_key(self, attributes, value):
        section = attributes.split('>')[0]
        key = attributes.split('>')[1]
        if value:
            if section not in self.data:
                self.data[section] = {}
            old_value = self.data.get(section, key, fallback=None)
            if old_value != self.preserve_value or self.preserve_value is None:
                self.data[section][key] = value
                self.changes.append((old_value, value))

    def dry_run(self):
        print(f'Modifications to be applied in {self.file_path}:')
        for old, new in self.changes:
            print(f'  {old} -> {new}')

    def write(self, overrides=None):
        with open(self.file_path, 'w') as configuration_file:
            self.data.write(configuration_file)


if __name__ == '__main__':
    fp = '../config-files/pirogue.conf'
    kv = IniParser(fp)
    kv.read()
    print(kv.get_data())
    # kv.set_key(('security', 'admin_password'), 'PiRogue34')
    kv.dry_run()
    kv.write()
