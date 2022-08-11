import os

import yaml


class YamlParser:
    def __init__(self, file_path, delimiter='=', comment_prefix='#', preserve_value=None):
        self.file_path = file_path
        self.delimiter = delimiter
        self.comment_prefix = comment_prefix
        self.preserve_value = preserve_value
        self.data = {}
        self.dirty = False
        self.changes = []
        if os.path.exists(file_path):
            self.read()

    def read(self):
        with open(self.file_path, mode='r', encoding='utf-8') as config_file:
            self.data = yaml.safe_load(config_file)

    def get_data(self):
        if not self.data:
            self.read()
        return self.data

    def set_key(self, attributes, value):
        parents, key = attributes
        if not value:
            return
        keys = parents.split('.')
        child = self.data
        found = True
        while keys and found:
            found = False
            k = keys.pop(0)
            if isinstance(child, dict):
                child = child[k]
                found = True
            elif isinstance(child, list):
                for c in child:
                    if isinstance(c, dict) and k in c:
                        child = c[k]
                        found = True
        if not found:
            print('Entry not found')
            return
        if isinstance(child, dict):
            old_value = child[key]
            if old_value != self.preserve_value or self.preserve_value is None:
                if old_value != value:
                    self.dirty = True
                    child[key] = value
                    self.changes.append((old_value, value))
        elif isinstance(child, list):
            for entry in child:
                if key in entry and isinstance(entry, dict):
                    old_value = entry[key]
                    if old_value != self.preserve_value or self.preserve_value is None:
                        if old_value != value:
                            self.dirty = True
                            entry[key] = value
                            self.changes.append((old_value, value))

    def get_key(self, attributes):
        parents, key = attributes
        keys = parents.split('.')
        child = self.data
        found = True
        while keys and found:
            found = False
            k = keys.pop(0)
            if isinstance(child, dict):
                child = child[k]
                found = True
            elif isinstance(child, list):
                for c in child:
                    if isinstance(c, dict) and k in c:
                        child = c[k]
                        found = True
        if not found:
            print('Entry not found')
            return
        if isinstance(child, dict):
            old_value = child[key]
            if old_value != self.preserve_value or self.preserve_value is None:
                return child[key]
        elif isinstance(child, list):
            for entry in child:
                if key in entry and isinstance(entry, dict):
                    old_value = entry[key]
                    if old_value != self.preserve_value or self.preserve_value is None:
                        return entry[key]

    def dry_run(self):
        print(f'Modifications to be applied in {self.file_path}:')
        if self.dirty:
            for old, new in self.changes:
                print(f'  {old} -> {new}')
        else:
            print('  no modification to apply')

    def write(self, overrides=None):
        if self.dirty:
            with open(self.file_path, mode='w') as config_file:
                yaml.dump(self.data, config_file, version=(1, 1), explicit_start=True)

    def write_to(self, output):
        with open(output, mode='w') as config_file:
            yaml.dump(self.data, config_file, version=(1, 1), explicit_start=True)


if __name__ == '__main__':
    import json

    fp = '../config-files/suricata.yaml'
    kv = YamlParser(fp, preserve_value='default')
    kv.read()
    # print(json.dumps(kv.get_data(), indent=2, sort_keys=True))
    kv.set_key(('af-packet', 'interface'), 'wlan0')
    print(json.dumps(kv.get_data(), indent=2, sort_keys=True))
    # print(kv.get_data())
    kv.dry_run()
    kv.write()
