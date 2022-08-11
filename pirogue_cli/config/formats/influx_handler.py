from parsers.ini_parser import IniParser


class InfluxHandler(IniParser):

    def __init__(self, file_path, delimiter='=', comment_prefix='#', preserve_value=None, mappings=None):
        super().__init__(file_path, delimiter, comment_prefix, preserve_value)
        self.mappings = mappings

    def _set_admin_password(self):
        print(self.mappings.get('influxdb>password'))

    def write(self, overrides=None):
        with open(self.file_path, 'w') as configuration_file:
            self.data.write(configuration_file)

