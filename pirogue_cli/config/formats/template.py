class Template:
    def __init__(self, template_file: str):
        self.template_file = template_file
        self.dirty = False

    def generate(self, destination: str, context: dict):
        self.dirty = True
        with open(self.template_file, mode='r') as template:
            with open(destination, mode='w') as output:
                for line in template.readlines():
                    for k, v in context.items():
                        if k in line:
                            line = line.replace(k, v)
                    output.write(line)

