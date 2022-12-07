import argparse
import threading

import frida

from pirogue_cli.frida.capture_manager import CaptureManager


def on_spawned(spawn):
    print('on_spawned:', spawn)
    FridaApplication.pending.append(spawn)
    FridaApplication.event.set()


def on_message(capture_manager, spawn, message):
    if message['type'] == 'send':
        data = message.get('payload')
        print('.')
        if data:
            if data.get('data_type') == 'json':
                data['pid'] = spawn.pid
                data['process'] = spawn.identifier
            capture_manager.capture_data(data)


class FridaApplication:
    pending = []
    sessions = []
    scripts = []
    event = threading.Event()

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '--capture-command',
            help=(
                'Specify directly a capture command instead of building it from interface. '
                'Useful for remote capture over SSH. Example: '
                'ssh root@openwrt "tcpdump -U -n -w - -i wlan0 \'host PHONE_IP\'"'
            )
        )
        parser.add_argument('-o', '--output', help='The output directory')
        parser.add_argument('-i', '--iface', help='The network interface to capture', default=None)
        self.options = parser.parse_args()

        self.capture_manager = CaptureManager(self.options.output, self.options.iface)

    def save_data(self):
        self.capture_manager.stop_capture()

    def run(self):
        self.capture_manager.start_capture(capture_cmd=self.options.capture_command)

        self._device = frida.get_usb_device()
        self._device.on('spawn-added', on_spawned)
        self._device.enable_spawn_gating()
        FridaApplication.event = threading.Event()

        print('Enabled spawn gating')
        print('Pending:', self._device.enumerate_pending_spawn())
        for spawn in self._device.enumerate_pending_spawn():
            print('Resuming:', spawn)
            self._device.resume(spawn.pid)
        while True:
            while len(FridaApplication.pending) == 0:
                print('Waiting for data')
                FridaApplication.event.wait()
                FridaApplication.event.clear()
            spawn = FridaApplication.pending.pop()
            if spawn.identifier:
                print('Instrumenting:', spawn)
                session = self._device.attach(spawn.pid)
                script = session.create_script(self.capture_manager.get_agent_script())
                script.on('message', lambda message: on_message(self.capture_manager, spawn, message))
                script.load()
                api = script.exports
                api.socket_trace()
                api.log_ssl_keys()
                api.log_aes_info()
                FridaApplication.sessions.append(session)
                FridaApplication.scripts.append(script)
            else:
                print('Not instrumenting:', spawn)
            self._device.resume(spawn.pid)
            print('Processed:', spawn)


if __name__ == '__main__':
    app = FridaApplication()
    app.run()
