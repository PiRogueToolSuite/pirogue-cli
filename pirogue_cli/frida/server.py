import logging
import lzma

import requests


FRIDA_SERVER_LATEST_RELEASE_URL = 'https://api.github.com/repos/frida/frida/releases/latest'
log = logging.getLogger(__name__)


class FridaServer:
    @staticmethod
    def download_frida_server(arch: str, output_file, platform: str):
        latest_release = requests.get(FRIDA_SERVER_LATEST_RELEASE_URL).json()
        for asset in latest_release['assets']:
            release_name = asset['name']
            if 'server' in release_name and f'{platform}-{arch}.xz' in release_name:
                log.info(f'⚡ Downloading {release_name}...')
                xz_file = requests.get(asset['browser_download_url'])
                log.info(f'⚡ Extracting {release_name}...')
                server_binary = lzma.decompress(xz_file.content)
                log.info(f'⚡ Writing {release_name} to {output_file}...')
                with open(output_file, mode='wb') as out:
                    out.write(server_binary)
                    out.flush()
                return


