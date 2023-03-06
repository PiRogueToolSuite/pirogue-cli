import logging
import lzma

import requests


FRIDA_SERVER_LATEST_RELEASE_URL = 'https://api.github.com/repos/frida/frida/releases/latest'
FRIDA_SERVER_RELEASES_URL = 'https://api.github.com/repos/frida/frida/releases'
log = logging.getLogger(__name__)


class FridaServer:
    @staticmethod
    def download_frida_server(arch: str, output_file, platform: str, client_version: str):
        if not arch:
            log.error(f'Unable to determine device ABI, please install Frida server manually at {output_file}')
            return 
        releases = requests.get(FRIDA_SERVER_RELEASES_URL).json()
        for release in releases:
            tag_name = release.get('tag_name')
            if tag_name == client_version:
                for asset in release.get('assets'):
                    asset_name = asset.get('name')
                    if 'server' in asset_name and f'{platform}-{arch}.xz' in asset_name:
                        log.info(f'⚡ Downloading {asset_name}...')
                        xz_file = requests.get(asset['browser_download_url'])
                        log.info(f'⚡ Extracting {asset_name}...')
                        server_binary = lzma.decompress(xz_file.content)
                        log.info(f'⚡ Writing {asset_name} to {output_file}...')
                        with open(output_file, mode='wb') as out:
                            out.write(server_binary)
                            out.flush()
                        return
