import logging
import lzma

import requests


FRIDA_SERVER_LATEST_RELEASE_URL = 'https://api.github.com/repos/frida/frida/releases/latest'
FRIDA_SERVER_RELEASES_URL = 'https://api.github.com/repos/frida/frida/releases?per_page=30'
log = logging.getLogger(__name__)


class FridaServer:
    @staticmethod
    def download_frida_server(arch: str, output_file, platform: str, client_version: str):
        found = False
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
                        found = True
                        log.info(f'⚡ Downloading {asset_name}...')
                        xz_file = requests.get(asset['browser_download_url'])
                        log.info(f'⚡ Extracting {asset_name}...')
                        server_binary = lzma.decompress(xz_file.content)
                        log.info(f'⚡ Writing {asset_name} to {output_file}...')
                        with open(output_file, mode='wb') as out:
                            out.write(server_binary)
                            out.flush()
                        return
        if not found:
            log.error(f'Unable to find frida-server version {client_version} in GitHub releases. Please install it by hand at /data/local/tmp/frydaxx-server and make it executable using chmod +x.')
            raise Exception(f'Unable to find frida-server version {client_version} in GitHub releases.')