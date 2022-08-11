import os
from dataclasses import dataclass
from typing import Optional

import netifaces


@dataclass
class Interface:
    name: str
    type: str
    ip_v4: str
    ip_v6: str
    netmask_v4: str
    netmask_v6: str


class NetworkSetup:
    @staticmethod
    def get_default_gateway_interface() -> Optional[Interface]:
        gateways = netifaces.gateways()
        try:
            _, iface = gateways['default'][netifaces.AF_INET]
            return NetworkSetup.get_interface(iface)
        except Exception:
            raise Exception('No default gateway found')

    @staticmethod
    def list_interfaces():
        ifaces = []
        for iface in netifaces.interfaces():
            try:
                ifaces.append(NetworkSetup.get_interface(iface))
            except Exception:
                pass
        return ifaces

    @staticmethod
    def get_interface(iface):
        try:
            ip_v4 = ''
            ip_v6 = ''
            netmask_v4 = ''
            netmask_v6 = ''
            if netifaces.AF_INET in netifaces.ifaddresses(iface):
                addrs_inet = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
                ip_v4 = addrs_inet.get('addr')
                netmask_v4 = addrs_inet.get('netmask')
            if netifaces.AF_INET6 in netifaces.ifaddresses(iface):
                addrs_inet = netifaces.ifaddresses(iface)[netifaces.AF_INET6][0]
                ip_v6 = addrs_inet.get('addr')
                netmask_v6 = addrs_inet.get('netmask')

            return Interface(
                name=iface,
                type=NetworkSetup.get_interface_type(iface),
                ip_v4=ip_v4,
                netmask_v4=netmask_v4,
                ip_v6=ip_v6,
                netmask_v6=netmask_v6,
            )
        except Exception:
            raise Exception(f'Interface {iface} not found')

    @staticmethod
    def get_interface_type(iface):
        if iface.startswith('e') and NetworkSetup.get_sys_type(iface) == 1:
            return 'ethernet'
        elif iface.startswith('w') and NetworkSetup.get_sys_type(iface) == 1:
            return 'wireless'
        elif iface.startswith('br-') and NetworkSetup.get_sys_type(iface) == 1:
            return 'bridge'
        elif iface.startswith('virbr') and NetworkSetup.get_sys_type(iface) == 1:
            return 'virtual bridge'
        elif iface.startswith('docker') and NetworkSetup.get_sys_type(iface) == 1:
            return 'docker'
        elif NetworkSetup.get_sys_type(iface) == 772:
            return 'loopback'
        elif NetworkSetup.get_sys_type(iface) == 65534:
            return 'wireguard'
        return f'unknown [{NetworkSetup.get_sys_type(iface)}]'

    @staticmethod
    def get_sys_type(iface):
        sys_file = f'/sys/class/net/{iface}/type'
        if not os.path.exists(sys_file):
            raise Exception(f'Interface {iface} not found')
        with open(sys_file, mode='r') as iface_type_file:
            return int(iface_type_file.read().strip())

    @staticmethod
    def get_ethernet_interfaces():
        eth_ifaces = []
        for iface in NetworkSetup.list_interfaces():
            if iface.type == 'ethernet':
                eth_ifaces.append(iface)
        return eth_ifaces

    @staticmethod
    def get_wireless_interfaces():
        wireless_ifaces = []
        for iface in NetworkSetup.list_interfaces():
            if iface.type == 'wireless':
                wireless_ifaces.append(iface)
        return wireless_ifaces


if __name__ == '__main__':
    for iface in NetworkSetup.list_interfaces():
        print(iface)
    print(NetworkSetup.get_default_gateway_interface())
