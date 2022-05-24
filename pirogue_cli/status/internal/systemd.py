from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from pydbus import SystemBus


@dataclass
class Unit:
    unit: str
    description: str
    load: str
    active: str
    running: str

    @property
    def is_running(self):
        return self.running == 'running' or self.running == 'waiting'


class Systemd:

    def __init__(self):
        bus = SystemBus()
        self.systemd = bus.get(".systemd1")

    def get_units_by_name(self, unit_name) -> List[Unit]:
        units = []
        for unit, description, load, active, running, *_ in self.systemd.ListUnitsByPatterns([], [unit_name]):
            u = Unit(unit, description, load, active, running)
            units.append(u)
        return units

    def get_unit_by_name(self, unit_name) -> Optional[Unit]:
        units = self.get_units_by_name(unit_name)
        if len(units) == 1:
            return units[0]
        return None
