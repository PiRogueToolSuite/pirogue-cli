import os.path
import time
from typing import Optional, Tuple

from pirogue_cli.status.internal.systemd import Systemd, Unit

suricata_rule_file = '/var/lib/suricata/rules/suricata.rules'
support = 'Find support at https://piroguetoolsuite.github.io/'


def check_suricata_rules() -> Tuple[bool, Optional[str], int]:
    try:
        last_update = time.ctime(os.path.getmtime(suricata_rule_file))
        size = os.path.getsize(suricata_rule_file)
        return True, last_update, size
    except:
        return False, None, 0
