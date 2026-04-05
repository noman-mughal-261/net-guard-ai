from __future__ import annotations

import platform
import subprocess
from typing import Tuple


def apply_iptables_drop(ip: str) -> Tuple[bool, str]:
    system = platform.system().lower()
    if system != "linux":
        return (
            False,
            f"iptables blocking skipped on {system}; record stored only. Deploy backend on Linux EC2 for OS-level drop.",
        )
    try:
        r = subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if r.returncode != 0:
            return False, (r.stderr or r.stdout or "iptables failed").strip()
        return True, "iptables DROP rule appended"
    except FileNotFoundError:
        return False, "iptables/sudo not available"
    except Exception as e:
        return False, str(e)
