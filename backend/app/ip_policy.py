from __future__ import annotations

import ipaddress

from .config import get_settings


def parse_ip(ip: str):
    return ipaddress.ip_address(ip.strip())


def is_blocked_target(ip: str) -> tuple[bool, str]:
    s = get_settings()
    raw = ip.strip()
    if raw in s["whitelist_ips"]:
        return False, "IP is whitelisted"
    try:
        addr = parse_ip(raw)
    except ValueError:
        return False, "Invalid IP address"
    if addr.is_loopback:
        return False, "Loopback addresses cannot be blocked"
    if addr.is_private or addr.is_link_local or addr.is_reserved:
        if not s["allow_block_private"]:
            return False, "Private/link-local/reserved IPs are blocked by policy"
    return True, "ok"
