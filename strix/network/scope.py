"""Scope enforcement for network assessment.

Network results are only ever analysed for hosts the user explicitly put in
scope (IP, CIDR range, or the host of a URL target). Anything else found in
tool output is dropped and reported, never assessed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


MAX_RANGE_ADDRESSES = 256

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class NetworkScope:
    networks: list[IpNetwork] = field(default_factory=list)
    hostnames: set[str] = field(default_factory=set)

    @classmethod
    def from_targets(cls, targets_info: list[dict[str, Any]]) -> NetworkScope:
        scope = cls()
        for target in targets_info or []:
            details = target.get("details") or {}
            kind = target.get("type")
            if kind == "ip_address" and details.get("target_ip"):
                scope._add_host(str(details["target_ip"]))
            elif kind == "ip_range" and details.get("target_cidr"):
                scope._add_network(str(details["target_cidr"]))
            elif kind == "web_application" and details.get("target_url"):
                host = urlsplit(str(details["target_url"])).hostname
                if host:
                    scope._add_host(host)
            elif kind == "api_spec":
                for base in details.get("base_urls") or []:
                    host = urlsplit(str(base)).hostname
                    if host:
                        scope._add_host(host)
        return scope

    def _add_host(self, host: str) -> None:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            self.hostnames.add(host.lower())
        else:
            self.networks.append(ipaddress.ip_network(ip))

    def _add_network(self, cidr: str) -> None:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > MAX_RANGE_ADDRESSES:
            raise ValueError(
                f"{cidr} spans {network.num_addresses} addresses; the limit is "
                f"{MAX_RANGE_ADDRESSES} (/24 for IPv4)"
            )
        self.networks.append(network)

    def __bool__(self) -> bool:
        return bool(self.networks or self.hostnames)

    def contains(self, host: str | None, ip: str | None = None) -> bool:
        """True if the hostname or the resolved IP is in scope."""
        if host and host.lower() in self.hostnames:
            return True
        for candidate in (ip, host):
            if not candidate:
                continue
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if any(address in network for network in self.networks):
                return True
        return False
