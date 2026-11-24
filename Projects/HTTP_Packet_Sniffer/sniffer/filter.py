from dataclasses import dataclass, field
from typing import Optional, Set
from sniffer.http_parser import HTTPRequest


@dataclass
class RequestFilter:
    """
    Phase 4: Request Filtering by HTTP method, source IP, destination IP, or any IP.
    """

    methods: Set[str] = field(default_factory=set)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    any_ip: Optional[str] = None

    def __post_init__(self):
        self.methods = {m.strip().upper() for m in self.methods if m and m.strip()}
        if self.src_ip:
            self.src_ip = self.src_ip.strip()
        if self.dst_ip:
            self.dst_ip = self.dst_ip.strip()
        if self.any_ip:
            self.any_ip = self.any_ip.strip()

    @property
    def is_active(self) -> bool:
        return bool(self.methods or self.src_ip or self.dst_ip or self.any_ip)

    def matches(self, req: HTTPRequest) -> bool:
        """
        Returns True if the HTTPRequest matches all configured active filter criteria.
        """
        if self.methods and req.method.upper() not in self.methods:
            return False

        if self.src_ip and req.src_ip != self.src_ip:
            return False

        if self.dst_ip and req.dst_ip != self.dst_ip:
            return False

        if self.any_ip and (req.src_ip != self.any_ip and req.dst_ip != self.any_ip):
            return False

        return True

    def summary(self) -> str:
        """
        Returns a human-readable summary of the active filters for the console banner.
        """
        if not self.is_active:
            return "NONE (Showing all HTTP requests)"

        parts = []
        if self.methods:
            parts.append(f"Methods={','.join(sorted(self.methods))}")
        if self.src_ip:
            parts.append(f"SrcIP={self.src_ip}")
        if self.dst_ip:
            parts.append(f"DstIP={self.dst_ip}")
        if self.any_ip:
            parts.append(f"AnyIP={self.any_ip}")
        return " | ".join(parts)
