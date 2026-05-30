"""
filter.py - Protocol-level packet filtering.

OSI context:
  Layer 3 (Network)    : IP presence check
  Layer 4 (Transport)  : TCP / UDP discrimination
  Layer 7 (Application): HTTP identification (TCP on port 80/8080/8000)
"""

_VALID_FILTERS = {'all', 'tcp', 'udp', 'http', 'dns'}


class PacketFilter:
    """
    Decides whether a parsed packet dict passes the active protocol filter.

    Usage:
        f = PacketFilter('tcp')
        if f.matches(packet_info):
            ...
    """

    def __init__(self, protocol: str = 'all'):
        protocol = protocol.lower()
        if protocol not in _VALID_FILTERS:
            raise ValueError(f'Unknown filter "{protocol}". Choose from: {_VALID_FILTERS}')
        self.protocol = protocol

    def matches(self, packet_info: dict) -> bool:
        """Return True if packet_info passes the active filter."""
        # Drop non-IP packets in every mode (no Layer-3 header to display).
        if packet_info['src_ip'] is None:
            return False

        if self.protocol == 'all':
            return True

        proto = packet_info['protocol'].lower()

        if self.protocol == 'tcp':
            # HTTP is TCP at layer 4, so include it when the user wants TCP.
            return proto in ('tcp', 'http')

        if self.protocol == 'http':
            return proto == 'http'

        if self.protocol == 'udp':
            # DNS is UDP at layer 4, so include it when the user wants UDP.
            return proto in ('udp', 'dns')

        if self.protocol == 'dns':
            return proto == 'dns'

        return False
