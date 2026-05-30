"""
capture.py - Raw packet parsing across OSI layers 2-7.

OSI layer map:
  Layer 2 (Data Link)  : Ethernet frame — scapy Ether
  Layer 3 (Network)    : IP header      — scapy IP
  Layer 4 (Transport)  : TCP/UDP header — scapy TCP / UDP
  Layer 7 (Application): HTTP payload, DNS queries/responses — scapy Raw / DNS
"""

from datetime import datetime
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR

_HTTP_SIGNATURES = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
                    b'OPTIONS ', b'PATCH ', b'HTTP/')

# Maps single-character scapy flag codes to readable names.
_TCP_FLAG_NAMES = {
    'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST',
    'P': 'PSH', 'U': 'URG', 'E': 'ECE', 'C': 'CWR',
}


def _format_flags(flags) -> str:
    """Convert scapy FlagValue to a bracketed string, e.g. '[SYN, ACK]'."""
    names = [_TCP_FLAG_NAMES[f] for f in str(flags) if f in _TCP_FLAG_NAMES]
    return '[' + ', '.join(names) + ']' if names else ''


def _extract_dns_answer(dns) -> str:
    """Walk the DNS answer chain and return the first A-record IP, or ''."""
    rr = dns.an
    while rr and hasattr(rr, 'rrname'):
        if hasattr(rr, 'type') and rr.type == 1 and hasattr(rr, 'rdata'):
            return str(rr.rdata)
        rr = rr.payload if hasattr(rr, 'payload') else None
    return ''


def parse_packet(packet) -> dict:
    """
    Extract structured information from a raw scapy packet.

    Returns a dict with keys:
        timestamp, src_ip, dst_ip, src_port, dst_port,
        protocol, length, tcp_flags, payload_preview,
        dns_name, dns_answer
    Non-IP packets still return the dict with None IP fields so callers
    can filter them out uniformly.
    """
    info = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': 'OTHER',
        'length': len(packet),
        'tcp_flags': '',
        'payload_preview': '',
        'dns_name': '',
        'dns_answer': '',
    }

    # --- OSI Layer 3: Network ---
    if not packet.haslayer(IP):
        return info

    ip_layer = packet[IP]
    info['src_ip'] = ip_layer.src
    info['dst_ip'] = ip_layer.dst

    # --- OSI Layer 4: Transport ---
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info['src_port'] = tcp.sport
        info['dst_port'] = tcp.dport
        info['protocol'] = 'TCP'
        info['tcp_flags'] = _format_flags(tcp.flags)

        # --- OSI Layer 7: HTTP ---
        http_ports = {80, 8080, 8000}
        if (tcp.dport in http_ports or tcp.sport in http_ports) and packet.haslayer(Raw):
            payload = packet[Raw].load
            if any(payload.startswith(sig) for sig in _HTTP_SIGNATURES):
                info['protocol'] = 'HTTP'
                first_line = payload.split(b'\r\n', 1)[0]
                info['payload_preview'] = first_line.decode('utf-8', errors='replace')

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info['src_port'] = udp.sport
        info['dst_port'] = udp.dport
        info['protocol'] = 'UDP'

        # --- OSI Layer 7: DNS (typically UDP port 53) ---
        if (udp.dport == 53 or udp.sport == 53) and packet.haslayer(DNS):
            dns = packet[DNS]
            info['protocol'] = 'DNS'
            if dns.qd:
                info['dns_name'] = dns.qd.qname.decode('utf-8', errors='replace').rstrip('.')
            if dns.qr == 1:  # response (qr=0 is query, qr=1 is response)
                info['dns_answer'] = _extract_dns_answer(dns)

    return info
