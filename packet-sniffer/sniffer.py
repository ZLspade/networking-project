"""
sniffer.py - CLI entry point.

Wires together capture (OSI L2-L7 parsing), filtering (L3-L7),
CSV logging, and the optional top-talkers dashboard.

Run with:
    python sniffer.py --help
"""

import argparse
import socket
from scapy.all import sniff

from capture import parse_packet
from filter import PacketFilter
from logger import CSVLogger
from dashboard import Dashboard

# ANSI helpers
_R = '\033[0m'
_BOLD = '\033[1m'
_PROTO_COLOURS = {
    'TCP':   '\033[94m',   # blue
    'UDP':   '\033[95m',   # magenta
    'HTTP':  '\033[92m',   # green
    'DNS':   '\033[93m',   # yellow
    'OTHER': '\033[90m',   # grey
}


def _resolve_service(port: int, proto: str = 'tcp') -> str:
    """Return a service name for a port (e.g. 443 → 'https'), or the port as a string."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return str(port)


def _print_packet(info: dict) -> None:
    """Pretty-print one packet line to stdout."""
    proto = info['protocol']
    colour = _PROTO_COLOURS.get(proto, _PROTO_COLOURS['OTHER'])
    transport = 'udp' if proto in ('UDP', 'DNS') else 'tcp'
    src_svc = _resolve_service(info['src_port'], transport) if info['src_port'] else ''
    dst_svc = _resolve_service(info['dst_port'], transport) if info['dst_port'] else ''
    src = f"{info['src_ip']}:{src_svc}" if src_svc else info['src_ip']
    dst = f"{info['dst_ip']}:{dst_svc}" if dst_svc else info['dst_ip']
    line = (f"[{info['timestamp']}] "
            f"{colour}{_BOLD}{proto:<5}{_R} "
            f"{src:<30} -> {dst:<30} "
            f"len={info['length']}")
    if info['tcp_flags']:
        line += f"  {colour}{info['tcp_flags']}{_R}"
    print(line)
    if info['payload_preview']:
        print(f"  {_PROTO_COLOURS['HTTP']}HTTP{_R}  {info['payload_preview']}")
    if info['dns_name']:
        dc = _PROTO_COLOURS['DNS']
        if info['dns_answer']:
            print(f"  {dc}DNS{_R}   {info['dns_name']} → {info['dns_answer']}")
        else:
            print(f"  {dc}DNS{_R}   query: {info['dns_name']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Network packet sniffer — captures and logs live traffic.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=('Examples:\n'
                '  python sniffer.py                          # capture all protocols\n'
                '  python sniffer.py -f http -d               # HTTP only + dashboard\n'
                '  python sniffer.py -i eth0 -c 100 -f tcp    # 100 TCP packets on eth0\n')
    )
    parser.add_argument('-i', '--interface', default=None,
                        help='Network interface to listen on (default: scapy picks one)')
    parser.add_argument('-f', '--filter', default='all',
                        choices=['all', 'tcp', 'udp', 'http', 'dns'],
                        help='Protocol filter (default: all)')
    parser.add_argument('-c', '--count', type=int, default=0,
                        help='Packets to capture before stopping (default: 0 = infinite)')
    parser.add_argument('-o', '--output', default='packets.csv',
                        help='CSV output file (default: packets.csv)')
    parser.add_argument('-d', '--dashboard', action='store_true',
                        help='Show live top-talkers dashboard every 20 packets')
    args = parser.parse_args()

    pkt_filter = PacketFilter(args.filter)
    logger = CSVLogger(args.output)
    dashboard = Dashboard() if args.dashboard else None

    print(f'{_BOLD}[*] Packet sniffer started{_R}')
    print(f'    Interface : {args.interface or "default"}')
    print(f'    Filter    : {args.filter.upper()}')
    print(f'    Output    : {args.output}')
    print(f'    Count     : {args.count or "unlimited"}')
    print(f'    Dashboard : {"on" if dashboard else "off"}')
    print(f'    Press Ctrl+C to stop\n')

    def handle_packet(pkt) -> None:
        info = parse_packet(pkt)
        if pkt_filter.matches(info):
            _print_packet(info)
            logger.log(info)
            if dashboard:
                dashboard.update(info)

    try:
        sniff(iface=args.interface, prn=handle_packet,
              count=args.count, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        logger.close()
        if dashboard:
            dashboard.print_summary()
        print(f'\n{_BOLD}[*] Capture finished. Data saved to {args.output}{_R}')


if __name__ == '__main__':
    main()
