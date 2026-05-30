"""
dashboard.py - Terminal dashboard tracking top talkers via collections.Counter.

OSI Layer 3 (Network): aggregates traffic by source/destination IP address.
OSI Layer 4 (Transport): breaks down traffic by protocol (TCP, UDP, HTTP).
"""

from collections import Counter

# ANSI colour helpers — no extra dependencies needed.
_R = '\033[0m'
_BOLD = '\033[1m'
_CYAN = '\033[96m'
_YELLOW = '\033[93m'
_GREEN = '\033[92m'
_SEPARATOR = '─' * 52


class Dashboard:
    """
    Maintains running counters and prints a formatted summary on demand.

    update_every: print a live snapshot every N matched packets (0 = never).
    top_n:        how many rows to show per table.
    """

    def __init__(self, update_every: int = 20, top_n: int = 5):
        self.src_counter: Counter = Counter()
        self.dst_counter: Counter = Counter()
        self.proto_counter: Counter = Counter()
        self.total = 0
        self.update_every = update_every
        self.top_n = top_n

    def update(self, packet_info: dict) -> None:
        if packet_info['src_ip']:
            self.src_counter[packet_info['src_ip']] += 1
        if packet_info['dst_ip']:
            self.dst_counter[packet_info['dst_ip']] += 1
        self.proto_counter[packet_info['protocol']] += 1
        self.total += 1

        if self.update_every and self.total % self.update_every == 0:
            self._print(f'Live snapshot — {self.total} packets captured')

    def print_summary(self) -> None:
        self._print(f'Final summary — {self.total} packets captured')

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _print(self, title: str) -> None:
        print(f'\n{_BOLD}{_YELLOW}{_SEPARATOR}{_R}')
        print(f'{_BOLD}{_YELLOW}  {title}{_R}')
        print(f'{_BOLD}{_YELLOW}{_SEPARATOR}{_R}')
        print(self._table('Top source IPs      (Layer 3)', self.src_counter))
        print(self._table('Top destination IPs (Layer 3)', self.dst_counter))
        print(self._table('Protocols           (Layer 4)', self.proto_counter, n=4))
        print(f'{_BOLD}{_YELLOW}{_SEPARATOR}{_R}\n')

    def _table(self, heading: str, counter: Counter, n: int = None) -> str:
        n = n or self.top_n
        lines = [f'{_BOLD}{_CYAN}{heading}{_R}']
        if not counter:
            lines.append('  (no data yet)')
            return '\n'.join(lines)
        total = sum(counter.values())
        for rank, (key, count) in enumerate(counter.most_common(n), 1):
            pct = count / total * 100
            bar = _GREEN + '█' * min(round(pct / 5), 20) + _R
            lines.append(f'  {rank}. {key:<22} {count:>5} ({pct:5.1f}%)  {bar}')
        return '\n'.join(lines)
