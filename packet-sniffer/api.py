"""
api.py - Flask API server that runs the packet sniffer in a background thread
and exposes live packet data as JSON for the Kali web dashboard.

Architecture:
  Scapy (raw socket) → capture.py → PacketStore → Flask API → Kali dashboard

Run with (as Administrator):
    python api.py
"""

import threading
from collections import Counter, deque
from datetime import datetime

from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import sniff

from capture import parse_packet
from filter import PacketFilter

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from the Kali dashboard at 192.168.126.128


class PacketStore:
    """
    Thread-safe shared store between the sniffer thread and Flask request threads.

    OSI context: aggregates data from L3 (IPs), L4 (protocols/ports), L7 (DNS/HTTP).
    """

    def __init__(self, max_recent: int = 100):
        self._lock = threading.Lock()
        self.recent: deque = deque(maxlen=max_recent)
        self.proto_counter: Counter = Counter()
        self.src_counter: Counter = Counter()
        self.dst_counter: Counter = Counter()
        self.total: int = 0
        self.started_at: str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def add(self, info: dict) -> None:
        with self._lock:
            self.recent.append(info)
            self.proto_counter[info['protocol']] += 1
            if info['src_ip']:
                self.src_counter[info['src_ip']] += 1
            if info['dst_ip']:
                self.dst_counter[info['dst_ip']] += 1
            self.total += 1

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'total': self.total,
                'started_at': self.started_at,
                'protocols': dict(self.proto_counter),
                'top_sources': self.src_counter.most_common(5),
                'top_destinations': self.dst_counter.most_common(5),
            }

    def get_recent(self) -> list:
        with self._lock:
            return list(self.recent)[-50:]


store = PacketStore()
_filter = PacketFilter('all')


def _sniffer_thread() -> None:
    def handle(pkt) -> None:
        info = parse_packet(pkt)
        if _filter.matches(info):
            store.add(info)

    sniff(prn=handle, store=False)


# --- API endpoints ---

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'total': store.total})


@app.route('/api/stats')
def stats():
    return jsonify(store.get_stats())


@app.route('/api/packets')
def packets():
    return jsonify(store.get_recent())


if __name__ == '__main__':
    t = threading.Thread(target=_sniffer_thread, daemon=True)
    t.start()
    print('[*] Sniffer thread started — capturing all traffic')
    print('[*] API available at http://192.168.126.1:5000')
    print('[*] Endpoints: /api/health  /api/stats  /api/packets')
    app.run(host='0.0.0.0', port=5000, debug=False)
