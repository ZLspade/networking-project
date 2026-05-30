"""
logger.py - Append captured packet metadata to a CSV file.

This operates above OSI Layer 4 — it persists the structured data extracted
by capture.py rather than touching raw frames directly.
"""

import csv
import os
import threading

_FIELDS = ['timestamp', 'protocol', 'src_ip', 'src_port',
           'dst_ip', 'dst_port', 'length', 'tcp_flags',
           'dns_name', 'dns_answer', 'payload_preview']


class CSVLogger:
    """
    Thread-safe, append-mode CSV writer.

    A header row is written only when the file does not already exist,
    so re-runs of the sniffer accumulate into the same file rather than
    clobbering it.
    """

    def __init__(self, filepath: str = 'packets.csv'):
        self.filepath = filepath
        self._lock = threading.Lock()
        write_header = not os.path.exists(filepath)
        self._file = open(filepath, 'a', newline='', encoding='utf-8')
        self._writer = csv.DictWriter(self._file, fieldnames=_FIELDS,
                                      extrasaction='ignore')
        if write_header:
            self._writer.writeheader()

    def log(self, packet_info: dict) -> None:
        with self._lock:
            self._writer.writerow(packet_info)

    def close(self) -> None:
        with self._lock:
            self._file.flush()
            self._file.close()
