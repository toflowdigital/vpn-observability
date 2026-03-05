"""
xfrm_fallback_check.py

Helpers for reading Linux kernel XFRM counters for ESP SAs.

Used as a fallback when StrongSwan `statusall` byte counters temporarily report
0 bytes during rekey / SA rollover.
"""

from __future__ import annotations

import logging
import re
import subprocess
from datetime import datetime
from typing import Tuple


def fallback_xfrm_bytes(spi: str, src: str, dst: str) -> Tuple[int, float]:
    """
    Return (bytes, age_seconds) for an ESP SA identified by spi/src/dst.

    spi: hex string WITHOUT '0x' prefix (e.g. 'a1b2c3d4')
    """
    try:
        result = subprocess.check_output(
            [
                "ip", "-s", "xfrm", "state", "get",
                "src", src, "dst", dst,
                "proto", "esp", "spi", f"0x{spi}",
            ],
            text=True,
        )

        # Example patterns vary a bit by distro; keep this resilient.
        byte_match = re.search(r"(\d+)\(bytes\)", result)
        time_match = re.search(r"add time: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", result)

        bytes_val = int(byte_match.group(1)) if byte_match else 0

        if time_match:
            add_time = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
            age = (datetime.now() - add_time).total_seconds()
        else:
            age = float("inf")

        return bytes_val, age

    except subprocess.CalledProcessError:
        logging.warning("XFRM fallback failed for SPI 0x%s src %s dst %s", spi, src, dst)
        return 0, float("inf")
