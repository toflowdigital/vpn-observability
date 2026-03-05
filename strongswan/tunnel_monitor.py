"""
StrongSwan tunnel monitor with XFRM fallback.

Why this exists:
`strongswan statusall` byte counters can briefly report 0 bytes during
rekey/SA rollover even when traffic is flowing. Naive monitors may treat
this as a failure and bounce healthy tunnels.

This script:
- checks `strongswan statusall` first (with retries)
- if counters are still zero, correlates SPI + src/dst and reads kernel
  XFRM counters via `ip -s xfrm state get`
- applies a short grace window for freshly-added SAs to avoid bouncing
  during rekey churn

Intended use:
Run periodically (cron/systemd timer) to alert or bounce specific
connections by name.
"""

from __future__ import annotations

import logging
import os
import re
import smtplib
import subprocess
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from typing import Dict, List, Tuple

from strongswan.xfrm_fallback_check import fallback_xfrm_bytes


# --- basic configuration (replace with YAML later) ---
REMOTE_PEERS: Dict[str, str] = {
    "client-network-1": "10.0.5.100",
}

HOSTNAME = "10G-LM-VPC5-SS-GW"
SENDER = "ssmonitor@localhost"
RECIPIENTS = ["example@example.com"]
SMTP_SERVER = "172.16.5.149"

CHECK_DIRECTION = "both"  # options: both, in, out
HEALTHCHECK_MODE = os.getenv("HEALTHCHECK_MODE", "0") == "1"
STATUS_COMMAND = "sudo strongswan statusall"

RETRY_COUNT = 3
RETRY_DELAY_SECONDS = 10
MISSING_RETRY_COUNT = 5
MISSING_RETRY_DELAY = 1
SA_GRACE_PERIOD_SECONDS = 30

LOG_FILE = "/var/log/strongswan_status_check.log"

def setup_logging() -> None:
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        filename=LOG_FILE,
        filemode="a",
    )


def send_email(subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SENDER
    msg["To"] = ", ".join(RECIPIENTS)
    with smtplib.SMTP(SMTP_SERVER) as server:
        server.sendmail(SENDER, RECIPIENTS, msg.as_string())


def ping_peer(peers: Dict[str, str]) -> None:
    for _, ip_address in peers.items():
        subprocess.run(f"ping {ip_address} -c 3 > /dev/null 2>&1", shell=True)


def tunnel_bounce(tunnels_to_bounce: List[str]) -> None:
    for tunnel_name in tunnels_to_bounce:
        logging.warning("Bouncing tunnel: %s", tunnel_name)
        subprocess.run(
            f"sudo strongswan up {tunnel_name} > /dev/null 2>&1",
            shell=True,
            check=True,
        )


def _parse_statusall_for_tunnel(status_text: str, tunnel_name: str) -> Tuple[str | None, str | None, str | None, str | None, int, int]:
    """
    Extract spi_i/spi_o + local_ip/remote_ip + bytes_i/bytes_o for a given connection.
    Returns (spi_i, spi_o, local_ip, remote_ip, bytes_i, bytes_o).
    """
    lines = status_text.split("\n")

    spi_i = spi_o = None
    local_ip = remote_ip = None
    bytes_i = bytes_o = 0

    for i, line in enumerate(lines):
        if tunnel_name in line and "ESP SPIs:" in line and "INSTALLED" in line:
            spi_match = re.search(r"ESP SPIs: ([0-9a-f]+)_i ([0-9a-f]+)_o", line)
            if spi_match:
                spi_i, spi_o = spi_match.group(1), spi_match.group(2)

            next_line = lines[i + 1] if i + 1 < len(lines) else ""
            byte_match = re.search(r"(\d+) bytes_i.*?(\d+) bytes_o", next_line)
            if byte_match:
                bytes_i, bytes_o = int(byte_match.group(1)), int(byte_match.group(2))

        elif tunnel_name in line and "ESTABLISHED" in line:
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                local_ip, remote_ip = ip_match.group(1), ip_match.group(2)

    return spi_i, spi_o, local_ip, remote_ip, bytes_i, bytes_o


def safe_check_bytes(tunnel_name: str) -> Tuple[int, int]:
    """
    Retry statusall a few times to tolerate rekeys, then fallback to XFRM if needed.
    Returns (bytes_i, bytes_o).
    """
    spi_i = spi_o = local_ip = remote_ip = None
    bytes_i = bytes_o = 0

    for _ in range(RETRY_COUNT):
        status_result = subprocess.run(
            STATUS_COMMAND,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        spi_i, spi_o, local_ip, remote_ip, bytes_i, bytes_o = _parse_statusall_for_tunnel(
            status_result.stdout, tunnel_name
        )

        if (CHECK_DIRECTION == "both" and bytes_i > 0 and bytes_o > 0) or \
           (CHECK_DIRECTION == "in" and bytes_i > 0) or \
           (CHECK_DIRECTION == "out" and bytes_o > 0):
            return bytes_i, bytes_o

        time.sleep(RETRY_DELAY_SECONDS)

    # fallback to XFRM after retries
    if spi_i and spi_o and local_ip and remote_ip:
        xfrm_i, age_i = fallback_xfrm_bytes(spi_i, remote_ip, local_ip)
        xfrm_o, age_o = fallback_xfrm_bytes(spi_o, local_ip, remote_ip)

        age_min = min(age_i, age_o)
        age_str = f"{int(age_min)}s" if age_min != float("inf") else "unknown"

        logging.info(
            "[Fallback XFRM] %s: spi_i=0x%s in=%sB, spi_o=0x%s out=%sB (min_age=%s)",
            tunnel_name, spi_i, xfrm_i, spi_o, xfrm_o, age_str
        )

        if (CHECK_DIRECTION == "both" and xfrm_i > 0 and xfrm_o > 0) or \
           (CHECK_DIRECTION == "in" and xfrm_i > 0) or \
           (CHECK_DIRECTION == "out" and xfrm_o > 0):
            return xfrm_i, xfrm_o

        if age_min < SA_GRACE_PERIOD_SECONDS:
            logging.info("SA within grace period (%ss). Skipping bounce.", int(age_min))
            return xfrm_i, xfrm_o

    return bytes_i or 0, bytes_o or 0


def missing_line_safe_check(tunnel_name: str) -> bool:
    for _ in range(MISSING_RETRY_COUNT):
        status_result = subprocess.run(
            STATUS_COMMAND,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if tunnel_name in status_result.stdout:
            return True
        time.sleep(MISSING_RETRY_DELAY)
    return False


def tunnel_verification(statusall_text: str) -> List[str]:
    broken_tunnels: List[str] = []

    for tunnel_name in REMOTE_PEERS.keys():
        if tunnel_name in statusall_text:
            b_i, b_o = safe_check_bytes(tunnel_name)

            unhealthy = (
                (CHECK_DIRECTION == "both" and (b_i == 0 or b_o == 0)) or
                (CHECK_DIRECTION == "in" and b_i == 0) or
                (CHECK_DIRECTION == "out" and b_o == 0)
            )

            if unhealthy:
                logging.warning("Tunnel %s unhealthy: bytes_i=%s bytes_o=%s", tunnel_name, b_i, b_o)
                broken_tunnels.append(tunnel_name)
            else:
                logging.info("Tunnel %s healthy: bytes_i=%s bytes_o=%s", tunnel_name, b_i, b_o)

        else:
            logging.warning("Tunnel %s not found in statusall output", tunnel_name)
            if not missing_line_safe_check(tunnel_name):
                broken_tunnels.append(tunnel_name)

    return broken_tunnels


def run() -> int:
    statusall_results = subprocess.run(
        STATUS_COMMAND,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    broken = tunnel_verification(statusall_results.stdout)

    if HEALTHCHECK_MODE:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if broken:
            subject = f"[ALERT] Daily Tunnel Health Report - Issues Found at {now}"
            body = f"The following tunnels are unhealthy: {', '.join(broken)}"
        else:
            subject = f"[OK][{HOSTNAME}] Daily Tunnel Health Report"
            body = f"Hostname: {HOSTNAME}\nHealthy at {now}\nAll monitored tunnels are up and healthy."

        send_email(subject, body)
        logging.info("Daily health report sent.")
        return 0

    if broken:
        print(f"\n{HOSTNAME}\nTunnels to bounce: {', '.join(broken)}")
        tunnel_bounce(broken)
        ping_peer({t: REMOTE_PEERS[t] for t in broken})
        return 1

    return 0


def main() -> None:
    setup_logging()
    try:
        rc = run()
        sys.exit(rc)
    except subprocess.CalledProcessError as e:
        logging.error("Command execution failed with return code %s", e.returncode)
        if getattr(e, "stderr", None):
            logging.error(e.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
