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

import argparse
import logging
import re
import smtplib
import subprocess
import sys
import time
from datetime import datetime
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import yaml

from strongswan.xfrm_fallback_check import fallback_xfrm_bytes


def cfg_get(cfg: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def load_config(path: str) -> Dict[str, Any]:
    p = Path(path).expanduser()
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="StrongSwan tunnel monitor with XFRM fallback.")
    parser.add_argument("--config", required=True, help="Path to YAML config file")
    parser.add_argument(
        "--mode",
        choices=["check", "bounce", "report"],
        default="check",
        help="check=exit code only, bounce=auto-bounce unhealthy, report=email report if enabled",
    )
    parser.add_argument(
        "--direction",
        choices=["both", "in", "out"],
        default=None,
        help="Override check_direction from config",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not bounce tunnels; print what would happen",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Override log file path (useful for local testing)",
    )
    return parser.parse_args()


def setup_logging(log_file: str) -> None:
    log_path = Path(log_file).expanduser()

    if not log_path.exists():
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.touch()
        except PermissionError:
            # Fallback for local testing without privileges.
            log_path = Path("./strongswan_status_check.log")
            log_path.touch()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        filename=str(log_path),
        filemode="a",
    )


def send_email(cfg: Dict[str, Any], subject: str, body: str) -> None:
    if not cfg_get(cfg, "email.enabled", False):
        return

    sender = cfg_get(cfg, "email.sender", "ssmonitor@localhost")
    recipients = cfg_get(cfg, "email.recipients", [])
    smtp_server = cfg_get(cfg, "email.smtp_server", "localhost")

    if not recipients:
        logging.warning("Email enabled but no recipients configured; skipping email.")
        return

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)

    with smtplib.SMTP(smtp_server) as server:
        server.sendmail(sender, recipients, msg.as_string())


def ping_peer(peers: Dict[str, str]) -> None:
    for _, ip_address in peers.items():
        subprocess.run(f"ping {ip_address} -c 3 > /dev/null 2>&1", shell=True)


def tunnel_bounce(cfg: Dict[str, Any], tunnels_to_bounce: List[str], dry_run: bool) -> None:
    up_prefix = cfg_get(cfg, "strongswan.up_command_prefix", "sudo strongswan up")
    for tunnel_name in tunnels_to_bounce:
        cmd = f"{up_prefix} {tunnel_name} > /dev/null 2>&1"
        logging.warning("Bouncing tunnel: %s", tunnel_name)

        if dry_run:
            logging.warning("[dry-run] would run: %s", cmd)
            continue

        subprocess.run(cmd, shell=True, check=True)


def _parse_statusall_for_tunnel(
    status_text: str,
    tunnel_name: str,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], int, int]:
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


def safe_check_bytes(cfg: Dict[str, Any], tunnel_name: str, direction: str) -> Tuple[int, int]:
    """
    Retry statusall a few times to tolerate rekeys, then fallback to XFRM if needed.
    Returns (bytes_i, bytes_o).
    """
    retry_count = int(cfg_get(cfg, "timing.retry_count", 3))
    retry_delay = int(cfg_get(cfg, "timing.retry_delay_seconds", 10))
    sa_grace = int(cfg_get(cfg, "timing.sa_grace_period_seconds", 30))
    status_cmd = cfg_get(cfg, "strongswan.status_command", "sudo strongswan statusall")

    spi_i = spi_o = local_ip = remote_ip = None
    bytes_i = bytes_o = 0

    for _ in range(retry_count):
        status_result = subprocess.run(
            status_cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        spi_i, spi_o, local_ip, remote_ip, bytes_i, bytes_o = _parse_statusall_for_tunnel(
            status_result.stdout, tunnel_name
        )

        if (direction == "both" and bytes_i > 0 and bytes_o > 0) or \
           (direction == "in" and bytes_i > 0) or \
           (direction == "out" and bytes_o > 0):
            return bytes_i, bytes_o

        time.sleep(retry_delay)

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

        if (direction == "both" and xfrm_i > 0 and xfrm_o > 0) or \
           (direction == "in" and xfrm_i > 0) or \
           (direction == "out" and xfrm_o > 0):
            return xfrm_i, xfrm_o

        if age_min < sa_grace:
            logging.info("SA within grace period (%ss). Skipping bounce.", int(age_min))
            return xfrm_i, xfrm_o

    return bytes_i or 0, bytes_o or 0


def missing_line_safe_check(cfg: Dict[str, Any], tunnel_name: str) -> bool:
    missing_retry_count = int(cfg_get(cfg, "timing.missing_retry_count", 5))
    missing_retry_delay = int(cfg_get(cfg, "timing.missing_retry_delay_seconds", 1))
    status_cmd = cfg_get(cfg, "strongswan.status_command", "sudo strongswan statusall")

    for _ in range(missing_retry_count):
        status_result = subprocess.run(
            status_cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if tunnel_name in status_result.stdout:
            return True
        time.sleep(missing_retry_delay)
    return False


def tunnel_verification(
    cfg: Dict[str, Any],
    statusall_text: str,
    remote_peers: Dict[str, str],
    direction: str,
) -> List[str]:
    broken_tunnels: List[str] = []

    for tunnel_name in remote_peers.keys():
        if tunnel_name in statusall_text:
            b_i, b_o = safe_check_bytes(cfg, tunnel_name, direction)

            unhealthy = (
                (direction == "both" and (b_i == 0 or b_o == 0)) or
                (direction == "in" and b_i == 0) or
                (direction == "out" and b_o == 0)
            )

            if unhealthy:
                logging.warning("Tunnel %s unhealthy: bytes_i=%s bytes_o=%s", tunnel_name, b_i, b_o)
                broken_tunnels.append(tunnel_name)
            else:
                logging.info("Tunnel %s healthy: bytes_i=%s bytes_o=%s", tunnel_name, b_i, b_o)

        else:
            logging.warning("Tunnel %s not found in statusall output", tunnel_name)
            if not missing_line_safe_check(cfg, tunnel_name):
                broken_tunnels.append(tunnel_name)

    return broken_tunnels


def main() -> None:
    args = parse_args()
    cfg = load_config(args.config)

    direction = args.direction or cfg_get(cfg, "check_direction", "both")
    mode = args.mode

    log_file = args.log_file or cfg_get(cfg, "logging.log_file", "./strongswan_status_check.log")
    setup_logging(log_file)

    hostname = cfg_get(cfg, "hostname", "vpn-host")
    remote_peers = cfg_get(cfg, "remote_peers", {})

    try:
        status_cmd = cfg_get(cfg, "strongswan.status_command", "sudo strongswan statusall")
        statusall_results = subprocess.run(
            status_cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        broken = tunnel_verification(cfg, statusall_results.stdout, remote_peers, direction)

        if mode == "report":
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if broken:
                subject = f"[ALERT] Tunnel Health Report - Issues Found at {now}"
                body = f"Hostname: {hostname}\nUnhealthy tunnels: {', '.join(broken)}"
            else:
                subject = f"[OK][{hostname}] Tunnel Health Report"
                body = f"Hostname: {hostname}\nHealthy at {now}\nAll monitored tunnels are up and healthy."
            send_email(cfg, subject, body)
            sys.exit(0)

        if broken:
            logging.warning("Unhealthy tunnels: %s", ", ".join(broken))
            if mode == "bounce":
                tunnel_bounce(cfg, broken, dry_run=args.dry_run)
                ping_peer({t: remote_peers[t] for t in broken})
            sys.exit(1)

        sys.exit(0)

    except subprocess.CalledProcessError as e:
        logging.error("Command execution failed with return code %s", e.returncode)
        if getattr(e, "stderr", None):
            logging.error(e.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
