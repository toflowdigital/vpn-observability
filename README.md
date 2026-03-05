# VPN Observability Toolkit

Operational tooling for monitoring and debugging IPsec / VPN infrastructure on Linux systems.

Includes tools for:

- StrongSwan tunnel monitoring
- Linux XFRM counter validation
- IPsec SA debugging
- Cisco DMVPN health checks

---

## Problem

During IPsec rekey events, `strongswan statusall` may temporarily report
`0 bytes_i` or `0 bytes_o` even when traffic is still flowing.

Monitoring systems that rely solely on these counters can generate false
alerts or bounce healthy tunnels.

This toolkit reduces those false positives by correlating StrongSwan
output with kernel XFRM counters.

---

## Usage

Install dependencies:

```bash
pip install -r requirements.txt
```

Run healthcheck

```bash
python strongswan/tunnel_monitor.py \
  --config examples/config.example.yaml \
  --mode check
```

bounce unhealthy tunnels
```bash
python strongswan/tunnel_monitor.py \
  --config examples/config.example.yaml \
  --mode bounce
```

dry run (no changes)
```bash
python strongswan/tunnel_monitor.py \
  --config examples/config.example.yaml \
  --mode bounce \
  --dry-run
```

## Config

See `examples/config.example.yaml` for a sanitized configuration example.

## Architecture

Monitoring flow:

strongswan statusall
        │
        ▼
parse SPI + peer IPs
        │
        ▼
retry window to tolerate rekeys
        │
        ▼
fallback to kernel XFRM counters
(ip -s xfrm state get)
        │
        ▼
determine tunnel health
        │
        ▼
alert or bounce tunnel
