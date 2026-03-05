# VPN Observability Toolkit

Operational tooling for monitoring and debugging IPsec / VPN infrastructure.

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


