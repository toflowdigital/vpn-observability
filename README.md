# VPN Observability Toolkit

Operational tooling for monitoring and debugging IPsec / VPN infrastructure.

Includes tools for:

- StrongSwan tunnel monitoring
- Linux XFRM counter validation
- IPsec SA debugging
- Cisco DMVPN health checks

## Problem

`strongswan statusall` can briefly report `0 bytes_o` or `0 bytes_i`
during SA rollover. Monitoring systems that treat this as a hard failure
can trigger false alerts or bounce healthy tunnels.

This toolkit uses retry logic and kernel XFRM counters to distinguish
between a real failure and transient rekey behavior.
