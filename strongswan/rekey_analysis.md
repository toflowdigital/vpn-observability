# Rekey false positives (StrongSwan `statusall` vs XFRM)

## Problem
In some environments, `strongswan statusall` may temporarily show `0 bytes_o` (or `0 bytes_i`)
during rekey / SA rollover even while traffic is flowing. Monitoring systems that treat this as an
immediate failure can generate false alarms or bounce healthy tunnels.

## Approach used in this repo
1. Retry `statusall` for a short period to tolerate SA churn.
2. If byte counters remain 0, extract ESP SPIs + local/remote IPs from `statusall`.
3. Query Linux kernel XFRM counters (`ip -s xfrm state get`) for the matching SAs.
4. Apply a grace period based on SA age to avoid bouncing immediately after a new SA is added.

## Why XFRM
The kernel XFRM counters reflect packets that actually traverse the IPsec stack, which can be more
reliable than user-space summaries during transient rekey states.
