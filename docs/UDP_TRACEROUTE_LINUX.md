# UDP Traceroute Behavior on Linux

## Overview

When using UDP traceroute on Linux with default settings, you may notice that many destinations appear to be only one hop away. This is not a bug in ftr or Linux - it's due to how network equipment handles UDP packets to high ports.

## The Real Issue: Port-Based Filtering

The "one hop" behavior is actually caused by how routers and firewalls handle UDP packets to different ports:

### Default High Ports (33434+) - Often Filtered
```bash
$ traceroute -U 8.8.8.8
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  dns.google (8.8.8.8)  0.382 ms  0.283 ms  0.238 ms
```

### Well-Known Ports (443, 53) - Usually Allowed
```bash
$ traceroute -U -p 443 8.8.8.8
traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  unifi.localdomain (192.168.1.1)  3.149 ms  3.120 ms  3.113 ms
 2  lo0.bras2.rdcyca01.sonic.net (157.131.132.109)  6.301 ms  6.295 ms  6.288 ms
 3  * * *
[... continues with more hops ...]
17  dns.google (8.8.8.8)  32.386 ms  32.432 ms  32.412 ms
```

## Why This Happens

### 1. Router/Firewall Behavior
Many routers and firewalls along the path:
- Don't send ICMP Time Exceeded for UDP packets to uncommon high ports
- May drop or ignore these packets entirely
- Consider high ports (33434+) as potentially malicious scanning activity

### 2. Well-Known Ports Are Treated Differently
Ports like 443 (HTTPS/QUIC) and 53 (DNS) are:
- Recognized as legitimate traffic
- Less likely to be filtered
- Handled normally by intermediate routers

### 3. How UDP Traceroute Works
- UDP traceroute traditionally uses "unlikely" ports starting at 33434
- Each packet has an incrementing TTL (Time To Live)
- Routers should decrement TTL and send ICMP Time Exceeded when TTL reaches 0
- But many routers don't do this for packets to high UDP ports

## Is This a Bug?

No, this is not a bug. It's a consequence of modern network security practices where:
- Routers and firewalls filter packets based on destination ports
- High ports are often associated with scanning or malicious activity
- Well-known service ports are allowed through as legitimate traffic

## How ftr Solves This

**ftr automatically uses port 443 (HTTPS/QUIC) for UDP traceroute**, which provides much better visibility through modern networks. When you run:

```bash
ftr --protocol udp 8.8.8.8
```

ftr will:
- Use UDP port 443 instead of traditional high ports (33434+)
- Display a note explaining this choice
- Show more complete network paths as routers are less likely to filter port 443

This is equivalent to running `traceroute -U -p 443` but automatic.

## What You Can Do

1. **Use UDP mode with ftr** for better results: `ftr --protocol udp <target>`
   - Automatically uses port 443 for better path visibility
   - No root privileges required on Linux (uses IP_RECVERR)
   - Shows more hops than traditional UDP traceroute

2. **Use ICMP mode** for traditional traceroute: `ftr --protocol icmp <target>`
   - ICMP Echo Request packets are specifically designed for network diagnostics
   - Most routers will properly respond with Time Exceeded messages
   - May require root privileges depending on system configuration

3. **With system traceroute, manually specify well-known ports**:
   - `traceroute -U -p 443 <target>` (HTTPS/QUIC port)
   - `traceroute -U -p 53 <target>` (DNS port)
   - `traceroute -U -p 123 <target>` (NTP port)

## Technical Details

When ftr uses UDP mode with IP_RECVERR on Linux:
- We send UDP packets to port 443 (HTTPS/QUIC)
- This port is less likely to be filtered by routers and firewalls
- We use IP_RECVERR socket option to receive ICMP errors without root privileges
- The kernel delivers ICMP Time Exceeded and Destination Unreachable messages via the error queue
- We parse these messages to identify responding routers and the destination

This approach provides:
- Better path visibility than traditional high-port UDP traceroute
- No root privileges required on Linux
- Compatibility with modern network security practices

## Comparison

| Method | Port | Root Required | Path Visibility |
|--------|------|---------------|----------------|
| Traditional UDP | 33434+ | No (Linux) | Poor - often filtered |
| ftr UDP mode | 443 | No (Linux) | Good - well-known port |
| ICMP mode | N/A | Usually | Best - designed for diagnostics |
| System traceroute -U | 33434+ | No | Poor - often filtered |
| System traceroute -U -p 443 | 443 | No | Good - well-known port |