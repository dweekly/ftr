# IPv6 Support: Design and Validated Findings

Design basis for adding IPv6 traceroute support to ftr
([issue #22](https://github.com/dweekly/ftr/issues/22)). Every claim in the
"Validated findings" section was observed by running the spike programs in
`examples/spike_*.rs` on real hardware — output below is pasted verbatim, not
paraphrased. The spikes stay in the repo as permanent diagnostics: re-run them
whenever kernel, library, or network behavior is in question.

**Validation environment:** macOS 26.5.1 (build 25F80), Apple Silicon (arm64),
rustc 1.97.0, socket2 0.6, dual-stack network with live public IPv6
(Sonic fiber). Linux, Windows, FreeBSD, and OpenBSD behavior is **unvalidated**
— see [Open questions](#open-questions-unvalidated-platforms).

Run all spikes with:

```bash
cargo run --example spike_icmpv6_socket
cargo run --example spike_traceroute6
cargo run --example spike_stun6
cargo run --example spike_asn6
```

## Validated findings (macOS)

### spike_icmpv6_socket — socket basics

| Question | Verdict |
|----------|---------|
| `Domain::IPV6`/`Type::DGRAM`/`Protocol::ICMPV6` without root | **Works** (euid 501) |
| `Type::RAW`/`Protocol::ICMPV6` without root | **EPERM** (os error 1) — needs root |
| Kernel computes ICMPv6 checksum on DGRAM send | **Yes** — echo sent with zeroed checksum got a reply |
| Received buffer starts at ICMPv6 header (no IPv6 header prepended) | **Yes** — first byte is 129, not a 0x6X version nibble |
| Kernel demuxes DGRAM replies by ICMP identifier | **NO** — every ICMPv6 DGRAM socket receives ALL ICMPv6 traffic |

Observed output (2026-07-09):

```
[1] Socket::new(IPV6, RAW, ICMPV6):
    FAILED: Operation not permitted (os error 1) (os error Some(1)) — raw needs root, as expected

[2] Socket::new(IPV6, DGRAM, ICMPV6):
    OK — unprivileged DGRAM ICMPv6 socket opened

[3] Echo Request to 2001:4860:4860::8888 with ZEROED checksum (id=0x1234 seq=1):
    sent 22 bytes
    received 22 bytes from Some(2001:4860:4860::8888)
    first byte = 129 (0x81) — ICMPv6 Echo Reply: buffer starts at ICMPv6 header, NO IPv6 header prepended
    checksum=0xddc0 identifier=0x1234 sequence=1
    => reply came back despite zero checksum on send: kernel computed the ICMPv6 checksum

[4] Demux test: two DGRAM sockets, ids 0x1111 and 0x2222:
    socket A (sent id=0x1111), draining:
      got type=129 id=0x1111 seq=7 (own)
      got type=129 id=0x2222 seq=8 (FOREIGN)
      => own reply: true, foreign reply: true — kernel does NOT demux by identifier; userspace must filter
    socket B (sent id=0x2222), draining:
      got type=129 id=0x1111 seq=7 (FOREIGN)
      got type=129 id=0x2222 seq=8 (own)
      => own reply: true, foreign reply: true — kernel does NOT demux by identifier; userspace must filter
```

**This is the key surprise.** SwiftFTR observed that Darwin demuxes IPv4 DGRAM
ICMP by echo identifier; for ICMPv6 it does not. A DGRAM ICMPv6 socket on
Darwin behaves like an unprivileged raw socket: it sees every inbound ICMPv6
packet, including other sockets' echo replies and link NDP chatter. During a
busier run, unsolicited NDP/RA noise arrived interleaved with the replies:

```
      got type=134 id=0x40c8 seq=1800 (FOREIGN)   <- Router Advertisement
      got type=135 id=0x0000 seq=0 (FOREIGN)      <- Neighbor Solicitation
      got type=136 id=0xc000 seq=0 (FOREIGN)      <- Neighbor Advertisement
```

(The "id/seq" on types 134-136 is just the echo-header interpretation of
unrelated bytes.)

### spike_traceroute6 — hop-limited probes and Time Exceeded

The make-or-break question: **an unprivileged DGRAM ICMPv6 socket on macOS
DOES receive ICMPv6 Time Exceeded on its normal receive path.** No errqueue,
no raw socket, no root required. Full validated list:

| Question | Verdict |
|----------|---------|
| `IPV6_UNICAST_HOPS` settable and read back on DGRAM | **Works** (set 3, read 3) |
| Time Exceeded (type 3) delivered to DGRAM socket | **Works** — from the hop-3 router |
| TE payload = invoking IPv6 header (40 B) + invoking ICMPv6 echo header | **Confirmed**; embedded id/seq match the probe |
| `IPV6_RECVHOPLIMIT` + recvmsg cmsg (`IPV6_HOPLIMIT`) | **Works** — reply hop limit 62 read from ancillary data |
| `ICMP6_FILTER` via raw setsockopt (level `IPPROTO_ICMPV6`, optname 18) | **Works**; BSD semantics, bit set = PASS |
| RAW ICMPv6 comparison | **Needs root** — open item, see below |

Observed output (2026-07-09):

```
[1] hop-limited probe on SOCK_DGRAM ICMPv6 socket:
    IPV6_UNICAST_HOPS readback: 3
    probe sent (hop_limit=3, id=0x3333, seq=1)
    got TIME EXCEEDED from Some(2001:5a8:5:403f::f0:2) (reply hop_limit cmsg: Some(62))
      embedded IPv6: version=6 next_header=58 hop_limit=1 src=2001:5a8:4684:c00:41b1:1c86:aee8:e97 dst=2001:4860:4860::8888
      embedded ICMPv6: type=128 code=0 identifier=0x3333 sequence=1
      => embedded id/seq MATCH our probe

    VERDICT: DGRAM ICMPv6 socket CAN receive Time Exceeded on macOS

[3] ICMP6_FILTER via raw setsockopt (socket2 has no API):
    phase A: filter passes ONLY Echo Reply (129); expect NO Time Exceeded:
    setsockopt(ICMP6_FILTER) OK
    probe sent (hop_limit=3, id=0x4444, seq=1)
    => Time Exceeded delivered with it filtered out: false (false means the filter blocks as intended)
    phase B: filter passes 1/3/129; expect Time Exceeded again:
    setsockopt(ICMP6_FILTER) OK
    probe sent (hop_limit=3, id=0x4444, seq=2)
    got TIME EXCEEDED from Some(2001:5a8:5:403f::f1:2) (reply hop_limit cmsg: Some(62))
      embedded ICMPv6: type=128 code=0 identifier=0x4444 sequence=2
      => embedded id/seq MATCH our probe
    => Time Exceeded delivered with filter passing type 3: true
```

Notes:

- The two-phase filter test is a positive control: the same probe that yields
  no answer when type 3 is blocked yields the Time Exceeded when type 3 is
  passed, proving the filter itself (not luck) caused the difference.
- socket2 exposes no `ICMP6_FILTER` API
  ([rust-lang/socket2#199](https://github.com/rust-lang/socket2/issues/199)),
  so the spike calls `libc::setsockopt` directly. The libc crate does not
  define `ICMP6_FILTER` for Apple targets either; the value 18 is verified
  against the macOS SDK header `netinet6/in6.h` line 392, and the
  `struct icmp6_filter` layout ([u32; 8]) against `netinet/icmp6.h` line 624.
- **Filter semantics differ by OS:** on BSD/macOS a set bit means PASS
  (`ICMP6_FILTER_SETPASS` ORs the bit in; `SETBLOCKALL` is memset 0). On
  Linux the semantics are inverted (set bit = block). Any shared abstraction
  must encode this per-platform.
- ftr's hop-1 heuristic (`2001:5a8:...` is Sonic's handoff at hop 3 here):
  the embedded invoking header's `hop_limit=1` confirms the router decremented
  to 1 then expired it, exactly like v4 TTL.

### spike_stun6 — public IPv6 via STUN

**Works.** Both Google and Cloudflare STUN answered over UDPv6 and the
XOR-MAPPED-ADDRESS (family 0x02) un-XORed to the same address, which exactly
matches an independent HTTPS check (`curl -6 -s https://api64.ipify.org` →
`2001:5a8:4684:c00:41b1:1c86:aee8:e97`, same day, same machine).

```
[stun.l.google.com:19302]
    resolved to [2001:4860:4864:5:8000::1]:19302
    received 44 bytes from [2001:4860:4864:5:8000::1]:19302
    public IPv6: 2001:5a8:4684:c00:41b1:1c86:aee8:e97 (mapped port 52410)

[stun.cloudflare.com:3478]
    resolved to [2606:4700:49::]:3478
    received 44 bytes from [2606:4700:49::]:3478
    public IPv6: 2001:5a8:4684:c00:41b1:1c86:aee8:e97 (mapped port 50733)

VERDICT: public IPv6 = 2001:5a8:4684:c00:41b1:1c86:aee8:e97 (servers consistent: true)
```

Implementation notes carried into stage 6: v6 XOR recovery per RFC 5389
§15.2 — port XORed with the top 16 bits of the magic cookie; the 16 address
bytes XORed with (magic cookie || transaction ID). Note there is no v6 NAT
here: STUN returns the host's own global address, so "public IP" for v6
usually equals the source address (still worth confirming via STUN to detect
NAT66/NPTv6 edge cases).

### spike_asn6 — Team Cymru origin6 lookup

**Works.** Nibble-reversed name + `.origin6.asn.cymru.com` TXT over plain UDP
DNS (same wire format as `src/dns/resolver.rs`) returns the expected origin
ASN:

```
query target: 2001:4860:4860::8888
origin6 name: 8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.origin6.asn.cymru.com
received 163-byte DNS response
TXT: "15169 | 2001:4860::/32 | US | arin | 2005-03-14"
  parsed: ASN=15169 prefix=2001:4860::/32 country=US registry=arin allocated=2005-03-14
  => AS15169 (Google) as expected — origin6 lookup works
```

TXT payload format is identical to the v4 `origin.asn.cymru.com` zone
(`AS | prefix | CC | registry | allocated`), so the existing parser generalizes;
only the query-name construction differs (32 reversed nibbles vs 4 reversed
octets).

## Design decisions for stage-6 integration

### Socket mode per platform

| Platform | v6 probe socket | Root needed | Status |
|----------|-----------------|-------------|--------|
| macOS | `IPV6`/`DGRAM`/`ICMPV6` | **No** | **Validated here** |
| Linux | `IPV6`/`DGRAM`/`ICMPV6` (ping socket, gated by `net.ipv4.ping_group_range`); fallback raw; UDP+`IPV6_RECVERR` for unprivileged UDP mode | Depends | Unvalidated |
| Windows | `Icmp6SendEcho2` (IP Helper) | No | Unvalidated |
| FreeBSD/OpenBSD | `IPV6`/`RAW`/`ICMPV6` | Yes (expected) | Unvalidated |

macOS gets a first-class unprivileged v6 mode — this is strictly better than
v4 on macOS, where ftr requires root for raw ICMP.

### Identifier/sequence demux strategy

Because Darwin delivers **all** inbound ICMPv6 to every DGRAM ICMPv6 socket:

- Assign a **unique ICMP identifier per concurrent traceroute session**
  (contract carried from SwiftFTR), and validate it on **every** receive path:
  echo replies (bytes 4..6 of the ICMPv6 header) **and** inside Time Exceeded /
  Destination Unreachable payloads (bytes 4..6 of the embedded ICMPv6 header at
  offset 48). A packet whose identifier does not match the session is silently
  skipped, not an error.
- Sequence numbers encode the probe slot (hop/attempt), as in v4.
- Apply `ICMP6_FILTER` passing only types 1, 3, 129 to shed NDP/RA noise in
  the kernel (validated working on macOS), but treat it as an optimization:
  **userspace identifier filtering is mandatory for correctness** regardless,
  since the filter cannot distinguish two concurrent ftr sessions' echoes.
  If `setsockopt` fails on some platform, log and continue.

### Parsing differences v4 vs v6

| Aspect | IPv4 (raw) | IPv6 DGRAM/raw |
|--------|------------|----------------|
| Received buffer | Starts at IP header (variable IHL), ICMP at `IHL*4` | **Starts at ICMPv6 header**; kernel never prepends the IPv6 header (RFC 3542 behavior, validated) |
| Checksum on send | Computed in userspace | **Leave zeroed; kernel computes** (pseudo-header requires it; validated) |
| TTL/hop limit of reply | Read from IP header byte 8 | **Not in buffer** — request `IPV6_RECVHOPLIMIT`, read `IPV6_HOPLIMIT` cmsg via `recvmsg` (validated; needs libc for cmsg parsing — socket2 0.6 has `recvmsg` but no cmsg parser) |
| Time Exceeded payload | 8 B ICMP + IP header (variable IHL) + 8 B ICMP | 8 B ICMPv6 + **fixed 40 B** IPv6 header + 8 B ICMPv6 (validated); check embedded `next_header == 58` before trusting the echo header |
| Echo types | 8 / 0 | 128 / 129 |
| Time Exceeded type | 11 | 3 |

### Address formatting contracts (carried from SwiftFTR)

- Emit **canonical, `inet_ntop`-stable strings**: Rust's `Ipv6Addr` `Display`
  implements RFC 5952 canonical form (lowercase, `::` compression of the
  longest zero run), matching modern `inet_ntop`. Always render through
  `Ipv6Addr`/`IpAddr` `Display`, never hand-format hextets.
- **Preserve `%zone` on link-local addresses**: hop routers frequently answer
  from `fe80::/10` and are only reachable/meaningful with the scope. Carry
  `sin6_scope_id` from the sender sockaddr into a `SocketAddrV6`/formatted
  string (`fe80::1%en0`-style). The spikes' hop responders were all global
  scope, so this path is asserted by design, not yet observed — add a unit
  test in stage 6.
- **Single family-agnostic entry point**: the public API takes an `IpAddr`
  target (or resolves a hostname to either family, v6-preferred when both
  exist and `-6`/`-4` flags to force). Address family lives in **error
  context** (message fields), not in the error **type** — no
  `TracerouteErrorV6` variants.

### What needs root

- **macOS RAW ICMPv6**: confirmed EPERM unprivileged. Not needed for the
  chosen design (DGRAM does everything we need), but the maintainer can
  complete the RAW-vs-DGRAM comparison by running:

  ```bash
  sudo cargo run --example spike_traceroute6
  ```

  The spike auto-detects euid 0 and adds the RAW socket test. Open item:
  record the output here once run.
- FreeBSD/OpenBSD are expected to require root for all ICMPv6 modes (as they
  do for v4); unvalidated.

## Open questions (unvalidated platforms)

Nothing below has been tested — these are hypotheses to validate by running
the spikes on the target OS before implementing stage 6 there:

- **Linux**: do ICMPv6 ping sockets (`IPPROTO_ICMPV6` DGRAM, gated by
  `ping_group_range`) deliver Time Exceeded on the normal receive path, or
  only via `IPV6_RECVERR`/`MSG_ERRQUEUE` like v4 UDP mode? Linux ping sockets
  are documented to demux by identifier (kernel rewrites the id to a per-socket
  value) — opposite of the Darwin finding, so the demux layer must not assume
  either behavior. `ICMP6_FILTER` optname is 1 and semantics are inverted
  (bit = block). The spikes compile on Linux; run them there.
- **Windows**: `Icmp6SendEcho2` should make traceroute mechanics moot (the
  API handles TTL and reply matching), but hop-limit reporting and embedded
  payload access need checking. Spikes currently print
  "only implemented for macOS/Linux/FreeBSD" on Windows.
- **FreeBSD**: spikes compile (libc is already a dev-dependency there); the
  ICMP6_FILTER section is skipped pending verification of the optname value
  from FreeBSD's own headers.
- **Zone-id preservation** end to end (see contracts above) — needs a
  link-local responder to observe in the wild.
- **Source address selection**: the embedded invoking header conveniently
  reveals which source address the kernel picked — here the active
  `autoconf temporary` (RFC 4941 privacy) address, `...:41b1:1c86:aee8:e97`
  per `ifconfig`, consistent across ICMPv6, STUN/UDP, and HTTPS. If ftr ever
  reports "your address", prefer the STUN/embedded-header observation over
  guessing among the interface's many v6 addresses.

## Dependency note

The spikes require `libc` on macOS (cmsg parsing for `IPV6_HOPLIMIT`,
`ICMP6_FILTER` setsockopt) — added as a **dev-dependency** under
`[target.'cfg(target_os = "macos")'.dev-dependencies]` so the shipped library
and binary gain no new dependencies. Stage 6 will need to promote it to a
regular target dependency (or upstream cmsg/ICMP6_FILTER support into socket2)
when the production receive path adopts `recvmsg`.
