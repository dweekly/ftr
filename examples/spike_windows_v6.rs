//! Spike: Windows `Icmp6SendEcho2` behavior for IPv6 traceroute.
//!
//! Companion to `spike_traceroute6` (macOS) and `spike_linux_v6`; this one
//! answers the Windows questions from docs/IPV6_DESIGN.md before
//! `src/socket/windows_v6.rs` relies on them:
//!
//! 1. Does `Icmp6SendEcho2` accept an unspecified (`::`) source address
//!    with `sin6_family = AF_INET6`, letting the stack pick the source
//!    (the API signature *requires* a source sockaddr, unlike v4)?
//! 2. Does the `IP_OPTION_INFORMATION.Ttl` field set the outgoing hop
//!    limit, producing Time Exceeded from intermediate routers with
//!    `Status = IP_HOP_LIMIT_EXCEEDED` (11013)?
//! 3. In async (event) mode, is `Icmp6ParseReplies` required, and what is
//!    the parsed buffer layout: is `ICMPV6_ECHO_REPLY_LH` at offset 0, are
//!    the `IPV6_ADDRESS_EX.sin6_addr` words in network byte order, and
//!    where does the echoed request payload land for an Echo Reply?
//! 4. On timeout, does `Icmp6ParseReplies` return 0 with
//!    `GetLastError() = IP_REQ_TIMED_OUT` (11010), or 1 reply carrying
//!    that status?
//!
//! Run (Windows): `cargo run --example spike_windows_v6 [target6]`
//! (default target is Google Public DNS, 2001:4860:4860::8888).
//!
//! Findings are recorded in docs/IPV6_DESIGN.md. This spike stays in-repo
//! as a permanent diagnostic: re-run it if OS behavior is in question.

#[cfg(target_os = "windows")]
mod spike {
    use std::ffi::c_void;
    use std::mem;
    use std::net::Ipv6Addr;
    use std::ptr;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMPV6_ECHO_REPLY_LH, IP_OPTION_INFORMATION, Icmp6CreateFile, Icmp6ParseReplies,
        Icmp6SendEcho2, IcmpCloseHandle,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6};
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    fn sockaddr6(addr: Ipv6Addr, scope_id: u32) -> SOCKADDR_IN6 {
        let mut sa: SOCKADDR_IN6 = unsafe { mem::zeroed() };
        sa.sin6_family = AF_INET6;
        sa.sin6_addr.u.Byte = addr.octets();
        sa.Anonymous.sin6_scope_id = scope_id;
        sa
    }

    fn dump(buf: &[u8], n: usize) {
        for (i, chunk) in buf[..n.min(buf.len())].chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("      {:04x}: {}", i * 16, hex.join(" "));
        }
    }

    /// One probe: send with the given hop limit, wait on the event, parse.
    fn probe(handle: *mut c_void, dest: Ipv6Addr, hop_limit: u8, timeout_ms: u32) {
        let source = sockaddr6(Ipv6Addr::UNSPECIFIED, 0);
        let dest_sa = sockaddr6(dest, 0);

        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        assert!(!event.is_null(), "CreateEventW failed");

        // Identifier+sequence payload, same shape as the v4 implementation.
        let mut send_data = Vec::with_capacity(32);
        send_data.extend_from_slice(&(std::process::id() as u16).to_be_bytes());
        send_data.extend_from_slice(&0x1234u16.to_be_bytes());
        send_data.extend_from_slice(b"ftr-windows-v6-spike");
        send_data.resize(32, 0);

        let reply_size = mem::size_of::<ICMPV6_ECHO_REPLY_LH>() + send_data.len() + 8;
        let mut reply_buffer = vec![0u8; reply_size];

        let options = IP_OPTION_INFORMATION {
            Ttl: hop_limit,
            Tos: 0,
            Flags: 0,
            OptionsSize: 0,
            OptionsData: ptr::null_mut(),
        };

        let result = unsafe {
            Icmp6SendEcho2(
                handle,
                event,
                None,
                ptr::null(),
                &source,
                &dest_sa,
                send_data.as_ptr() as *const c_void,
                send_data.len() as u16,
                &options,
                reply_buffer.as_mut_ptr() as *mut c_void,
                reply_size as u32,
                timeout_ms,
            )
        };
        if result == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                println!("  hop_limit={hop_limit}: Icmp6SendEcho2 FAILED, GetLastError={err}");
                unsafe { CloseHandle(event) };
                return;
            }
        }

        let wait = unsafe { WaitForSingleObject(event, timeout_ms + 1000) };
        if wait == WAIT_TIMEOUT {
            println!("  hop_limit={hop_limit}: event never signaled (WAIT_TIMEOUT)");
            unsafe { CloseHandle(event) };
            return;
        }
        assert_eq!(wait, WAIT_OBJECT_0, "unexpected wait result {wait}");

        // Read the struct BEFORE Icmp6ParseReplies to see whether parsing
        // is actually required in async mode (v4 skips IcmpParseReplies).
        let raw_status = u32::from_ne_bytes(reply_buffer[28..32].try_into().expect("4 bytes"));

        let parsed = unsafe {
            Icmp6ParseReplies(reply_buffer.as_mut_ptr() as *mut c_void, reply_size as u32)
        };
        let parse_err = unsafe { GetLastError() };

        println!(
            "  hop_limit={hop_limit}: replies={parsed} (GetLastError after parse={parse_err}) raw_status_pre_parse={raw_status}"
        );
        if parsed >= 1 {
            // SAFETY: buffer is at least reply_size and the API filled it.
            let reply = unsafe { &*(reply_buffer.as_ptr() as *const ICMPV6_ECHO_REPLY_LH) };
            let addr_ex = reply.Address;
            let words = addr_ex.sin6_addr;
            let mut octets = [0u8; 16];
            for (i, w) in words.iter().enumerate() {
                octets[i * 2..i * 2 + 2].copy_from_slice(&w.to_ne_bytes());
            }
            let from = Ipv6Addr::from(octets);
            let scope = addr_ex.sin6_scope_id;
            let status = reply.Status;
            let rtt = reply.RoundTripTime;
            println!("    status={status} rtt_ms={rtt} from={from} scope_id={scope}");
            println!(
                "    struct sizes: ICMPV6_ECHO_REPLY_LH={} IPV6_ADDRESS_EX={}",
                mem::size_of::<ICMPV6_ECHO_REPLY_LH>(),
                mem::size_of::<windows_sys::Win32::NetworkManagement::IpHelper::IPV6_ADDRESS_EX>()
            );
            println!("    buffer hex (first 64B; echoed data offset check):");
            dump(&reply_buffer, 64);
        }
        unsafe { CloseHandle(event) };
    }

    pub fn main() {
        let target: Ipv6Addr = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "2001:4860:4860::8888".to_string())
            .parse()
            .expect("target must be an IPv6 address");

        let handle = unsafe { Icmp6CreateFile() };
        assert!(!handle.is_null(), "Icmp6CreateFile failed");
        println!("[1] Icmp6CreateFile: OK");

        println!("[2] loopback ::1, full hop limit (sanity: Echo Reply path)");
        probe(handle, Ipv6Addr::LOCALHOST, 128, 2000);

        println!("[3] {target}, hop limits 1..=4 (Time Exceeded path)");
        for hl in 1..=4 {
            probe(handle, target, hl, 2000);
        }

        println!("[4] {target}, hop limit 128 (destination Echo Reply)");
        probe(handle, target, 128, 2000);

        println!("[5] unroutable 2001:db8::1, 50ms timeout (timeout path)");
        probe(
            handle,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            128,
            50,
        );

        unsafe { IcmpCloseHandle(handle) };
        println!("done");
    }
}

#[cfg(target_os = "windows")]
fn main() {
    spike::main();
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("spike_windows_v6 only runs on Windows (see docs/IPV6_DESIGN.md)");
}
