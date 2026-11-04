# Detailed Technical Findings — PS5 14.10

> **Evidence scope (2026-10-18):** The 45c controls concern selected syscall-object metadata mutations, not every loader path. Later 56c/56f captures record selected CClosure redirects to existing Lua C functions with returned values and restoration. Those userland results do not establish arbitrary native calling conventions, a working ROP chain, injected-page execution, kernel R/W, or KASLR defeat. See [the evidence ledger guide](RESEARCH_EVIDENCE.md) and Findings 79/82.

Earlier findings describe their cited probe sets, not a uniform current capability state. Later observations may answer earlier open questions; the 2026-10-17 audits remain dated snapshots.

## Finding 1: W^X + Execute-Only Memory (XOM)

**Probes:** 26, 26b, 26c, 26d, 26e

The PS5 enforces write-XOR-execute strictly:
- `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` → grants `RW` only (EXEC stripped)
- `mprotect(PROT_EXEC)` → always fails with -1
- Code pages are **execute-only**: attempting to read from the code segment causes SIGBUS
- The crash handler at address `0x533118f4` handles SIGILL/SIGBUS/SIGSEGV; output starts with `77` followed by binary data

**Impact:** No ROP/JOP gadget scanning from userland. No code injection. Must find kernel R/W through data-only paths.

---

## Finding 2: Threading Completely Blocked

**Probe:** 27

All threading primitives return -1:
- `fork()` — blocked
- `rfork()` — blocked  
- `thr_new()` — blocked

**Impact:** No race conditions possible. Eliminates TOCTOU, UAF-via-race, refcount race classes entirely.

---

## Finding 3: sigaltstack Kernel Write is Dead

**Probes:** 22, 23, 24, 25, 25b

The classic sigaltstack trick (set altstack to kernel address → signal delivery writes sigframe there) fails because:
- `copyout()` validates the destination address during signal frame delivery
- Writing to a kernel address triggers EFAULT
- The kernel then kills the process

`sigprocmask` is also a no-op — returns 0 but the signal mask is never modified.

---

## Finding 4: F_SETFL is Cosmetic Only

**Probes:** 30b, 30c, 33a–33c

`fcntl(F_SETFL, O_NONBLOCK)` returns -1 but **updates the visible flags word** (F_GETFL shows the change). However the kernel **does not honor the flags**:
- O_NONBLOCK has no effect on actual read/write behavior
- O_APPEND flag also set but not honored  
- O_ASYNC flag also set but not honored
- Each F_SETFL call REPLACES the flags word (not bitwise OR)

The sandbox intercepts F_SETFL, rejects it (returns -1), but patches the userland-visible flags struct field. The actual kernel I/O path checks a separate internal socket state.

`F_SETOWN` is truly blocked — returns -1 AND the value is not applied (F_GETOWN stays -1). No SIGIO possible.

---

## Finding 5: MSG_DONTWAIT is the Real Nonblocking Mechanism

**Probes:** 33d, 33e, 33f

Since F_SETFL O_NONBLOCK is fake, nonblocking I/O must use per-call flags:
- `sendmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`
- `recvmsg(fd, msg, MSG_DONTWAIT)` with `MSG_DONTWAIT = 0x80`

Confirmed behavior:
- `recv(empty socket)` → returns -1 immediately (EAGAIN)
- `send(full buffer)` → returns -1 immediately (EAGAIN)
- SNDBUF=1 partial writes work correctly (request 4 bytes → rv=1)
- 100x rapid send/recv cycling: 100/100 success
- Both buffers=1, 50x cycling: 50/50 success

**CRITICAL:** `sendto` (syscall 133) and `recvfrom` (syscall 29) **crash the Lua loader** when registered in `syscall.resolve()`. Use only `sendmsg`/`recvmsg`.

---

## Finding 6: SCM_RIGHTS fd Passing Works Correctly

**Probes:** 28, 30b

Unix domain socket credential passing via SCM_RIGHTS is fully functional:
- Can pass 16+ file descriptors in a single message
- 5x send/recv cycle: all 5 correct (refcounts accurate)
- No refcount leak or double-free observed
- Passed fds are usable (can read/write/close)

---

## Finding 7: RAW Socket + IP_HDRINCL = Kernel Packet Injection

**Probe:** 34

This is the **most significant finding** for exploit development:
- `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` succeeds → fd allocated
- `setsockopt(IP_HDRINCL)` → rv=0 (reads back as 8 = INP_HDRINCL)
- `sendmsg()` with crafted IP+UDP packet to 127.0.0.1 → **packet reaches UDP listener**
- Confirmed: `BEEFCAFE` payload data arrived intact
- RAW socket `bind()` and `connect()` to loopback both work

TCP SYN packet was dropped — likely due to invalid TCP checksum (sent 0). TCP requires valid checksums even on loopback.

**Impact:** We can inject arbitrary IP packets into the kernel's `ip_input()` path. This opens:
- IP fragment reassembly (`ip_reass()`)
- IP options parsing (`ip_dooptions()`)
- Protocol demultiplexing
- ICMP input processing
- Any protocol handler reachable via loopback

---

## Finding 8: Fragment Reassembly — Inconclusive (Bind Issue)

**Probes:** 35, 35b

All fragment reassembly tests returned no data. However, probe 35b revealed the root cause: **`bind()` was returning -1** for the UDP listener port. Without a valid listener, no packets can be received regardless of reassembly.

The bind failure may be due to:
- Port range restrictions on the PS5
- Socket/fd limit reached
- Specific port number filtering

**Status:** Needs re-testing with verified bind success before concluding anything about fragment reassembly.

---

## Finding 9: PS5 Custom Socket Options are Benign

**Probe:** 31c

Five Sony-extended SOL_SOCKET options exist:
```
0x2000, 0x10000, 0x20000, 0x40000, 0x100000
```

All are **boolean flag bits** in the socket's `so_options` field. The option number IS the bitmask value:
- `setsockopt(SO_0x2000, 1)` → readback = 0x2000
- Same behavior on all socket types (UNIX, TCP, RAW, IPv6 RAW)
- No complex parsing, no buffer handling, no kernel pointer exposure

**Not exploitable.**

---

## Finding 10: poll() is Fully Functional

**Probe:** 32c

`poll()` works with correct BSD semantics:
- `nfds=0` → rv=0 (immediate return)
- Invalid fd → POLLNVAL (0x0020)
- `fd=-1` → ignored (standard behavior)
- Closed peer → POLLIN|POLLHUP (0x0051)
- `read(closed peer)` → rv=0 (EOF)
- Mixed fd array → correct per-fd results

---

## Finding 11: TCP_INFO Contains No Kernel Pointers

**Probe:** 31b

The 236-byte TCP_INFO structure was fully dumped and scanned:
- Contains only protocol metadata: timestamps, RTT values, window sizes, congestion state
- Connected vs unconnected socket comparison shows expected field changes
- **No kernel addresses leaked** — all pointer-sized values are protocol counters or timestamps

---

## Finding 12: Memory Layout

**Probe:** 03

Key addresses observed:
- Signal handler (crash): `0x533118f4`
- Code segment is execute-only (cannot read)
- Heap is RW, stack is RW
- `MAP_FIXED` works for page-aligned addresses in userland range

---

## Finding 13: AIO Outcomes Are Not Uniformly Established

**Probes:** 19, 19b–19g, 43p; focused retest 53a prepared, not run.

Older probe summaries describe AIO calls as blocked or as causing the loader to exit, but those summaries do not establish a common kernel-level termination for every call. The raw `19g` record shows `aio_error` returning `rv=-1`. The saved `43p` output ends immediately before its first raw AIO call result, so it supplies no result or kill record for the `make_syscall()` path. It also does not reach the planned Sony syscall scan or test syscall 663.

**Conclusion:** Exact behavior remains scoped to each logged call, argument set, and invocation path. Do not describe the AIO family as completely sandbox-killed or infer a kernel kill from a missing output tail. Retest 53a is prepared to capture per-call outcomes; it has not been run.

---

## Finding 14: kqueue and kevent Work for Tested Filters

**Probes:** 20, 21; see also [CVE-2026-58083 assessment](CVE-2026-58083-PS5-14.10.md)

- `kqueue()` returns a valid fd.
- Probe 20 registered and polled read filters, observed three events, exercised close-while-registered and 200 register/delete rounds, and registered/deleted 50 timer filters (9 timer events observed).
- Probe 21 registered signal and user filters and up to 2,000 knotes. These are bounded API observations, not proof that all filters or races behave correctly.
- The saved runs do not exercise copy-on-fork. The available process-creation run records `fork`, `rfork`, and `thr_new` returning `-1`.
- No use-after-free, kernel corruption, crash, or privilege change was observed or tested by these runs. See the CVE assessment for the evidence boundary.

---

## Finding 15: writev with IOV_MAX Boundary

**Probe:** 30b

- `writev` with 16 iovecs of 64 bytes each (1024 total) → rv=1024 ✓
- `writev` with 1024 iovecs of 1 byte each (1024 total) → rv=1024 ✓
- `writev` with 1025 iovecs → rejected (IOV_MAX=1024)

No buffer overflow at the IOV_MAX boundary. Kernel handles correctly.

---

## Finding 16: Port Bind Policy (probe 36, live)

- Ports **<1024 blocked** (rv=-1), ports **≥40000 blocked**
- Ports 1024–32767 work: 1024, 5000, 8080, 9027, 31337–31340 all bind (UDP+TCP)
- TCP 9026 fails (loader owns it); UDP 9026 binds (different protocol slot)
- INADDR_ANY binds fine; SO_REUSEADDR double-bind correctly rejected
- **This solves the 35/35b mystery:** nothing was wrong with bind on good ports; the earlier failure was port-selection-related

---

## Finding 17: ip_reass() Handles All Standard Cases Correctly (probe 39, live)

With a working listener on 31338, all fragment cases reassemble correctly:
- baseline 2-frag, out-of-order, overlap (-8B), tiny-first (8B), dup-final-overwrite, 9×8B chain — **all delivered with correct data**
- First-fragment-wins on overlap (BSD semantics preserved)
- proto=47 fragments correctly not delivered to UDP listener
- **No crash, no corruption.** Basic ip_reass attack surface is well-behaved; deeper fuzzing (timeout expiry, reassembly queue limits, 64+ fragment chains) still untested.

---

## Finding 18: ip_dooptions() Processes Options but Drops Routed Ones (probe 37, live)

- Well-formed RR/TS/NOP: sent and delivered
- Malformed option lengths (len=0, oversized, truncated): **rejected at send time** (rv=-1) — `ip_output()` validates before `ip_dooptions()` ever runs on loopback. The classic length-confusion cases never reach the parser this way.
- **LSRR, SSRR, TS-overflow-flag: send OK but NOT delivered** — kernel processes the option and drops/redirects the packet. Source routing is disabled, as expected, but this confirms option-processing code runs.
- To reach input-side `ip_dooptions()` with malformed lengths, packets must arrive from the **real network** (PC-side scapy), not loopback injection — output-path validation is the gatekeeper.

---

## Finding 19: Crash Record = ASLR Oracle (probes 41m/41o, live)

The crash handler (magic `0x13371337`) emits a ~280-byte binary record on SIGSEGV:
- `+0x08`: signal number (0x0b = SIGSEGV)
- `+0x28`: fault address (si_addr)
- `+0x20/+0x40/+0x58/+0x60/+0x80/+0xD0`: heap pointers (Lua state registers)
- `+0xB8/+0xF8/+0x100`: **code pointers into the main module**
- Code base shifted 0x2393xxxx → 0x2558xxxx between runs: **per-process ASLR, but the delta is consistent across all code pointers** — one crash leaks the module base.
- Heap base `0x3_10000000` region is stable across sessions; only the top frontier moves.

**Strategic value:** any future PC-control primitive (fake vtable etc.) needs gadget addresses. The crash record hands you the module base every time; gadgets can be resolved offline from a dumped copy of the same binary (Relapse can dump on ≤13.60).

---

## Finding 20: The 0x1A3A4EE0 "vtable" is a Session Artifact (probes 41m–41q, live)

- `0x1A3A4EE0` as a raw address is **unmapped** (SIGSEGV, si_addr confirmed 0x1A3A4E00)
- Full scans of the entire mapped heap `[0x310000000, 0x310DC0000)` plus 4 MB anchor-relative windows: **zero objects with dword 0x1A3A4EE0 exist** in fresh sessions
- The 41i/41k/41l "objects with vtable header" were artifacts of that session's heap spray (41j AFAF spray) — not naturally occurring loader objects
- **Do not chase this value without recreating the 41j spray conditions first**

---

## Finding 21: New Syscall Map (probes 38/42a/42b, live)

**Newly confirmed working:**
- `ktimer_create` (clock 0=REALTIME, 4=MONOTONIC), `ktimer_settime`, `ktimer_getoverrun` — **partially open POSIX timer surface**
- `getsockname` — works
- `accept4`, `preadv`, `pwritev`, `copy_file_range` — resolve and error correctly on bad fds (untested on real fds; no usable file fd exists since memfd is stubbed)

**Newly confirmed blocked/stubbed:**
- `ktimer_gettime`, `ktimer_delete` — blocked even on valid ids (inconsistent with settime being open — odd split)
- `getrandom` — blocked
- `ppoll` — blocked
- `cap_rights_limit/get` — blocked
- `memfd_create` — stub, returns fake fd=1
- itimerspec validation is CORRECT (nsec>1e9, negative, huge sec all rejected)
- Timer cap: 27 concurrent timers

**Incomplete minherit/msync captures (outcome and cause unresolved):**
- `minherit` — probe 38 stops at its isolated minherit section header, with no call result; cause unresolved
- `msync` — probe 42b stops after the msync section prints its region address, with no call result; cause unresolved

---

## Finding 22: Loader Session Model (live observations)

- pid increments across connections (451→458→472→493→500): the loader respawns a fresh process per TCP connection, **fresh ASLR each probe**
- Heap anchors shift per session (0x310878000, 0x310bdcfc0, 0x310e05520…) — all heap scanning must be **anchor-relative**, never hardcoded
- The mapped heap top ends in a guard page (fault at exactly page-aligned 0x310DC0000); scanning UP into the guard kills the process. Scan DOWN from a known-mapped address, or keep progress output flowing to survive the 30s socket timeout.

---

## Finding 23: Early ROP-Chain Interpretation (superseded by probe 45c)

Probes 41v/41z found ROP-shaped metadata in the Lua loader's heap, including writable `fn_addr` and argument slots. At the time, the metadata was mistaken for the active syscall path.

Probe 45c later showed that `make_syscall()` continues to work when `fn_addr` points to NOP, `ud2`, null, or unmapped memory, and when the recorded chain is corrupted. The chain is not an established execution path; the claimed arbitrary-function call and stack-pivot primitives are not confirmed.

---

## Finding 24: Direct Memory Physical Addressing Constraints

**Probes:** 15, 18, 42d, 42f, 42f2, 42g–42g4

- `/dev/dmem0` opens reliably at `fd=22` (or `fd=24`).
- Direct physical mmap survey across 90+ physical offsets revealed:
  - **Offset 0x00000000:** Consistently returns `0x80000000_C0012800` (GPU hardware status/control register).
  - **Offsets > 0x0 up to 4GB:** Return all zeros or fail.
  - **Offsets ≥ 4GB (DRAM range):** Return zeros or fail (`0xFFFFFFFFFFFFFFFF`).
- **Conclusion:** `/dev/dmem0` is an interface to the GPU's dedicated GDDR6 memory aperture, not system CPU DRAM. It cannot be used to read or modify kernel page tables or kernel data structures directly.

---

## Finding 25: FreeBSD sysarch AMD64 Architecture & Segments

**Probes:** 42b, 42c, 43c

- Standard FreeBSD `<machine/sysarch.h>` defines:
  - `AMD64_GET_FSBASE = 128`
  - `AMD64_SET_FSBASE = 129`
  - `AMD64_GET_GSBASE = 130`
  - `AMD64_SET_GSBASE = 131`
- `sysarch(128)` confirms `FSBASE` holds the userland Thread Control Block (TCB) at `0x88xxxxxxxx`. Scanning the TCB reveals only userland TLS thread pointers.
- Calling `sysarch(129)` with a zero buffer overwrites `FSBASE` to 0, which immediately crashes userland libc.
- `AMD64_GET_GSBASE (130)` queries `%gs:0`, which in FreeBSD points directly to the kernel's `curthread` structure.

---

## Finding 26: Sysctl Tree Traversal and False-Positive Sentinels

**Probes:** 42b, 42c, 42e, 42h2

- Dense memory dumps from `kinfo_proc` (+0x060) and `fstat` (+0x068) frequently show `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF`. These are **sentinel values / bitmasks** (`-1`, `0xFFFFFFFF`), NOT kernel pointers. Real kernel pointers are in the canonical higher half `0xFFFF8xxx_xxxxxxxx`.
- Walking the sysctl MIB tree (`42e`) via `sysctl.name2oid` / MIB exploration shows that Sony's kernel rejects non-leaf MIB queries or returns size 0.
- Live readable leaf MIBs: `kern.version`, `kern.ostype`, `kern.osrelease`, `hw.machine`, `hw.pagesize`, `kern.securelevel` (1024).

---

## Finding 27: Process-Termination Claims and Evidence Gaps

**Probes:** 19, 29, 30, 38, 42a, 42b, 42g2

Several old probe notes describe calls as instant kills, but a truncated socket capture alone cannot distinguish a kernel termination from a Lua failure, connection loss, or capture truncation. The AIO and kenv claims in particular were too broad: 43p ends before its first AIO result, 19g records `aio_error` returning `-1`, and the 42a/42g2 logs stop at the kenv header.
1. `minherit` (probe annotation: syscall 250) — probe 38 ends at its minherit section header without a call result or termination record.
2. `msync` (probe annotation: syscall 226) — probe 42b ends after printing the msync region address, without a call result or termination record.
3. `kenv` (syscall 390) — unresolved: the 42a and 42g2 captures stop at the call header, with no result or kill record.
4. AIO-family outcomes vary across the available records; 19g records `aio_error rv=-1`, while 43p ends before its first AIO result. Do not label all `aio_*` calls as kills. The raw 14.10 AIO retest is pending (53a).
5. Reading Execute-Only Memory (XOM) system lib `.text` sections — unrecoverable userland faults were observed in the cited probes.

---

## Finding 28: sceKernelMtypeprotect (Syscall 585) Returns Success

**Probes:** 42f

Sony's `sceKernelMtypeprotect` (syscall 585) returned `ret=1` — a positive value indicating success with a status code — while all neighboring Sony syscalls (576, 580, 581, 586, 616, 619) returned -1. This syscall changes memory type protections on PS5 and may bypass the standard W^X enforcement that blocks `mprotect(EXEC)`. If `mtype_protect` operates on a different protection domain (GPU memory types, SPU pages), it could grant execute permissions that `mprotect` cannot.

**Impact:** Potential W^X bypass. Probe 43h and 43k test this with actual mmap'd pages and various protection arguments. If RWX can be achieved, arbitrary code execution without ROP becomes possible.

---

## Finding 29: sceKernelGetCpuUsage (Syscall 617) Is Live

**Probes:** 42f

`sceKernelGetCpuUsage` (syscall 617) returned `ret=0` with an empty 8-byte buffer. This is the only other Sony-specific syscall besides 585 that succeeded. PS5 has 16 logical cores (Zen 2 8C/16T), and CPU usage data structures in the kernel typically contain per-CPU scheduler data, thread lists, and pointers to kernel structures. A larger output buffer or per-CPU index argument may reveal kernel addresses.

**Impact:** Potential kernel info leak. Probe 43k tests with various buffer sizes and argument patterns.

---

## Finding 30: kern.msgbuf Returns Data (Partial Read)

**Probes:** 42b

`sysctl kern.msgbuf` (MIB {1, 33}) returned 8 bytes with value `0x7EF710000`. The kernel message buffer (`dmesg`) is typically 32-256KB and contains boot messages including kernel module load addresses, memory layout, driver init data, and KASLR base. The 8-byte value `0x7EF710000` (~34 GB range) could be a direct-map physical address or a pointer to the message buffer region. A full-size read could capture the entire dmesg output with KASLR-defeating addresses.

**Impact:** Most promising KASLR defeat vector. Probe 43j reads the full buffer (up to 64KB) and scans for kernel pointers.

---

## Finding 31: mincore() Works as Memory Residency Oracle

**Probes:** 42i

`mincore()` (syscall 78) returned `ret=0` with `vec=0x1F` (5 consecutive pages resident). This syscall reports whether virtual address pages are backed by physical memory. It can be used as a side-channel oracle: probing page residency at guessed kernel virtual addresses may detect the kernel base without a direct pointer leak (cache-based KASLR defeat). Even if kernel VA probing fails, it maps the full process VA space layout.

**Impact:** Side-channel KASLR oracle. Probe 43l tests kernel VA range probing and process VA space mapping.

---

## Finding 32: PS5 Socket Options Accept Oversized Buffers

**Probes:** 31c

Five PS5-specific socket options (0x2000, 0x10000, 0x20000, 0x40000, 0x100000) all accept `setsockopt(len=256)` with `rv=0`. These are boolean flags (4 bytes) but the kernel accepted 256-byte writes on UDP, TCP, and RAW sockets. If the kernel copies the full user buffer length into a smaller kernel struct field, this is a kernel heap overflow — writing 256 bytes into a 4-byte field would corrupt adjacent kernel heap objects.

**Impact:** Potential kernel heap corruption primitive. Probe 43m tests with progressively larger buffers (up to 4KB) and checks getsockopt return length for over-read indicators.

---

## Finding 33: /dev/hid Opens Successfully

**Probes:** 42c

`/dev/hid` (the HID/Human Interface Device driver) opens with `fd=24`. While ioctl was "blocked" via `syscall.resolve()`, it is untested via `make_syscall(54)`. The HID driver manages PS5 controller/gamepad input and exposes device descriptors, report buffers, and internal state through ioctls. If ioctl works via make_syscall, we gain access to HID kernel state which may contain kernel addresses.

**Impact:** Potential kernel info leak or write primitive via HID ioctls. Probe 43n tests ioctl(54) via make_syscall with standard HID and USB ioctl codes.

---

## Finding 34: thr_self Returns Real Thread ID

**Probes:** 42j

`thr_self()` succeeded with `ret=0`, returning `tid=101819`. While this is not directly a kernel pointer, the thread ID is a handle into kernel thread structures. Combined with other primitives, the TID could be used to locate the `struct thread` in kernel memory (e.g., via `kern.proc.pid` if it leaks `ki_tdaddr`).

**Impact:** Building block for kernel exploitation. The TID value is consistent and identifies the kernel thread object.

---

## Finding 35: fn_addr Encoding Pattern (0x9FE5 Prefix)

**Probes:** 42f, 42g, 42h, 42i, 42j

All fn_addr values across different PIDs share a constant `0x9FE5` upper 16-bit prefix with ASLR-varying middle bits and `0130` suffix:
- PID 582: `0x9FE510A60130`
- PID 610: `0x9FE511078130`
- PID 645: `0x9FE510DF0130`

The `0x9FE5` constant survives ASLR and may encode a non-randomized memory region, a GPU command buffer prefix, or an instruction encoding (`E5 9F` = `IN EAX, 0x9F` on x86-64). Understanding this encoding is key to reliable fn_addr manipulation across connections.

**Status:** The observed prefix pattern is descriptive only. Probe 45c found tested syscall results persisted after specific fn_addr mutations, so the proposed ROP-targeting impact is not established; the field's role and entropy interpretation remain unverified.

---

## Finding 36: AF_ROUTE Request Delivery Was Not Established (probe 43o)

**Probes:** 43o

- `socket(PF_ROUTE=17, SOCK_RAW, 0)` succeeds → `fd=22`
- `RTM_GET` for the default route (0.0.0.0): the write returns -1; successful delivery is not established
- The read returned 108 bytes and zero detected pointers; its attribution to a request echo or a kernel-generated response is unresolved
- Writes for the other tested destinations also fail
- The passive read also reports 108 bytes; the log does not provide a separate byte dump establishing its origin or equality
- The `NET_RT_DUMP`/`NET_RT_IFLIST` fallback branch was not reached in this saved run: it is conditional on socket creation failure, whereas the log records fd=22

**Conclusion:** The AF_ROUTE leak was not validly tested. The failed writes and read of unresolved origin cannot establish either a leak or a 14.10 patch. A corrected retest is prepared as 53b and remains unrun.

---

## Finding 37: Raw AIO Result Is Unresolved (probe 43p)

**Probe:** 43p

- The saved output shows the sysctl canary succeeded, then prints that `aio_error` syscall 317 is about to be called.
- The file ends before any result, error, or post-call canary is printed.
- The planned later Sony syscall scan, including syscall 663, therefore has no result in the saved run.

**Conclusion:** The saved log is incomplete and does not establish the outcome of syscall 317 or the state of Sony syscall 663 on 14.10. Treat both as untested by this artifact; see [the secondary exploit audit](SECONDARY_EXPLOIT_AUDIT_13.60.md).

---

## Finding 38: kldstat/kldsym Results Are Missing (probes 43a, 43b)

**Probes:** 43a, 43b

- The 43a log is 145 bytes and contains only a header
- The 43b log is 116 bytes and contains only a header
- Neither log contains a syscall result, error, or kill record

**Conclusion:** The outcomes and cause of truncation are unknown. KLD introspection has not been established as blocked or successful. Retest 53c is prepared and remains unrun.

---

## Finding 39: fn_addr and ROP-Field Writes Did Not Alter Tested Calls (probes 43i, 45c)

Probe 43i records writes/readback of `fn_addr` and slot0. Its source restores slot0 before getpid; the modified slot was not tested across that call. The fn_addr sentinel persisted across getpid. Neither observation establishes dispatch control. Probe 45c then changed those fields to invalid targets, corrupted the chain, and observed normal syscall results with no crash.

**Conclusion:** The tested writes did not establish an arbitrary function-call primitive. Probe 45c's calls continued after specific mutations, but the complete dispatch path and the fields' role remain unknown. Do not treat them as kernel read/write.

---

## Finding 40: fstat Works via make_syscall, ioctl/dup Still Blocked (probe 43e)

**Probes:** 43e

- `fstat` (syscall 189) via make_syscall → **works** on fd 0, 3, 4, 5. Returns full stat structs.
  - `+0x68` contains `0xFFFFFFFF_FFFFFFFF` — sentinel, not kernel pointer
  - Different inode numbers per fd (0x2A, 0x18, 0x63, 0x64)
  - All files show same timestamps and `st_blksize=0x4000` (16KB = PS5 page size)
- `ioctl` (syscall 54) via make_syscall → returns -1 for FIONREAD, TIOCGETA, SIOCGIFADDR
- `dup`/`dup2` (syscalls 41/90) → return -1
- `thr_new` (syscall 455) → crashed the process (garbled output = crash record)

**Conclusion:** fstat works but leaks no kernel pointers. ioctl is kernel-blocked even via make_syscall. Threading remains completely blocked.

---

## Finding 41: GS Base is Zero, FS Base is Userland (probe 43c)

**Probes:** 43c

- `sysarch(GET_FSBASE=128)` → `0x8817C8080` (userland TCB, expected)
- `sysarch(GET_GSBASE=130)` → `0x0` (zero — no kernel `curthread` pointer leaked)
- `sysarch(GET_XFPUSTATE=132)` → `ret=0`

**Conclusion:** GS base does not contain a kernel pointer on PS5. This is likely because `%gs` is not used for `curthread` in the PS5 kernel variant, or Sony zeroed it in userland context.

---

## Finding 42: Recorded Sysctl Operations (probe 43f)

**Probes:** 43f

- The read and write(-1) labeled `kern.securelevel` each returned -1.
- Reads labeled `kern.coredump`, `security.bsd.unprivileged_proc_debug` and `kern.maxproc` returned -1. Their conditional writes were not reached.
- The read labeled `kern.somaxconn` returned 0/value 1024; no write was attempted.
- Reads labeled `tcp.mssdflt` and `kern.maxfiles` returned -1.

**Conclusion:** `results/43f_sysctl_write_20261016_180756.txt` records one failed write attempt, not a survey proving all sysctl writes blocked. The labels follow the probe's assumed MIB mappings; failed calls do not independently verify those Sony mappings or the cause of failure. See the conditional write branches in `probes/phase10_untested_theories/43f_sysctl_write.lua`.

---

## Finding 43: Sony Syscall 557 Returns Live Data (probe 43g)

**Probes:** 43g

- Sweep of syscalls 540-650 found **syscall 557 returns `ret=16901`** — a non-error positive value
- The process was killed shortly after (likely hit a kill-trigger syscall in the sweep)
- Syscall 620 also returned `ret=0` (alive but empty)
- All other swept syscalls returned -1

**Conclusion:** Syscall 557 is a live Sony-custom syscall returning meaningful data. Needs targeted investigation with proper arguments. The value 16901 (0x4205) could be a status code, count, or flags.

---

## Finding 44: mtypeprotect Returns 1 for All Protection Values Including RWX (probes 43h, 43k)

**Probes:** 43h, 43k

- `sceKernelMtypeprotect` (syscall 585) returns `ret=1` for all tested protection values:
  - PROT_READ|PROT_EXEC (RX): ret=1
  - PROT_READ|PROT_WRITE|PROT_EXEC (RWX): ret=1
  - PROT_EXEC only: ret=1
  - PROT_READ|PROT_WRITE (RW): ret=1
  - PROT_READ only: ret=1
- After calling mtypeprotect(RWX), the page is still readable and writable
- Standard `mprotect(RX)` still returns -1 on the same page
- Execution test was not performed (safety flag in probe)

**Conclusion:** mtypeprotect consistently returns 1 (success?) but does not appear to change `mprotect`-visible permissions. It may operate on a separate protection domain (GPU memory types) or its return value of 1 may indicate "not applicable" rather than success. Needs execution test to determine if EXEC permission was actually granted.

---

## Finding 45: kern.msgbuf Returns Only 8 Bytes (probe 43j)

**Probes:** 43j

- Size query returns 8 bytes (not the expected 32-256KB dmesg buffer)
- Content: `0x00 0x40 0xBE 0xEF 0x07 0x00 0x00 0x00` — looks like a truncated header or sentinel
- `kern.features` returns `00000000-0000-0000-0000-000000000000` (null UUID)
- `kern.boottime` readable: `0x6AD29A84` (Unix timestamp) + microseconds
- `kern.proc.auxv` blocked (ret=-1)

**Conclusion:** kern.msgbuf is heavily filtered — returns a minimal 8-byte stub instead of the full dmesg. No kernel pointers available through this path.

---

## Finding 46: mincore Cannot Probe Kernel VA Space (probe 43l)

**Probes:** 43l

- mincore works correctly on userland mappings (eboot, GPU mmap)
- Returns `vec=[0x0B, 0x0B, 0x0B, 0x09]` for eboot text pages
- **All kernel VA probes return -1**: KERNBASE (0xFFFF8000_*), DMAP (0xFFFFF800_*), high kernel (0xFFFFFF80_*)
- Unmapped userland addresses correctly return -1
- Interesting: address `0x800000000` (32GB) returns ret=0, vec=0x00 (mapped but not resident)

**Conclusion:** mincore validates that the address is in the current process's VA space. Kernel addresses are rejected. No KASLR oracle via mincore.

---

## Finding 47: Socket Options Accept Large Buffers but Don't Overflow (probe 43m)

**Probes:** 43m

- `setsockopt` accepts buffers up to 4096 bytes for SO_SNDBUF (0x1001) and PS5 custom options
- `getsockopt` always returns the correct 4-byte value regardless of input size
- Same behavior on UDP, TCP, and RAW sockets
- Standard options (SO_KEEPALIVE, SO_DONTROUTE, etc.) also accept 256-byte buffers

**Conclusion:** The kernel likely clamps the copy length to the expected option size internally. No kernel heap overflow — the large accept is benign (kernel ignores excess bytes). Not exploitable.

---

## Finding 48: /dev/hid Open but ioctl Returns Sony Error (probe 43n)

**Probes:** 43n

- `/dev/hid` opens at fd=23
- `fstat(/dev/hid)` works — different inode (0x5A) from pipe fds
- All ioctl codes return `-2143617020` (`0x80740004`) — a Sony-specific error code meaning the operation is not supported for this device type
- FIONREAD returns 0 (no data available)
- `read()` returns 0
- `/dev/null`, `/dev/zero`, `/dev/urandom` all open successfully
- `/dev/console`, `/dev/tty`, `/dev/bpf`, `/dev/crypto`, `/dev/pf` all blocked

**Conclusion:** ioctl via make_syscall reaches the kernel (not sandbox-killed), but the HID device rejects all tested ioctl codes with a Sony error. The error code `0x80740004` appears device-specific. Other devices (/dev/bpf, /dev/crypto) remain blocked at open().

---

## Finding 49: CpuUsage Returns Empty Data, Syscall 620 Alive (probe 43k)

**Probes:** 43k

- `sceKernelGetCpuUsage` (617) with buffers from 8 to 4096 bytes: ret=0 but all-zero output
- Per-CPU queries (cpu 0-15): all ret=0, zero data
- Various argument patterns (null, 1, -1): all zero
- Syscall 620: ret=0 (another live Sony syscall, unknown function)
- Syscalls 615, 616, 618, 619: all ret=-1

**Conclusion:** CpuUsage returns success but no data — likely requires specific argument structures or calling conventions not yet discovered. Syscall 620 is alive but unknown.

---

## Finding 50: `mtypeprotect` Did Not Establish Native Code Execution (probes 44a, 45c)

Probe 44a prints its NOP execution-success banner when pcall survives, without requiring a distinguishing side effect. The mov-eax test requested 0x41414141 but returned PID 121. Neither that return nor mtypeprotect ret=1 establishes execution. Probe 45c recorded tested syscall results persisting with NOP, ud2, null, unmapped, and redirected fn_addr values and after selected chain mutations. This contradicts the claimed dependency for those calls but does not identify the complete dispatch path.

**Conclusion:** W^X bypass and native code execution are unconfirmed. A return value of 1 from `mtypeprotect` is not proof that a page became executable or that instructions ran.

---

## Finding 51: Sony Syscall 557 is a Type/Status Query (probe 44b)

**Probes:** 44b

- Returns `0x4205` (16901) **only when arg1 is a valid buffer address**
- Returns -1 with no args, null args, or with arg1 as a small integer
- No data written to the output buffer (0 changed dwords)
- Neighboring syscalls 553-560 all return -1 (14.10 isolation sweep, 2026-10-20). 561 does
  **not** return: it is an absent slot and terminates the process, so this line's original
  "553-561" range was never actually covered at its top end. See
  `docs/SYSENT_PRESENCE_14_10.md`.
- Value breakdown: byte 0 = 0x05 (flags?), byte 1 = 0x42 (type 66?)

**Conclusion:** Syscall 557 appears to be a process type/sandbox level query. The return value itself IS the data (not written to a buffer). The value 0x4205 likely encodes the process sandbox class. Not directly useful for KASLR but documents the sandbox state.

---

## Finding 52: Sockopt Heap Corruption Not Possible (probe 44c)

**Probes:** 44c

- Sprayed 40 sockets around target, wrote 4KB patterns to PS5 custom options
- No corruption detected on any adjacent socket at any buffer size (64-4096)
- SO_SNDBUF/SO_RCVBUF reject oversized buffers (ret=-1)
- getsockopt always returns exactly 4 bytes

**Conclusion:** The kernel's `sosetopt()` path clamps the copy to the option's expected size. The large `setsockopt()` acceptance is benign — excess bytes are ignored, not written to kernel heap. Confirmed not exploitable.

---

## Finding 53: Creative Sysctl Paths — NET_RT_IFLISTL Returns 6.5KB (probe 44d)

**Probes:** 44d

- **NET_RT_IFLIST** (MIB {4,17,0,0,3,0}): returns 1408 bytes, no kernel pointers
- **NET_RT_IFLISTL** (MIB {4,17,0,0,5,0}): returns **6536 bytes** of interface data, no kernel pointers
- **kern.usrstack**: returns `0x7EF5A8000` (userland stack top)
- **kern.proc.auxv**: returns only 4 bytes (truncated/filtered: `0x08008011`)
- **kern.proc.sigtramp**: returns 0
- Signal handlers: all at `0x511FD8F4` (userland crash handler address — another ASLR data point)
- Blocked: pathname, groups, rlimit, umask, osrel, cwd, ps_strings, hw.pagesizes

**Conclusion:** NET_RT_IFLISTL provides substantial network interface data but Sony scrubbed all kernel pointers from it. The signal handler address `0x511FD8F4` is consistent with eboot ASLR (confirms the crash handler offset). No KASLR defeat from these paths.

---

## Finding 54: Apparent Shellcode Execution (probe 45a; superseded by 45c)

Probe 45a recorded normal syscall returns and actual_len=2048, initially attributed to shellcode. Its source initialized oldlenp to 0x800, which equals 2048; no length change is established, and the result slot retained its sentinel. Probe 45c later recorded tested calls continuing after specific fn_addr and chain mutations. The 45a observations therefore do not establish that the shellcode ran; the dispatch implementation remains unidentified.

---

## Finding 55: Shellcode Side Effects Were Not Demonstrated (probe 45b; superseded by 45c)

Probe 45b found no observable writes from the proposed shellcode path and noted that return values stayed equal to the process ID. Probe 45c showed tested syscall results persisting after specific fn_addr and chain mutations. Native shellcode execution remains unconfirmed, and the dispatch implementation is unresolved.

---

## Finding 56: Tested Syscall Results Persisted Across fn_addr and Chain Mutations (probe 45c)

**Probe:** 45c (execution reality check)

The completed `results/45c_execution_reality_check_20261016_192713.txt` run reports (the earlier `192602` artifact stops in section B and is not merged with it):

- sysctl(202) returned 1096 bytes with fn_addr set to a NOP+ret page, and again with its original value.
- getpid continued returning PID 135 for the tested fn_addr offsets, including null, an unmapped value, and ud2.
- getpid still returned PID 135 after chain entries 0–7 were overwritten.
- The logged fn_addr value did not match any loaded module text range checked by the probe; the probe skipped reading it because of execute-only memory.

These observations contradict the earlier model for the tested calls: changing those fields did not change their recorded results. They do not show how the loader implements dispatch, whether errors are caught elsewhere, or whether every call path ignores the fields. The checks are from one probe run, not independent replications.

**Conclusion:** These 43i–45c observations do not establish that fn_addr or the ROP-shaped metadata provides a callable function primitive, native code execution, or kernel read/write. Later CClosure redirects (Finding 82) concern a separate mechanism. Treat the earlier execution and W^X interpretations as unsupported. The complete dispatch implementation remains unidentified; see the partial structural observation in Finding 58.

## Finding 57: Syscall 557 Buffer-Modification Claim Was a Probe False Positive (probe 46a)

**Probe:** 46a; saved runs `results/46a_sony_syscall_deep_20261016_194741.txt` (format-string crash) and `results/46a_sony_syscall_deep_20261016_195704.txt` (re-run).

The `(0, {size=0x160})` pattern zeroes the struct, writes `0x160` at offset 0, and reports return -1. Its original modification checker compares dwords at offsets `+4..+0x50` against `0xDEADDEAD`, not the initialized zero baseline. An unchanged buffer therefore triggers `struct modified after offset 4!`.

The first dword in the saved dump was supplied by the probe; it is not evidence of a kernel write. The dump contains only the first 64 bytes, less than the checked `+4..+0x53` byte window, so it also cannot establish that the entire window or allocation was unchanged.

**Conclusion:** The earlier claim that this proves the kernel reads and writes the struct is retracted. The probe now passes an explicit zero baseline at this caller and the analogous syscall-620 caller, while sentinel-filled checks retain their original baseline. The actual probe passes the offline Lua 5.1 regression harness, including injected writes and range boundaries; no corrected console run has been performed. Interface identity and kernel effects remain unestablished. See [the 14.10 evidence correction and retest plan](SYSCALL_557_14_10_EVIDENCE.md).

## Finding 58: Syscall Objects Share a C-function __call (probe 46b; implementation unknown)

Probe 46b's partial log reports that syscall entries are Lua tables sharing a metatable at 0x3110237c0. It labels __call at 0x311023aa0 as a C function and also lists __tostring, create_initial_chain, new, arg_addr, and chain fields. The output ends during Section D.

This is a structural observation, not a disassembly of the function. It does not establish what __call invokes, whether it uses a syscall instruction, or how it relates to the ROP-shaped data. Probe 45c's results show only that selected calls persisted after the tested metadata mutations.

**Conclusion:** The loader's complete dispatch implementation remains unknown. Do not treat the reported C-function address or metatable layout as a redirection primitive; further analysis must first identify the function's implementation and validate effects in a controlled test.

## Finding 59: socketpair Works via make_syscall — New IPC Primitive (probe 46d)

**Probe:** 46d (socket bypass)

- `socketpair(AF_LOCAL, SOCK_STREAM)` via make_syscall → **ret=0, fd0=22, fd1=23** — works!
- `socketpair` does not exist in `syscall.resolve()` (nil)
- Socket creation is otherwise identical between make_syscall and resolve — no hidden socket types
- SCTP still fails (-1) via both paths
- TCP connect-back to PC timed out (no server running)

socketpair gives us a bidirectional local IPC channel within the same process. This could be useful for: self-pipe tricks, poll/select testing, or as a data channel if we find code execution.

## Finding 60: Recorded Syscall 557 Return Patterns (probes 47a, 46a re-run)

**Probes:** 47a (version sweep 0-255), 46a (re-run with format fix)

The saved runs must not be merged into a per-connection formula. The two 46a patterns also change the header layout, not just a version value:

| Saved capture | Dwords initialized at offsets `+0`, `+4` | Recorded return |
|---|---|---:|
| `results/46a_sony_syscall_deep_20261016_194741.txt` | `0x200`, `0` | 16901 |
| `results/46a_sony_syscall_deep_20261016_194741.txt` | `1`, `0x200` | 518 |
| `results/47a_dispatch_deep_20261016_195632.txt`, version sweep | `0`, `0x200` | 16901 |
| `results/47a_dispatch_deep_20261016_195632.txt`, version sweep | `1`, `0x200` | 518 |
| `results/46a_sony_syscall_deep_20261016_195704.txt` | `0x200`, `0` | 1038 |
| `results/46a_sony_syscall_deep_20261016_195704.txt` | `1`, `0x200` | 1039 |

Within 47a's version sweep, positive versions 1–255 follow `return = 517 + version`; version zero is an exception. The same displayed `0`, `0x200` header later returns 1034 in that run's size sweep, which initializes a different extent of the allocation. This is an observed confound, not evidence for its cause or a fixed kernel interface.

Finding 57 explains why 46a's struct-modification alarm is a probe artifact, not evidence of a write primitive. 47a's sentinel checks monitor only offsets `+8..+0x1FF`; their no-modification messages are not universal negatives. No kernel pointer or exploit was demonstrated. A resource/allocation-metric interpretation remains a hypothesis; see [the source and capture citations](SYSCALL_557_14_10_EVIDENCE.md).

The saved 46a re-run records return 0 for the tested syscall-620 calls. Its zero-struct dump uses the same incorrect sentinel baseline and is not write evidence. These limited observations do not prove syscall 620 is universally inert.

## Finding 61: CClosure Write Test Skipped — Address Parse Bug in 47a (probe 47a)

Probe 47a's critical Section C (writable CClosure function pointer test) produced **zero output** because the `__call` address `"function: 3108dbaa0"` has no `0x` prefix — the regex `match("0x([0-9a-fA-F]+)")` returns nil. The entire CClosure scan was silently skipped.

This parse issue was addressed by 47b. The remaining evidence gap is separate: 47b's write loop omitted offset +0, so it does not establish whether the C function pointer is writable. Retest 53d covers the missing offset and restores each tested value immediately; it does not attempt control-flow redirection.

Key chain metadata from 47a Section B:
- `chain.stack_base = 0x3109b60f0` (ROP chain base)
- `chain.jmpbuf = 0x3109b8130` (longjmp buffer — could be writable!)
- `chain.recover_from_call = 0x3109b8100`
- `chain.fcall_stub = table: 3108d00e0`
- `chain.retval_addr = table: 3108ae100`
- `chain.finalized = true`, `chain.enable_mock_push = false`

## Finding 62: SCM_RIGHTS Over Socketpair — Incomplete (probe 47a)

sendmsg with SCM_RIGHTS on socketpair succeeds (ret=4) and recvmsg succeeds (ret=4), but the cmsg data was all zeros — the ancillary data wasn't properly received. Either the cmsg buffer layout is wrong, or the kernel stripped the control message. LOCAL_PEERCRED returns uid=1, gid=1, pid=0 — sandbox credentials.

## Finding 63: CClosure C Function Pointer Writability Is Unresolved (probe 47b) ★★

**Probe:** 47b (CClosure hijack — fixed uint64 format bug)

The 47b log examined a CClosure, but its write loop covered offsets `{16,24,32,40,48}` and omitted `+0`. The log also labels `+16` writable in one section while other sections make conflicting statements about the candidate at `+0`.

| Offset | Value | Writable | Purpose |
|--------|-------|----------|---------|
| +0 | `0x3_105AF820` | **NOT TESTED** | Candidate pointer; write loop omitted this offset |
| +8 | `0x206` | — | Type flags |
| +16 | `0x3_105AF820` | CONFLICTING | Log labels this writable in one section; interpretation is inconsistent |
| +24 | `0x3_104CE000` | Reported writable | Field role is not independently established |
| +32 | `0x3_10549160` | Reported writable | Field role is not independently established |
| +40 | `0xF8AFAFAF_AFAFAFAF` | Reported writable | The log calls it sentinel/padding; no dispatch effect is shown |
| +48 | `0x1_83D58EE0` | Reported writable | Value range alone does not identify it as executable code |

**No conclusion about offset +0 is supported.** The `+16` observation is inconsistent across the log, so it should not be used to infer the layout or control-flow behavior. Retest 53d checks all relevant qword offsets and records restoration status.

**ROP chain and `fn_addr`:** probe 45c demonstrated that `make_syscall()` continues to work when those metadata fields are invalidated or the chain is corrupted. Their writability does not show that this dispatch path consumes them.

**Status for the original probe set:** no native execution was established through fn_addr/ROP. Probe 45c contradicts that dependency for tested calls without identifying the dispatcher. Later 53d records writes/restoration, and 56c/56f record selected CClosure redirects; see Finding 82. These do not validate the earlier fn_addr model.

---

## Finding 64: SCTP Raw Socket Available — New Kernel Attack Surface (probe 48a) ★★

**Probe:** 48a (SCTP/IPv6/ICMP protocol availability sweep)

SCTP raw sockets are available on the PS5:
- `socket(AF_INET, SOCK_RAW, 132)` returns fd=22 — **SCTP raw socket open**
- SCTP stream/dgram/seqpacket all fail (-1) — only raw mode works
- SCTP/INET6 stream and seqpacket also fail

SCTP is a complex protocol with its own state machine, chunk processing, and association management in the FreeBSD kernel (`netinet/sctp_*`). Raw SCTP sockets allow crafting arbitrary SCTP chunks that hit the kernel's SCTP input path — a large, rarely-audited code surface.

**Impact:** SCTP input processing (init/cookie/data/sack/heartbeat chunks) is a fresh kernel attack surface. FreeBSD's SCTP implementation has had historical vulnerabilities. Crafted SCTP packets from the PC to PS5 can exercise this code.

---

## Finding 65: IPv6 Fully Available — TCP, UDP, RAW, ICMPv6 All Open (probe 48a) ★★

**Probe:** 48a

IPv6 is fully operational:
- TCP/IPv6: OPEN (fd=22)
- UDP/IPv6: OPEN (fd=22)
- RAW/IPv6: OPEN (fd=22)
- ICMPv6/IPv6: OPEN (fd=22)
- DGRAM/IPv6 proto=0: OPEN
- IPV6_V6ONLY default=1, can be disabled (dual-stack possible)
- 17 IPv6 raw protocols available (0,1,2,6,17,41,47,50,51,58,59,89,103,112,132,136,255)

**Impact:** IPv6 adds entire parallel kernel code paths — NDP, IPv6 fragment reassembly, extension header processing, ICMPv6 handling. These are separate implementations from IPv4 and represent substantial untested kernel attack surface.

---

## Finding 66: 143 Raw IPv4 Protocols All Create Sockets (probe 48a)

**Probe:** 48a

Every IP protocol number from 0 to 142 successfully creates a SOCK_RAW socket. Notable named protocols: HOPOPT(0), ICMP(1), IGMP(2), IP-in-IP(4), TCP(6), UDP(17), IPv6-encap(41), GRE(47), ESP(50), AH(51), ICMPv6(58), OSPF(89), PIM(103), VRRP(112), SCTP(132), UDPLite(136).

Socket option enumeration on a UDP socket shows standard SOL_SOCKET options (SNDBUF=9216, RCVBUF=42080) and IPPROTO_IP options including IP_OPTIONS (len=0), IP_RECVOPTS, IP_RECVRETOPTS, IP_RECVDSTADDR, IP_IPSEC_POLICY, IP_RECVORIGDSTADDR.

**Impact:** Socket creation and send results do not independently establish delivery to each protocol's input handler or handler coverage. Protocols like GRE, ESP, AH, IGMP, PIM, VRRP have complex parsers that may not be hardened on PS5.

---

## Finding 67: IP Options Listener Works, Awaits PC-Side Injection (probe 46c)

**Probe:** 46c (IP options listener)

The PS5 successfully:
- Created UDP socket (fd=22) and bound to port 31338
- Set IP_RECVOPTS sockopt (ret=0)
- Created RAW(UDP) socket (fd=23) for IP header access
- Ran 1200-iteration receive loop (120s window)

Received 0 packets — the PC-side `ip_fragment_inject.py` was not running during the window. The listener infrastructure works; this is a coordinated two-machine test requiring simultaneous PC+PS5 execution.

**Impact:** Test infrastructure validated. When run with PC-side injection, this will test whether IP options survive to the PS5 application layer and whether malformed options can trigger kernel bugs in `ip_dooptions()`.

---

## Finding 68: SCTP Chunk Parser Handles All 39 Fuzz Variants Without Crash (probe 48b)

**Probe:** 48b (SCTP loopback fuzz via raw IP + IP_HDRINCL to 127.0.0.1)

Sent 39 malformed SCTP packets to loopback via `sendto()` on raw socket with IP_HDRINCL. All packets delivered successfully (ret = packet length). No crashes.

Variants tested: INIT with len=0/1/3/0xFFFF, vtag!=0, 0/0xFFFF streams, rwnd=0; ABORT with T-bit; SHUTDOWN cum_tsn=max; ERROR cause_len=0; HEARTBEAT 124B payload; COOKIE_ECHO garbage/empty; COOKIE_ACK no-assoc; SACK with 100 gaps/max gaps+dups/undersized; multi-chunk INIT+ABORT, double INIT, 50 ABORTs, type 0-15 chain; unknown chunk types 62-255 with all action bits; FWD_TSN max/48 streams. Also sent 5 variants to LAN IP (10.0.0.96).

**Impact:** The SCTP chunk parser (`sctp_input()` → `sctp_process_init()` etc.) is robust against basic malformed chunks. Deeper attacks needed: established SCTP associations (INIT→INIT-ACK→COOKIE-ECHO→COOKIE-ACK handshake), state-dependent chunks (DATA/SACK/FWD-TSN on live associations), and timing-based attacks.

---

## Finding 69: IPv6 Extension Header Parser Handles All 83 Fuzz Variants Without Crash (probe 48c)

**Probe:** 48c (IPv6 extension header fuzz via raw IPv6 socket to ::1)

Sent 83 malformed IPv6 packets with crafted extension headers. Zero crashes, zero send errors.

Sections tested:
- **Hop-by-Hop (B):** PadN overrun (len=100), len=255 with 8B sent, Router Alert, Jumbo 4GB, unknown types with all action bits (0x40/0x80/0xC0/0x3F/0x7F/0xBF/0xFF), double HBH
- **Routing (C):** Type 0 CVE (deprecated), segleft=255 overflow, Type 2 MobileIPv6, unknown type 255, len=0 with segleft=10 underflow, len=255 truncated
- **Fragment (D):** Start reassembly, max offset (8191), overlapping fragments, atomic fragment, 32 fragment bomb IDs, nested fragment headers
- **Destination Options (E):** Home Address (MobileIPv6), unknown types with action bits
- **Chained Headers (F):** Full chain (HBH→RH→Frag→Dest→None), 16-deep nesting, self-loop, HBH not first, Routing→HBH mid-chain
- **ICMPv6 (G):** NS too short, NS option length=0 (parser loop risk), RA max lifetimes, Redirect option length=0, Echo 1KB, unknown types 200-255
- **No Next Header (H):** payload_len=0, payload_len=16 with next=59
- **Payload Length (I):** len=0 with data, len=65535 truncated, version=4/0 confusion

**Impact:** The saved 48c run reports 83 packets, zero send errors and COMPLETE. This establishes continued probe output after those sends, not complete parser/handler coverage or general hardening. Next-level attacks: actual IPv6 fragment reassembly with real first+last fragments, NDP cache poisoning with valid checksums, and IPv6-in-IPv4 tunneling edge cases.

---

## Finding 70: TCP_INFO Leaks Sequence Numbers at Offsets +108/+112 (probe 49a) ★★

**Probe:** 49a (TCP stateful injection via loopback)

TCP_INFO (236 bytes on PS5, getsockopt level=6 optname=32) exposes exact TCP sequence numbers:
- **Offset +108 (dword):** SND_NXT — changes by exact byte count of sent data
- **Offset +112 (dword):** RCV_NXT — changes by exact byte count of received data

Observed values — Before data exchange: CLI +108=`0x7F10A75E`, SRV +108=`0x57DB27AD`. After client sends 100B, server sends 50B: CLI +108=`0x7F10A7C2` (+100), SRV +108=`0x57DB27DF` (+50).

Differential analysis method: dump TCP_INFO before and after sending a known number of bytes, scan for dwords that changed by exactly that count. This reliably identifies sequence number fields without needing FreeBSD header definitions.

Combined with loopback checksum bypass (if_simloop sets CSUM_DATA_VALID), this enables injection of crafted TCP segments into live connections with exact sequence/ack targeting.

**Impact:** New primitive. TCP_INFO seq number extraction + raw IP socket + loopback checksum bypass = ability to inject arbitrary TCP segments into established connections. Critical for targeting deep TCP state machine code (SACK processing, challenge ACK, persist timer).

---

## Finding 71: TCP State Machine Handles 182 Injected Segments Without Crash (probe 49a)

**Probe:** 49a (TCP stateful injection via loopback)

Injected 182 crafted TCP segments into an ESTABLISHED loopback connection. Zero crashes.

Sections tested:
- **RST injection (D):** exact-seq RST, SYN-in-ESTABLISHED, FIN+ACK, RST+SYN combo, all-flags 0xFF, zero-window, window-shrink, URG pointer past data (past/future), future/past seq data, future ACK
- **TCP options (E):** SACK 1-block, 4-block max, left>right invalid, overlapping, zero-width, len mismatch, in-window SACK, timestamp PAWS violation (future/past), MSS in non-SYN, WinScale in non-SYN, TCP-MD5 fake digest, unknown option kind=253, option length=0 (parser crash target), length=1 undersize, length=255 overread
- **State transitions (F):** data after FIN, RST in TIME_WAIT, SYN recycle, 100 ACK storm, 50 SYN flood to random ports

Notable: RST injection with exact seq did NOT tear down the connection (state remained ESTABLISHED=4). This observation alone does not establish RFC 5961 challenge ACK behavior; no challenge/response exchange is demonstrated by that state value.

Ports ≥40000 are blocked (bind returns -1) — use ports 1024-32767.

**Impact:** The saved 49a run reports 182 injected segments and reaches COMPLETE. It does not independently establish which handler paths processed each segment, complete TCP coverage or RFC compliance. Deeper targets: race conditions with simultaneous data transfer + injection, or kernel timer manipulation via persist/keepalive.

---

## Finding 72: IPv6 Fragment Reassembly Handles 280 Fragments Without Crash (probe 49b)

**Probe:** 49b (IPv6 fragment reassembly state attacks)

Sent 280 IPv6 fragments targeting the kernel's ip6_reass() reassembly code. Zero crashes, zero send errors.

Sections tested:
- **Baseline (B):** 2-fragment, 3-fragment, out-of-order, reverse-order reassembly
- **Overlapping (C):** exact duplicate, teardrop (different data at same offset), fully contained, overlapping last fragment, conflicting last fragments (different total lengths), zero-offset overlap with different sizes
- **Tiny/minimum (D):** minimum 8-byte fragments, sub-minimum (4B) with MF=1, zero-length payload, 8 minimum-size chain, gap in fragment offsets
- **Queue exhaustion (E):** 50 incomplete reassemblies (first-frag-only), 101-fragment bomb (6432B total), fragment ID reuse after completion
- **Huge totals (F):** max-size reassembly (65535B), over-max (65592B), way-over-max (65784B)
- **Edge cases (G):** atomic fragments (off=0 MF=0), atomic interrupting pending reassembly, fragment ID=0, ID=0xFFFFFFFF, 3 simultaneous reassemblies
- **Offset boundaries (H):** fragments with gaps, swiss-cheese pattern, gap-filling, late large first fragment
- **Extension header combos (I):** HBH+fragment, Routing+fragment, DestOpt+fragment, nested fragment-in-fragment
- **Interleaving (J):** 3 interleaved IDs, 10 interleaved with reverse completion, same ID from different sources
- **ICMPv6 fragments (K):** fragmented Echo Request, fragmented NDP Router Solicitation
- **Payload length (L):** declared vs actual mismatch, zero payload length with fragment

**Impact:** `results/49b_ipv6_frag_reassembly_20261016_205926.txt` reports 280 fragments sent, zero send errors and COMPLETE after the listed overlap, queue-stress, size and header-combination cases. This does not independently establish which reassembly paths were exercised, complete handler coverage or RFC 5722 compliance.

---

## Finding 73: Exotic Protocol Handlers All Robust — 86 Packets, No Crashes (probe 50a)

**Probe:** 50a (IGMP, GRE, ESP, AH, PIM, OSPF, VRRP + batch protocol sweeps)

Sent 86 packets across 8 protocol families via raw socket + IP_HDRINCL to loopback:
- **IGMP (B):** general/specific query, v1/v2 report, v2 leave, v3 report with 65535 groups/sources (truncated), truncated (4B), zero-length, unknown type 0xFF
- **GRE (C):** basic encap, checksum/key/sequence flags, all flags, recursive GRE-in-GRE, truncated, zero-length, version 1 (PPTP), IPv6 payload, reserved flags + bad version
- **ESP (D):** SPI=0/1/0xFFFFFFFF, truncated (4B), zero-length, 512B payload
- **AH (E):** basic, SPI=0, truncated (8B), payload_len=0/255, zero-length
- **PIM (F):** Hello, Register, Assert, unknown type 15, version 0, truncated (1B), zero-length
- **OSPF (G):** Hello, zero-length, truncated (8B)
- **Misc (H):** EGP, L2TPv3, IP-in-IP, IPv6-in-IPv4 (hop limit=0), VRRP, experimental proto 253, proto 0 (HOPOPT), batch sweeps of protos 3-7, 9-15, 60-70, 130-142

**Impact:** All exotic protocol input handlers are robust against basic malformed packets. The kernel drops invalid packets cleanly without crashing. These protocols may still have deeper state-dependent bugs (e.g., GRE tunnel establishment, IGMP group membership state).

---

## Finding 74: TCP Keepalive Options Blocked by Sandbox (probe 50b)

**Probe:** 50b (timer manipulation — partial, timed out after Section A)

TCP keepalive socket options are blocked:
- `SO_KEEPALIVE=1`: works (ret=0)
- `TCP_KEEPIDLE=1`: ret=-1 (blocked)
- `TCP_KEEPINTVL=1`: ret=-1 (blocked)
- `TCP_KEEPCNT=1`: ret=-1 (blocked)
- MAX values (all three): ret=-1

Write after peer close: succeeded (ret=16). 50x rapid keepalive toggle: survived.

The probe timed out after Section A (keepalive) — likely stalled on a blocking timer/sleep operation in a later section. Sections B-H (linger, timeouts, buffer resize, shutdown races) were not reached.

**Impact:** TCP keepalive timer manipulation is blocked at the setsockopt level. The kernel doesn't allow tuning keepalive intervals from this sandbox. Timer-based UAF attacks via keepalive are not viable.

---

## Finding 75: Sandbox FD Limit is ~63 (probe 50c)

**Probe:** 50c (resource exhaustion — partial, timed out after Section A)

TCP connection flood hit the fd limit at 63 connections (target was 200). Socket creation starts failing after fd=63 — this is the sandbox's file descriptor limit. All 63 connections were cleanly closed afterward.

The probe then attempted backlog flood (100 connects to listen backlog=1) and timed out — likely blocked on connect() to a full backlog.

**Impact:** The sandbox limits each process to ~63 open file descriptors. This constrains resource exhaustion attacks but also means fd exhaustion is easy to trigger. Combined with raw sockets using fd slots, heavy socket operations could starve the process of fds.

---

## Finding 76: Probe 50d Consistently Crashes Loader (probe 50d)

**Probe:** 50d (cross-protocol tunneling)

50d consistently returns 0 bytes and kills the Lua loader. After 50d is sent, all subsequent probes (including `print("PING")`) also return 0 bytes until the loader is manually restarted on the PS5.

After loader restart, 50c works (produces output), confirming the loader is functional. Sending 50d immediately kills it again. Even a minimal version with just the helper functions and a raw socket creation (identical to 50a's working code) fails after 50d has run.

The crash is persistent across connections — 50d doesn't just kill the per-connection process, it puts the loader itself into a broken state where it accepts TCP connections but doesn't execute Lua.

**Possible causes:**
1. A Lua parse error specific to 50d's source that corrupts the loader's Lua state
2. The raw socket proto=255 + tunnel packet construction triggering a kernel state corruption that affects the loader process
3. Memory corruption from the tunnel packets that persists in the loader's address space

**Impact:** This is the most interesting failure mode observed — a probe that reliably kills the entire loader, not just the per-connection process. Needs the probe-writing session to debug the Lua source for parse errors, or this could be a real kernel/loader bug.

---

## Finding 77: Sony Syscall Survey Output Is Partial (probe 51a)

The saved log `results/51a_sony_syscall_survey_20261016_214814.txt` says it attempted 110 calls, but contains 55 per-syscall result records. The later zero-argument rerun contains only 29 records and stops at syscall 560. Treat the survey as partial; it does not establish coverage of the full 532–676 range.

In the saved records, calls 596, 572, and 563–566 returned 0, and call 624 returned 3377. A return of 0 only establishes that this argument pattern returned successfully. A return of -1 is ambiguous without captured `errno` and valid arguments; it does not prove a syscall is blocked or absent.

## Finding 78: Deep Sony-Syscall Checks Did Not Find a Kernel Pointer (probe 51b)

The saved `51b_accessible_syscall_deep` log records 30 call patterns. It adds successful zero-argument returns for 585, 606, and 643, and a zero return from 640 with a zero-filled output buffer. Together with 51a, this identifies several calls worth understanding, but not a vulnerability.

The output buffers exercised in this probe contained no observed kernel pointers. The 624 return changed from 3377 to 3376 between separate connections; this is not enough to establish a counter, side channel, or kernel-state leak.

Other evidence limits the interpretation:

- Probe 46a/47a characterized syscall 557's return as a version-dependent formula; the `%b` formatting error interrupted the first run. No kernel pointer or memory corruption was demonstrated.
- Probe 51c saved only results for syscalls 625 and 626, so its claimed 54-call survey did not complete in the available log.
- Probe 51b's later `dynlib_cluster_fuzz` file contains only the header and start of phase 1; it has no usable results.

The raw result files are the source of truth. Success returns from unusual syscall numbers should be treated as behavior to characterize, not as evidence of an exploit primitive.

---

## Finding 79: CClosure +0x20 Target Bytes and Write Boundary (probes 55g, 54r)

**Probes:** 55g, 54r, 54q, 53d

Probe 55g wrote `old_value + 1` to the low dword of type()'s CClosure+0x20 field. The saved capture records MARKER_BEFORE_DIFFERENT_WRITE, then binary output and capture termination, without a completed-write or returned-call marker. That capture alone does not confirm a process crash or identify the executed instruction stream or termination cause. Later 56c returned discriminating outputs after selected +0x20 target changes, supporting a dispatch-field interpretation for those functions.

Key evidence:
- **55g section [H]**: `MARKER_BEFORE_DIFFERENT_WRITE` printed before binary output; no returned-call or completed-write marker identifies the instruction executed or the termination cause.
- **55g sections [D]-[F]**: Selected different-value writes to +0x00 and +0x18 returned without a recorded behavioral change. This does not prove that only +0x20 can affect dispatch.
- **55g section [A]**: CClosure lives in SceLibcHeap (region 74, prot=0x3 = RW, flags=0x0). Fully writable from userland.
- **54r**: All seven tested C functions' +0x20 targets decode as `push rbp; mov rbp, rsp` (bytes `55 48 89 E5`) — standard x86-64 function prologues in eboot's RX .text section.
- **54q limitation**: The capture ends before the post-write marker. A successful redirect, a tonumber loop, and an internal call to type() are hypotheses, not observed returned effects.

**Impact:** Writability, target bytes and a truncated write do not alone establish arbitrary execution. Finding 82 supplies later returned-value evidence for selected existing Lua C targets. A general native ABI, working ROP chain and injected-page execution remain unverified.

**Candidate CClosure layout (55g section [B]; role labels are inferred from layout and selected later behavior, not exact-build source):**
| Offset | Value | Role |
|--------|-------|------|
| +0x00 | next GCObject pointer | GC linked list |
| +0x08 | type/flags tag (0x00010206) | Lua type metadata |
| +0x10 | gclist pointer | GC list |
| +0x18 | env table pointer | Lua environment |
| +0x20 | **C function pointer** | **DISPATCH TARGET** |
| +0x28 | 0xF8AFAFAF_AFAFAFAF | Poison/padding |
| +0x30 | eboot-range pointer | Unknown (secondary code ptr?) |
| +0x38 | 0x47 | nupvalues or flags |

---

## Finding 80: Syscall 624 is a VM Operation Counter (probe 52b)

**Probe:** 52b

Syscall 624 returns a monotonically increasing integer that increments by exactly +5 for each `mmap` call, regardless of the mapping size (1 page or 16 pages). It does not decrement on `munmap`. It is unaffected by socket creation, kqueue, memory.alloc, or dynlib_get_info.

Key evidence:
- Section 2: 16 mmap calls of varying size (1-16 pages), each incremented by exactly +5
- Section 3: 512-page mmap, touching pages caused only +1 total delta (not per-page)
- Section 4: 100 tight samples showed zero jitter (all identical = 3463)
- Section 5: sockets (+0), kqueue (+0), memory.alloc (+0), dynlib_get_info (+0)

**Impact:** This is a process-level VM operation counter / budget meter. It counts kernel VM operations, not pages or bytes. It could serve as a side channel to detect kernel VM activity triggered by other syscalls, but is not directly exploitable. The +5 per mmap suggests 5 internal kernel VM operations per mapping (create vm_object, insert into pmap, wire pages, update accounting, etc.).

---

## Finding 81: Syscall 631 is Lethal (probe 52a)

**Probe:** 52a

The syscall survey 627-676 reached sys 631 with zero arguments and the process was immediately killed. Syscalls 627-630 all returned PCALL-FAIL (exception caught by pcall). Sys 631 kills past pcall, making it the third confirmed lethal syscall alongside AIO (661) and thr_new.

---

## Finding 82: Controlled CClosure Function Redirect Confirmed (probe 56c)

**Probe:** 56c

The saved 56c capture records output and restoration after four selected CClosure +0x20 target changes:
- rawequal → rawget: `rawequal(t, "foo")` returned `"bar"` (rawget behavior)
- rawget → type: `rawget(42, "x")` returned `"number"` (type behavior)
- select → tostring: the printed result is `42`; the capture stringifies it and does not independently record its Lua type
- rawequal → tostring: the printed result is `42`, also without a captured type check

Write+restore cycles take 0.0001s each (10 cycles in 0.0007s). All functions restored correctly after redirect.

**Constraint:** Earlier type()-targeting captures stop around the attempted write. The proposed explanation that memory.write_dword internally calls type() requires exact-build source/disassembly evidence. The tested rawequal/rawget/select changes returned; this does not prove all other functions redirect safely.

**Impact:** A/B provide discriminating output consistent with controlled redirection to selected existing Lua C functions. Later 56f also records string.len/math.abs target-like values and restoration. The 111606/111610 56c files are byte-identical captures, not independent replications. The 56e gadget experiments record nil returns; they do not establish a working general ROP chain. Arbitrary native targets, machine-register argument control, injected-page execution and kernel access do not follow from these records. See [the hash-pinned ledger guide](RESEARCH_EVIDENCE.md).

---

## Finding 83: Syscall 572 Returns a Fixed Heap Record and Follows No Caller Pointer (probes 501a-501c)

**Probes:** 501a, 501b, 501c

501a filled a 0x400 caller struct with a canary-page address at every qword and called each reachable Sony syscall with two argument layouts. No call wrote a kernel-shaped value into the struct (`kern=0` for all 16 syscalls in both layouts). The one apparent canary hit was an artefact: `canary_dirty()` counted four pages while only two were filled, so its baseline was a constant `128`.

501b then gave every struct qword its own page (128 pages, all `0xA5`). Syscall 572 with `(struct, 0x400, out, 0x100, 0, 0)` left all 128 pages untouched (`changed dwords=0`), so the earlier `130` was syscall 572 writing its output into the third argument, not following a pointer out of the struct.

501c dumped that output. It is a fixed record, identical for every struct value tested (all-zero struct, `struct[0]=0..4`, `struct+0x10=0..3`), with `ret=0`:

```
+0x00 0x115F0000  +0x08 0x11600000  +0x18 0x00000003
+0x04 0x00000003  +0x0C 0x00000003  +0x20 "\x11SceLibcHeap"
```

The name string at `+0x20` (`0x11` then `SceLibcHeap`) identifies the record family. It contains no caller-derived field and no `0xFFFF8xxx` value.

**Impact:** 572 is not a pointer-following write primitive and not a leak. The earlier "empty buffer" reading in `docs/ATTACK_SURFACE.md` comes from calling it with the output buffer in a different argument position; the record is only written when the buffer is the third argument and a size is the fourth.

**Not established:** which field of the record means what (`0x115F0000`/`0x11600000` are not addresses in any observed address space), and whether a different argument shape asks for a different record type.

---

## Finding 84: Syscall 649 Fills Its Member Records With Userland Addresses on Every Module

The module-member query takes `649(handle, member, out, size, 0, 0)` — handle first, member
second. `54k` swept members 0-255 on handle 0 only; `579b` swept all 256 members of all 39
handles that `592` reports (9984 calls):

- 233 `(handle, member)` pairs returned `ret=0` with data: 5 for handle 0 (eboot) and 6 for
  every other module.
- **Zero qwords had a high half in `0xFFFF8000`-`0xFFFFFFFF`**, so no member record of any
  module hands back a kernel address.

The member tables are therefore fully mapped and fully benign, and this closes the last
unexplored corner of 649 as a KASLR source. Capture:
`results/phase17_new_vectors/579b_sys649_all_handles_20261024_192940.txt`.

## Finding 94: Devices Open From the Loader, and a Pty Read Wedges It (probe 778a)

`open(5)` works on real paths from the Lua loader (`/savedata0/thread.lua` in
747a). A sweep of `/dev` with `O_NONBLOCK` returned:

| path | result |
|---|---|
| `/dev/null` | opens; `read` returns 0 |
| `/dev/zero` | opens; `read` returns 64 zero bytes |
| `/dev/random`, `/dev/urandom` | open; `read` returns random bytes |
| `/dev/ptmx` | **opens**; `read` blocks forever |

The `/dev/ptmx` read blocked the only Lua thread, and every later connection
was accepted with no reply: the pty path wedges the loader exactly like the
blocked aio wait in 498c. A game relaunch is the only recovery. Pty
allocation is therefore reachable, but any probe that touches it must use
`O_NONBLOCK` and must not read.

The rest of the device list has not been measured: the sweep stopped at
`/dev/ptmx` in the first run, and the follow-up (778b, open-only) could not
run because the loader was already wedged.


## Finding 95: Two Sony Syscalls Read AMD Performance MSRs Into Userland (probes 796a-796d, 797a)

`sys 626` is an `rdmsr` front end, and it was previously written off as dead
(probes 54k, 54a2) because those probes passed an MSR number as argument 1.
Argument 1 is a **command**, argument 3 is the index, and the MSR number is
computed by the kernel.

13.60 body `0x604cf0` (base `0xffffffff8a9c0000`), case at `0x604f32`:

```
00604f57  cmp dword ptr [r15 + 8], 0            ; arg2 must be 0
00604f61  jne +0x16 (EINVAL)
00604f63  cmp qword ptr [r15 + 0x18], 0          ; arg4 must be non-NULL
00604f68  je  +0x16
00604f6d  cmp qword ptr [rsi + 0x20], 0          ; arg5 must be 0
00604f72  setne dl
00604f75  cmp ebx, ecx                           ; ebx = arg3, ecx = 3 or 7 by CPU model
00604f77  seta cl
00604f7a  or  cl, dl
00604f7c  jne +0x16
00604f7e  lea ecx, [rbx + rbx]                   ; ecx = arg3*2
00604f84  ja  +0x0c
00604f86  or  ecx, 0xc0010241                    ; arg3 <= 3: MSR (arg3*2)|0xc0010241
00604f8c  rdmsr
00604f8e  jmp +0x0a
00604f90  add ecx, 0xc0010189                    ; arg3 >  3: MSR  arg3*2 +0xc0010189
00604f96  rdmsr
00604fc3  lea rdi, [rbp - 0x128]                 ; kernel source
00604fcf  mov rsi, rbx                           ; user destination = arg4
00604fca  mov edx, 8
00604fd2  call 0x8ac191d0                        ; copyout
```

Measured on 14.10 (`results/phase17_new_vectors/796a-796d_*.txt`):

| call | result |
|---|---|
| `626(1..4, 0, 0, out, 0)` | `-1` |
| `626(5, 0, idx, out, 0)`, idx 0..3 | `0`, eight bytes written |
| `626(5, ...)`, idx 4..8 | `-1` |
| `626(5, 1, 0, out, 0)` | `-1` — arg2 must be 0 |
| `626(5, 0, 0, NULL, 0)` or `arg5=1` | `-1` |
| `626(5, 0, 0, unmapped, 0)` | `-1` — it is a real copyout |
| `626(6, 0, 0, p4, p5)` | `0`, **four counters per page**, both pointers required |
| `626(6, ...)`, idx != 0 or arg2 != 0 | `-1` |

`626` command 6 writes four 32-bit values at offsets `0, 8, 0x10, 0x18` of each
page, and they increase between calls in step with wall time
(`405E7113 -> 405ED0DA -> 46DC0497`), i.e. they are live cycle counters, not
addresses. Command 5 reads one counter, index 0..3.

`sys 625` is the sibling (`0x603c90`, narg 4). Commands 1..17 and 21..23 return
`-1` for every shape tried; commands **18, 19, 20** return `0` with `arg2 = 0`
and any `arg3`, and **write nothing** — `arg4` is ignored entirely (NULL and
unmapped both give `0`). Its neighbouring block performs four `wrmsr` over
`0xc0010230..0xc0010238` with `and eax, 0xffbf0000`, so the family is the
performance-monitor block, not a general MSR interface.

What this establishes, and what it does not:

- A userland syscall executes `rdmsr` and copies the raw result to a user
  pointer. The MSR number is bounded by a small table, so `LSTAR`, `GS_BASE`,
  `EFER` and friends are **not** reachable.
- The values are live performance counters (they advance with time and differ
  per call), so this is **not** a KASLR source and not a memory primitive.
- `sys 567` (`0x6039d0`, narg 3) is in the same block: argument 1 is a TID
  (`thr_lookup`), argument 2 must be `<= 5`, and the thread must be the caller
  and in states `[thr+0x380]==1`, `[thr+0x400]==4`; it then reads
  `0xc0010201`. It is a per-thread counter query.

The value of the finding is that the family is *reachable at all*: earlier
probes concluded "MSR access is dead on 14.10". It is not dead, it is just
bounded to the performance block.

## Finding 96: The Hypervisor Call Opcode Is Not in Any Readable Executable User Page (probe 798a)

The kernel text holds 34 `vmmcall` trampolines between `0xc16a19` and
`0xc1720d` (kernel base `0xffffffff8a9c0000`), each shaped `mov eax,<id>;
vmmcall; ret`, plus two Intel `vmcall` (`0f 01 c1`) sites at `0xcb8562` and
`0xcb8605`. `VMMCALL` is not a privileged instruction on AMD: the hypervisor
intercepts it from any CPL, so if the opcode were reachable from user code a
ring-3 call into Sony's hypervisor would be possible with attacker registers.

It is not reachable, for two separate reasons:

- **No opcode in user text.** `probes/phase17_new_vectors/798a_vmmcall_bytes.lua`
  scans every region sys 674 reports with the executable bit, for
  `0F 01 D9/D8/DA/DB/DC/DD`. The `.executable` region (eboot, prot 5,
  `0x4CD70000`-`0x4D204000` in that run) yields two byte-pattern coincidences
  that are not instructions (`vmsave` at `0x4CEF885C` followed by `48 0F 48`,
  `stgi` at `0x4D162317` followed by `0F B0 0F`); `libc.prx` (prot 5) yields
  none. Every other system module is exec-only and unreadable, so its text
  cannot be searched.
- **No syscall forwards to a trampoline.** Every `call` whose target lands in
  the trampoline window was enumerated: 49 sites, all in kernel-initialisation
  or device code, none inside a handler that passes a user argument through.

The practical consequence is that the hypervisor path needs a writable and
executable page, which is exactly the `mprotect`/`W^X` wall already recorded;
`VMMCALL` from this process is not a shortcut around it.

## Finding 97: Two More Object Tables Are Not Reachable With One Argument (probes 799a, 800a)

Two subsystems looked promising from the 13.60 handler bodies and are closed
by measurement on the running console.

**Named-object table (`549` create, `558` destroy).** `549` copies a name
string with a 0x20 bound into a fresh 0x20 buffer, allocates a 0x60 object,
initialises it through `0x8b5d55a0(obj, flags, a3, a4)` and registers it with
`0x8ad598e0([proc+0xc48])`; the identifier comes back in the **return value**
(probe 799a: `0xA207`, `0xC21D`, `0xC21E`, `0xC21F`, then `0xE205` for a
repeated name, i.e. one object per name). `558` looks an id up in the same
table, removes it and frees `[obj]` and `obj`, with no reference count and no
callback. Feeding `558` any of the ids `549` returned gives `-1`; unknown ids
(`0`, `0x7fffffff`, `0x12345678`) also give `-1`. So the two calls do not share
an identifier space from this process and the destroy path cannot be driven.

**fd release (`541`, `552`).** Both bodies decrement a reference count
(`[obj+0x50]` and `[obj+0x54]`) and free at zero, with a valid fd as the only
gate. On the console both return `-1` for a live socketpair end (fd `126`),
for fd `0`, and for an out-of-range fd. Whatever table `0x8ad59e20` is indexing,
this process does not reach it through these numbers.

The surviving rule is the same one the aio work produced: a Sony handler that
looks reachable from its disassembly is not reachable until its own lookup
returns something, and the lookup is where every one of these paths ends.

## Finding 98: The Module-Info Copyouts Reject an Oversized Length (probe 801a)

Both module-info calls copy a fixed kernel struct whose length the caller supplies, so
a length larger than the struct would have returned adjacent kernel memory. It does
not. `593(handle, buf)` with `[buf+0] = 0x2000` returns `-1` for handle `0`, whereas
the recorded `0x160` succeeds: the size field is validated, not trusted. `649(handle,
member, buf, 0x2000, 0, 0)` returns `0` for members 1-4, 7 and 8 on every one of the
39 handles from `592` and leaves the page bounded — no byte past the records and no
`0xFFFF8xxx` qword anywhere in the 0x2000-byte page (`probes/phase17_new_vectors/
801a_oversized_copyout.lua`, capture `results/phase17_new_vectors/
801a_oversized_copyout_20261026_111134.txt`).

Together with Finding 84 (the 9984-call 649 sweep) and Finding 85's null result for
593's fields, the whole module-introspection surface is closed as a leak source.

## Finding 99: `mmap` strips PROT_EXEC at creation, so no mapping can ever become executable (probes 803c-803i)

The repository has listed "`mprotect(EXEC)` always fails" as a hard wall since
phase 3. Probes 803c-803i show *why*, and the reason rules out every variant of
the idea, including the syscall-548 bypass that looked promising on paper.

**548 is a batch VM API.** The handler at 13.60 offset `0xabbe60` takes
`uap[0]` (ignored), `uap[8]` (must be 0), `uap[0x10]` = array of 0x20-byte
records, `uap[0x18]` = a signed count. Record layout: `+0x00` qword address,
`+0x08` qword payload, `+0x10` qword length, `+0x18` byte prot, `+0x1c` dword op.
Measured op map:

| op | behaviour | evidence |
|---|---|---|
| 0 | `-1` always (capability gates at `0x8b47bff3`: `[proc+0x1c9]>=2`, `[proc+0x464]&2==0`, `[proc+0x5d4]>=0x2500000`) | 803d |
| 1 | unmap — `region=GONE`, `ret=0` | 803d |
| 2 | **protect** — calls `0xffffffff8ac8bdb0`, which is `vm_map_protect` (locks `[map+0x170]`, bumps `[map+0x1c0]`, clamps to `[map+0x20]`/`[map+0x28]`, `lookup_entry`, per-entry `0x8ac8b4e0`) | 803d/803e |
| 3 | anonymous map — payload is ignored, `len` must be a multiple of `0x4000`, returns the address | 803f |
| 4 | `-1` always | 803d |

**`mmap` (477) clears the X bit before the mapping exists.** With flags
`0x1012`, one page per requested protection, the stored protection read back
from sys 674 is:

| requested | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 0x30 | 0x31 | 0x32 | 0x33 | 0x34 | 0x35 | 0x36 | 0x37 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| stored | 0 | 1 | 3 | 3 | **0** | **1** | **3** | **3** | 0x30 | 0x31 | 0x33 | 0x33 | **0x30** | **0x31** | **0x33** | **0x33** |

Bit 2 (X) is always cleared, bit 3 is always cleared, and a request for write
implies read. The same holds with kernel-chosen addresses (`flags=0x1002`).

**`max_protection` is exactly the stored creation protection.** 548 op 2 on a
fresh RW page: `want 1 → 1`, `want 2 → 3`, `want 3 → 3`, and `want 4/5/6/7 →
-1`. On an existing `prot=5` text page (eboot `.executable`, `libc.prx`):
`want 3 → -1`, `want 5 → 0`, `want 7 → -1`. On a `prot=3` heap page:
`want 3 → 0`, `want 5 → -1`, `want 7 → -1`.

So the wall is a **VM-layer invariant**, not a syscall filter: the kernel never
creates a mapping whose `max_protection` includes a right the mapping did not
start with. This is stronger than stock FreeBSD, where `flags2maxprot` gives
`mmap(RW)` a max of RWX precisely so that a later `mprotect(RWX)` is legal —
the classic FreeBSD W^X bypass does not apply here.

**File-backed mappings are refused outright.** With valid read-only fds on
`/savedata0/thread.lua` and `/savedata0/main.lua` (opened by sys 5, fds 22 and
23), all twenty `prot × flags` combinations (`0x1002`/`0x1001`, prot
3/5/7/0x33/0x37) return `-1`. Syscall 477 is anonymous-only in this loader, so
there is no executable-file mapping to inherit an X-capable `max_protection`
from.

**Consequence.** No attacker-supplied byte can ever be executed: every route to
memory the game controls (477, 74, 548 op 2, 548 op 3) yields a mapping with
`max_protection` ⊆ {R,W}, and every route to executable memory refused the W
right. The 13.60 `vmmcall` trampolines (Finding 96) stay unreachable for the
same reason — they need a writable-and-executable page to place the call.

Captures: `results/phase17_new_vectors/803c_mmap_548_protect_20261026_115236.txt`,
`803d_548_op_matrix_20261026_115307.txt`,
`803e_548_maxprot_matrix_20261026_115339.txt`,
`803f_548_op3_payload_20261026_115424.txt`,
`803g_548_text_pages_20261026_115523.txt`,
`803h_mmap_prot_matrix_20261026_115541.txt`,
`803i_file_mmap_exec_20261026_115603.txt`.

## Finding 100: the 549 object table checks generations, unlike the aio one (probe 804a)

`549(nameptr, flags, arg3, count)` allocates a 0x60-byte object, initialises it
from a 0x20-byte user buffer and returns an id; `550(id)` looks the id up,
removes the entry and frees. The id is `slot | generation << 13` — the create in
probe 804a returned `0x4205` (slot 0x205), `0x206`, `0x6205` (slot 0x205 again,
generation 3), and a stale `0x4205` issued against the live `0x6205` returns
`-1` while the live id still deletes with `0`. A second delete of a removed id
also returns `-1`. `551` returns `-1` for a live id.

The table therefore has the generation check whose absence in the aio table is
the subject of the 14.20 fix note, and the 549/550 lifecycle is clean.
Capture: `results/phase17_new_vectors/804a_named_object_lifecycle_20261026_115819.txt`.

## Finding 101: The `/dev/dmem0` aperture is GPU bus space, not system RAM (probes 806a-809a)

**Claim.** `mmap(/dev/dmem0, va, 0x4000, PROT_RW, MAP_SHARED|MAP_FIXED, fd, phys)` accepts
**any 0x4000-aligned physical offset**, returns the requested address, and two mappings of
one offset alias each other. What it does *not* do is expose the kernel's physical memory,
which is what would make it a jailbreak primitive.

**Measured.**

| Probe | Result |
|---|---|
| 806a | `phys` 0, `0x100000`, `0x100000000`, `0x110000000` map; `0x1000` and `0x100001000` → `-1`; `0x120000000` and `0x140000000` → `-1`. The only check is **0x4000 alignment**, and success returns the requested VA, not 0. |
| 806c | Two VAs over one phys alias: write `0xDEADBEEF` at VA1+0x40 → read back at VA2+0x40; reverse direction also aliases. |
| 806d | `[0,0x20000000)` at 0x4000 step: 32768 pages mapped, **13 non-zero** (`0` = `80000000C0012800`, `0x14000` = `0000000200000002`, `0x10014000`-`0x10028000` structured, `0x10D80000`/`0x11600000`/`0x11E80000`/`0x12700000` = `AFAFAFAF…`). A write at `0x100000` persisted **inside that process**. |
| 808c | `[0x20000000,0x80000000)`: 8192 mapped / 24576 holes per 128 MB and **zero non-zero pages** in 1.5 GB. The 1-in-4 ratio is only the 0x1000 probe step against the 0x4000 alignment. |
| 806d | `[0x100000000,0x120000000)`: 16388 pages, all zero. |
| 808a | Page 0 = GPU register; `0x1001000`-`0x1003000` are **unmappable holes**; `0x10018000` carries `@rbShdr`-shaped bytes and `0x1001C000`/`0x10024000` continue as an ELF section-header table — a device image, not the kernel. |
| 809a | The `A5A5A5A5` marker a **previous process** wrote at `0x100000` reads **zero** in a new process, while `0x10014000`, `0x10018000` and the `AFAFAFAF` pages at `0x10D80000` are **byte-identical across the restart**. |

**Reading.** A mapping operation that validates only alignment and returns aliasing views of
one offset is a device aperture. The restart test separates a real physical page from a
private one: the page we wrote was not preserved, the device pages were. Two models fit the
data — a demand-zero GART window where a write allocates a private page, or real pages that
the OS sanitises when the owning process exits — and the measurements do not distinguish
them. **Neither model yields the kernel image:** 1.5 GB above 512 MB and 512 MB of the pool
window are entirely zero, and the only non-zero content in the low 512 MB is a device image
and allocator fill.

**Why this matters.** `mmap` of `/dev/dmem0` was the last unchecked route to physical memory,
and physical memory is the one place Sony's VM-layer `max_protection` rule (Finding 99) does
not apply. It is closed for kernel access. What remains is a real but narrow capability:
arbitrary 0x4000-aligned *device* offsets can be mapped, aliased and written, which reaches
GPU firmware and the pool manager's free fill and nothing else.

**Harness limits.** A large mapping (32 MB, probe 807a) **succeeds** and then faults fatally
when a hole inside it is read; `808c` shows the holes are real. Only per-page 0x4000 mappings
fail cleanly. Scanning physical memory from Lua is also self-defeating: probe 808d's 268 M
reads starved the loader for a whole process lifetime.

---

## Finding 102: `sigreturn` (417) Installs a Caller-Supplied Register Frame, Cookie is RFLAGS (probes 813a, 814a, 814b, 2026-10-26)

**What 421 returns.** `syscall 421` (`0xc37860`) zeroes a 0x500 stack buffer, calls
`0x8af1d900`, stores `[td+0x3b0]`/`[td+0x3b8]`, and copies **0x4c0 bytes** to the caller
(`copyout 0x8ac191d0`). The record is the sigreturn frame itself. Probe 814a in one process
(pid 157):

| offset | value | field |
|---|---|---|
| `0x0E0` | `0x0815794B5C` | RIP (inside libkernel) |
| `0x0E8` | `0x43` | CS — the *user* selector on this firmware |
| `0x0F0` | `0x202` | RFLAGS |
| `0x0F8` | `0x310648868` | RSP |
| `0x100` | `0x3B` | SS |
| `0x108` | `0x480` | the same word `thr_create` wants at `+0x108` |
| `0x110` | `0x10002` | the `+0x110` gate word |
| `0x118` | `0x20001` | the `+0x118` gate word |
| `0x048` | caller's RDI | first GP slot |

So the "userland context" used by `thr_create`, by 421/422 and by sigreturn is one structure,
and 421 will hand a live copy of it to any caller.

**Why the 813a frames were rejected.** 417 (`0xa07280`, narg 1) `copyin`s 0x500 bytes to
`rbx+0xa0` and then tests, with `rbx = user - 0xa0`:

- `[rbx+0x170] < 8` → user `0x0D0` must be below 8;
- `([rbx+0x190] ^ [[td+0x460]+0xf8]) & 0xFFFFFFFFFFDAB22A == 0` → user `0x0F0` must match
  the live frame word at `+0xf8`;
- `[rbx+0x188] & 3 == 3` → user `0x0E8`, the CS;
- `[rbx+0x1b0] == 0x10000|0x10002` → user `0x110`;
- and at `0xa074c7` a further `[rbx+0x1b8] - 0x20001 < 2` → user `0x118`.

Probe 813a sent `0x0F0 = 0` and failed every time. The `0x4c0` record shows the word is
**RFLAGS = 0x202**, and `0x202 & 0xFFDAB22A = 0x202 ≠ 0`, so a zero cookie cannot pass. That
is the whole explanation for the three `-1` results.

**What the success path does** (offset `0xa0759a`, reached when the gates pass):
`bcopy(src=user+0x48, dst=[td+0x460], 0x90)` then `bcopy(src=user+0xD8, dst=[td+0x460]+0xe0,
0x30)` — `0x8ac19be0` is `bcopy(src=rdi, dst=rsi)`, proven by its `xchg rsi,rdi; rep movsq`
body. So the handler writes **0xC0 bytes of user data into the trapframe**, then
`[r13+0x40]=[user+0x480]`, `[r13+0x48]=[user+0x488]` (FS/GS base, `r13=[td+0x3f8]`),
`kern_sigprocmask(td, SIG_SETMASK=3, user, NULL, 0)` (`0x8af1d900` ORs/ANDs
`[td+0x3b0..0x3bc]` and masks `0xfffefeff`), and returns **`0xfffffffe` = EJUSTRETURN**.

**Measured.** Probe 814b took the kernel's own record and sent it straight back: `417 ret=0`,
and the process continued to the next statement. EJUSTRETURN tells the syscall return path to
skip storing `tf_rax`, so the frame's own RAX (zero in that record) is what Lua sees — the
`0` return is the frame's register, not an error code.

**The one privilege field, and it is closed.** The frame carries RIP, CS, RFLAGS, RSP and SS.
RFLAGS is the only field with a privilege meaning that survives a same-level `iretq`: IOPL,
which makes `cli`, `in` and `out` legal at CPL 3 and would be a route to device DMA. It cannot
be reached, and the reason is the shape of the check rather than a missing feature. The mask is
an *equality* test against the live frame, not a blacklist:

```
0x8b3c7326  mov rax, qword ptr [rbx + 0x190]   ; user 0x0F0 = the record's RFLAGS
0x8b3c732d  mov rdx, qword ptr [r15 + 0xf8]    ; the live trapframe's RFLAGS
0x8b3c7334  xor rdx, rax
0x8b3c7337  test rdx, -0x254dd6                ; sign-extended 0xFFFFFFFFFFDAB22A
0x8b3c733e  je   0x8b3c73b0                    ; must be zero on every masked bit
```

and the installer keeps the live value for exactly those bits:

```
0x8b3cacb9  mov r15, 0xffffffffffdab22a
0x8b3cacce  and r15, qword ptr [r12 + 0xf8]    ; bits inside the mask come from the live frame
0x8b3caea9  or  r15, r9                        ; r9 = user 0x0F0, bits outside the mask
0x8b3caf3d  mov qword ptr [r12 + 0xf8], r15
```

Bits 12 and 13 (IOPL) and bit 9 (IF) are **inside** the mask, so the user's copy is discarded
and the live value is installed; a user value that differs on any of them fails the `xor`.
Measured in 816a and 816c (`probes/phase17_new_vectors/816a_rflags_iopl.lua`,
`816c_frame_readback.lua`, captures `results/phase17_new_vectors/816[ac]_*_20261026_12*.txt`),
each row a fresh `421` with one bit changed:

| frame RFLAGS | bit | 417 |
|---|---|---|
| `0x000202` | none — the live value | accepted |
| `0x000242` | ZF 6 | accepted |
| `0x000282` | SF 7 | accepted |
| `0x000602` | DF 10 | accepted |
| `0x010202` | RF 16 | accepted |
| `0x000302` | TF 8 | accepted — **the process then single-steps and dies on `#DB`** |
| `0x001202` | IOPL 12 | **`-1`** |
| `0x003202` (816a) | IOPL 12-13 | **`-1`** |

The TF row is the positive control: the install is verbatim for bits outside the mask, so the
IOPL rejection is the cookie and not a broken path. A CPL-3 `iretq` is the only one available
and its live RFLAGS never has IOPL set, so the field is unreachable by construction. Only
persistent bits (TF, AC, RF, NT, IOPL) can be observed by reading the frame back — any
intervening instruction clobbers CF/PF/AF/ZF/SF/DF — which is why the table is read from the
417 verdict and the TF row rather than from readback values.

**422 is not a bypass.** `sys 422` (`0x8b5f7970`) copies the same `0x4c0` record in and calls
`0x8b3cac60` — the identical validator/installer — after its own copies of the `0x108 == 0x480`
and `0xD0 < 8` gates. There is no second, gate-free install path.

**And it is not an arbitrary write.** The destination is `[td+0x460]`, the calling thread's
own trapframe, and nothing in the path takes a pointer from user memory. A full 0x5a0 scan of
the 13.60 text for writes to `+0x460` found 30 sites, all on other structures; none reads a
user pointer into the frame slot (bg_15).

## Finding 108: A Semaphore Objects Cannot Be Freed Under a Waiting Thread (probes 841a-846a, 2026-10-26)

Correction of an earlier reading of these same probes: the woken waiter's
`mtx_unlock` does **not** run on freed memory. The semaphore entry carries an
rwlock and `553` holds it **shared for the entire wait**, so `550`'s detach -
which needs it exclusive - can only run after the waiter has finished.

`0x399EE0(table, id, type, &holder)` takes the table spin mutex
(`table+0x218` via `0x4C6A00`), resolves the slot, and takes the **entry rwlock
shared**; `0x399EB0(holder)` releases it, choosing reader or writer unlock by
`and rax, ~0xf; cmp rax, curthread` → `0xC4C4B0` (writer) or `0xC4C300`
(reader). `sys 553` calls `0x399EE0` at `0xC1644D`, waits in `0xC15600`, and
only then calls `0x399EB0` at `0xC16478`, so the reader lock is held across the
whole wait. `550` releases its own shared lock, re-resolves with the exclusive
form (`0x39A2A0` → `0xC4BB20`, which requires the lock word to be 1), removes
the entry (`0x399E30`), and only then decrements the refcount (`0xC16348`) and
frees the name and the object (`0xC1636A`, `0xC16375`).

Inside the wait, the destructor `0xC15DD0` marks `[obj+0x44] |= 0x1000`,
unlinks every waiter node (`[obj+0x30]`, each tagged `0x10000000d`), calls
`cv_broadcast 0x73F010` on `obj+0x20`, and then **drains** the waiter counter
`while ([obj+0x50] != 0) cv_signal(0x73E780)`. The woken thread decrements
`[obj+0x50]` (`0xC159B4`), optionally signals the event (`0xC159C6`, only when
its decrement reaches 0 and the dead bit is set), and unlocks the object mutex
(`0xC159D4`, `0x4C6FA0`, writing 4). All three writes happen under the object
mutex and before the thread releases its shared entry lock, so they always
precede the free.

Measurements on 14.10 (loader 192.168.1.121:9026):

| probe | setup | result |
|---|---|---|
| `841a` | `553(id, n, tmo)` with `tmo` = 400 | returns in 10 ms: the timeout unit is microseconds, 400 us |
| `841a` | `tmo` = 2,000,000 | marker unchanged for 800 ms - the waiter really blocks |
| `842a` | one waiter queued, then `550(id)` | `ret=0`, the waiter resumed within 10 ms, six creates afterwards all succeed |
| `843a` | 15 spinning `thr_create` children, then destroy + immediate reclaim create | spinners delay the woken waiter only to the next tick; nothing observable on the reclaimed object |
| `843b`/`845a` | destroy, immediate reclaim create, then destroy the reclaim object with its own waiter | the reclaim object still drains normally (waiter woken at 10 ms, not at its 400 ms timeout) |
| `846a` | 90 rounds of release-and-destroy in the same breath | every round `destroy=0`, health create succeeds, process alive |

`553` argument semantics from the disassembly: arg1 = id; arg2 = token count
(must be `> 0`, else EINVAL `0x16`); arg3 = pointer to a **microsecond** timeout
(`0xBAEE20` splits it into seconds/nanoseconds), copied in and back out with the
remainder; arg3 = 0 means wait without a timeout (`0xC15891`/`0x73E780` loop).
The wait takes the fast path when `[obj+0x40] - n >= 0`; it returns `0xD` for a
dead object, `0x16` when `[obj+0x4C] < n`, `0x3C` (60) on timeout, `0` on
success.

Consequence: the object lifetime here is protected three independent ways - the
counter drain under the object mutex, the mutex-ordered woken writes, and the
shared/exclusive entry lock separation before the free. This family is not a
memory-safety lead; the one reachable damage is a wedged table when a waiter is
killed before it decrements (the drain loop then never sees 0), which matches
the earlier `498c` wedge.

## Finding 109: The 14.10 Guide Runs a 2023 WebKit Base With No JIT, and Sony Ships Its Source (2026-10-26)

Sony publishes the WebKit source used by each firmware band. For "14.00 -"
(which covers 14.10) the archive is
`https://www.playstation.com/content/dam/global_pdc/en-us/external-resources/oss/PS5/webkit/WebKit_1400.zip`,
1,637,794,253 bytes, Last-Modified 2026-10-15, with
`Configurations/Version.xcconfig` = `616.1.27.211.1`. Its
`WebKit-1400-changes.txt` is Sony's own change list: **894 commits from
2023-06-08 to 2026-08-29** (2023: 754, 2024: 100, 2025: 36, 2026: 4) over 4,067
files. The guide is therefore a fixed 2023 engine with a selective security-fix
stream, not a rolling import - so a fix Sony never took is still shipped, and
the shipped source can be diffed against upstream to prove it.

Build flags from `Source/cmake/OptionsPlayStation.cmake` decide the reachable
surface:

| flag | value | consequence |
|---|---|---|
| `ENABLE_JIT` / `ENABLE_DFG_JIT` / `ENABLE_FTL_JIT` | OFF | no baseline, DFG or FTL JIT: every JIT/wasm exploit class is unreachable |
| `ENABLE_WEBGL` | OFF | no WebGL (confirmed on the console: every context is null) |
| `ENABLE_WEB_AUDIO` | OFF | no WebAudio, so `WaveShaperNode::curveForBindings` (`cf7cd9dbde`) cannot be reached |
| `ENABLE_VIDEO` | ON | `<video>` is live |
| `ENABLE_MEDIA_SOURCE`, `ENABLE_ENCRYPTED_MEDIA` | forced ON | MSE/EME and Sony's `MediaPlayerPrivatePlayStation` are script-reachable |
| `ENABLE_LAYOUT_TESTS` | tied to the WebCore build | why the binary may expose `window.internals` at all |

Measured on the console (beacons in `results/webkit/server_20261026_201114.log`):
Workers (including module workers), `crypto.subtle`, streams,
`DecompressionStream`, fetch/WebSocket, `ResizeObserver`,
`IntersectionObserver`, `FontFaceSet`, MediaSource, `Intl.Segmenter` and
`toSorted`/`fromAsync`/`regexV` are present; WebAssembly,
SharedArrayBuffer, WebGL, IndexedDB, ServiceWorker, WebRTC, AudioWorklet,
OffscreenCanvas, WebGPU, `requestIdleCallback`, gamepad, `float16arr`,
`Object.groupBy`, `Promise.withResolvers`, `Symbol.asyncDispose` and
`RegExp.escape` are absent. `window.internals`, `window.testRunner` and
`GCController` are **undefined**, which rules out every LayoutTests trigger
that needs the testing API (measured with the datalist probe, see below).

Three source-verified consequences:

1. `Source/WebCore/css/FontFaceSet.cpp:154` still builds
   `Vector<std::reference_wrapper<CSSFontFace>> matchingFaces` and walks it with
   `face.get().load()` / `face.get().status()` / `face.get().wrapper()`, so the
   14.10 FontFaceSet UAF (Finding 12) is present in the shipped source, not
   just in behaviour. `Source/WebCore/css/CSSFontFace.h:59` is
   `DECLARE_ALLOCATOR_WITH_HEAP_IDENTIFIER(CSSFontFace);`, which is why the
   freed slot only ever accepts another `CSSFontFace`.
2. The 2026-09-18 upstream fix `f457aa2ebe` (heap-use-after-free in
   `Style::commitRelations` via `MatchResultCache`) cannot apply:
   `MatchResultCache.cpp` does not exist in this tree (`grep MatchResultCache`
   over Source/WebCore = 0 hits). Likewise `CanvasRenderingContext2DBase::beginLayer`
   (`e0558372aa`) is not compiled.
3. The 2026-08-12 datalist UAF (`be08720593`) **is** shipped:
   `Source/WebCore/html/shadow/DataListButtonElement.cpp` calls
   `m_owner.dataListButtonElementWasClicked()` through a raw owner reference
   which `TextFieldInputType::removeShadowSubtree()` never clears. Its upstream
   regression test reaches the button with `internals.shadowRoot()` and
   `UIHelper.activateElement`; on 14.10 `internals` is undefined and
   `document.elementFromPoint()` over the input returns the shadow host, so the
   trigger is not reachable from the guide. Probe: `DL-ENV` reported
   `internals=undefined testRunner=undefined GCController=undefined`,
   `DL-BUTTON` reported `none`.

A patch-gap detector makes the "which fixes are missing" question mechanical.
With a blobless clone of upstream (`git clone --filter=blob:none --no-checkout`),
`.local/patchgap2.py` compares the pre-image blob of every fix that mentions a
crash/overflow keyword against the blob hash of the file Sony ships; a match
proves the vulnerable code is present verbatim. Over `Source/WebCore` that
yields 292 path rows from 111 commits, and over `Source/JavaScriptCore` 22 rows.
Caution: `git log --raw` triggers promisor blob fetches and fails offline, so
only `--name-status` and `git ls-tree` are usable there.

The same list also has a limit worth recording: most of its WebCore entries are
not reachable from a page (`drawLinesForText` was an IPC-only hardening, the SQLite
and reporting-observer fixes need APIs this build lacks), and the audio and ANGLE
entries are excluded by the build flags above.

## Finding 110: Syscall 557/558 Is a Named Handle Pair with a Caller-Chosen Word, and It Is Clean (probes 854a, 854b, 855a, 2026-10-26)

`557` (13.60 offset `0xac7240`, narg 3) is a create; `558` (`0xac73c0`, narg 2) is the
matching destroy. Both were measured on 14.10 for the first time.

`557`: rejects a null arg1 (`0x16`); `malloc(0x20)` plus `copyinstr 0x259900` holds a
20-byte name; `malloc(0x18)` holds the entry `{[0]=name buffer, [8]=arg2}`; `0x3998e0`
allocates the id; `0x399de0(record, type, entry, name)` writes
`[record+0x20] = (u16)type`, `[record+0x10] = entry`, `[record+8] = name`,
`[record+0x22] = 0`, where the type is **`0x1000 | (u32)arg3`**. The `0xb078d0` boot
gate and a notification follow.

`558`: `type = (u16)arg2 | 0x1000`, an exclusive lookup at `0x39a2a0` (which compares the
rebuilt `(gen<<13)|slot` id, requires `word [record+0x26] == 3`, and requires
`word [record+0x20]` to equal the type **exactly**), then `0x399e30` marks the record
removed (`[record+0x26] = 1`) and clears its payload pointer, `0x399eb0` unlocks, and the
handler frees `[entry]` (the name buffer) and then `entry` itself. No name map, no
refcount, no callback - and the record keeps no dangling pointer because the payload is
cleared under the same lock.

Measured:

| call | result |
|---|---|
| `557(name, 0x1234, 0x200)` | id `0x208` |
| `558(0x208, 0x200)` | `0` |
| `558(0x208, 0x200)` again | `-1` |
| `558(id, 0x300)` on a `0x300` object | `0` |
| `558(0x300-object, 0x200)` (wrong type) | `-1` |
| `557` with an already-used name | a new id (`0x4208`) - duplicates are allowed |
| `558(0, 0)`, `558(0xFFFF, 0x2000)`, `558` on any osem id | `-1` |

Two consequences. The family's type word always has bit 12 set, which is why `558` can
never match the semaphore (`0x120`), aio (`0x160`) or `0x2000` records, and why the
previous "ungated destroy of an osem object" idea was wrong. And the handler's mismatch
path returns `-1`, not the `3` a table miss would give, so `-1` alone cannot distinguish
"absent" from "wrong type" here.

The entry payload is a single 64-bit word chosen by the caller, but no syscall reads the
`0x1000|T` family back: `556` is the semaphore reader (`0x399ee0` with type `0x120`,
`0xc15c20`, a 4-byte copyout), and `559`/`560` are per-process bookkeeping. A controlled
word that nothing consumes is not a primitive, so this pair is closed as a memory-safety
lead.


## Finding 111: Syscall 532's Command Family Is Gated on Per-Process Device State (probes 856a-861a, 2026-10-26)

Syscall 532 was the "unprivileged handle table" candidate; it had never been
given valid arguments. The handler (`0xaf0040`, dump base `0xffffffff8a9c0000`)
loads `uap[0]` as the command, `uap[8]` as arg2 (dword), `uap[0x10]` as arg3
(status out pointer), `uap[0x18]` as arg4 and `uap[0x20]` as arg5.

Two gates come first:

- `0xaf00e6 call 0xadfa30(thread, 0x2aa)`: a privileged caller may issue only
  commands `0x18..0x1E`, `0x20` and `0x2F`; anything else jumps to the error tail
  `0xaf1223`.
- an unprivileged caller requires `0x609080([proc+0x140]) == 1`, else the code
  continues at `0xaf02a6`; that is the path this process always takes.

The dispatch is two jump tables, both at addresses **outside** `kernel_text.bin`
(`0x189E230` for `arg4 == 0`, `0x189E34C` for `arg4 != 0`), so the command
bodies could not be read from the capture and the surface was measured instead:

- Before the second table, `arg5` is compared as a **size**: `cmp rdx,0x30` for
  command `0x20`, `cmp rdx,0x818` for everything else, a mismatch storing
  `0x800D0208`; then `0xaf0345 bzero([rbp-0x850], 0x818)` and
  `0xaf03e9 copyin(arg4, &stack, <that size>)`.
- `arg3 == 0` stores `0x800D0202` and returns without touching the command, which
  is why every earlier probe with a NULL status pointer saw "no answer".

Measured on 14.10, with a mapped 0x18-byte record in `arg4` and a mapped status
page in `arg3`:

| command | arg4 = 0 | arg4 = 0x18 record, `record[0] == 0` | `record[0] != 0` |
|---|---|---|---|
| `0x18`-`0x1D` | `0x800D0202` | `0x800D0203` | `0x800D0204` |
| `0x1E` | `0x800D0202` | `0` | `3` |
| `0x20` | `0x800D0202` | `0x800D0208` (size 0x818) / `0x800D0219` (size 0x30) | same |
| `0x2F` | `0x800D0202` | `0` for every size 0..0x2000, buffer untouched | same |

`0x1E` returns a constant `3` for any non-zero first word across twelve repeats
(not a counter or an id source); a sweep of `record[0]` over 1..0x1000 for
commands `0x18`-`0x1D` produced only `0x800D0204`; fifty calls to `0x1E` do not
change what `0x18` answers; and **no command ever writes the caller buffer**.

Status-code provenance supports the reading: `0x800D020F` occurs four times in
the whole capture, all inside 532 (`0xaf04cf`), and `0x800D0210` three times
(`0xaf0e5a`); the codes seen in the ungated path (`0202`, `0203`, `0204`, `0208`,
`0218`, `0219`) are shared with other handlers.

Conclusion: the family needs the per-process device state at `[proc+0x140]` that
this process never has; the ungated path performs one lookup that fails and, for
`0x1E`, a boolean report. There is no write, no copyout and no leak. 532 is
closed as a primitive, and the earlier "532 does nothing" results were the
NULL-status-pointer guard seen through an unmapped `arg4`.

## Finding 112: The kernel image is present in the page table but not mapped for user access (probes 1056a, 1057a, 1058a, 2026-11-03)

**Correction (1058a review, same day).** The chain in 1056a and the first revisions of 1058a
began with a `pop rax` gadget while `RIP` was already that gadget, so the operand the initial
`pop` consumed was the gadget address and the following `ret` jumped to the **probed page**.
Those children therefore faulted on instruction fetch at the page, not on a data read. The
measured `readable=0 of 512` is a statement about instruction fetches; it does not establish
that the pages are unreadable. The corrected form (as in the working `1008a`) is
`{ page, mov_rax_[rax], pop_rdi, out, mov_[rdi]_rax, ... }` with `RIP` = the `pop` gadget.

What survives the correction:

- Kernel addresses fault with error code `0x15` where the image is mapped and `0x14` where it
  is not (the `#PF` error word at trapframe offset `0x130`: `P` bit, `U` bit, `I/D` bit). Since
  `I/D` is set in both, these were instruction fetches, which is exactly what the presence
  oracle in `docs/FAULT_CODE_ORACLE_14_10.md` needs: presence is established without any
  read attempt, so the image base, size and per-boot slide stand.
- The number of dumps equals the number of children, and the process keeps one pid across all
  of them, which confirms containment of child faults in favour of `726a`.
- `1057a` dumped four 0x80-byte chunks of the fault context at `+0x40`, `+0x100`, `+0x180`,
  `+0x200`; everything past the register and fault fields is zero. The FPU/XSAVE area holds
  no stale bytes to harvest.

The read question was re-opened with the corrected chain. What 1058a/1059a then measured:

- The chain's control read returns a user page's contents (`[C] control=1122334455667
  want=1122334455667`), so the fixed layout really does execute `mov rax,[rax]`.
- Pages `0xFFFFFFFF95000000` through `0xFFFFFFFF9503F000` (the first 64 x 4 KB of the image)
  are **not readable**: every slot kept the `0xDEADBEEF` sentinel while the handler delivered
  one 64-byte context dump per page, so each child ran and each load faulted.
- **The whole image is supervisor-only, measured.** `tools/kernel_read_sweep_chunks.py
  --chunk 60` walked all 6 272 pages of the 98 MB image at 16 KB granularity across 105
  connections in one process: every chunk printed `readable=0`, the aggregate is
  `readable pages: 0  unmeasured: 0`, and the process answered a witness after the last
  chunk. No user-readable gap exists in the kernel image.
- **Retraction of the fault-budget claim.** An earlier revision recorded a wall at 64
  faulting children per process. That wall was our own defect: the child chain was written at
  the mapping base and the kernel builds the signal frame *below* the faulting rsp, so those
  children died without the handler running and their pages read as unreadable for a delivery
  reason. With 0x800 of headroom, 75 faulting children in one process left it alive
  (`[C] control=1122334455667`, `[R] readable=0 of 60`, `[E] alive pid=274`). Any child-thread
  probe must write its chain at least 0x800 above a mapped stack base.
- Consequence: the `#PF` error word can report page state but never page contents. The oracle
  in `docs/FAULT_CODE_ORACLE_14_10.md` stays presence-only, and this is now measured over the
  full image rather than sampled.
