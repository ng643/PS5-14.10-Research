# Complete Attack Surface Map — PS5 14.10

## Syscall Status

### Fully Working
| Syscall | Number | Notes |
|---------|--------|-------|
| `read` | 3 | Works on socket fds |
| `write` | 4 | Works on socket fds |
| `close` | 6 | Standard fd close |
| `getpid` | 20 | Returns process PID |
| `recvmsg` | 27 | Full functionality with MSG_DONTWAIT |
| `sendmsg` | 28 | Full functionality with MSG_DONTWAIT |
| `socket` | 97 | AF_INET, AF_INET6, AF_UNIX; STREAM, DGRAM, RAW |
| `connect` | 98 | TCP and raw socket connect |
| `bind` | 104 | Works on loopback (port restrictions may apply) |
| `setsockopt` | 105 | Limited options writable (see below) |
| `listen` | 106 | TCP listen works |
| `getsockopt` | 118 | Most options readable |
| `readv` | 120 | Up to IOV_MAX=1024 iovecs |
| `writev` | 121 | Up to IOV_MAX=1024 iovecs, 1025 rejected |
| `socketpair` | 135 | AF_UNIX SOCK_STREAM |
| `shutdown` | 134 | Standard shutdown |
| `poll` | 209 | Correct POLLIN/POLLHUP/POLLNVAL semantics |
| `mmap` | 477 | RW only (no EXEC). MAP_FIXED works. |
| `munmap` | 73 | Standard |
| `madvise` | 75 | Most advisories work (not MADV_PROTECT) |
| `mlock` | 203 | Works |
| `sigaction` | 416 | Can set SIG_IGN/SIG_DFL, install handlers |
| `fcntl` | 92 | F_GETFL works; F_SETFL cosmetic only |

### Partially Working / Limited
| Syscall | Notes |
|---------|-------|
| `setsockopt` | Only: TCP_NODELAY, TCP_KEEPINIT, SO_SNDBUF, SO_RCVBUF, SO_RCVLOWAT, SO_LINGER, SO_TIMESTAMP, IP_TTL, IP_MINTTL, IP_HDRINCL, PS5 custom flags |
| `mmap` | RW only — PROT_EXEC always stripped. MAP_FIXED works for page-aligned remapping. |
| `fcntl F_SETFL` | Returns -1 but updates visible flags. **Kernel does NOT honor the flags** (O_NONBLOCK has no effect). Each call REPLACES flags (not OR). |
| `sigaltstack` | Can set alternate stack, but signal delivery to it triggers copyout() validation → EFAULT → process killed |
| `kqueue` / `kevent` | Valid fd; tested read, signal, user, and timer filters register or produce events. See saved probes 20 and 21. Copy-on-fork behavior is untested; process creation returned -1 in probe 27. |
| Sony sys 649 (module member) | ret=0 for member types 1-4, 7, 8 — returns userland module addresses only, no kernel pointers. (probe 54k, 2026-10-18) |
| Sony sys 674 (VM map) | Returns 317 named regions with protections. All userland VA, zero kernel pointers. (probes 55e/55f, 2026-10-18) |
| Sony sys 624 (VM op counter) | +5 per mmap, zero jitter, monotonic. Useful as kernel-operation side channel. (probe 52b, 2026-10-18) |
| Sony sys 587 (credential metadata) | ret=0, returns 0x88 bytes. Only +0x0C = 0x20000000. No kernel pointers. (probe 55e, 2026-10-18) |
| Sony sys 671 (resource class) | Returns memory budget values. Explicit selectors need credential bit 62. (probe 55e, 2026-10-18) |
| Sony sys 643 (chicken switches) | All 32 bits accepted (ret=0) but no observable effect on W^X/sandbox. (probe 55a, 2026-10-18) |
| Sony sys 675 (reset globals) | ret=0, resets 3 globals. mprotect(RWX) still fails after. (probe 55e, 2026-10-18) |
| `_umtx_op` (454) | Ops 5 (MUTEX_LOCK) and 21 (NWAKE_PRIVATE) returned 0 via make_syscall, op 5 writing a TID-shaped owner word (probe 56i2, 2026-10-18). The earlier "umtx" probes 04/10-13 actually called syscall 557 (namedobj_create) — see [UMTX_454_EVIDENCE](UMTX_454_EVIDENCE.md). SHM(25)/ROBUST_LISTS(26) and the wider op matrix untested; probe 110a prepared. |

### Completely Blocked (return -1 or killed)
| Syscall | Number | Notes |
|---------|--------|-------|
| `fork` | 2 | Blocked |
| `rfork` | 251 | Blocked |
| `thr_new` | 455 | Blocked |
| `dup` | 41 | Blocked |
| `dup2` | 90 | Blocked |
| `fstat` | 189 | Blocked via resolve(); WORKS via make_syscall — no kernel pointers in output (probe 43e) |
| `pipe` | 42 | Blocked |
| `pipe2` | 542 | Blocked |
| `ioctl` | 54 | Blocked |
| `sysctl` | 202 | Blocked via resolve(); WORKS via make_syscall — kern.proc.pid returns 1096B, no kernel pointers (probes 41w, 42a, 43d) |
| `mprotect` | 74 | PROT_EXEC always denied |
| `aio_read` | 255 | Blocked — kills process (confirmed 2026-10-18 via probes 54c/54f) |
| `aio_write` | 256 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_return` | 314 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_suspend` | 315 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_cancel` | 316 | Blocked — kills process (confirmed 2026-10-18) |
| `aio_error` | 317 | Blocked — kills process (confirmed 2026-10-18) |
| Sony AIO 661 (event_create) | 661 | SIGSYS under the default disposition; returns -1 with `SIG_IGN` installed (54c, 711a), so the slot is absent. 662-670 are separate and were reached later — see `docs/AIO_RANGE_14_10_EVIDENCE.md` |
| Sony sys 626 (RDMSR) | 626 | ret=-1 for all 11 MSR indices, 3 arg layouts (probe 54k, 2026-10-18) |
| Sony sys 567 (RDMSR read) | 567 | ret=-1 for all MSR indices, flat + struct args (probe 54k, 2026-10-18) |
| Sony sys 629 (jail bypass) | 629 | ret=-1 for all arg patterns; kld* retests crash (probe 54b, 2026-10-18) |
| Sony sys 598 (dynlib context) | 598 | ret=-1 for all arg patterns (probe 54f, 2026-10-18) |
| Sony sys 612 | 612 | ret=-1 for member values 0-8 (probe 54k, 2026-10-18) |
| Sony sys 639/638 | 639 | Not "memory region": the pair is `localtime_to_utc`/`utc_to_localtime` over a 258-record timezone table at a fixed RVA. 638 copies 16 bytes of that table to uid 1 per call (bounded `index <= count-1`, keys 1968..2099) — a real but useless kernel read — and 639 mirrors it. Probe 54f's `ret=-1` was a bad-output-pointer `EFAULT`, not a refusal. See [the 638 analysis](TZ_TABLE_638_14_10.md) |
| `shm_open` | 482 | Crashes loader |
| `sendto` | 133 | Crashes syscall.resolve() |
| `recvfrom` | 29 | Crashes syscall.resolve() |
| `fcntl F_SETOWN` | — | Truly blocked (F_GETOWN stays -1) |
| `sigprocmask` | 340 | No-op: returns 0 but never modifies mask |
| `kevent` with nonzero timeout | 363 | Returns -1 with a 100ms timeout (probe 30c, PART 6). Zero-timeout register, poll, batch register, and delivery all work: 3+ events (probe 20), 31 signals, 20 user, 2000 knotes (probe 21) — including combined add+poll calls. See [the kevent analysis](KEVENT_TIMEOUT_VARIABLE.md). |
| `kldstat` | 308 | Raises SIGSYS, so the **default disposition** terminates the caller; with `SIG_IGN` installed it returns -1 and the process survives (353a/353b, 710a/711a). The slot is absent, not a hostile handler (56k4, 2026-10-18) |
| `kldnext` | 307 | Same shape as 308: SIGSYS under the default disposition, -1 under `SIG_IGN` (56k5, 353b, 711a) |
| Sony sys 548 (batch VM ops) | 548 | ret=-1, processed=0 for all opcodes (probe 55b, 2026-10-18) |
| Sony sys 622 (device control) | 622 | Sony error 0x800E0001 for all 400+ commands in the slot-1 layout — no device context (probe 55c, 2026-10-18). The handler reads the command from **slot 0**; in that layout 0x300/0x301 return 0 and write 0xFFFFFFFF, and 0x302 is lethal for every input tested: len=0 (1039a), a fully defined 0x40-byte zero buffer (1053a) and 0x40 bytes of valid user pointers at every 8-byte offset (1054a, 2026-11-03) ; the `0x201`-`0x271` arm is fully mapped (113 commands) and the only non-default status is `0x271` -> `0x8002004E` with `rv=0`, a handler-level credential-mask predicate that never touches errno (1152a, 2026-11-04) |
| Sony sys 601 (process control, `mdbg_service`) | 601 | **CLOSED as a kernel-R/W route (1195a, tenth boot).** All 0x28 command slots measured with `arg3 = 0x28`: no command writes 0x28 bytes, none writes `arg3`, the EPERM set never flips, and `0x8b6612d5`/`0x8b66180c`/`0x8b662320` have **zero direct callers** in the whole image, so those cases are not in 14.10's table. Behavioural map stands; route is dead. **Two interfaces, not one.** (a) the 0x00-0x27 case table (measured, see `docs/MDBG_601_COMMAND_MAP_14_10.md`; its "-1" column is errno-blind) and (b) a second-stage dispatcher `0xca2320(td, arg2, arg3)` reached from exactly one branch, `0xca0cda: test byte [td+0x529],1; jne 0xca180c`. Bit 8 of `td+0x528` is set by 601's own attach case (`0xca131f: or qword [td+0x528],0x100`, reading `td_proc` from `[td+8]` — no kernel pointer needed). Stage two copyin's a 0x3c struct, dispatches on `struct+0x24` (**types 3,4,5,7 pass with no credential**), ingests blobs into a per-process **0x80000 kernel buffer** (`ctx+0x58`, plain `memcpy` at `0xca295f`), sends type 3 to `0x8b663e30(td, buf, len)`, and copyout's 8 bytes to `arg3`. The log drain (`0xca32b0`) is still unattributed: the case table lives at RVA `0x1a51160`, above the 15.1 MB text dump. Wedges: **`0x08`/`0x0C` never return** (1170a/1172a), **`0x1B`/`0x27` kill the process**, **`0x03`/`0x04` panic** (raw `struct proc*` deref), and **`0x00` with a non-zero `arg3` wedges the loader** (1192a). See [SYS601_SECOND_STAGE_14_10.md](SYS601_SECOND_STAGE_14_10.md) and [the wedge list](LOADER_WEDGE_COMMANDS_14_10.md) |
| Sony sys 672 (dynlinker list) | 672 | ret=-1, predicate gate failed (probe 55e, 2026-10-18) |
| Sony sys 676 (CPU mode) | 676 | ret=-1, gate failed (probe 55e, 2026-10-18) |
| Sony sys 631 | 631 | SIGSYS under the default disposition; returns -1 under `SIG_IGN` (52a, 353a, 711a), so the slot is absent |
| Sony sys 627-630 | 627 | PCALL-FAIL / exception for all four (probe 52a, 2026-10-18) |

### Untested (Potential Targets)
| Syscall | Number | Notes |
|---------|--------|-------|
| `ktimer_create` | 235 | **WORKS** — clocks 0 (REALTIME) and 4 (MONOTONIC), cap 27 timers |
| 236 (42a: `ktimer_settime`) | 236 | 42a's label; upstream numbers 236 as `ktimer_delete` (1 arg) — numbering disputed, differential prepared in probe 56l (unrun) |
| `ktimer_getoverrun` | 239 | **WORKS** |
| `ktimer_gettime` | 238 | Probe-labeled gettime blocked on 42a-created ids; interpretation depends on the disputed 236/237 pair |
| 237 (42a: `ktimer_delete`) | 237 | 42a's label; upstream numbers 237 as `ktimer_settime` (4 args) — numbering disputed, differential prepared in probe 56l (unrun) |
| Sony sys 563-566 (PMC config) | 563 | ret=0 but effect is PMC configuration, not info leak (probes 54f, 2026-10-18) |
| `ppoll` | 545 | Blocked |
| `cap_rights_limit/get` | 533/515 | Blocked |
| `memfd_create` | 585 | Stub — returns fake fd=1 |
| `minherit` | 250 | Outcome unresolved: probe 38 ends at the minherit section header, without a result or termination record |
| `msgsnd` | 226 | 226 is `msgsnd` in the 13.60 sysent table (`docs/sysent-names-13.60.csv`), not `msync`; probe 42b's "msync" call therefore sent a region address as a message buffer and ended after printing it, without a result or termination record |
| `accept` / `accept4` | 30 / 541 | Resolves, EBADF on bad fd; needs live TCP listener test |
| `preadv` / `pwritev` | 289/290 | Resolve, EBADF on bad fd; no real file fd available to test |
| `copy_file_range` | 580 | Resolves, EBADF; untestable without file fds |
| `getsockname` | 32 | Works |
| `getpeername` | 31 | Resolves |
| `sctp_peeloff` | 471 | Resolves (SCTP socket creation untested) |
| Native sysent 677-734 | 677-734 | **Out of range on 14.10** — the live dispatch table ends at 677 entries: 677/678 panic the console, and every accounted number below that answers. Names from `docs/sysent-names-13.60.csv`: 725 `mmap2`, 726 `get_aio_debug_submit_info`, 727 `get_aio_debug_request_info`, 728 `virtual_query_by_pid`, 729-731 `fgcinfo_*`, 734 `trace_ctrl`. 726/727 would export raw kernel pointers on 13.60 (`docs/AIO_DEBUG_726_727_13_60.md`); no probe is written and none should be. Probe 57a is withdrawn: it prints a notice and returns (`docs/PROBE_INDEX.md`). |

## Bind Policy (probe 36)
- Ports <1024: blocked. Ports ≥40000: blocked. 1024–32767: open.
- Listener port for all future probes: **31337/31338** (confirmed working).

## Network Input Path Status (probes 37/39)
- `ip_reass()`: all standard fragment cases handled correctly — deeper fuzz (queue exhaustion, timeout, 64+ frags) still open.
- `ip_dooptions()`: runs on loopback injection (LSRR/SSRR/TS-overflow get processed and dropped), but **malformed option lengths are rejected in ip_output before reaching the parser**. Input-side option fuzzing must come from the real network (PC → PS5 LAN IP), not loopback.

## Socket Options Accessible

### SOL_SOCKET (level 0xFFFF) — 23 options
```
0x0001 SO_DEBUG          0x0002 SO_ACCEPTCONN     0x0004 SO_REUSEADDR
0x0008 SO_KEEPALIVE      0x0010 SO_DONTROUTE      0x0020 SO_BROADCAST
0x0080 SO_LINGER         0x0100 SO_OOBINLINE      0x0200 SO_REUSEPORT
0x0400 SO_TIMESTAMP      0x0800 SO_NOSIGPIPE
0x1001 SO_SNDBUF         0x1002 SO_RCVBUF         0x1003 SO_SNDLOWAT
0x1004 SO_RCVLOWAT       0x1005 SO_SNDTIMEO       0x1006 SO_RCVTIMEO
0x1007 SO_ERROR          0x1008 SO_TYPE
0x1011 SO_SETFIB         0x1012 SO_USER_COOKIE    0x1013 SO_TS_CLOCK
```

### PS5 Custom Socket Options (Sony-extended)
```
0x2000   — boolean flag bit in so_options
0x10000  — boolean flag bit
0x20000  — boolean flag bit
0x40000  — boolean flag bit
0x100000 — boolean flag bit
```
All are simple on/off toggles. set(any_nonzero) → readback = option_number. Same behavior on all socket types. **Not exploitable.**

### TCP Level (level 6)
- `TCP_NODELAY` (1) — writable
- `TCP_KEEPINIT` (128) — writable
- `TCP_INFO` (32) — 236 bytes readable, all protocol metadata, no kernel pointers
- `TCP_CONGESTION` (64) — "newreno"

### IP Level (level 0)
- `IP_TTL` (4) — writable (accepts 256, -1)
- `IP_MINTTL` (66) — writable
- `IP_HDRINCL` (2) — writable on RAW sockets (value reads back as 8 = INP_HDRINCL flag)


## Sony 601-660: measured on 14.10 (2026-10-20)

One connection per number, six zero `uint64` arguments, via
`tools/syscall_isolation_sweep.py --range 601-660 --wait-for-loader 120`.
Capture: `results/phase15_native_sent/syscall_isolation_sweep_20261020_194148.txt`.

| syscall | 13.60 name | zero-arg result |
|---|---|---|
| 601 | `mdbg_service` | -1 |
| 602 | `randomized_path` | 0 |
| 603 | `rdup` | -1 |
| 604 | `dl_get_metadata` | -1 |
| 605 | `workaround8849` | -1 |
| 606 | `is_development_mode` | 0 |
| 607 | `get_self_auth_info` | -1 |
| 608 | `dynlib_get_info_ex` | -1 |
| 609 | `budget_getid` | kills |
| 610 | `budget_get_ptype` | -1 |
| 611 | `get_paging_stats_of_all_threads` | -1 |
| 612 | `get_proc_type_info` | -1 |
| 613 | `get_resident_count` | -1 |
| 614 | `prepare_to_suspend_process` | kills |
| 615 | `get_resident_fmem_count` | -1 |
| 616 | `thr_get_name` | -1 |
| 617 | `set_gpo` | 0 |
| 618 | `get_paging_stats_of_all_objects` | -1 |
| 619 | `test_debug_rwmem` | -1 |
| 620 | `free_stack` | 0 |
| 621 | `suspend_system` | kills |
| 622 | `ipmimgr_call` | slot-0 command; 0x300/0x301 return 0 with 0xFFFFFFFF, 0x302 kills for len=0, zero and pointer-shaped input (`1039a`/`1053a`/`1054a`); slots 1/5/6 untested (`1055a`) |
| 623 | `get_gpo` | -1 |
| 624 | `get_vm_map_timestamp` | 3377 |
| 625 | `opmc_set_hw` | -1 |
| 626 | `opmc_get_hw` | -1 |
| 627 | `get_cpu_usage_all` | -1 |
| 628 | `mmap_dmem` | -1 |
| 629 | `physhm_open` | -1 |
| 630 | `physhm_unlink` | -1 |
| 631 | `resume_internal_hdd` | kills |
| 632 | `thr_suspend_ucontext` | -1 |
| 633 | `thr_resume_ucontext` | -1 |
| 634 | `thr_get_ucontext` | -1 |
| 635 | `thr_set_ucontext` | -1 |
| 636 | `set_timezone_info` | -1 `EPERM` for every argument shape, because the bit-62 credential test runs before the `count` validation (1162a) — with bit 62 it would be a bounded 8 KB write into the timezone table. See [the 638 analysis](TZ_TABLE_638_14_10.md) |
| 637 | `set_phys_fmem_limit` | 0 for self with `limit >= 0x40000000` (340a/343a/344a/887a), -1 for a foreign pid (888a). **`limit` in `[17, 0x40000000)` wedges the calling process and the loader permanently** — `637(0,17)` never returns and the console needs a relaunch (1162a; 339a hit it silently on 2026-10-22). Do not probe this range. See [the 637 wedge](PROC_LOCK_WEDGE_637_14_10.md) |
| 638 | `utc_to_localtime` | 0 |
| 639 | `localtime_to_utc` | 0 |
| 640 | `set_uevt` | 0 |
| 641 | `get_cpu_usage_proc` | -1 |
| 642 | `get_map_statistics` | -1 |
| 643 | `set_chicken_switches` | 0 |
| 644, 645 | unnamed in the 13.60 capture | -1 |
| 646 | `get_kernel_mem_statistics` | -1 |
| 647 | `get_sdk_compiled_version` | -1 |
| 648 | `app_state_change` | -1 |
| 649 | `dynlib_get_obj_member` | -1 |
| 650 | `budget_get_ptype_of_budget` | kills |
| 651 | `prepare_to_resume_process` | kills |
| 652 | `process_terminate` | -1 |
| 653 | `blockpool_open` | handle (22, then 23, 24, then -1) |
| 654 | `blockpool_map` | -1 |
| 655 | `blockpool_unmap` | -1 |
| 656 | `dynlib_get_info_for_libdbg` | -1 |
| 657 | `blockpool_batch` | 0 (zeroes 16 bytes at arg3 when arg2=0) |
| 658 | `fdatasync` | -1 |
| 659 | `dynlib_get_list2` | -1 |
| 660 | `dynlib_get_info2` | -1 |

### Follow-up probes on the interesting slots

- **619 `test_debug_rwmem` (179a)** - fifteen argument layouts, including the calling pid in
  arg1, a canary page in each of arg1..arg3, and `(pid, src, dst, size, write)` in both
  directions. Every call returned `-1` and no byte changed. The handler runs and refuses all
  of it, which reads as a privilege or process-flag gate rather than an argument problem.
  Capture `results/phase17_new_vectors/179a_debug_rwmem_args_20261020_194308.txt`.
- **625 `opmc_set_hw` / 626 `opmc_get_hw` (180a, 181a, 182a)** - 625 accepts exactly
  `arg1` in `{0x0D, 0x0E, 0x0F, 0x10}` with `arg2` in `{1, 2, 3}` and returns `0`; everything
  else is `-1`. 626 returned `-1` for 1270 shapes, including the exact pairs 625 accepts, both
  with a canary page in arg3 and with NULL. So the setter takes a narrow window and the getter
  never answers - no MSR read, no readback. Captures
  `results/phase17_new_vectors/180a_opmc_hw_20261020_194332.txt`,
  `181a_opmc_set_hw_surface_20261020_194345.txt`,
  `182a_opmc_get_hw_surface_20261020_194421.txt`.
- **653-657 blockpool (183a, 184a)** - `blockpool_open` is not a stub: it returns 22, then 23,
  then 24, then `-1` for every later call in the same process, so it allocates handles from a
  small per-process pool. `blockpool_map` and `blockpool_unmap` returned `-1` for every shape
  tried, including the live handle in arg1 with size and buffer variants. `blockpool_batch`
  returns `0` and zeroes the first 16 bytes of arg3 when arg2 is 0, and `-1` for arg2 1-8. No
  mapping was obtained. Captures
  `results/phase17_new_vectors/183a_blockpool_20261020_194445.txt`,
  `184a_blockpool_batch_20261020_194508.txt`.
