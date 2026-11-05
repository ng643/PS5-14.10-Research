# Changelog

## First measured sysent presence map: 538-621 (2026-11-05)

- **Probe 1255a mapped 538-621 with the SIG_IGN oracle in one connection**: 53 present, 26 absent. Present: 538-560, 567, 572, 586-588, 591-596, 598-608, 611-613, 615-618, 620. Absent: 561-562, 568-571, 573-584, 589-590, 597, 609-610, 614, 619, 621. The twelve consecutive absent slots 573-584 are a removed family, the same shape as the earlier 561/562 and 568-571 removals.
- **Each present handler now has a clean errno for zeroed arguments** — the first such reading for most of the range. EPERM/EACCES rows are the capability gate refusing zeros; `ret=0` rows (548, 560, 596, 602, 606, 617, 620) accept a zero argument and are the only ones that reach real code without a valid argument shape.
- **622 is a real handler that faults on a NULL first argument.** `622(0,0,...)` (1255a) and `622(0,valid_buf,...)` (1256a) both killed the process under SIG_IGN, so arg1 = 0 is the trigger, not a missing handler. The 55b/55c command sweep used 0x100-0x520 in arg1 and never hit it. 622 must always be called with a non-zero first argument.
- New doc `docs/SYSENT_PRESENCE_MAP_538_621_14_10.md`; probes `1255a_presence_map_538_676.lua`, `1256a_presence_map_622_676.lua`.

## AIO is absent on 14.10; 631 and 677/678 are nosys, not hostile (2026-11-05)

- **`aio_submit`(661), `aio_get_data`(665) and `aio_create`(668) return `-1 / ENOSYS` under `SIG_IGN` for SIGSYS** (probe 1254a): they are absent on 14.10. No AIO ID can ever be created, so the `aio_multi_delete`(662) TOCTOU — the Lapse/Prolapse bug, patched in 14.20 — is unreachable on this firmware despite 14.10 being inside the announced vulnerable range. This supersedes "unreachable by construction": there is no entry point at all.
- **631, 677 and 678 are `nosys` slots, not lethal handlers.** 631 "killed the process" (52a) and 677/678 "killed the process and crashed the game" (2026-10-20) only because the default SIGSYS disposition terminates the process; with SIG_IGN all three return ENOSYS and the process is untouched. The syscall map's "lethal" column was measuring the process's signal disposition, not the kernel's behaviour, and must be re-derived with the oracle.
- **628, 629 and 630 are present and rejecting zeros** (EINVAL 22, EFAULT 14, EFAULT 14) — the first clean errno readings for 629/630, which 52a had recorded as PCALL-FAIL.
- New doc `docs/AIO_ABSENT_AND_KILL_LIST_RECLASSIFIED_14_10.md`; `docs/AIO_RANGE_14_10_EVIDENCE.md` carries a supersession note.

## The sysent tail is absent, measured; three more static closures (2026-11-05)

- **The 14.10 sysent ends at 676 — measured, not inferred** (probe 1253a). With `SIG_IGN` for SIGSYS installed and verified by read-back, the control number 4095 returns `-1 / ENOSYS` with the process alive, and so do 705 `get_phys_page_size` (called with no arguments), 687 `pipe2`, 690 `ppoll`, 728 `virtual_query_by_pid`, 725 `mmap2` and 715 `ioreq`, each with valid non-faulting arguments. The earlier 677-707 kills were the default SIGSYS disposition, not faulting handlers. The table resolves 677 entries against the 13.60 capture's 735; `wait6`, `procctl`, `apr_*`, `get_phys_page_size`, `begin_app_mount` and the rest of the tail are unreachable. New doc `docs/SYSENT_TAIL_ABSENT_14_10.md`.
- **Call-aware direct-deref census: 0 bodies** (`.local/deref_callee_saved.py`). Keeping taint across `call` for callee-saved registers, tracking `[rbp+disp]` spills and seeding `rsi = uap`, no body dereferences a user-derived value. The closure holds under the model it was accused of missing; plan rows P1 and P8 lose their justification.
- **The blockpool installer hypothesis is refuted.** Decoding 0x9a6c00-0x9a7d10 and 0x9a7f00-0x9a9560 gives 68 call targets and **zero** calls to mmap's insert wrapper `0xab9f60` or its apply helper `0x2d2e50`. Blockpool builds a type-0xb `vm_object` and never inserts it into a map.
- **R1 is dead twice over.** `547(va,out)` returns the non-PTE branch (`out+0x10` low dword 3 = RW), which measures `proc+0xc81 == 0` at runtime; `0xc81` has one writer image-wide, RVA `0x38f7bf`, inside process creation. And 379's `vm_map_protect` only searches the caller's vmspace, so no foreign PTE is reachable. R1 needed the PTE branch, so a type-0xb mapping would not have produced physical addresses.
- **Four rows the plan still listed as open were already closed**: the 17 OBJECT-sourced copyout candidates (upstream, 2026-10-28, zero kernel pointers), CVE-2026-49412 IPV6_MSFILTER (measured clean, probe 50w), CVE-2026-45251 poll+close (60 raced closes, no corruption, probe 1234a), and socket-level SIOC\* (probe 1222a). New doc `docs/STATIC_CLOSURES_2026_11_05.md`.

## Three more routes closed: Spectre transmitters, 674 bounds, tag provenance (2026-11-05)

- **No Spectre v1 transmitter exists in the 13.60 text.** Full linear capstone sweep (6,134,149 instructions) for indexed-load -> shift -> indexed-store on the same register found exactly one hit, and its second access is a load, not a store. The CPU route has no kernel-side gadget to build on.
- **674's handler is bounded by construction** (thunk `0x265FA0` -> body `0xABB980`, narg=5): `copyout` length is `min(stride,0x48)`, `max` is only a loop bound, and the record is a fixed 0x48-byte stack slot. No integer or count overflow is available there.
- **Every capability tag is read from a proc field, never from user memory.** Of 239 call sites to the 45 tag helpers, all `rdi` provenance resolves to `[proc+0x40]` or `[proc+0x140]` via `gs:[0]`. Forging a tag to unlock 607 is not possible.

## PROT_EXEC is stripped for vnode mappings too; the CPU route is a Meltdown design (2026-11-05)

- **674 is now a calibrated oracle that reports EFFECTIVE protection** (probe 1251a). One call with 55f's shape returns 322 regions; the record is start +0x00, end +0x08, prot +0x18, length-prefixed name at +0x20. Calibration against four knowns: anon `prot=7` records as `0x3` rw-, file `prot=5` as `0x1` r--, file `prot=7` as `0x3` rw-, and eboot's own `.text` as `0x5` r-x.
- **`PROT_EXEC` is dropped at `mmap()` time for vnode objects as well as anon** - a `MAP_PRIVATE` `prot=7` mapping of `/app0/eboot.bin` is recorded `rw-`. `docs/SPECULATION_READ_14_10.md` §4's last live candidate is dead, and **probe 1251b must not be run** (it would be a guaranteed loader kill for a known answer). 1248a's fcall branch now skips unconditionally.
- **The whole executable surface is measured** (probe 1252a): 322 regions, 41 executable (11.7 MB), and **zero writable** - W+X does not exist anywhere in the process. Four `r-x` regions (eboot text `0x10B4000-0x1548000`, `libc.prx`, `libSceFios2.prx`, one unnamed 0x4000 page) and 37 `--x` XOM library texts that can be called but not read.
- **The CPU route in the doc is a Meltdown-class design.** Its userland gadget loads a supervisor address and asserts the data is forwarded before the fault retires; that is CVE-2017-5754, which Zen 2 does not do. Spectre v1 requires the out-of-bounds load to be architecturally legal for the code executing it, so a ring-3 gadget can never read supervisor memory. Finding a writable executable page would not have made it work.
- **Redirected design:** a Spectre v1 kernel read needs a *kernel* syscall path with an attacker-controlled index, a mispredictable bounds check, and a dependent scaled load that stores into a caller-supplied user buffer. That needs no executable user page and is unaffected by PTI. Work moves to a static census of speculatable bounds checks in the 13.60 image.
- **New doc** `docs/EXEC_SURFACE_AND_SPECULATION_14_10.md`; new probes `1251a_674_calibration.lua`, `1252a_exec_surface_map.lua`.

## 607 is live but gated; 629 is a mapping-level stub; copyin does fault pages in (2026-11-05)

- **Syscall 607 is present on 14.10 and its errno ladder is fully readable** (probe 1249a, repaired). `/app0/eboot.bin` -> EACCES 13; `/dev/null`, `/`, `/app0`, `/dev` -> EINVAL 22; `/user`, `nosuchpath`, `""` -> ENOENT 2; `607(NULL,buf)` -> EFAULT 14; `607(path,NULL)` -> EACCES 13. Order: `copyinstr`, then the VFS lookup at `0xafba6e0`, then the vnode-subtype gate `cmp dword [vnode+0x1d4],1`, then a privilege check that fires **before arg1 is read**. The 0x88 block is unreachable, which confirms the `cred+0x58` prediction in `docs/CAPABILITY_TAG_MAP_14_10.md` dynamically - with the correction that the gate returns EACCES instead of zeroing the block and returning 0. Residual value: 607 is a free filesystem oracle (ENOENT / EINVAL / EACCES = missing / not a regular file / regular file) that leaks nothing and cannot crash.
- **629 arg2 is `oflag`, not a size** (probe 1250b). `629(1,2,0)` returns a real descriptor (23, 24, 25 across three calls in probe 1250c); every other oflag value returns EINVAL because of the decoded `test r15d,0xffdff1fc` mask and the `test r15b,1` O_WRONLY rejection. Probe 1250a's nine uniform EINVALs were an artifact of sending `0x4000` as oflag.
- **629 is a stub at the mapping level too** (probe 1250c). `fstat(23)` fills a FreeBSD-11 `struct stat` with `st_size = 0x4000` at `+0x58`, and `477(..., MAP_SHARED, 23, 0)` returns `0x310D44000` with no error - but the first userland read of that page faults with `tf_err = 0x4` (P=0, W=0, U=1, `T_PAGEFLT`) at CR2 = the mapping, so the vm_object has no pager and no swap backing. Reading a 629 mapping **kills the game**, not just the Lua process; the probe was filed CRASH_CLASS: LOW and should have been MEDIUM.
- **`copyin` DOES fault demand-zero pages in** (probe 1250b). A never-touched anonymous page copied out as zeros through `write(sock, va, 8)`; only a genuinely unmapped VA gives EFAULT. Probe 1240a's "the mapping is not present / PTE absent" inference is **withdrawn**.
- **674 is now the gate for the fatal exec test** - `1248a` was changed to skip its fcall whenever the oracle is unavailable or self-contradictory, so it can no longer spend a crash on a guess. `1251a_674_calibration.lua` calibrates the oracle against four knowns (anon prot3, anon prot7 which 1245a proved dead, file prot1/5/7 of eboot, eboot's own RX .text); `1251b_force_exec_call.lua` is the isolated deliberate-crash test.
- **674 argument shapes are not interchangeable** - a blind three-shape sweep in the first draft of `1251a` returned from the known-good shape and then took the loader *and the game* down on one of the alternatives (`arg5 = 0`, or the plain-number variant; no capture, so the fatal step is unidentified). The probe now calls 674 exactly once with 55f's shape (`STRIDE=72`, `MAX=512`, `arg5=0x40000000`) into a `STRIDE*MAX+0x100` buffer, creates every mapping before the snapshot, and prints a `step N ok` marker after each section. Also recorded: `memory.read_dword`/`read_byte` return uint64 tables, so every read needs `N()` before comparison or formatting.
- **New doc** `docs/SHM_629_AND_COPYIN_14_10.md` with the full errno matrix, the fstat layout, the fault trapframe table and the copyin table.
- **New probes:** `1250b_shm_shape_and_copyin.lua`, `1250c_shm_object_inventory.lua`, `1251a_674_calibration.lua`, `1251b_force_exec_call.lua`. Repaired for Lua 5.1: `1248a`, `1249a`, `1250a` (no `&`, no `uint64.get_addr`/`uint64.new`, no `%016X` on a double, `N(memory.alloc(n))` for buffer addresses).


## Uaccess helpers decoded; 619 dead; 532-P2 and dmem closed (2026-11-05)

- **New doc** `docs/UACCESS_HELPERS_14_10.md` — semantics of all thirteen helpers in `0x2590b0..0x259b60`, the whole-image stac/clac census (17 stac, only three outside the helper block), the syscall liveness map (703 live / 32 dead of 735), the pmap A/D walker and the `0xffff800000000000` DMAP base, and the dmem re-check.
- **`copyout` semantics:** the destination is masked with `0x7fffffffffff` after a carry test; the **source is never masked or range-checked**. The only remaining way to abuse that is a kernel object that stores a user pointer and later supplies it as the source — `COPYOUT_SOURCE_PROVENANCE_14_10` measured 93 sites with zero attacker-controlled sources.
- **Unguarded `copystr` (`0x2599f0`) is unreachable from userland**: its dispatcher `0x782760` is called only by `0x7064e0`, which is only reached from the blockpool three-string builder `0x7063f0` (`0x9a6c19`, `0x9a6e53`).
- **The unmasked 8-byte `[rdi]→[rsi]` copy at `0x2581a0`** (stac, fault recovery returning EFAULT) has seven callers, all inside execve (body `0x6e2dc0`); every address it reads is `img_firstpage` + a 16/32-bit ELF offset, so it cannot reach supervisor space.
- **Syscall 619 `test_debug_rwmem` is DEAD** — body `0xa37650` is the `mov eax,0x4e` ENOSYS stub. Any plan built on a debug read/write syscall is void. `obs_vread`/`obs_vtrace` are also nosys.
- **532 P2 is dead:** decoding `0xaf0040` from the body start shows `priv_check(td, 0x2aa)` at `0xaf00e6` precedes the `c81` clamp, the indexed load at `0xaf06d9` and the ±4 GB read; probe 1242a measured that privilege as REFUSED. `READ_IDEA_ATLAS_14_10` P2 marked closed.
- **dmem re-check:** 586 `set_vm_container` resolves an index into a fixed ≤5-entry global table and needs priv `0x2ad`; 628 `mmap_dmem` *passes* its three capability checks but its worker `0x3cb450` requires the requested physical range (`r8 < 0x5000000000`, `r8+len <= 0x5000000000`) to be **inside an already-allocated container descriptor** (`cmp byte [desc+0x69],0xfe`, `desc+0x48 <= r8 < desc+0x50`). No descriptor can be created without priv, so arbitrary physical mapping is closed.
- **Indexed-load "W" class emptied:** all 11 variable-bound rows are fd-table lookups guarded by `cmp <idx>, [table] / jae` before the load.
- New scripts under `.local/`: `uaccess_callers.py`, `copystr_sites.py`, `w7064e0.py`, `w7063f0.py`, `resolve619.py`, `liveness.py`, `stac.py`, `stac3.py`, `pmap.py`, `dpmap2.py`, `d532gates.py`, `d586.py`, `d628b.py`, `d628c.py`.

## Cross-link — related WebKit research (2026-10-19)

- **README "Related WebKit Research" section** linking pastawithpesto/PS5-14.10-Jailbreak-Research as the browser side of the same 14.10 chain (their Stages 1-2 = WebKit corruption → R/W; this repo = userland/kernel side; their Stage 3/4 candidates validated against our ATTACK_SURFACE).
- **WEBKIT_FINDINGS.md refreshed** with an "Updates Since This Snapshot" block: p156 corruption confirmed on a second independently-owned 14.10 console (bait-and-switch required, plain p142 survive does not hold), p160 Relapse death independently reproduced, CVE-2026-43715 CSSFontFace UAF device test deployed, their kernel audit (CVE-2026-45251 not yet assessed here), and the length-window audit cross-referenced.

## Evidence correction — the umtx corpus called syscall 557, not `_umtx_op(454)` (2026-10-19)

- **Phase-1/2 "umtx" probes (04, 10-13) and the first revision of probe 82a bound `sc_umtx_op` to syscall 557** — the 13.60 capture labels 557 as `namedobj_create` and 454 as `_umtx_op`. Probe 10's "SHM double-destroy OK" and "oversized robust accepted" findings described 557 calls and are inconsistent with FreeBSD `_umtx_op` semantics. See [docs/UMTX_454_EVIDENCE.md](docs/UMTX_454_EVIDENCE.md).
- **454 is alive on 14.10:** probe 56i2's section [F] is the only saved 454 execution — op 5 (MUTEX_LOCK) ret=0 with a TID-shaped owner writeback, op 21 (NWAKE_PRIVATE) ret=0. Probe 56i's SHM(25)/WAKE2(22) sections never ran (capture ends in section B).
- **UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) were never exercised on 454**, and FreeBSD 11 reads their key/params pointer from `uaddr1` (4th positional arg) — a layout no earlier probe used. CVE-2024-43102 reachability is open, not answered.
- Probe 110a prepared (`probes/phase19_umtx_454/110a_umtx_shm_reachability.lua`, CRASH_CLASS: LOW): correct-layout SHM lifecycle/churn, robust-lists registration, mutex owner readback, and a same-shape syscall 557 negative control.
- Probe 82a repaired: `make_syscall(454)` binding, `SHM_DESTROY` flag corrected 3→4, SHM/ROBUST_LISTS arguments moved to the `uaddr1` position.
- Updated ATTACK_SURFACE.md (`_umtx_op` row), PROBE_INDEX.md (rows 10-13, 56i, 56i2, 82a, 110a), and added `tools/test_umtx454_correction.py`.

## WebKit — length-window audit (2026-10-19)

- **Audit:** the p146 result `.length = 81400` on 100,000-character strings does not give an out-of-bounds read. `charCodeAt` is gated by `JSString::canGetIndex` (`i < length()`), so a smaller length narrows the readable window to 0-81399 instead of extending it past the 100,000-char buffer.
- **Corrected** Finding 2/3 impact text and the status table in `docs/WEBKIT_FINDINGS.md`; the ASLR-leak stage is now marked blocked on length or data-pointer control.
- **Noted** that `54g`'s OOB branch requires `len > STR_LEN` and cannot fire under the recorded p146 value.
- **New probe** `probes/phase13_webkit/p161-length-window.js`: re-runs the p146 groom and measures the window directly (`LAST` at `len-1`, `TAIL` at index 99999, `PAST` at `len`, `SUB` to confirm the buffer). `?mode=pair` repeats the run with two identifier keys at identical source size to test whether the written length value is content-dependent.
- **New doc** `docs/WEBKIT_LENGTH_WINDOW_AUDIT.md` with the arithmetic (`38348816 * 112 = 2^32 + 100096`), the JSC read path, and the three paths that would produce a real OOB primitive.

## Phase 14c — Controlled Function Redirect Confirmed (2026-10-18)

- **★★★ CONTROLLED CClosure REDIRECT PROVEN END-TO-END** (probe 56c)
  - All 4 test redirects returned the target function's output:
    - rawequal → rawget: `rawequal(t,"foo")` returned `"bar"`
    - rawget → type: `rawget(42,"x")` returned `"number"`
    - select → tostring: `select(42)` returned `"42"`
    - rawequal → tostring: `rawequal(42)` returned `"42"`
  - Write+restore cycles: 0.0001s each, all functions restored correctly
  - **Critical insight:** `type()` cannot be redirected because `memory.write_dword` internally calls `type()` — non-VM functions (rawequal, rawget, select) redirect freely
  - 56a/56b confirmed the type() hang mechanism; 56c solved it by targeting non-VM functions
  - **This is a confirmed arbitrary code execution primitive with controlled dispatch and return**
- Updated FINDINGS.md with Finding 82
- Updated PROBE_INDEX.md with 56c results

## Phase 14b — CClosure Function Pointer Confirmed (2026-10-18)

- **★★★ BREAKTHROUGH: CClosure +0x20 confirmed as C function dispatch pointer** (probes 55g, 54r)
  - 55g: writing +1 to +0x20 low dword → immediate garbage output + crash (misaligned execution)
  - 54r: all 7 tested functions' +0x20 targets are real x86-64 prologues (`push rbp; mov rbp, rsp`)
  - 54q reinterpreted: the 15s timeout was a successful redirect to tonumber's C code, not a hang
  - CClosure lives in SceLibcHeap (prot=0x3 RW) — fully writable
  - **This is an arbitrary function pointer redirect primitive**
- **Syscall 624 characterized** as VM operation counter: +5 per mmap, zero jitter, monotonic (probe 52b)
- **Syscall 631 confirmed lethal** — kills process past pcall (probe 52a)
- Syscalls 627-630 all PCALL-FAIL (probe 52a)
- Updated CLAUDE.md evidence correction: userland code execution via CClosure redirect IS established
- Updated FINDINGS.md with Findings 79-81
- Updated PROBE_INDEX.md with 55g, 54r, 52a, 52b results

## Phase 10d — Relapse Intelligence Integration (2026-10-16)

- Analyzed Relapse exploit (fw 7.00-13.60) for techniques applicable to fw 14.10
- Developed `43o_afroute_kaslr` — AF_ROUTE socket RTM_GET KASLR defeat (Relapse's proven technique)
- Developed `43p_aio_bypass` — AIO syscalls via make_syscall to test if sandbox kill is resolve()-side only
  - If AIO lives: reopens the entire race condition bug class without threading
  - Tests all 10 FreeBSD AIO syscalls (aio_read, aio_write, lio_listio, etc.)
  - Hunts for Sony's aio_multi_wait in syscall range 532-700
- Added Theories 18-20 and Attack Chain D to UNTESTED_THEORIES.md
- Added Relapse intelligence and userland exploit chain documentation to STRATEGY.md
- Key insight: AIO was only tested via resolve() (probes 19-19g), never via make_syscall
  - The same pattern as sysctl: resolve() said blocked, make_syscall proved it works
  - If this pattern holds for AIO, we get kernel-level concurrency without threading

## Phase 10b — Deep Data Analysis & New Exploit Vectors (2026-10-16)

- Comprehensive cross-phase data audit uncovered 8 new findings (Findings 28–35) from overlooked probe results
- Developed 5 new probes (`43j`–`43n`) targeting newly discovered vectors:
  - `43j_msgbuf_full_read`: Full kern.msgbuf read (up to 64KB) for KASLR-defeating boot messages
  - `43k_cpuusage_deep`: sceKernelGetCpuUsage(617) with proper buffers + mtypeprotect(585) W^X bypass test
  - `43l_mincore_kaslr`: mincore() as KASLR side-channel oracle probing kernel VA ranges
  - `43m_sockopt_overflow`: PS5 socket option 256-byte buffer potential kernel heap overflow
  - `43n_hid_ioctl`: /dev/hid + ioctl(54) via make_syscall for HID driver kernel state access
- Key discoveries from audit:
  - sceKernelMtypeprotect (585) returned success (ret=1) — only Sony syscall to return positive
  - sceKernelGetCpuUsage (617) returned success (ret=0) — live Sony syscall with empty buffer
  - kern.msgbuf returned 8 bytes with value 0x7EF710000 — full read may leak kernel addresses
  - mincore() works as memory residency oracle — side-channel KASLR probing possible
  - PS5 socket options accept 256-byte buffers for 4-byte boolean flags — potential kernel heap overflow
  - /dev/hid opens successfully — ioctl untested via make_syscall
  - thr_self returns real TID (101819) — kernel thread handle
  - fn_addr has constant 0x9FE5 prefix across all ASLR'd processes — reduced entropy

## Phase 10 — Untested Theories & Probe Suite Preparation (2026-10-16)

- Developed 9 targeted probes (`43a`–`43i`) addressing Tier S and Tier A theories:
  - `43a_kldstat_kaslr`: `kldstat` tested against both syscall 308 (standard FreeBSD) and 367 to defeat KASLR
  - `43b_kldsym_resolve`: `kldsym` (337) to look up arbitrary kernel symbols by name (`prison0`, `allproc`, `copyin`, `copyout`)
  - `43c_sysarch_gsbase`: `sysarch` GET_GSBASE (op 130) to leak kernel `curthread` address
  - `43d_kinfo_proc_full`: Full byte-by-byte dump of all 1,096 bytes of `kern.proc.pid` and `kern.proc.filedesc`
  - `43e_blocked_syscall_bypass`: Raw `make_syscall` testing of `thr_new` (455), `ioctl` (54), `dup`/`dup2`, `pipe2` (542)
  - `43f_sysctl_write`: Sysctl write testing on `kern.securelevel` (-1), `kern.coredump`, and debug MIBs
  - `43g_sony_syscall_sweep`: Comprehensive automated sweep of Sony syscalls 540–700
  - `43h_mtypeprotect_wxbypass`: Memory type and protection investigation via `sceKernelMtypeprotect` (585)
  - `43i_fn_redirect`: ROP chain function target redirect and persistence verification across syscall invocations
- Fixed critical bugs across probe suite:
  - Corrected `sysarch` command numbers in `43c` (130 is `GET_GSBASE`; avoided fatal crash from calling 129 `SET_FSBASE` with NULL)
  - Fixed byte-reading routines in `43a` and `43d` (`safe_rb` byte access instead of `safe_rd` dword truncation)
  - Fixed undefined global `MB` variable in `42g_rop_kptr_leak.lua`
- Repository consolidation: unified tools and complementary phase results from split downloads.

## Phase 9 — KASLR Defeat Attempts & ROP Architecture Deep Dive (2026-10-16)

- **ROP Chain Call Architecture Decoded (probe 42i):**
  - Mapped complete gadget sequence across entire 0x300-byte chain
  - Decoded argument loading pattern (`pop rax` -> `mov rax,[rax]` -> `pop rdi` -> `mov [rdi],rax`)
  - Pinpointed exact argument source slots (`0x31071C040`–`0x31071C0B0`) and destination registers (rdi, rsi, rdx, rcx, r8, rsp pivot)
  - Confirmed stack pivot gadget (`pop rsp; ret` at eboot+0x9A2) targets `fcall_stub.fn_addr`
- **Dense Sysctl & Kinfo_proc Auditing (probes 42b, 42c, 42e, 42h2):**
  - Clarified false-positive kernel pointer alerts: `0xFFFFFFFF_00000000` and `0xFFFFFFFF_FFFFFFFF` are sentinels/bitmasks
  - Identified live sysctl leaf nodes: `kern.version`, `kern.ostype`, `kern.osrelease`, `hw.machine`, `hw.pagesize`
  - Confirmed sandbox blocks `kern.proc.all`, `kern.file`, `kern.proc.kstack`, `kern.proc.auxv`, and `net.inet.tcp.pcblist`
- **Physical Memory Survey via `/dev/dmem0` (probes 42d, 42f, 42f2, 42g–42g4):**
  - Direct memory device fd=22/24 opened successfully
  - Scanned 90+ physical offsets: offset 0x0 returns GPU hardware register `0x80000000_C0012800`
  - Tested 4GB, 4.5GB, and high physical address spaces: unmapped or all zeros
  - Proves `/dev/dmem0` access is strictly isolated to GPU memory and cannot map kernel/CPU physical RAM
- **Thread and Sandboxed Subsystem Exploration (probes 42d, 42f, 42j):**
  - `thr_self` returns valid TID (101819); `procctl` ASLR/stackgap/priv controls blocked
  - Probed Sony syscalls 576–619: `sceKernelMtypeprotect` (585) returns 1; `sceKernelGetCpuUsage` (617) works; memory queries blocked
  - Confirmed `kenv` (390) and `msync` (226) are instant-kill syscalls

## Phase 8 — Live Network Path Testing (2026-10-15/16)

- TCP connect-back fuzz confirmed working end-to-end (probe 40)
- Port bind policy mapped: 1024–32767 open, <1024 and ≥40000 blocked (probe 36)
- `ip_reass()` verified correct on all 7 standard fragment cases (probe 39)
- IP options rejected at `ip_output()` before reaching `ip_dooptions()` (probe 37)
- ktimer surface partially open: create/settime work, gettime/delete blocked (probe 42a)
- `memfd_create` is a stub; `msync` confirmed as instant-kill syscall (probe 42b)
- Crash handler decoded as ASLR oracle (magic `0x13371337`, leaks module base)
- Kernel info via sysctl: FreeBSD r230171, securelevel=1024, 16KB pages (probe 42a)

## Phase 7 — Heap Exploitation & ROP (2026-10-15)

- GPU mmap heap R/W primitive: 256+ adjacent pages, no guard pages (probes 41c–41e)
- ASLR bypass: `dynlib_get_info` leaks all 39 module bases (probe 41o)
- Complete ROP gadget catalog extracted from eboot (probes 41r–41t)
- Loader ROP chain reverse-engineered: full call mechanism mapped (probe 41v)
- **ROP chain hijack confirmed** — chain + fn_addr writable from heap (probe 41z)
- Vtable chase closed: 41k-era objects were heap-spray artifacts (probes 41m–41q)

## Phase 6 — Raw Packet Injection (2026-10-15)

- RAW socket + IP_HDRINCL confirmed working (probe 34)
- Crafted UDP packets reach kernel `ip_input()` through loopback

## Phase 5 — Buffer & I/O Edge Cases (2026-10-15)

- `MSG_DONTWAIT` (0x80) discovered as the real nonblocking mechanism (probe 33f)
- F_SETFL confirmed cosmetic-only: kernel ignores flag changes (probes 32–33c)

## Phase 4 — IPC & Network Internals (2026-10-15)

- `writev` works (IOV_MAX=1024), SCM_RIGHTS validated (probe 30b)
- F_SETFL is cosmetic; poll() works; kqueue fd allocates but kevent returns -1 (probe 30c)
- TCP_INFO: 236 bytes, no kernel pointer leaks; 23 SOL_SOCKET options (probe 31b)
- PS5 custom socket options (0x2000–0x100000) are boolean flags, not exploitable (probe 31c)

## Phase 3 — Signals & Code Execution (2026-10-15)

- W^X strictly enforced; execute-only memory (XOM) on system libs (probes 26–26e)
- sigaltstack kernel write dead: copyout() validates destinations (probes 23–25)
- sigprocmask is a no-op (probe 25c)

## Phase 2 — Kernel Object Stress (2026-10-15)

- Threading fully blocked: fork/rfork/thr_new all return -1 (probe 27)
- AIO completely sandbox-killed (probes 19–19g)
- UMTX/nwake behavior mapped (probes 10–13)
- Device ioctls all blocked by sandbox (probe 14)

## Phase 1 — Identity & Layout (2026-10-15)

- Firmware 14.10 confirmed, Lua 5.1 loader on TCP 9026
- ~40 working syscalls mapped out of 600+
- Process memory layout and filesystem access mapped
