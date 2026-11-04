> **Closed as a kernel-R/W route, 2026-11-04 (tenth boot).** 1195a measured all 0x28 command slots with `arg3 = 0x28`; no command writes 0x28 bytes to `arg2`, none writes `arg3`, and the attach body `0x8b6612d5` / dispatcher `0x8b662320` have zero direct callers in the whole image, so those cases are not in 14.10's table. The map below remains accurate as a *behavioural* description. See [SYS601_SECOND_STAGE_14_10](SYS601_SECOND_STAGE_14_10.md) section 9.

# 601 (mdbg_service) command map on 14.10, measured

> **Correction, 2026-11-04 (seventh boot).** Two claims in this document are wrong or unsupported, see
> [SYS601_SECOND_STAGE_14_10.md](SYS601_SECOND_STAGE_14_10.md):
> 1. **"-1" here is errno-blind.** The loader's syscall path is the libkernel wrapper
>    (`gettimeofday+7`), which returns **-1 for every error**; the errno only exists in libc errno
>    (`get_error_string()`). Every -1 in the tables below conflates EPERM(1), EINVAL(22) and
>    ENOSYS(78). The handler itself can only return 0, 1, 4, 0x16, 0x1c, 0x23, 0x3f or 0x4e.
> 2. **The type gate at `0xca2320` is not behind attach-only state.** It is behind bit 8 of
>    `td+0x528`, and 601 contains the setter itself (`0xca131f: or qword [td+0x528], 0x100`) in a case
>    body that reads `td_proc` from the *calling thread* — no kernel pointer is needed, contrary to
>    the conclusion below. Types 3 and 7 then reach the main body, which is a whole blob-ingest
>    interface with a per-process 0x80000 kernel buffer.
>
> Also measured since: `601(0x00, mapped buffer, non-zero arg3)` **wedges the loader** (1192a).
> `601(0x00, buf, 0)` stays safe (1170a).

All calls are `601(cmd, buf, len, 0, 0, 0)` with a 0xA5A5A5A5-filled buffer unless stated. "writes"
means bytes in the buffer that differ from the sentinel.

## Commands 0x00-0x2F

| cmd | rv | writes | notes |
|---|---|---|---|
| 0x00 | 0 | 8 B | always `{0x00000100, 0x00000000}`, independent of buffer, length and flags |
| 0x01 | -1 | none | |
| 0x02 | -1 | none | |
| 0x03 | — | — | **panic**: body takes a raw `struct proc*` (SMAP #PF) |
| 0x04 | — | — | **panic**, same reason |
| 0x05 | -1 | none | |
| 0x06 | -1 | none | |
| 0x07 | 0 | none | |
| 0x08 | — | — | **parks forever** in the kernel (1170a) |
| 0x09 | 0 | none | |
| 0x0A | -1 | none | |
| 0x0B | 0 | none | |
| 0x0C | — | — | **parks forever** (1172a, and 1175a parked it on a thread) |
| 0x0D | 0 | none | |
| 0x0E | 0 | 8 B | always `{0, 0}`, independent of length/flags |
| 0x0F | -1 | none | |
| 0x10 | -1 | none | |
| 0x11 | -1 | none | |
| 0x12 | -1 | none | |
| 0x13 | 0 | none | |
| 0x14 | 0 | none | |
| 0x15 | -1 | none | |
| 0x16 | -1 | none | |
| 0x17 | -1 | none | |
| 0x18 | -1 | none | |
| 0x19 | 0 | none | |
| 0x1A | 0 | 4 B | always `{0}` |
| 0x1B | — | — | **kills the process** (no crash blob, LOADER-DEAD) |
| 0x1C | -1 | none | |
| 0x1D | 0 | none | |
| 0x1E | -1 | none | |
| 0x1F | -1 | none | |
| 0x20 | 0 | none | |
| 0x21-0x26 | -1 | none | |
| 0x27 | — | — | **kills the process** (1171a) |
| 0x28-0x2F | -1 | none | |

No command in this range ever wrote ASCII, and the word `mDBG` has still never appeared in any capture
(`grep -r mDBG results/` = 0 hits, one session of sweeps later).

## The argument shape is settled (1179a)

* arg1 is the buffer and arg2 is the length. Swapping them (`0x200, buf`) or putting the buffer in
  arg3 returns -1 for every command that otherwise returns 0.
* arg3, arg4, arg5 do not change any observed answer (`1` in either slot, and 0x200 vs 0x4000 length).
* The three writing commands write the same two/four bytes regardless of length, so they are
  out-parameters of a fixed size, not a stream.

## What this does and does not say about the log drain

`docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 describes a body that memcpy's the kernel log list into a
0x4000 bounce buffer and `uiomove`s it to the caller, with no credential check. Nothing in 0x00-0x2F
behaves that way, and 0x0E's constant `{0,0}` is the closest shape (a "bytes read" counter that is
always zero).

The reconciliation is the type gate at `0xca2320`, called from the shared entry at `0xca1833`: with
`(*(u64*)(td+0x528) & 0x100) == 0` only types 3, 4, 5 and 7 are dispatched, and that bit is set by the
**attach** command, which needs a kernel `struct proc*`. So the drain is most likely gated behind the
same state bit as everything else useful in 601, and the -1 answers in the table above are that gate.

## Method notes, so this is repeatable

* One command per thread (`probes/phase17_new_vectors/1176b_mdbg_threaded_sweep.lua`,
  `1177a_mdbg_sweep_high.lua`) absorbs the parkers: see `docs/SACRIFICIAL_THREAD_14_10.md`.
* The heavy buffer work must stay on the main thread; a child that did 2048 native memory ops killed
  the process with no crash blob (1176a).
* Sentinel comparisons must be hex (`0xA5A5A5A5` = 2779096485). Two probes compared against a decimal I
  derived by hand and printed `changed=1024` on an untouched buffer.

## Commands 0x30-0xFF: all of them answer -1 and write nothing (1180a, 1181a)

`1180a` swept 0x30-0x4F (32 commands, 2.8 s) and `1181a` swept 0x50-0xFF (176 commands); every single one
returned `-1` with an untouched buffer, no park, no kill, no panic. Together with the table above the
whole 8-bit command space is now measured:

| class | commands |
|---|---|
| writes a fixed out-param and returns 0 | 0x00 {0x100,0}, 0x0E {0,0}, 0x1A {0} |
| returns 0, writes nothing | 0x07 0x09 0x0B 0x0D 0x13 0x14 0x19 0x1D 0x20 |
| returns -1 | everything else, 0x21-0x26, 0x28-0x2F, 0x30-0xFF |
| parks forever | 0x08, 0x0C |
| kills the process | 0x1B, 0x27 |
| panics the console | 0x03, 0x04 |

## Conclusion: 601 is closed as an unprivileged kernel-read source

Nothing in 601's command space copies kernel text or a kernel pointer into a user buffer as uid 1.
The log drain in `docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 is real code, but it is not reachable from
this credential with any of the seven argument shapes tried in `1179a`, and the most likely reason is the
type gate at `0xca2320`: with `(*(u64*)(td+0x528) & 0x100) == 0` only types 3, 4, 5 and 7 dispatch, and
that bit is set by the attach command, which requires a kernel `struct proc*`. 601 therefore inherits
the same shape as the rest of the corpus: a real primitive that needs a leak to unlock a leak.
