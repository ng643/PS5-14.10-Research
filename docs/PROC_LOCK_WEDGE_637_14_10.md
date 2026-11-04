# 637 `set_phys_fmem_limit` at the bottom of its range wedges the process — and the loader with it

**Status:** measured on 14.10 (probe 1162a, 2026-11-04), and it reproduces a
silent hang first hit on 2026-10-22 by probe 339a.

## The measurement

`637(pid=0, value=17)` never returns. The probe's capture stops between the
`value=16` line (`EINVAL`, as expected) and the `value=17` line, and the console
then answers `LOADER-STUCK: accepted, no reply` to `tools/port_witness.py` — the
listening socket still completes TCP handshakes (so the kernel is alive) but the
Lua loader never services them again. The session only recovers with a manual
relaunch, i.e. the calling thread never leaves the kernel.

The same call ended probe 339a on 2026-10-22 the same way, in the same place:

    339a_637_598_659_20261022_124747.txt
      1| === PROBE 339a: 637 / 598 / 659 ===
      2|
      3| [A] 637 value sweep with id = 0
      4|   637(0, 0x10) = -1          <- value 16, EINVAL
                                   <- value 17 was the next iteration; never printed

That capture was never diagnosed: the "637 returns 0 for self" claim in
`docs/ATTACK_SURFACE.md` comes from later probes (340a, 343a, 344a, 345a, 887a,
890a) which all used values of `0x40000000` and above. The wedge sits in the
value range nobody had retried: the first value that clears the `value < 17`
check.

## Measured value map, 14.10, self (`pid = 0`)

| value | result |
|---|---|
| 0, 1, 16 | `-1`, `errno = 22 EINVAL` (the `value < 17` guard) |
| **17** | **never returns; process wedged, loader wedged, needs relaunch** |
| `0x40000000`, `0x7FFFFFFF`, `0xFFFFFFFF`, `0x10000000`, `0x200000000`, 4 GiB, 64 MiB | `0` (340a/343a/344a/345a/887a/890a) |
| foreign pid (`0x40000000`) | `-1` (887a/888a) |

The exact lower edge of the wedge window between 17 and `0x40000000` is
**unmeasured** and is not worth measuring with a wedging console: every attempt
costs a manual relaunch.

## Why it wedges (static, 13.60 body `0xffffffff8b47d930`)

`results/kernel_handlers/decompiled/sys_637.c`:

    } else sub_ffffffff8ae86a00((char *)p+0x148,0,0,0);   // lock parent
    flags = U32(p,0xb0);
    if ((flags & 0x2200) || U32(p,0xb8) != 1) { unlock; return 3; }
    ++U32(p,0x358);                                        // refcount
    if (!(flags & 0x10000000)) sub_ffffffff8aefaa10(p);     // <-- called under the lock
    sub_ffffffff8ae86fa0((char *)p+0x148,0,0,0);            // unlock

The flags/state check passed, so execution reached the refcount bump and the
`0xffffffff8aefaa10(p)` call **while holding the process lock at `p+0x148`**, and
nothing after that line was observed. Two consistent explanations, both static:

1. `0xffffffff8aefaa10` itself takes `p+0x148` (a non-recursive mutex) — a
   self-deadlock that is invisible from outside;
2. `0xffffffff8aefaa10` spins/waits on a condition that a 17-byte limit makes
   unsatisfiable, so the lock is never released.

Either way the lock is left held forever. That the *loader* stops answering too —
and not only the wedged child process — is the important part: the listener and
the probe process share that same parent process object, so the held lock takes
the whole session with it. A one-call, unprivileged (`uid 1`, no bit 62),
permanent denial of the loader on 14.10.

## Consequences for this research

* **Never call 637 with a value in `[17, 0x40000000)`.** It is the only syscall in
  this corpus that has cost a console session without a panic, and the cost is a
  manual relaunch every time.
* 637's interesting surface — `U64(child, 0x280) = value`, a caller-chosen qword
  written into the current process's child object with **no capability check** on
  the self path — remains untested, because every path that reaches it also
  reaches the helper that wedges. The self path is indistinguishable from the
  hang point: `0xffffffff8aefaa10(p)` runs before `child = PTR(p,0x200)`.
* The cross-process path is bit-62 gated (`0xffffffff8afc8f90` = bit 62 of
  `cred+0x60`), so foreign pids are out of reach by the same predicate as
  everything else.

## Note for the next probe that touches 637

Keep it a single call, and if the loader goes silent, do not retry: witness the
port once, tell the operator, and treat the session as lost. The stored-value
hypothesis cannot be settled from the current primitives.
