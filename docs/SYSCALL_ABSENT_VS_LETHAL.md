# An absent syscall slot terminates the caller (14.10)

## The measurement

`make_syscall(4095)` with six zero `uint64` arguments terminated the process inside the
call. 4095 is past the end of any sysent table this kernel can have, so no handler exists
for it.

Capture: `results/phase17_new_vectors/173a_unimplemented_syscall_slot_20261020_184436.txt`,
probe `probes/phase17_new_vectors/173a_unimplemented_syscall_slot.lua`.

## Why this matters for every earlier "lethal" verdict

A real FreeBSD stub returns `ENOSYS`; it cannot terminate its caller. The numbers that have
killed this process are:

| syscall | what it is | why the slot is plausible absent |
|---|---|---|
| 307 | `kldnext` | host-side module loader, meaningless on a console |
| 308 | `kldstat` | same |
| 337 | `kldsym` | same |
| 570 | `sysctlbyname` | the console keeps `sysctl` (202) but not the by-name entry |
| 661 | AIO submit | AIO compiled out |
| 665 | `nosys` stub in the 13.60 capture | literally labeled absent there |
| 668 | `nosys` stub in the 13.60 capture | same |
| 4095 | past the end of the table | absent by construction |

One rule explains all eight: a slot that is not present terminates the process. The
alternative — eight unrelated handlers each choosing to kill a caller that a normal kernel
would answer with `ENOSYS` — has no mechanism behind it.

## What the statuses mean now

- **KILLED_IN_CALL** — the slot is absent on 14.10. It is not a hostile handler and it is
  not exploit surface. The process death is the dispatcher's response to a missing entry.
- **RETURNED with `-1`** — the slot exists and rejected these arguments. This is a positive
  result: it proves the handler is present and reachable, which is where bug surface lives.
- **RETURNED with `0` or a value** — the slot exists and accepted the arguments.

The earlier reading treated `-1` as failure and a kill as the interesting case. It is the
other way round: `-1` means the handler is there, and a kill means it is not.

## Consequences for recorded verdicts

- The "AIO 661-670 hard wall" was 661 (and 665, 668) being absent, not hostile. The six
  numbers that returned `-1` — 662, 663, 664, 666, 667, 669 — are **present handlers** that
  rejected six zero arguments. That is the part of the range worth attacking with real
  structures, and it was written off as dead.
- `kldsym` (171a), `kldstat`/`kldnext` (56k4/56k5) and `sysctlbyname` (172a) are not
  "lethal Sony guards"; the console simply does not have them. No further argument shapes
  need testing on those numbers.
- The 13.60/14.10 "stub-path divergence" question disappears: 665 and 668 are absent in both.

## Rule for future sweeps

Before calling any number hostile, check whether it is absent: a call that returns anything
at all proves presence, and presence is required for a handler to be exploitable. A sweep
record whose only evidence is a kill carries no information about the handler, because
there is none.

## Present but gated: 662-669 (174a, 175a, 2026-10-20)

The six surviving numbers in 661-670 are present, and 162 calls say so:

- `174a` gave 662, 663, 664, 666, 667 and 669 a zeroed 0x400 page in `RDI` and `0x400` in
  `RSI`. All six returned `-1` and wrote nothing.
- `175a` swept selectors 0-8 in each of the first three argument positions, 27 calls per
  number, 162 in total. Every call returned `-1`.

Rejection is therefore independent of argument layout and of the buffer. The remaining
explanation is a state gate: an AIO context must exist, and the number that would create
one (661) is an absent slot. The range is unreachable by construction, which is a stronger
statement than "returns -1".

`175a`'s first run printed 162 "hits" because the probe compared the return against the Lua
number `-1` while `get_hi_lo` returns the low dword unsigned (`4294967295`). The comparison
now uses `0xFFFFFFFF`; the corrected run is the one recorded here.

## The death is process-wide, so the map costs a relaunch per gap (176a, 2026-10-20)

`176a` spawned a `thr_create` child with `RAX = 4095` at `syscall_address`, parked on a
`jmp $` slot, and busylooped the main thread on `getpid`. The capture ends at
`[1] spawning thread RAX=4095`: the print that follows `thr_create` never ran, so the child's
absent-slot call took the whole process with it.

The killer is not confined to the calling thread, which means a child thread cannot be used
to probe slots cheaply. Mapping an absent number always costs one game relaunch: the sweep
stops there, and the numbers after it need a fresh process.

## Correction: the game restarts the loader by itself (2026-10-20)

Earlier entries said an absent slot costs a game relaunch. It does not. A kill still takes
the whole process, but the game brings the loader straight back:

    before: PID 292  SW 0x807584B57
    call 4095 (absent)  -> connection dropped
    waited 9.31s        -> port 9026 accepting again
    after:  PID 299  SW 0x818C90B57

A new pid and a new module base, so this is a fresh process rather than a surviving one, and
nobody touched the console. The same thing happened during the 572-600 sweep: numbers 573, 589,
590 and 597 killed the process and the sweep continued without help, because
`--wait-for-loader` simply waited about nine seconds.

The relaunch prompts in the earlier entries were a measurement artefact: the sweeps aborted on
the first `CONNECT_FAILED` and never sat long enough to observe the recovery. The lesson is
that "the port refused" is not "the console needs a human" - poll before concluding.

## A kill does not prove the slot is absent (2026-10-20)

The rule above was written after 4095 showed that an unimplemented slot kills the process. It
is a one-way implication and it was read as two: an absent slot kills, therefore a kill means
an absent slot. The 601-660 sweep supplies the counterexample.

`622 ipmimgr_call` kills the process when called with six zero arguments. It cannot be absent:
`55c` called it through `make_syscall(622)` with `(cmd, 0, buf, buf, 0x100)` for 400+ command
values and got `ret=0` with `buf[0]=0x800E0001` every time. So a present handler took the
process down on zeros and worked on a real request.

The same ambiguity covers every "absent" reading taken from a zero-argument sweep: 561
`suspend_process`, 562 `resume_process`, 573 `mdbg_call`, 589 `dynlib_dlopen`, 590
`dynlib_dlclose`, 597 `dynlib_prepare_dlclose`, 609, 614, 621, 631, 650, 651 - and 661, 665,
668. All of them have a real handler RVA in the 13.60 capture (`docs/sysent-names-13.60.csv`),
none is the `nosys` stub at `0x265760`.

What survives: 4095 has no handler in any version and kills, so a kill is what an absent slot
looks like. What does not survive: concluding absence from a kill. The honest status is
"kills with zeros", and the follow-up is a probe with plausible arguments - a path string for
`dynlib_dlopen`, a pid for `suspend_process`, a command for `mdbg_call`.

The distinction matters for exploit work in both directions. A kill was being filed as "no
handler, nothing here", which discards the four AIO handlers and every dlopen-style call
without looking. And a `-1` was being read as "dead", when it means the opposite: the handler
ran and checked its arguments, which is the more interesting of the two answers.

## What the tail sweep adds (2026-10-20)

The 677-734 sweep is the first block where every number kills: 677 through 707, thirty-one
in a row, then the loader took more than two minutes to return. Thirty-one consecutive kills
is not thirty-one hostile handlers - the parsimonious reading is that those numbers are past
the end of the table, which is the same shape as 4095.

So there are three readings a kill can have and observation alone cannot separate them:

1. the slot is not implemented (4095, and 677+);
2. the slot is implemented and the zero arguments fault it (622 returns `0` to a real request);
3. the slot is implemented and the kernel kills the caller on purpose.

Case 3 is not hypothetical for this platform: a console kernel that kills on unimplemented
numbers is doing exactly that, and the same policy applied to a privileged call would look
identical from the outside. The practical consequence is the same for all three: a kill is a
result about the *call*, never a result about the *handler*.

> **Correction (2026-10-25):** the shield used for the sweep below passed `SIG_IGN` as a
> direct value, `416(12,1,0,0)`, and its return value was never printed. Probe 353a installs the
> same disposition through a `struct sigaction` pointer and gets `0`; the direct form is
> unverified. Every `-1` in this section therefore has to be re-taken with a proven shield and
> the `4095` control (probe `710a_shield_verify.lua`), which must return `-1` instead of killing
> when the shield is really installed.

## The shield separates absent from blocking (2026-10-25)

With `sigaction(12, SIG_IGN)` in place (the shield from probe 353a), a sweep of the numbers
that used to kill reveals a third behaviour besides `-1` and death: the call **blocks and
never returns**, and because the loader runs one Lua state, the whole loader stops answering
until the game is relaunched.

- **619 `test_debug_rwmem`** and **652** answer `-1` for four argument permutations each and
  leave the output page at its `0xDEADBEEF` prefill. Under the shield that is the absent-slot
  answer, and the 13.60 capture agrees (`619` is `mov eax,0x4e; ret`). Neither is a kernel
  read/write slot on 14.10.
- **561 `suspend_process`** and **562 `resume_process`** do not answer at all. `561` with six
  zeros prints nothing, the connection times out, a plain `print("PING-OK")` still works
  afterwards, and the next attempt at `562` is refused. The parsimonious reading is a real
  handler that suspends or resumes something it was not given, leaving the calling thread
  parked. The 13.60 capture stubs both (`0x265760`, `jmp 0x5620e0`), so if the behaviour is
  real it is a **14.10 difference**, and both need a plausible pid before anything can be
  concluded.

The practical rule is now: under the shield the answers are `-1` (absent), a value (present),
or **silence** (present and blocking). Silence costs a relaunch, so any sweep has to treat it
as a stop condition rather than a timeout to retry.

A follow-up on the same day narrows `561` further. Called **without** the shield as
`561(999999,0,0,0,0,0)` it prints nothing after the probe header and the connection closes;
the loader then refuses every new connection, so the game is gone. With six zeros the same
number hangs instead of dying. Two different outcomes for two different arguments means the
handler ran far enough to read its argument and act on it - an invalid pid takes the
fatal-signal path, a valid-looking zero parks the caller. That is a real `suspend_process`
on 14.10, not the 13.60 stub, and the next step is the same call under the shield to see
whether the invalid-pid death is the SIGSYS path (`-1`) or a genuine fault.

## The shield works, and every "lethal" number is just absent (2026-10-25)

Probe `710a_shield_verify.lua` settled the shape question:

| call | return | meaning |
|---|---|---|
| `416(12, 1, 0, 0)` | `-1` | the direct-value form installs **nothing** |
| `416(12, act, old)` with `act[0] = 1` | `0` | the struct form installs `SIG_IGN` |
| `4095(...)` after the struct form | `-1` | the absent-slot signal is absorbed, process alive |

Probe `711a_lethal_under_shield.lua` then re-ran every number that has ever killed
this process, with that shield in place. All of them return `-1` and the process
survives: `589`, `590`, `597`, `619`, `631`, `650`, `651`, `652`, `661`, `665`,
`668`, `677`, `678`, plus the control `4095`.

That collapses a whole claim class. The death was always the **nosys** path
delivering `SIGSYS`; there was never a hostile handler that killed on bad
arguments. `677`/`678` are past the end because they are absent, not because
thirty-one consecutive numbers were booby-trapped.

The one number that still behaves differently is `561` (`suspend_process`): it
returns nothing for six zeros and kills on an invalid pid, and no shield changes
either outcome, so it reads its argument and is genuinely implemented on 14.10
although the 13.60 image stubs it.

**Method note for future probes.** `select` (93) blocks forever on
`select(0,0,0,0,0)`, which wedged a whole-table sweep at number 51-99 and cost a
relaunch. Never sweep unused numbers with six zeros; skip any call that can wait.

## 48 (`getegid`) is absent on 14.10, and it takes the console with it (2026-11-04)

Probe `1151a_devfs_open_modes.lua` run 1 printed `uid`, `euid` and `gid` for the loader and
then called `getegid` (48) with the **default** `SIGSYS` disposition still in place. The capture
ends after `[ID] gid=1` and the loader then refused connections: the process died with the game.
That is the same nosys path as `677`/`678`, on a number nobody had ever called.

Run 2 installed `416` `SIG_IGN` first and moved the call to the end of the probe, after the
data the probe exists for. With the shield:

```
[LATE] getegid(48)   ok=true rv=-1
[LATE] getgroups(79) ok=true rv=1
```

So `48` belongs in the absent list next to `589`, `619`, `677`, `678`; `47` (`getgid`) and
`79` (`getgroups`) work, which makes the gap a single removed entry rather than a removed block —
the same pattern as the native tail. Two rules come out of it. The shield belongs in the prologue
of *every* probe that calls a number it has not called before, not just in sweeps. And a probe
that mixes a known-safe section with an unknown number must run the unknown number **last**, so
an unshielded death cannot cost the section that carries the result.

