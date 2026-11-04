# Threading is alive on 14.10

Status: **console-verified, firmware 14.10, 2026-10-20.** The evidence files are
in `results/phase17_new_vectors/`; the probes are `156a`–`156d` in
`probes/phase17_new_vectors/`. The loader process answered throughout with the
same pid (91) and the console never restarted.

## A native child can run a syscall, and two can be released together (712c-720a, 2026-10-25)

A `thr_create(430)` child normally only runs its own code, because the Lua harness serialises syscalls (509b) and a helper thread that issues them kills the process. Both limits are gone as long as the child is pointed at the loader's own trampoline.

**A child makes real syscalls.** `syscall.pipe.fn_addr` read in Lua is *code* (ASLR-relocated; `0x808858B57`, `0x804640B57`, `0x800430B57` in three runs). Set the context `RIP` to that address, `RAX` to the syscall number, `RDI`/`RSI`/`RDX` to the arguments, and point `RSP` at a chain on the child's own stack. The first `ret` after the syscall pops the chain (712c, marker = the child's own `getpid`):

```
[A] fn_addr=0x826BC0B57
[A] mov [rsi],rax;ret=0x6E614BA9 jmp$=0x6E489481
[B] thr_create ok=true rv=0 tid=0x18F76
[B] marker=0xAE        <- 174, the child's pid
```

Note that two different things are called `fn_addr`: the pipe string's `fcall_stub.fn_addr` (`0x310c49fd0`) is a heap stack frame the loader chain pivots into; `syscall.pipe.fn_addr` as read in Lua is the executable trampoline. Passing `tonumber(fn_addr)` to `native.fcall_with_rax` kills the process, and reading bytes at it kills too - the text is execute-only.

**Chain gadgets in eboot** (`0x494000` bytes; scan with `memory.read_buffer` + `string.find(.., 1, true)`, never a per-dword walk - that walk once ran past the region and killed the game):

| gadget | file offset | count |
|---|---|---|
| `pop rax; ret` (`58 C3`) | `+0x992` | 15 |
| `pop rdi; ret` (`5F C3`) | `+0xC9DFE` | 18 |
| `pop rsi; ret` (`5E C3`) | `+0xD77D` | 18 |
| `pop rdx; ret` (`5A C3`) | `+0x3B02D7` | 3 |
| `pop rcx; ret` (`59 C3`) | `+0xE64` | 18 |
| `pop rsp; ret` (`5C C3`) | `+0x9A2` | 15 |
| `jmp $` (`EB FE`) | `+0x15481` | 19 |
| `mov [rsi],rax; ret` | `+0x1A0BA9` | 1 |
| `mov [rdi],rax; ret` | `+0x92C67` | 4 |
| `mov [rdx],rax; ret` | - | **0** |

There is no `syscall; ret` in eboot; the trampoline is the only way in.

**Looping children starve the process.** A chain that repeats `fn(662) -> pop rax,662 -> fn -> pop rsp,<chain>` keeps a thread inside a table-locking syscall forever. Four of them made the loader silent for minutes and needed a relaunch (717a). Every child should end with `thr_exit(431)`.

**Two children can be released together with one umtx wake.** `_umtx_op` (454) blocks on a word and op 3 wakes it, so the children sleep in the kernel and one parent wake releases all of them in the same lock batch:

```
child:  fn(454 WAIT on W, expected 0) -> pop rdi,<id> -> pop rsi,1 -> pop rdx,<out>
        -> fn(662) -> pop rax,431 -> fn        (no spinning thread left)
parent: wake 8x -> read the out pages
```

719b proves the gate alone (the child waits, is woken, and stores its pid); 719a/720a use it to put two to four children into the same `aio_multi_delete` at once.

Two details that cost a run each: the context enters `fn` with `RAX` already set, so a chain that starts by loading `240` again sleeps twice (718a v1 slept 240 ms against a 200 ms wait and every status page stayed untouched); and after a `_umtx_op` the argument registers still hold the umtx arguments, so *every* register the next call needs must be reloaded from the chain, not just `RDI` (719a v1 ran the delete with `count=2` and a NULL status pointer). `nanosleep` (240) itself works from a child - 718a v2 used it as the release timer.

## Result

`thr_create(430)` starts a second userland thread on 14.10 when the context
carries the three fields the handler validates **and** `CS = 0x43`,
`SS = 0x3B`. The child executes our `RIP`, with our registers and our stack, in
ring 3, and the process survives.

| probe | context | outcome |
|---|---|---|
| 80a | `CS`/`RIP`/`RSP`/`SS` written at `+0x90..0xB0`, magic at `+0x118` | `rv = -1`, no thread, process alive |
| 156a | same offsets, child aimed at `jmp $` | `rv = -1`, TID written, `thr_kill(tid, 0) = -1` |
| 156b | `thr_get_ucontext(634)`, two argument shapes | `rv = -1`, buffer untouched |
| 156c | gates passed, `CS = 0x43`, `RIP = jmp $`, `RSP =` our stack | `rv = 0`, TID 0x18EE3, `thr_kill(tid, 0) = 0` |
| 156d | gates passed, `RIP = mov [rdi], rax; ret`, `RAX = 0xDEADBEEFCAFE` | marker written into our page, `thr_kill(tid, 0) = 0` |

156d is the decisive one: the child ran two real instructions
(`48 89 07 C3` at `0x64832C67`, in eboot's RX `.text`), stored
`0x00000000DEADBEEFCAFE` through `RDI`, hit `jmp $` at `0x647B5481` and stayed
alive. A live TID alone would only prove that a thread object exists.

## What the earlier captures actually contain

The 2026-10-19 thread series is the reason this document exists, and it does not
say what its index rows say. Read line by line:

- `80c_thread_register_exec` returned `rv = -1` and printed `marker unchanged —
  thread did not write`.
- `80h_thread_write_test` returned `rv = 0`, so its context *was* accepted, but
  the capture ends in binary bytes and never reads the marker back.
- `80i_thread_write_final` stops at `calling thr_create` in all four captures;
  none records a return value or a marker readback.

So the earlier series proved context acceptance (`rv = 0`) and nothing about
execution. The index rows for 80a/80c/80h/80i have been corrected here rather
than left as they were. The difference between their accepted contexts and the
rejected ones is the gate fields, not the segment selectors.

## The context the kernel accepts

The 13.60 decode (`docs/THR_CREATE_430_CONTEXT.md`, `docs/THR_CREATE_PANIC_PATH_13.60.md`)
supplies the offsets; 14.10 now confirms them by acceptance and by execution.

| field | offset | value used | source |
|---|---|---|---|
| magic | `+0x108` (qword) | `0x480` | validator, must match exactly |
| flags | `+0x0d0` (dword) | `0` | validator, must be `<= 7` |
| type | `+0x110` (qword) | `0x10000` | validator, `0x10000` or `0x10002` |
| subtype | `+0x118` (qword) | — | checked only for type `0x10002` |
| GPRs | `+0x048`..`+0x0B8` | `rdi, rsi, rdx, rcx, r8, r9, rax, rbx, rbp, r10, r11, r12, r13, r14, r15` | register copy |
| CS | `+0x0c0` | `0x43` | `tf_cs` |
| RIP | `+0x0e0` | our gadget | `tf_rip` |
| RSP | `+0x0f8` | our stack | `tf_rsp` |
| SS | `+0x100` | `0x3b` | `tf_ss` |

The 430 body copies `0x500` bytes, and the id out-pointer is written **before**
the context is validated. That is why `rv = -1` arrives together with a fresh
TID: the TID proves the call reached thread allocation, not that a thread
exists. `thr_kill(id, 0)` is the discriminator — `0` means the TID is real,
`-1` means it was never created.

80a's earlier "CS=0x43 prevents the panic" line was **not** a threading result.
That context had none of the three gates set (`+0x108` was zero), so the handler
rejected it before it read CS, and the process survived because no thread was
ever started.

## What this changes

The "no threading" wall is gone for `thr_create(430)`. A second execution
context with attacker-chosen `RIP`, GPRs, `RSP` and stack contents is available
from the loader, which is the precondition for the UMTX-class races
(`docs/UMTX_454_EVIDENCE.md`) that every public PS5 chain inherits from WebKit
instead of creating.

## What this does not establish

- **Not a kernel primitive by itself.** The child runs in ring 3 with the same
  process privileges as the loader. No kernel memory was read or written.
- **CS attribution is still inferential.** 58e section D (`CS = 0`, `RIP = 0`)
  panicked; 156c/156d (`CS = 0x43`, real `RIP`) did not. Both the selector and the
  entry point differ between the two, so CS is the best explanation, not a
  measured single-variable result. The clean control — `CS = 0` with a valid
  `RIP` — would reboot the console and has not been run.
- **Thread lifetime.** The child keeps running after the probe returns;
  `thr_suspend(442)` returned `-1` for it, so there is no userland way yet to
  stop it. Two probes left two spinning threads in the loader process.
- **No TLS.** The child starts with whatever FS base the thread inherits; no
  probe has exercised a libc call inside the new thread.
- **No scheduling or signal work.** Priority, affinity, signal delivery and
  `thr_exit` from the child are untested.

## Reproduce

```bash
python tools/send_probe.py probes/phase17_new_vectors/156c_thr_create_correct_offsets.lua \
    --ip <console> --port 9026 --save --metadata --timeout 150
python tools/send_probe.py probes/phase17_new_vectors/156d_thr_create_child_executes.lua \
    --ip <console> --port 9026 --save --metadata --timeout 150
```

156c prints `THREAD EXISTS` when `thr_kill(tid, 0)` answers `0`; 156d prints
`CHILD EXECUTED` when the marker page receives `0xDEADBEEFCAFE`. Both take about
a second of console time after the eboot scan, which is the slow part (a 1 MB
byte scan over the loader bridge; pass `--timeout 150` so the client does not
give up while the scan runs).

## The loader's own thread class runs two concurrent syscalls (probe 631a, 2026-10-24)

The payload exposes a `thread` class (`thread:new(syscall_object)`, `run(async)`,
`join()`) built on libc `Thrd_create` plus `longjmp` into a **per-thread ROP
chain**. That is a different route from both `thr_create(430)` (raw context) and
`run_lua_code_in_new_thread` (a second Lua state), and it is the first one that
lets two threads issue syscalls without killing the process.

| route | result |
|---|---|
| `run_lua_code_in_new_thread(body, {async=true})` | body never runs: the `started` word stayed `0` through 200 000 polls (`625a`) |
| Lua helper issuing syscalls | process dies as soon as the helper starts (`509b`, capture ends at `helper spawned`) |
| `thr_create(430)` child + `syscall.pipe.fn_addr` | works with full GP control, but a second child running the *shared* chain races on the stub |
| loader `thread:new(sc):run(true)` | **two threads, both `getpid` calls returned `320`, process alive** |

Probe `probes/phase17_new_vectors/631a_loader_threads.lua`:

```
[A] pid=320
[B] one thread getpid -> 320 ok=true
[C] two threads -> 320 320 ok=true
[D] alive=320
```

`thread:new` must be called with the colon syntax and a real syscall object:
`thread:new({syscall_no=20})` fails at `thread.lua:41` (`obj` is nil because the
method takes `self` first), and a bare table fails the assertion at
`ropchain.lua:385` (`syscall.fn_addr` missing). `thread:new(make_syscall(20))`
works.

### What it took to build a race, and why it has not landed

- `632a`: two chains of 160 `aio_multi_delete` calls (20 rounds x 8 ids), each
  thread with its own chain and status page. Both joined, `health=4/4`,
  `alive`. **`A zeros=8 B zeros=0`** - thread A deleted the block in round 1 and
  thread B arrived afterwards, so the two never shared a call. Spawn jitter
  (~50-100 us) is larger than the delete window.
- Pointing the syscall object's `fn_addr` at the chain's own `fcall_stub` slot
  corrupts the chain: that slot holds a plain function address, while the
  syscall stub slot holds a tagged trampoline. The chain dies at launch.
- `633a` tried to remove the jitter with a `_umtx_op(WAIT)` barrier: both chains
  begin with `454(W, 2, 0)` and the parent releases them with one
  `454(W, 3, INT_MAX)`. Building that chain crashed the process before launch
  in two runs, with 64 ids and with a 6-argument `push_syscall_with_ret`
  (passing `rcx`/`r8`/`r9` explicitly is the main suspect; `push_sysv` then
  needs pop gadgets for each).
- `634a` isolates the barrier with no aio calls: one chain = `[454 WAIT]` +
  20 `getpid`, parent wakes it, then reads the last stored return value.

Until the barrier lands, the two-thread delete race stays untested rather than
refuted. The kernel window itself (the ten instructions between the re-lookup at
`0x8ad6fe7c` and the `[W+0x18]` guard at `0x8ad6fec3`) is unchanged and still
the target.


## The loader makes every syscall through a heap ROP chain (2026-10-25)

`tostring(syscall.pipe)` prints the chain it uses, and probe `712a` caught it whole:

```
0x310c4a0f0: 0x472d8042  ; ret
0x310c4a0f8: 0x472d8992  ; pop rax; ret
0x310c4a100: 0x310c48040
0x310c4a108: 0x472f6ebb  ; mov rax, [rax]; ret
0x310c4a110: 0x473a1dfe  ; pop rdi; ret
0x310c4a118: 0x310c49fd0
0x310c4a120: 0x4736ac67  ; mov [rdi], rax; ret
...
0x310c4a3d0: 0x472d89a2  ; pop rsp; ret
0x310c4a3d8: 0x310c49fd0
```

Two different things are called `fn_addr`:

- `fcall_stub.fn_addr` printed inside the pipe string (`0x310c49fd0`) is a **heap**
  stack frame; the chain's final `pop rsp; ret` pivots into it, so the first qword
  there is the next return target.
- `syscall.pipe.fn_addr` read directly in Lua (`0x808858B57` in a different
  process) is the **code** entry the chain reaches - it changes per process, so it
  is ASLR-relocated and must be read at run time.

Reading the bytes at that code address kills the process (probe `712b`), which is
the execute-only-text signature already recorded for libkernel: the trampoline is
in an XOM region and cannot be copied. It can still be *called*, which is what
`native.fcall_with_rax` does and what `712c` tries from a `thr_create` child.

## The trampoline returns into an RSI store, and a child does not contain a process exit (729b, 730a, 2026-10-25)

Two chain shapes were compared on the same process, each run twice, with the child's RIP set to
`syscall.pipe.fn_addr`:

| chain | getpid result |
|---|---|
| `[mov [rsi],rax; ret][pop rax; 431][fn][jmp $]`, `ctx.RSI` = status page | `0xD0` = 208 = the pid |
| `[pop rdi; ret][status][mov [rdi],rax; ret][pop rax; 431][fn][jmp $]` | `1`, every call |

The first shape is the one that works, and it is now the template: **store through RSI and pass the
status page as argument 2**. The second shape returns 1 for `getpid`, `syscall(0)`, `561` and `562`
alike, so the value says nothing about the call; the cause of the `1` was not identified. Every
child probe that stored through `rdi` before this run (including all of `729a`) reported values from
this artefact rather than from the syscalls.

**A fault is contained; a process exit is not.** `726a` showed three faulting children dying alone
with the game still alive. `730a` shows the limit: its getpid control returned the pid and the
following health line still read 208, then `561` with a *mapped user page* as its first argument
killed the whole process from inside the child. With the earlier `561(0)` hang and `561(999999)`
kill, that makes `561`/`562` a handler that ends the process rather than one that blocks, and no
amount of thread isolation changes it. Do not call either number again.

## The thread context carries RFLAGS, and the kernel masks it (769a-770b, 2026-10-25)

`thr_create` takes a 0x500-byte context whose known fields are GP registers at
`+0x048..+0x0b8`, `CS` at `+0x0c0`, `RIP` at `+0x0e0`, `RSP` at `+0x0f8` and `SS`
at `+0x100`.  Probe 769a tested the four unclaimed qwords between `CS` and `RSP`
by seeding each with `0x246` (`ZF|PF|IF`) and reading the child's flags back with
`lahf;ret` (eboot `+0x2b5fc`) storing `RAX` through `RSI`:

| candidate | child `AH` |
|---|---|
| none (baseline) | `02` |
| `+0x0f0` | **`46`** |
| `+0x0e8`, `+0x0d8`, `+0x0c8` | not reached (match found) |

So `+0x0f0` is `RFLAGS` and it reaches the new thread.  The value is *masked*:
probe 769b seeded `0x3246` (`IOPL=3`) and the child read back `0x4672`, i.e.
IOPL cleared.  Probe 770a then tried the two CPU-side routes from inside a
child: `popfq;ret` (eboot `+0x2d327`) with `0x3246` set the user flags
(`AH=0x46`) but left IOPL at 0, which is the documented CPL check; `iretq;ret`
(eboot `+0x37b0a0`) killed the process with *either* an `IOPL=3` frame or a
plain `0x246` frame (770b), so `iretq` is unusable from this context at all
rather than being rejected over the IOPL bits.  `IOPL` is therefore not reachable from a native child, and the
hardware (`in`/`out`, `cli`/`sti`) route to kernel memory is closed.

Two method notes for later probes:

- The first instruction of a child is the loader's syscall stub, so `RAX` at
  entry must be a harmless syscall number.  A zeroed `RAX` is syscall `0`,
  which exits the whole process; that is what ended the first 769a run.
- `lahf` only writes `AH`, so a stored `RAX` shows the preceding syscall's
  return value in the low three bytes.  Read `AH` for the flags.
