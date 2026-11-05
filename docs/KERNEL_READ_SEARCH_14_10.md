# Looking for a reader: base recovered, aio validated, ten deref candidates to triage

Static and live, 2026-11-05 (probes 1001a, 1231b, 1232a, 1233a).

## 1. The base is a solved input

Upstream's `1001a_kernel_map_sweep.lua` runs 512 `thr_create` children, each with `RIP` set to a
2 MB candidate; the SIGSEGV chain writes 0x80 bytes of the fault context per attempt and the parent
parses `(ctx+0x130 >> 8) & 0xF` - 5 present, 4 absent.

This boot: 50 mapped, 462 absent, `spawned=512 failed=0 alive`, image at
**`0xFFFFFFFF85000000` .. `0xFFFFFFFF8B000000`** (98 MB). The slide is per boot and the sweep costs
no relaunch.

## 2. aio is not a reader (closed)

* `669(cmd=0x1002)` from a **user** marker buffer: state 3 and the exact 16 marker bytes arrive on the
  socketpair - so the write path does copy *from* the address we supply.
* the same call with `+0x10 = 0xFFFFFFFF85000000`: accepted, state 3, **zero bytes delivered**.
  The user-range mask (`and rdi,0x7fffffffffff`) turns it into `0x7FFFFFFF85000000` and the copy takes
  the bad-pointer path.

So both aio directions go through validated user copies. (Also recorded: FreeBSD `MSG_DONTWAIT` is
**0x80**; 0x40 is `MSG_WAITALL` and is what wedged the loader in 1231a.)

## 3. The classic kernel-memory files do not exist

`/proc/kcore`, `/proc/kallsyms`, `/proc/self/mem`, `/proc/self/maps`, `/dev/kmem`, `/dev/mem`,
`/dev/mem0`, `/dev/physmem` all return **ENOENT**. No procfs, no memory device.

## 4. Where a reader can still come from: a kernel dereference of an influenceable pointer

With the copy helpers validated, the only shape left is a handler that treats a **value** from the
argument array as a pointer and dereferences it - ideally without the mask, ideally before any
validation. A first pass over the 301 bodies (track `mov rX,[rsi+slot]`, then look for
`mov rY,[rX+disp]` before the next `call`) yields ten candidates:

| body | syscall | instruction |
|---|---|---|
| 0x34B510 | 592 | `mov r14,[rax+0x3e8]` |
| 0x34B790 | 659 dynlib_get_list2 | `mov r14,[rax+0x3e8]` |
| 0x3B01F0 | 663 aio_multi_wait | `mov rax,[rax]` |
| 0x3B0FB0 | 664 aio_multi_poll | `mov rax,[rax]` |
| 0x531080 | 30 | `mov rax,[rcx]` |
| 0x91C640 | 629 physhm_open | `mov rcx,[rax+0x10]` |
| 0xAB83C0 | 477 mmap | `mov r14,[rcx+0x40]` |
| 0xAB8AF0 | 65 | `mov rbx,[rcx+0x200]` |
| 0xAB8BB0 | 73 | `mov rbx,[rcx+0x200]` |
| 0xC42760 | 404 | `mov rax,[rdx]` |

Most are certainly false positives - the register was reloaded from a kernel source before the deref,
or the slot read was the uap array itself rather than an argument value. **None has been triaged.**
That triage is the next static job: for each candidate, decide what the register actually holds at the
dereference, using the instruction-by-instruction window, and keep only the ones where the value came
straight out of `[rsi+slot]` with no intervening copyin, mask or kernel load.

A true candidate would be a *reader*: point the argument at a known kernel address
(`0xFFFFFFFF85000000` this boot), have the handler dereference it, and recover the loaded value in
whatever it returns or copies back.
