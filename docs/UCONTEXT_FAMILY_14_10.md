# The ucontext family works on 14.10: 430, 632, 634 and 633 all return 0

Measured 2026-11-05 (probes 1228a, 1228b, 1228c; session pid 87). This is the first time 632, 634
and 633 have been called in this corpus, and the first time the get is known to copy.

## 1. The context offsets decide everything

| probe | context layout | 430 result |
|---|---|---|
| 1228a | 156a layout: CS/RIP/RSP/SS at ctx+0x98/0x90/0xA8/0xB0, magic at +0x118 | **-1 EINVAL**, TID written but not a thread |
| 1228b | same, plus zeroed context and gates at +0x0d0/+0x110 | -1 EINVAL |
| 1228c | 156c layout: **CS +0xc0, RIP +0xe0, RSP +0xf8, SS +0x100, magic +0x108 = 0x480, flags +0x0d0 = 0, type +0x110 = 0x10000** | **0**, TID 0x18E3D, `thr_kill(tid,0)` = 0 |

`PROBE_INDEX` row 80a already recorded that 156a's offsets are the rejected ones; this run is the
behavioural confirmation, and it cost three probes because the wrong recipe was read first.

## 2. 632 / 634 / 633

With a live, spinning child (RIP = `jmp $`, RSP = mmap'd 64 KB stack page):

| call | result |
|---|---|
| `632(tid)` thr_suspend_ucontext | **0** |
| `634(tid, buf)` thr_get_ucontext | **0**, and the 0x600-byte buffer that was prefilled with 0xA5A5A5A5 has its first dwords **zeroed** |
| `633(tid)` thr_resume_ucontext | **0** |
| `433(tid,0)` after resume | 0 - the thread is alive |

So the kernel does copy into the caller's buffer. The earlier EINVAL in 1227b was the "thread is
running" path at `0x4391d7` (`cmp dword [thread+0xe4],0 ; jns error`), exactly as the body
predicted: **a thread must be suspended before its ucontext can be read**.

## 3. No kernel pointer in the copy

A scan of the full 0x4c0 bytes for qwords in the supervisor range found **zero**, and the surviving
tail of the 0xA5 fill (beyond the copied length) was untouched. For a user thread suspended at
`jmp $` the saved context is user state only: CS 0x43, RIP in eboot, RSP in our stack page, and the
GPR block we passed at create time. That is the expected result and it closes the "634 leaks the
kernel thread structure" hypothesis before anyone spends more runs on it.

## 4. What is still worth one probe

1. **Dump the copied context in full** (0x4c0 bytes, 16 rows of hex) and confirm the layout: the
   fields at +0xc0/+0xe0/+0xf8/+0x100 should come back as 0x43, the `jmp $` address and our stack
   pointer. If they do, the getter is a faithful mirror and `635 thr_set_ucontext` becomes the
   interesting half: it is the inverse write direction, and the same field table decides what a
   caller can install into a suspended thread.
2. **`635` on the suspended child**: write a context whose RIP points at a second gadget and see
   whether the resumed thread executes it. That is a kernel-mediated register install path, and it
   has never been exercised.
3. The thread family is otherwise now proven end to end, which matters for every race in the plan
   (a suspended-and-resumed thread is a deterministic scheduler lever the earlier probes did not
   have).
