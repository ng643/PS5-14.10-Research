# Uninitialised-stack copyout: census method, 450 sites, zero survivors

Static census of the 13.60 image (`docs/dumps_13.60/kernel_text.bin`, base 0xffffffff8a9c0000,
offset == RVA) looking for the classic kernel info leak: a `copyout()` whose source is a stack buffer
that the handler only partly fills, so the uninitialised remainder reaches userland.

## 1. The idea being tested

`copyout(kernel_src, user_dst, len)` at RVA 0x2591d0 never inspects what it copies. If a handler
does `lea rdi,[rbp-0x590] ; mov edx,0x200 ; call copyout` and only writes a few fields of that 0x200
buffer, the remaining bytes are whatever the previous syscall left on this thread's kernel stack -
kernel pointers, saved frame addresses, other processes' data. Unlike every other route in this
project, that shape needs no capability, no privilege, and no bug beyond a missing initialisation, so
it is worth a full census rather than a spot check.

## 2. Method (four passes, each on the retained text)

    .local/uninit_copyout_scan.py   # all copyout sites: source register, length provenance
    .local/uninit_cov.py            # per-site store coverage of the source buffer
    .local/uninit_refine.py         # drop buffers that a callee receives as an argument
    .local/uninit_map.py            # map surviving sites to syscalls via sysent thunks
    .local/gap4_aligned.py          # re-scan from an aligned function start for bzero/memset fills

Pass 1 found 971 direct call sites to the two copy helpers (432 copyin at 0x259280, 539 copyout). Of
the 539 copyout sites, 450 have a stack source (`lea rdi,[rbp-X]`) and an immediate length - the only
shape where "how much was written" is statically decidable. Length provenance across all 971:
immediate 573, register 189, memory 34, unset-within-12 175.

Pass 2 walked each function window (`ret`/`ud2`+padding, tail `jmp`, padding run) and recorded every
store into `[rbp-X .. rbp-X+len)`. Sites where a `bzero` (0x258ff0) with an immediate smaller length
preceded the copyout: **0**. Sites with no bzero at all in the window: 233; after dropping buffers
that are also passed to a callee in rdi/rsi/rdx/rcx/r8 within three instructions of a call: 56.

Pass 4 addressed the main known blind spot by re-disassembling from the nearest `push rbp ; mov rbp,
rsp` before each site and looking for `bzero`/`memset` with a register length. Result: **30 of the 56
are cleared** by a full-length call. Of the 26 remaining, every candidate inspected by hand turned out
to be cleared by a helper the scanner did not model:

| site | bytes | what actually clears it |
|---|---|---|
| 0x4f71e0 | 0xa58 | `0x8aeb6c91 mov esi,0xa58 ; lea rdi,[rbp-0xa88] ; call 0x8ac18ff0` (bzero) |
| 0x73a7b4 | 0x7e8 | `0x8b0fa732 mov esi,0x7e8 ; lea rdi,[rbp-0x818] ; call 0x8ac18ff0` |
| 0x73b144 | 0x7e8 | same function family, bzero 0x7e8 at `0x8b0fb0ca` |
| 0xab81fa | 0x470 | `0x8b478145` bzero 0x470 |
| 0x7016c3 | 0x200 | `0x8b0c1632 mov edx,0x200 ; xor esi,esi ; call 0x8ae5af30` (memset variant) |

`0x8ae5af30` is a memset entry that is neither 0x258ff0 (bzero) nor 0x8b344440, so a scanner keyed on
two helper addresses will always over-report. The same reasoning applies to the three AIO completion
copyouts found in the length census (0x3b018a, 0x3b1612, 0x3b1f6d): kernel-buffer sources with
`nbytes` taken from the same request, not stack buffers.

## 3. Verdict

**No survivor.** Across 450 stack-source copyout sites there is not one where an immediate length
exceeds what the handler is known to write, and the ten sites that survived two passes of filtering are
each cleared by a full-length bzero/memset on inspection. That is consistent with the rest of the
corpus: this kernel is FreeBSD 14-era code where `bzero`-before-fill is a house rule, and the Sony
syscalls follow it.

The census is nevertheless not a proof, and the failure mode is worth stating precisely: the pass-2
coverage model only sees stores in the same function expressed as `[rbp-disp]` with an immediate
length, so any buffer filled by a callee, by a `rep movs`, or through a second base register is
counted as unfilled. That is exactly how all ten survivors were produced.

## 4. What would settle it

A dynamic oracle rather than more static filtering: call the same syscall twice in one process with a
deliberately different kernel-stack history (for example after a deep recursion of other calls) and
diff the bytes the kernel writes back. Genuinely uninitialised bytes change between the two runs,
because they are leftovers; deliberately written bytes do not. Requirements: a syscall whose args can
be satisfied so it reaches the copyout, and a buffer filled with a pattern below 2^53 so a Lua
comparison does not round (`0x0000A5A5A5A5A5A5`, see the correction in
`docs/UCONTEXT_FAMILY_14_10.md`). This is cheap and it covers callee fills, which the static model
cannot.

## 5. Reproduce

    python .local/uninit_copyout_scan.py
    python .local/uninit_cov.py
    python .local/uninit_refine.py
    python .local/uninit_map.py            # writes .local/uninit_copyout.json, .local/uninit_gaps.json
    python .local/gap4_aligned.py          # aligned re-scan, prints the 26 remainder
    python .local/gap_7016c3.py            # per-site window dumps used for the hand triage table

Known scanner defects, all encountered here: a window that starts mid-instruction desynchronises the
whole pass (this hid a bzero at 0x73a73a on the first attempt); `mov esi,<len>` is not an immediate
operand of the helper call; and helper addresses beyond the two named ones are invisible.
