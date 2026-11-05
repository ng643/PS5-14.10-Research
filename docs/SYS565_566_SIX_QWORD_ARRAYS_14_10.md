# syscalls 565 and 566: six qwords at per-thread +0x160 and +0x190

## The shape

Both bodies are in the thread-control cluster and both write caller data into a six-entry qword
array inside a kernel object. 565 (`0x6034e0`) writes **masked** values at `[obj + idx*8 + 0x160`;
566 (`0x603710`) writes **unmasked** values at `[obj + idx*8 + 0x190`, where `obj = [thread + 0x3f8]`.

Argument decoding, 565:

    6034ee  mov r12d,[rsi+8]        ; arg1 = index
    6034f2  mov r13, [rsi+0x10]     ; arg2 = value
    6034f6  movabs rcx,0xfffffff0007b0000
    603506  cmp r12,6 / setae al    ; index must be < 6
    60350d  test r13,rcx / setne cl ; value may only use bits outside that mask
    60351b  mov r15d,[rsi]          ; arg0 = thread id (or a small handle)
    603528  movabs rcx,0x100000070 / and rax,r13 / cmp rax,rcx  ; and cmp rax,0x6e
    603540  movabs rax,0xfff8400ff / and r13,rax                ; second-stage mask
    6035cd  mov rbx,[rax+0x3f8]     ; obj
    603608  mov [rbx+r12*8+0x160],r13

566 is the same skeleton with `lea eax,[r13-6]; cmp eax,-7; jb` admitting `{-1, 0..5}` (index -1
means "all six"), and the store is

    6037e5  mov [r15+r13*8+0x190], r12     ; r12 = [rsi+0x10], no masking at all
    603874  mov [rbx+r13*8+0x190], r12     ; same store inside the list walk

so 566 accepts **any 64-bit value** and places it at a caller-chosen slot of a six-qword kernel
array. Both bodies end by kicking the target thread through `0x602d40` / `0x602e80`, which read
`[obj+0x400]`, set bits in `[obj+0x380]`, and issue `0x81e4d0(id, 4|5|6)` - an IPI or
scheduler notification.

## The lookup, and what it costs

    lea eax,[r15-1] / cmp eax,0x1869e / ja  takes the handle path
    603747  mov rdi,[rdi+0x140] / call 0x26d0a8     ; capability check on the caller
    603764  call 0x53c170                            ; handle -> object
    603780  call 0x609890                            ; object+0x10 -> [+0x140] -> check
    60378d  mov r14d,1                               ; EPERM when that check fails

    the other path is the thread hash resolver already decoded in THR_LOOKUP_14_10.md:
    6037ad  call 0xb92420(tid, curproc->p_pid)       ; ESRCH 3 when the tid is not ours

So a caller may aim at any thread **of its own process**; a foreign tid returns ESRCH.

## What is not established

`[thread+0x3f8]` is a pointer to a per-thread block, and the block has arrays at +0x160 and +0x190.
Nothing in this session identifies the block. Two candidate readings were tested and one was
rejected:

- **Not the debug registers.** The DR installer at `0xa07860` loads DR0-DR3 and DR6/DR7 from
  RIP-relative globals (`a078e7 mov rax,[rip+0x31ac932] / a078ee mov dr0,rax`), not from a
  per-thread block, and the context switch save/restore at `0x25234d`- `0x25255d` copies the six
  registers through registers, not through this structure.
- **Unresolved.** An image-wide scan finds 37 sites that load a qword from `[reg+0x190]` and
  dereference it. Six of them share one shape and are the only ones that read a plausible kernel
  field:

      37bfd8  mov rdi,[rbx+0x190] ; 37bfdf mov eax,[rdi+0x7c]
      37c2c5  mov rdi,[rbx+0x190] ; 37c2cc mov eax,[rdi+0x7c]
      a81dc1  mov rdi,[rbx+0x190] ; a81dc8 mov eax,[rdi+0x7c]
      ac5e23  mov rdi,[rbx+0x190] ; ac5e2a mov ecx,[rdi+0x7c]
      ae6ad8  mov rdi,[rbx+0x190] ; ae6adf mov eax,[rdi+0x7c]
      ae6cf8  mov rdi,[rbx+0x190] ; ae6cff mov eax,[rdi+0x7c]

  None of them is shown to take `rbx` from `[thread+0x3f8]`, and several are in assertion and
  error-string helpers where the base is a different object that happens to have a field at +0x190.
  Treating them as consumers would be the same guessing that produced the retracted rows earlier in
  this project.

## Verdict

565/566 are a **bounded kernel write of six qwords into one per-thread block**, with a fully
caller-chosen value in 566 and a caller-chosen slot index. That is a real write primitive only if
something later consumes those slots; today the consumer is unknown and no evidence ties any of the
six reader sites to this block. The next step is static and cheap: find the initialiser of
`[thread+0x3f8]` (the store that installs the pointer), which names the object and therefore its
consumer. Until then this stays a lead, not a primitive.

## Reproduce

    python .local/dis_565.py     # bodies 0x6034e0 and 0x603710
    python .local/scan_3f8.py    # 312 [reg+0x3f8] accesses image-wide
    python .local/scan_160_190.py# 698 [+0x160]/[+0x190] accesses, 37 load-then-deref
    python .local/dis_drblk.py   # the DR installer at 0xa07860
