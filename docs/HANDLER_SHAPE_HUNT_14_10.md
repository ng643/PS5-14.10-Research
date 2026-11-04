# HANDLER_SHAPE_HUNT_14_10 — syscall 601 (mdbg_service) and corpus shape scan

Scope: static, code-level hunt in `results/kernel_handlers/` (fw 13.60 dump corpus; 14.10 handler bodies assumed identical
where the 601 body matches the 14.10 offsets already used by the team). No console access used.
Labels: **STATIC** = read directly out of a dump/asm line quoted here. **INFERRED** = follows from code shape but not executed.

Corpus/mapping notes (needed to reproduce every quote):
- `docs/dumps_13.60/kernel_data.bin` covers RVA 0x1000000–0x1400000; **file offset = RVA − 0x1000000**
  (verified: "mDBG: Invalid syscall…" RVA 0x12c892a = file 0x2c892a).
- `results/kernel_handlers/asm/sys_601_deep.asm` is a raw objdump of the 601 body, RVA 0xca0600–0xca6a00, 4017 lines.
  Quotes below are `L<line> @0x<rva>`.
- 601 entry: `L21 @0xca065a cmp rax,0x27` → `L23 @0xca0664 lea rcx,[rip+0xdb0af5] # 0x1a51160` →
  `L27 @0xca0676 movsxd rdx,DWORD PTR [rcx+rax*4]` / `L29 @0xca067d jmp rdx`. **STATIC**: 40-entry self-relative
  command table at 0x1a51160, i.e. every command is a direct jump into the body. Table contents are outside every
  retained dump (0x1a51160 > 0x1400000), so **command numbers cannot be bound to bodies from this corpus** (unchanged
  from the prior audit; nothing below depends on knowing a number).

---

## 0. HARD CONSTRAINT discovered first: SMAP is ON (kills the pointer-injection class)

**STATIC.** `docs/dumps_13.60/kernel_text.bin` contains 17 `stac` (0f 01 cb) and 46 `clac` (0f 01 ca) instructions;
the dense cluster at 0x259235/0x25930d/0x2593b7/0x259428/0x2594a7/0x259517 sits exactly in the copyin/copyout helpers
used by 601 (`call 0x259280` = copyin, `call 0x2591d0` = copyout).

Consequences, and they are load-bearing for the ranking:
1. Any 601 command that dereferences a **user** pointer as a kernel pointer is a #PF panic, not a primitive.
2. This is the correct explanation of the previously recorded "601 cmd 0x03/0x04 lethal": those bodies take a raw
   `struct proc *` (see §2). They were not lethal because of a deep bug — they were lethal because the argument was
   not a kernel pointer.
3. Therefore the only 601 commands reachable *today* (uid 1, bit 61, no leak) are the ones that move data through
   copyin/copyout/uiomove. Everything pointer-taking is **post-leak** only.

---

## 1. FINDING 1 (top): a 601 command drains the kernel mdbg log to userland — no credential gate

**Body: 0xca32b0, `L2681`–`L2800`. STATIC.** No call to the bit-62 predicate (0x608f90) anywhere in it.

    L2681 @0xca32b0 push rbp                       ; fn(uio *rsi)  — r14 = rsi
    L2689 @0xca32c1 lea rdi,[rip+0x316a5a0] # 0x3e0d868   ; static mutex
    L2698 @0xca32d9 cmp QWORD PTR [rip+0x316a58f],0x0 # 0x3e0d870   ; log-list head == NULL?
    L2706 @0xca330a call 0xc06260                  ; log_create(0x3e0d880, &0x3e0d850, 0x1000, "mdbglog", 0,0, 0x100)
                                                    ;   rcx = 0x1305178 = "mdbglog"
    L2716 @0xca333a mov r12,QWORD PTR [r14+0x18]    ; uio_resid
    L2726 @0xca3360 cmp r12,0x4000 ; cmovae       ; clamp to 0x4000-byte bounce buffer
    L2737 @0xca3392 movsxd rax,DWORD PTR [rbx+0x10] ; entry->read_off
    L2738 @0xca3396 mov r15d,DWORD PTR [rbx+0x14]   ; entry->len
    L2749 @0xca33b0 call 0x2590b0                   ; memcpy(bounce, entry->buf + off, n)
    L2759 @0xca33bf mov QWORD PTR [rip+0x316a4aa],rax # 0x3e0d870  ; unlink consumed entry
    L2766 @0xca33fc call 0xc08df0                   ; free(entry->buf)
    L2785 @0xca3451 call 0x782520                   ; uiomove(bounce, n, uio)  -> userland
    L2788 @0xca3456 mov r12,QWORD PTR [r14+0x18]    ; loop while resid > 0

**Mechanism.** The handler owns a kernel log (`0x3e0d870` list head, `0x3e0d868` mutex, created lazily as a
0x1000-byte / 0x100-entry `log(9)` object named "mdbglog"). One command walks that list, memcpy's each entry into a
0x4000 kmalloc buffer and uiomoves it to the caller's uio. The log is fed by `log_printf` calls throughout mdbg, and
the format strings are in the data dump:

- `0x1359707` = "mDBG: Debughandler starting(%d:%s)\n" (emitted at `L1076 @0xca1833`, immediately before the request
  dispatcher is called — **every 601 call writes a log record**),
- `0x12c9cb5` = "mDBG: Kernel Build ID = %lx\n",
- `0x12c892a` = "mDBG: Invalid syscall on debughandler (%d)\n",
- and the %p-bearing dump formats at 0x12ed609 / 0x13218a4 / 0x136ae93 recorded in the prior audit.

**Why it matters.** This is a kernel→userland read channel that exists *today*, is not behind bit 62, and carries text
produced by code that formats kernel pointers. It is the cheapest candidate for the KASLR defeat the project still
needs, and it is a different mechanism from the two public 2026 tricks (no AF_ROUTE, no race).

**Falsification (1 syscall once the number is known).** `cmd(arg1 = mapped user buffer, arg2 = 0x1000, arg3 = 0)`:
- CONFIRM: return 0 and the buffer contains ASCII beginning "mDBG:" (or any prior log text); a second call returns 0
  with resid consumed.
- KILL: EINVAL/ENOSYS, or a zero-length result on every argument shape, or (after the sweep) no command produces
  "mDBG:" text.
Note the zero-length case is a *useful* fingerprint: with arg2 = 0 the loop never runs, the log is still created and
the call returns 0 — so the command is "harmless with len 0, produces text with len 0x1000".

**INFERRED (not executed):** that the 601 wrapper builds the uio from uap[1]/uap[2] (the same wrapper pattern is
**STATIC** for 667, which passes uap[1] + a clamped count into 0x782520). If the drain command instead takes a raw
`struct uio *`, SMAP turns it into a panic — that outcome is itself the kill signal.

---

## 2. FINDING 2: the attach command takes a raw `struct proc *` from userland and runs a write chain

**Body: 0xca12d5 (`L756`–`L809`). STATIC.** Reached only from the command table (zero branch references to 0xca12d5 in
the body) — i.e. it *is* a command, not a helper.

    L756  @0xca12d5 push rbp
    ...   r14 = uap[1] ; call 0xc9afc0(r14)        ; get-or-create ctx:
                                                     mtx_lock(proc+0x148); ctx = *(proc+0x568);
                                                     if (ctx==0) { ctx = malloc(0x1f0); *(proc+0x568) = ctx; }
    L773  @0xca131f or QWORD PTR [rax+0x528],0x100 ; *** current td state bit set ***
    L775  @0xca132f lea rbx,[r13+0x28] ; mtx_lock(ctx+0x28)
    L783  @0xca134e mov DWORD PTR [r13+0x94],eax  ; ctx->field = td->td_tid (from [td+0x9c])
    L786  @0xca135f cmp DWORD PTR [r13+0x88],0x0
    L789  @0xca1362 mov DWORD PTR [r13+0x34],0x2 ; ctx->state = 2 ; call 0x73ef00(ctx)
    L794  @0xca1388 mov DWORD PTR [r13+0x34],0x1 ; ctx->state = 1
    L797  @0xca1383 call 0x73e780(ctx, ctx+0x10, 0)
    L803  @0xca13b6 mov DWORD PTR [r13+0x88],0x0 ; ctx->field = 0

**Mechanism.** `uap[1]` is used verbatim as a `struct proc *`: the kernel takes a mutex inside it, reads a pointer out
of it (+0x568), takes a second mutex through *that* pointer, and then writes three fields through it (+0x94, +0x34,
+0x88) plus two calls. There is no validation, no credential test, and no copyin.

**With SMAP on, this is only usable with a valid kernel pointer** — which is exactly why it panics today. Once ANY
kernel read/leak exists (§1), the chain is an **arbitrary kernel write primitive**:
choose X = any readable kernel address; the kernel does `mtx_lock(X+0x148)` and loads `ctx = *(X+0x568)`; if we can
plant a qword at X+0x568 (or find an X whose +0x568 already points where we want), the kernel then writes
`ctx+0x94`, `ctx+0x34`, `ctx+0x88` and calls through `ctx`. That is a write-what-where-ish primitive of a shape the
project currently lists as "kernel WRITE: none".

**Side effect worth its own line:** `L773 or QWORD [td+0x528],0x100` is a *self-state escalation* performed by a
command. It is the flag that unlocks the request types in §3.

**Falsification (post-leak, 1 syscall).** With a leaked pointer to our own `struct proc` (or any kernel object with a
controlled +0x568): `cmd(arg1 = that pointer, arg2 = 0, arg3 = 0)` → CONFIRM if return 0 and the process continues to
run/debug normally (ctx installed); KILL if EINVAL or a #PF panic naming a kernel address.
Pre-leak version: `arg1 = 0` panics (already observed) — that only proves the raw deref, not exploitability.

---

## 3. FINDING 3: the request dispatcher is gated by a *thread state bit*, and 3 of its 7 types have no validation

**Body: sub_00ca2320 @0xca2320 (`L1680`–`L2390`), called from `L1076 @0xca1833`. STATIC.**

    L1726 @0xca23cd mov ecx,0xb8                  ; allowed-type mask {3,4,5,7} when the state bit is CLEAR
    L2101 @0xca29d0 lea rcx,[rip+0xdae85d] # 0x1a51234   ; 7-entry type table, indexed by type 1..7
    L1355 @0xca1cfb lea rcx,[rip+0xdaf4fe] # 0x1a51200   ; second table (type-1 append path)
    L1529 @0xca2048 lea rcx,[rip+0xdaf1c1] # 0x1a51210   ; third table (type-100 parser path)

Validation matrix (all STATIC):
| type | pre-dispatch validation | body |
|---|---|---|
| 3, 4 | `local_5c <= 0x10000` else 0x3f | copyout 8 bytes from stack `local_40` via 0x2591d0 |
| 7 | `local_68 <= 0x100` && `local_74 <= 0xf` else 0x16 | table 0x1a51234 |
| 1 | length clamped to 0x80000−used, copyin 0xc9c9a0, memcpy to ctx+0x58+used | table 0x1a51234 |
| 100 | `copyin(min(len,0x1000))` then `func_0x007b0ae0(buf,len)`, **return value discarded**, returns 0 | parser |
| **2, 5, 6** | **none** | table 0x1a51234 |

The gate itself: if `(*(u64*)(td+0x528) & 0x100) == 0` the type must be in 0xb8, else EPERM(1); if the bit **is** set the
mask is skipped entirely, so 1, 2, 6 and 100 become reachable — and 2/5/6 then go to the type table with no length,
count or pointer check in this function.

**Why it is novel.** Privilege here is not a credential — it is a *per-thread flag set by another command of the same
handler* (§2, L773). That means the handler is an ordered state machine: command A flips the thread into "trusted"
mode, command B then accepts request types that are otherwise EPERM. No public 2026 technique uses this shape
(command-sequenced state, not a race and not a parser bug).

**Falsification (2 syscalls, needs the two command numbers).** Call the type-request command with `type=2, len=0x10000,
buf=mapped` **before** attach → expect EPERM(1). Then attach (arg1 = 0 is a panic, so this specific chain is
post-leak). Cheaper pre-leak variant: sweep the type-request command with type ∈ {3,4,5,7} and observe EINVAL vs 0;
the EPERM-vs-EINVAL boundary identifies the gate, and the absence of a length check for type 5 can be shown by
`type=5, len=0x10000` returning something other than 0x3f/0x16.

---

## 4. FINDING 4: a 9-slot named object registry + a 256-entry user-object table (category "user data into a kernel object")

**STATIC.** Registry creation/registration strings resolved from `kernel_data.bin` (RVA−0x1000000):

    0x1382c26 "Sce.PSM:SdbInfo"      0x13251a9 "Sce.PSM:LogArea"     0x1305161 "Sce.Debug:UserObjArray"
    0x12dc08b "Sce.Debug:Gnm"        0x13641af "Sce.Debug:Gn2"       0x13251b9 "Sce.Debug:Gn3"
    0x12c6e96 "Sce.Debug:Gn4"        (9 slots total: kmalloc 0xd8, anchored at ctx+0xf0; per-slot name/slot/flags)

    L3663 @0xca40b3 mov r15,QWORD PTR [rdi+0xa8]        ; descriptor (user-controlled fields)
    L3665 @0xca40c0 test BYTE PTR [r15+0xc],0x1         ; flag consistency check on the descriptor
    L3681 @0xca40f7 call 0xc08b50                        ; malloc(0x30, M_WAITOK|M_ZERO)
    L3688 @0xca411f movzx eax,BYTE PTR [r15+0x10]        ; user byte copied into the kernel object
    L3695 @0xca4127 call 0xca64b0                        ; validate/attach
    L3725 @0xca41a8 mov rsi,QWORD PTR [r15+r13*8+0x2c0]  ; 256-entry pointer table, index from a user byte
    L3731 @0xca41b5 movzx edx,WORD PTR [rsi+0x11c]       ; u16 id compare
    L3736 @0xca41c0 cmp QWORD PTR [rsi+0xf0],0x0

**Mechanism.** A command takes a user descriptor, allocates a 0x30 kernel object, copies user dwords/bytes into it
(+0x18, +0x1c, +0x20, +0x28), validates it, then walks a 256-entry table of pointers at ctx+0x2c0 matching a u16 id at
+0x11c and a non-null field at +0xf0 — insert/replace semantics. This is the mechanism by which libmdbg registers
per-process debug buffers with the kernel. It is the mission's category (c) "store user data/pointers in a kernel
object for later use" in its purest form; the open question is whether any later consumer dereferences the stored
pointer as a *kernel* pointer (SMAP makes that a panic) or copies into it (safe, and a candidate kernel→user channel).

**Falsification (1–2 syscalls).** Register a descriptor with id 0x1234 and a pointer to our own buffer, then trigger
the log/printf path and see whether our buffer receives text (consumer is a copyout) or the call panics (consumer is a
raw deref). CONFIRM = bytes appear in our buffer without a 601 log-drain call.

---

## 5. Negatives from the corpus-wide shape scan (do not re-derive)

**STATIC.** Indirect-dispatch census over all 145 handlers: tables exist in 601 (×4: 0x1a51160, 0x1a51200, 0x1a51210,
0x1a51234), 622 (×5 @0x178xxxx), 532 (×2 @0x18de2xx), 630 (0x181d504), 643 (0x18d3f38), 646/647
(0x18dbfdc/0x18dc304/0x18dc244), 649/656/659/660/672 (0x14c02b0), 650/651/652/654/655 (0x159b8b0, 0x159ba7c,
0x159bb38, 0x18cdb30, 0x1a477b8/0x1a477ec/0x1a4785c/0x1a48030/0x1a480b8/0x1a480a8), 667 (0x1592fe8 + 6),
673 (0x18cdc98), 674 (0x18dbf54/0x18dbf68), 676 (0x172bf7c/0x172bf8c/0x172c134/0x172c144).
- **Every one of these tables lies outside the retained dumps** (all > 0x1400000 except 0x14c02b0, also outside), so no
  table index can be bound to a body statically. One heuristic hit at 0x13b9ed0 decoded as nonsense (not a table).
- No handler anywhere takes a function pointer or ops-table pointer from user memory and calls it (the only
  user-influenced indirect control transfer found is 601's own command table, where the index is range-checked by
  `cmp rax,0x27`).
- 601's copyin/copyout sites are all preceded by a log call naming the direction ("copyin" 0x1397f3d, "copyout"
  0x134f297, "copyinstr" 0x135a084 — **STATIC** strings, so the log records every transfer); no site uses a
  caller-supplied length without a clamp in this function.
- 601 registers deferred/event handlers at init, not from user input: 0x73dd40 is called with
  "process_exit"/"procexit_handler", "process_exec"/"procexec_handler", "process_exec_end", "procfork_handler",
  "process_suspend_phase2"/"_handler", "process_resume_phase2" (priority 20000). No user-influenced callout.
- 667's 0x28-byte thread records (u32 proc+0xbc, u32 thread+0x9c, 4×u64 thread+0x5b0..+0x5c8) remain behind the
  bit-62 predicate 0x608f90 (which is `(*(u64*)(cred+0x60) >> 62) & 1`), i.e. unreachable from bit 61.

---

## 6. Ranking

| # | finding | reachable now (bit 61) | yield | probe cost |
|---|---|---|---|---|
| 1 | log drain 0xca32b0 (§1) | **yes** (no gate in body) | kernel→user read; KASLR candidate | 1 syscall after number is known |
| 2 | attach 0xca12d5 (§2) | no — needs a valid kernel pointer (SMAP) | arbitrary kernel write | 1 syscall post-leak |
| 3 | type-gate state machine (§3) | partly (types 3/4/5/7 today) | unvalidated types 2/5/6 after attach | 2 syscalls, ordered |
| 4 | user-object registry (§4) | unknown (body has no credential test) | user data into kernel object; possible copyout channel | 1–2 syscalls |

Recommended order of work: (i) find the drain command number by sweep (§1 fingerprint), (ii) if the log carries a %p,
the project has KASLR and §2/§3 open up, (iii) otherwise try §4's register-then-trigger.

## 7. The one measurement per finding

1. **Drain:** `cmd(buf=0x1000 mapped, len=0x1000, 0)` → does the buffer start with "mDBG:"?
2. **Attach:** `cmd(arg1=<kernel pointer>, 0, 0)` → return 0 (ctx installed) vs #PF at arg1+0x148?
3. **Type gate:** `type=2,len=0x10000` before vs after the state-bit command → EPERM(1) vs dispatch?

## Measured correction (2026-11-04 16:10): finding 1 is not reachable from uid 1

Finding 1 (the unprivileged log drain) was a static read of the body. It has now been swept behaviourally
over the whole command space with the sweep in `docs/MDBG_601_COMMAND_MAP_14_10.md`:

* 0x00-0xFF all measured, seven argument shapes tried on the ten commands that return 0 (`1179a`), buffer
  in argument 1 and length in argument 2 confirmed by shape C/D/E returning -1.
* **No command ever wrote ASCII**, `grep -r mDBG results/` is still zero, and the three writing commands
  emit fixed out-params (0x100/0, 0/0, 0) that do not vary with buffer, length or flags.

So the drain body exists but is behind the type gate at `0xca2320`, which is unlocked by attach - and
attach needs a kernel `struct proc*`. Finding 2 (attach) is therefore the only live item in this document,
and it is post-leak only.
