# The fourth syscall argument never reached the kernel

Date: 2026-11-04 (eighteenth boot). Firmware target 14.10, measurements taken with the
Lua loader on TCP 9026 at 192.168.1.121, statics from `docs/dumps_13.60/kernel_text.bin`
(base `0xffffffff8a9c0000`, file offset == RVA).

## 1. What was believed

Every probe in `probes/phase17_new_vectors/` builds a syscall object with

```lua
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n ... end
```

and calls it as `mk(n)(a0, a1, a2, a3, a4)`, assuming the five Lua arguments land in
`rdi, rsi, rdx, rcx, r8` and therefore in `uap[0] .. uap[4]`. Four-argument calls
(`663` mode, `379` prot, `612`/`649` shapes, `622` mode) were interpreted that way.

## 2. What the loader actually executes

`.local/loader_payload/syscall.lua` builds the primitive in two different ways.

PS4 branch (lines 17-25): it scrapes libkernel .text for the wrapper pattern

```
48 c7 c0 ?? ?? ?? ??   mov rax, imm32      ; the syscall number
49 89 ca               mov r10, rcx        ; argument 4
0f 05                  syscall
```

and stores `libkernel_base + offset - 1` per syscall number. That wrapper moves `rcx`
into `r10` itself, so the C calling convention of the loader (argument 4 in rcx) is
translated into the kernel convention (argument 4 in r10).

PS5 branch (lines 26-28):

```lua
local gettimeofday = memory.read_qword(libc_addrofs.gettimeofday_import)
syscall.syscall_address = gettimeofday + 7  -- +7 skips "mov rax, <num>"
```

It takes the `gettimeofday` wrapper and skips only its `mov rax, imm32`. But
`gettimeofday(struct timeval *, struct timezone *)` has **two** arguments, so clang emits
no `mov r10, rcx` in that wrapper. The stub the loader jumps to is therefore

```
syscall
jc  error
ret
```

with `rax` supplied by the caller. Whatever `r10` holds at that moment is what the
kernel sees as syscall argument 4.

## 3. The kernel side confirms argument 4 is r10

`sy_call` for 663 is thunk RVA `0x265720` -> body `0x3b01f0`. The body begins with an
argument unpacker, not a uap dereference:

```
3b01f0  push rbp
3b01f1  mov rbp, rsp
3b01f4  mov rax, qword ptr [rsi]        ; uap[0]
3b01f7  mov edx, dword ptr [rsi + 8]    ; uap[1]
3b01fa  mov rcx, qword ptr [rsi + 0x10] ; uap[2]
3b01fe  mov r8d, dword ptr [rsi + 0x18] ; uap[3]
3b0202  mov r9,  qword ptr [rsi + 0x20] ; uap[4]
3b0206  mov rsi, rax
3b020a  jmp 0x3b0210                    ; real body, rdi = struct thread *
```

`uap[3]` is filled by the syscall entry from the trap frame, and on amd64 FreeBSD that
slot is `r10`, not `rcx` (the `syscall` instruction destroys rcx). So argument 4 travels
in r10, and the thunk has no way to see a value the loader put in rcx.

## 4. The measurement that exposed it

Probe 1211a (`results/phase17_new_vectors/1211a_aio_multi_wait_mode0_20261104_224549.txt`)
called `aio_multi_wait` twice on two freshly submitted, still-pending requests:

| call | arguments | observed |
|---|---|---|
| control | `663(ids, 2, out, mode=1, timeout=2000us)` | `ret=-1`, errno 60 ETIMEDOUT, both requests still pending |
| exploit shape | `663(ids, 2, out, mode=0, timeout=2000us)` | `ret=-1`, errno **22 EINVAL**, immediately, states unchanged |

The entire body contains exactly two instructions that materialise EINVAL (whole-function
regex over `0x3b0200-0x3b1080`): `3b03a3 mov r14d, 0x16` (the num bound) and
`3b041c mov r14d, 0x16` (the mode bound).

The num bound is

```
3b0384  mov rcx, qword ptr [rbx + 0x70]   ; argument 1, the count
3b0388  lea eax, [rcx - 0x81]
3b038e  cmp eax, 0xffffff7f
3b0393  ja 0x3b03b8                        ; jump over the error = accepted
```

For `count = 2`: `2 - 0x81 = 0xFFFFFF81`, which is greater than `0xFFFFFF7F`, so `ja` is
taken and the error is skipped. Both calls used count 2, and the control call with mode 1
completed normally, so the num bound did not fire.

That leaves the mode bound at `3b03b8`:

```
3b03b8  cmp r13d, 3
3b03bc  jae 0x3b040e     ; mov r14d, 0x16 -> EINVAL
```

`r13d` is `r8d` from the unpacker, i.e. `uap[3]`, i.e. the value we passed as mode 0. A
value we did not pass was >= 3. r10 is read-only from the loader's stub, so it held a
stale register from the previous call and the bound rejected it.

Conclusion: `663`'s EINVAL came from the instrument, not from the kernel refusing mode 0.

## 5. What this invalidates

Every measurement whose result depended on the fourth argument must be re-run through a
correct trampoline. In this corpus that is:

- `1205a`/`1206a` syscall `379` **prot** sweeps (`uap[0x18]` is argument 4). The ids and
  the return-code shape stand; the claim "every protection value the map accepts gives
  EACCES" was measured with a stale r10, not with the printed values.
- `1211a` aio mode (this document).
- Any `612`/`649`/`622` shape that varies argument 4.
- `605`'s service magic is argument 1 and is unaffected; `547(va, out)` is two arguments
  and is unaffected.

The five-argument calls are unaffected in their arguments 1, 2, 3, 5 and 6: SysV and the
kernel agree on rdi, rsi, rdx, r8 and r9. Only slot 4 differs by design.

## 6. The fix

Scan libkernel for the bare trampoline

```
49 89 ca   mov r10, rcx
0f 05      syscall
```

and call *that address* through `fcall(addr, sysno)` instead of the gettimeofday stub.
The loader's own `fcall` takes an arbitrary `fn_addr` and sets `rax`, `rdi`..`r9` from the
Lua arguments (`.local/loader_payload/ropchain.lua:594-657`), so any libkernel code
sequence can be used as the syscall entry.

Two side effects, both useful:

1. A bare `syscall` trampoline has no wrapper error handling, so the raw rax comes back
   unchanged. Error codes are then visible as numbers (`22`, `14`, `2`) instead of being
   squeezed through `errno` and a `-1` return. That is a second, cleaner error channel than
   `docs/ERRNO_CHANNEL_14_10.md` describes.
2. The value in rcx is preserved into r10, so arguments 4 to 6 are all controllable.

## 7. Instrument hazards found on the way

- `memory.read_buffer(libkernel_base, 0x40000)` **wedges the payload** on 14.10. Probe
  1212a printed `libkernel_base=0x83CB38000` and then never printed again;
  `tools/port_witness.py` reported `LOADER-STUCK accepted, no reply` afterwards. Scan with
  `memory.read_qword` and a rolling window instead (probe 1212b).
- `memory.read_dword` returns a uint64; `string.byte` on a short literal returns nil and
  `uint64` then throws `invalid type passed to constructor (nil)`.

## 8. Status

| item | state |
|---|---|
| argument 4 reaches the kernel in r10 | CONFIRMED (thunk unpacker + bound-check measurement) |
| stock PS5 stub can set argument 4 | NO (gettimeofday has two arguments) |
| a replacement trampoline exists in libkernel | NOT YET LOCATED (1212b prepared, loader wedged) |
| `663` mode 0 really refused by the kernel | REFUTED - the EINVAL was the instrument |
| aio_multi_wait mode-0 node reuse on 13.60 | PRESENT in the image, see below |

## 9. The aio bug itself is still in the image

Static, body `0x3b0210` (argument unpacker at `0x3b01f0`):

- mode dispatch at `0x3b078c`: `mov eax, [rbx + 0x2c]` (mode); `cmp eax, 1` sends mode 1 to
  `0x3b0798`, which advances the node pointer `r14` by 0x38 per iteration (correct).
- every other accepted mode falls to `0x3b0839`:
  ```
  3b0839  mov rcx, qword ptr [rbx + 0x40]   ; the malloc'd waiter array BASE, reloaded each pass
  3b083d  mov qword ptr [rbx + 0x50], r13
  3b0841  cmp eax, 2
  3b0844  jne 0x3b08e5                      ; mode 0 lands here, every iteration
  3b08e5  mov rax, qword ptr [rbx + 0x58]   ; last looked-up container
  3b08e9  mov rdx, qword ptr [rbx + 0xa8]   ; index
  3b08f0  mov rax, qword ptr [rax + 0x28]
  3b08f4  mov rax, qword ptr [rax + rdx*8]
  3b08f8  mov r13, qword ptr [rax + 0x20]   ; the request
  3b0900  mov dword ptr [rcx + 0x20], eax   ; node->status
  3b0924  mov rcx, qword ptr [rbx + 0x40]   ; base again
  3b0956  mov rax, qword ptr [r13 + 0x50]   ; request->waiters head
  3b0965  mov qword ptr [rcx + 0x30], rax   ; node->next
  3b0969  mov qword ptr [r13 + 0x50], rcx   ; head = the same node, every time
  3b096d  mov qword ptr [rcx + 0x18], r13   ; node->owner = the current request
  ```
  With count >= 2 the same node is linked onto every request and its owner field is
  overwritten each time, so the cleanup loop (which unlinks through `node->owner`,
  `0x3b0db0`..`0x3b0e93`) detaches it from the last request only. The array is then freed
  (`0x3b0f93`) while requests 0..n-2 still point into it: a deterministic use-after-free with
  no race, exactly the shape of the published Bagagwa/Relapse aio_multi_wait bug (target
  11.40 there, `0x45f060`; here 13.60, `0x3b0210`).

Reaching it needs argument 4, which is section 6.


## 10. Getting argument 4 back: the stub-harvest trampoline

Offline work, 2026-11-04 (the console was rebooting, so nothing here was measured live). The
input is `.local/dumps/eboot_chunk0.bin`, the 1,048,576-byte dump of `eboot_base` produced by
probe 1186a (method in `docs/EXEC_ONLY_LIBKERNEL_14_10.md`).

### 10.1 The gadget search on the only image we can read

| pattern | meaning | hits in 1 MB of eboot text |
|---|---|---|
| `49 89 ca 0f 05` | `mov r10, rcx ; syscall` | 0 |
| `0f 05 c3` | `syscall ; ret` | 0 |
| `41 5a c3` | `pop r10 ; ret` | 0 |
| `49 87 ca` | `xchg r10, rcx` | 0 |
| `0f 05` | any syscall | 1, at `0x93CBD` — **not an instruction** |

The single `0f 05` is the displacement of `0x93CBA  48 89 05 0f 05 8e 00  mov qword ptr [rip + 0x8e050f], rax`.
Capstone on `0x93CB5`..`0x93CC2` shows the whole run is one `lea`/`mov` sequence storing pointers into a
global table; there is no `syscall` instruction in it. This is the trap that makes byte scans for
`0f 05` useless: two bytes of any `rip`-relative displacement can look like one.

`mov r10, r64` in the same megabyte, 35 sites:

| form | count | offsets |
|---|---|---|
| `mov r10, rcx` (`49 89 ca`) | 6 | 0xC6837, 0xD52D7, 0xD728A, 0xDE7E1, 0xF9DAD, 0xF9FEF |
| `mov r10, rdx` (`49 89 d2`) | 8 | — |
| `mov r10, rbx` (`49 89 da`) | 8 | — |
| `mov r10, r9` (`4d 89 ca`) | 5 | — |
| `mov r10, rsi` / `rdi` / `r8` | 3 / 3 / 2 | — |
| `pop r10` (`41 5a`) | 0 | — |

All six `mov r10, rcx` sites are ordinary arithmetic, not gadgets. Disassembly of the first
instructions after each: `0xC6837 and r9,0xffffffffffffffc0 ; cmp rax,0x41 ; cmovl rsi,rdx ; ... ; sub r10,r8`
(memcpy tail logic), `0xD52D7 neg r10 ; cmovl r10,rcx ; test r10,r10 ; je` (strtol),
`0xD728A neg r10 ; cmovns r10,rcx` (another strtol), `0xDE7E1 shl r10,4 ; mov r14,[rbp+r10-0x278]`,
`0xF9DAD not r10 ; add r10,rdi` (memchr), `0xF9FEF sub r10,rsi`. Not one of them reaches a `ret`
without touching r10 again, and none of them is near a `syscall`.

Combined with the full-image scans already in the corpus (41r/41s/41t: `syscall;ret` = 0 over
`eboot+0x0`..`eboot+0x448000`, and only `0x448000`..`0x494000` never swept), the conclusion is
structural rather than statistical: **Sony userland does not execute `syscall`; every syscall goes
through a libkernel stub.** eboot therefore will not hand us a `syscall` instruction, and libkernel
will not hand us its bytes (PKU, `docs/EXEC_ONLY_LIBKERNEL_14_10.md`). Searching for
`mov r10, rcx ; syscall` anywhere readable is a dead end on 14.10.

### 10.2 What libkernel *does* hand us: stub addresses in plain text

The stub page is unreadable, but every pointer *to* it is stored in ordinary readable data — the
import slots. `syscall.lua:26` already exploits exactly that
(`syscall.syscall_address = *libc_addrofs.gettimeofday_import + 7`), so the mechanism is proven by the
loader itself; what was never done is harvest it for more than one slot.

A libkernel wrapper stub has a fixed shape:

    48 c7 c0 <imm32>   ; mov rax, <syscall number>        bytes 0..6
    49 89 ca           ; mov r10, rcx                      bytes 7..9   (only if the call has >= 4 args)
    0f 05              ; syscall                           byte  10 (or 7)
    c3                 ; ret                               byte  11 (or 8)

`gettimeofday` is a two-argument call, so `sa - stub = 7` — measured, probe 1183b. That single fact
fixes the prologue length at exactly 7 bytes and makes `stub + 7` a guaranteed **instruction
boundary** for every stub in the table, of either class:

* two/three-argument stub: `stub + 7` is `0f 05 ; c3` — runs our `rax` with a stale r10 (what the
  loader does today);
* four-or-more-argument stub: `stub + 7` is `49 89 ca ; 0f 05 ; c3` — **`mov r10, rcx` then the
  syscall with our `rax`**, which is a generic trampoline for any syscall number and any argument 4.

So the search becomes: find a stub whose arity is >= 4, without reading it. Arity does not need to
be *known* in advance — it only needs to be *tested*, and the test is behavioural.

Note what this does **not** need: a `syscall` gadget, a `pop r10`, a writable text page, or any kernel
primitive. It is pure userland register plumbing, and it turns syscalls 663 (aio_multi_wait),
379 (hidden mmap), 547, 572 and every other 4-argument handler in the corpus from "arg4 never
arrived" into "arg4 under control".

### 10.3 Test design, and why a wrong guess is bounded

`enumerate → verify → use`:

1. **enumerate.** Read the import slot we already know (`libc_addrofs.gettimeofday_import`) plus a
   0x2000-byte window on both sides, and every data segment of eboot as reported by
   `sceKernelGetModuleInfoFromAddr` (segment table at `mod_info+0x160`, 0x10 bytes per segment).
   Keep every qword `q` with `libkernel_base <= q < libkernel_base + 0x100000`. Those q values are,
   by construction, real stub addresses — the table is a list of pointers, not a guess.
2. **verify.** For each candidate within ±0x1800 of `gettimeofday`'s offset 0xB50 (i.e. inside the
   same stub page, not in libkernel data), call `stub + 7` with `rax = 20` (getpid) and accept the
   candidate only if it returns our own pid. Both stub classes answer this identically and
   harmlessly; libkernel data would not.
3. **use.** For every verified candidate, call `stub + 7` with `rax = 663`, `rdi = ids`, `rsi = 2`,
   `rdx = status`, `rcx = 0` (mode 0), `r8 = timeout pointer`. The 13.60 handler materialises
   `EINVAL` at exactly two instructions (`0x3b03a3` count bound, `0x3b041c` mode bound), and the
   count bound accepts 2. So:

   * `errno = 22` ⇒ two-argument stub, argument 4 was still r10, nothing learned but nothing broken;
   * anything else, in particular the mode-0 UAF path walking both requests, ⇒ **argument 4 arrived**,
     and the same address is the trampoline for every future 4-argument syscall.

Probe: `probes/phase17_new_vectors/1213a_stub_harvest_r10_trampoline.lua` (written, not yet run —
the console was rebooting). It prints the module-info segment table, the harvested offset set and a
page histogram, then the verify and use phases. The harvested set is itself a new artifact: the
first map of which libkernel stub offsets this process references, obtained without reading a byte
of libkernel.

### 10.4 Residual risks

* A stub using a 5-byte `b8 <imm32>` prologue instead of the 7-byte `48 c7 c0 <imm32>` would put
  `stub + 7` two bytes into `0f 05 c3` and fault. `gettimeofday` proves the 7-byte form exists on
  this build; it does not prove it is universal. Mitigation is ordering: the verify phase tests the
  candidates nearest 0xB50 first, so the cheapest information arrives before the riskiest guess.
* A window that crosses into unmapped libc data faults the payload (pcall does not catch SIGSEGV).
  The window is deliberately small (±0x2000) and anchored on a slot the loader itself dereferences.
* Any death here costs one manual relaunch, which is why the probe is staged to leave usable output
  after every phase.

### 10.5 Fallback if no 4-argument stub exists in reachable tables

Dump the remaining 3.6 MB of eboot text (readable, method of 1186a) and search the whole image for a
`mov r10, rcx` that reaches `ret` through register-only instructions. Such a gadget, plus the known
`0f 05` byte at `gettimeofday + 7`, is a complete pure-ROP argument-4 path with no new primitive:
the chain sets rdi..r9 with the existing `push_set_*` helpers, pushes `set rax = 663`, jumps to the
gadget, and the gadget's `ret` lands on `syscall.syscall_address`. The 1 MB available today contains
no such gadget, so this fallback needs the rest of the image first.

### 10.6 Status

| route | state |
|---|---|
| aio_multi_wait mode 0 through the stock stub | CLOSED BY MEASUREMENT — `EINVAL 22` before the mode-0 path, because argument 4 is stale r10 |
| `mov r10, rcx ; syscall` found in readable text | CLOSED (negative) — 0 hits, 1 MB eboot; `syscall;ret` 0 over 4.3 MB |
| `pop r10 ; ret` in readable text | CLOSED (negative) — 0 hits in 1 MB; no r10 gadget in any of the 11 game gadget tables |
| **stub-harvest trampoline (1213a)** | **OPEN — probe written, needs a live loader** |
