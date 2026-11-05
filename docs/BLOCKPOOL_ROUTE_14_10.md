# blockpool: open returns a handle, map needs an existing type-0xb mapping

Measured 2026-11-05 (probes 1223a-d, pid 80). Route R1 of `docs/ROUTES_III_14_10.md`, taken as far
as the console would let it go in one session.

## 1. What was measured

| probe | call | result |
|---|---|---|
| 1223a | `653(0,0)` | handle **0x17** |
| 1223b | `653(0,0)` | handle **0x18** |
| 1223c | `653(0,0)` | handle **0x19** |
| 1223d | `653(0,0)` | **-1** |
| 1223a | `477(0,0x4000,prot,flags,fd=0x17,0)` for (3,0x1002),(3,0x2),(0x33,0x1002),(3,0x1) | EINVAL 22 every shape |
| 1223b | `654(0,0x10000,acc,0,0)` for acc 3,0,10,2 | EINVAL 22 |
| 1223b | `654(0,len,3,0,0)` for len 0x4000, 0x200000 | EINVAL 22 |
| 1223c | `654(va,0x10000,acc,0,0)` for va 0x2000000000, 0x3000000000, 0x1000000000, 0x40000000 and acc 3,0,10 | EINVAL 22, 12/12 |
| 1223c | handle in `uap[3]` / `uap[4]` | EINVAL 22 |
| 1223a | `547(anon_va, buf24)` | 0, record `109F8000 00000003 109FC000 00000003 00000003 00610020` |

The three successful opens returned consecutive small values, so the handle space is real and
per-process; the fourth run failed with the identical argument shape, which means a precondition
exists that three runs happened to satisfy and the fourth did not (1223d was the only run that did
not map an anonymous page first).

## 2. Why 654 returns EINVAL: it looks up, it does not create

Body `0x9a9560`, verified here instruction by instruction:

```
9a957f mov rax,[rdi+8]        ; td_proc
9a9586 mov rbx,[rax+0x200]    ; the vm_map hung off the process
9a9592 cmp [rbx+0x20],r14     ; min_offset <= uap[0]
9a9596 jbe 0x9a95b4
9a95b4 test r14w,r14w         ; uap[0] must be 0x10000-aligned
9a95ba mov rcx,[rbx+0x28]     ; max_offset
9a95c3 mov r8,[rsi+8]         ; uap[1] = length, same alignment
9a95d8 mov r13d,[rsi+0x10]    ; uap[2] = access code, bitmask 0x409 -> {0,3,10}
9a9691 call 0x2c6820          ; mtx_lock(map)
9a96a0 call 0x2c6c40          ; vm_map_lookup(map, uap[0], &entry)   <-- the decisive call
9a96c2 mov rsi,[rcx+0x50]     ; entry->object
9a96cf cmp byte [rsi+0x9d],0xb; class must be 0xb
```

So `654` takes an address that is **already mapped**, requires the mapping's object class to be
`0xb`, and only then does page work (`0x9a971c call 0x9a97a0`). Our EINVALs are the
`vm_map_lookup` failure path at `0x9a976f`: none of the addresses we supplied had an entry, let
alone a type-0xb one. `655` confirms the same shape: `9a9ebe cmp byte [rsi+0x9d],0xb`.

The type-0xb object is built at `0x9a77c7 mov edi,0xb` inside the blockpool code, but whatever call
installs it in a user mapping is still unidentified. `mmap(477)` with the handle as `fd` is not it:
EINVAL on four prot/flags shapes, and the failure came before any pager message.

## 3. What this does and does not close

* `blockpool_map` / `blockpool_unmap` are **not** object creators. Any future attempt must first
  produce a mapping whose `entry->object->class` is `0xb`, and the only instruction that builds such
  an object (`0x9a77c7`) lives in the same blockpool file, so the creator is either 653 itself with
  a precondition we have not met, or a syscall that hands the blockpool object to `vm_map_insert`.
* `653` returning `-1` on one run out of four is the immediate puzzle: three identical calls
  succeeded. The difference between 1223d and the others is that 1223d never mapped an anonymous
  page or called 547 first. One run that opens a page, then calls 653, then repeats 653 in the same
  process would settle whether the precondition is process state or an allocation.
* The `0x18` argument in `547`'s `0xaba5d4` branch is still the prize: `cmp byte [obj+0x9d],0xb`
  is the only gate between 547 and the PTE-shaped answer, and it has never been taken on 14.10.

## 4. Next three experiments, in order

1. **653 determinism**: in one process, call `653` twice with nothing in between, then map an
   anonymous page and call `653` twice more. If the second pair differs from the first, the handle
   depends on vm state, not on a global.
2. **Find the installer**: disassemble the blockpool file's remaining functions (0x9a7000-0x9a7d10
   and 0x9a8000-0x9a9560) for a `call` to the vm_map insertion helper (`0x2c6c40`'s counterpart,
   the one that takes an object pointer) and for `0x9a77c7`'s caller. That gives the syscall that
   installs the object, which is the missing link.
3. Only then retry `654` with the VA of an installed mapping and read `547`.


## 5. blockpool slots are a small consumable table (persistence model unresolved)

Probes 1224a and 1224b, same boot:

* `653(0,0)` returns **-1 with errno 24 EMFILE** on the *first* call of a fresh connection.
* `getrlimit(RLIMIT_NOFILE=8)` returns `cur = max = 13952`, so the process descriptor table is
  nowhere near full. `setrlimit` is therefore not the answer and was skipped.
* The **pid is 80 in every probe of this boot** (1213a through 1224b), which is consistent with the
  loader forking one child per connection from a single parent. The libkernel base does change
  between some probes (0x83D58C000 in 1213a/b, 0x817E1C000 in 1216b-1219a, 0x803534000 in 1221a),
  so new address spaces do appear; a forked child would inherit the parent's layout and repeat the
  base, which is what the consecutive identical runs look like. The exact model is unproven, and the
  earlier sentence in this document that called the process persistent should not be relied on.

That explains the earlier sequence: `653` returned 0x17, 0x18, 0x19 in three consecutive probes
(23, 24, 25 - consecutive slots), and then EMFILE forever after. The handle is a **slot in a small
per-process table**, not a file descriptor from the 13952-entry fd table, and that table is now
exhausted for this game session. EMFILE is therefore an operational state, not a property of the
call.

Consequences for the route:

* the blockpool experiment can only continue after the game (or at least the loader) is relaunched;
* any future probe that allocates a blockpool slot must run **first** in a fresh session, and must
  free it with `655`/`657` if it wants to run more than a handful of shapes;
* the earlier `mmap(fd=handle)` EINVAL results from 1223a-c are still valid as measured, but they
  were taken when the handle was one of slots 23-25, so they cannot be blamed on exhaustion.

## 6. Where the installer hunt stands

The function containing the type-0xb constructor starts at `0x9A75B0`. It is a page mover, not an
installer: it checks a privilege threshold (`cmp dword [proc+0x5d4], 0x4ffffff` at 0x9a75d6 and
`0x6000000` at 0x9a760e), bumps a per-process counter at `[proc+0x58c]` with `lock xadd`
(0x9a7626), allocates a buffer, copies 0x4000-byte pages through `0x8de950` in a loop
(0x9a7746/0x9a775a/0x9a776e/...), and only then builds the type-0xb object at `0x9a77c7` to hold
them. The map insertion that would make `654`/`655` accept an address is still not identified;
the next places to read are `0x9ABCA0` (called at 0x9a76a5) and the page worker `0x9A97A0`
(called by 654 at 0x9a971c).

**One more operational note worth carrying forward:** 1224a's very first call already failed with
EMFILE while 1223d's returned -1 with a stale errno, so the exhaustion happened between 1223c and
1223d. Anything that opens blockpool slots should be treated as consumable and counted.
