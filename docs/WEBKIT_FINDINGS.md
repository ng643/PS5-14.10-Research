# WebKit Findings — PS5 14.10

Independent browser-side research on PS5 firmware 14.10. Findings are from probes run on the actual console via the PS5's built-in browser (User's Guide DNS redirect). No raw beacon logs are included; the results below are from the probe results table maintained in the source repository.

Source: [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research)

## Console Fingerprint

Validated on device (p163).

| Property | Value |
|----------|-------|
| Platform | PlayStation 5 |
| Firmware | 14.10 |
| Browser | Safari 17.0 / AppleWebKit 605.1.15 |
| Source match | WebKit-1200 snapshot (Dec 2023) |
| JIT | Disabled (LLInt interpreter only) |
| CPU cores | 4 |
| Display | 1920x1080 |

### Measured engine level (p162, 2026-10-19)

The UA string is pinned; the API surface is not. `probes/phase13_webkit/p162-engine-fingerprint.js`
ran in the User's Guide page on 14.10 and beaconed a per-feature bitmap, each feature tagged with the
Safari release that shipped it:

| shipped in | feature | result |
|---|---|---|
| 12.0 | `Array.prototype.flatMap`, `BigInt` | present |
| 13.0 | `String.prototype.matchAll` | present |
| 13.1 | optional chaining, nullish coalescing, `replaceAll` | present |
| 14.0 | `#x in obj` | present |
| 14.1 | `WeakRef`, `FinalizationRegistry`, `Intl.Segmenter` | present |
| 15.0 | `||=`, `&&=`, `??=` | present |
| 15.4 | `Object.hasOwn`, `Array.prototype.at`, `findLast`, `findLastIndex`, `Error.cause`, `structuredClone`, RegExp `d` | present |
| 16.0 | `Atomics.waitAsync` | present |
| 16.4 | `toSorted`, `Array.prototype.with`, `isWellFormed` | present |
| 17.0 | `Set.prototype.union`, RegExp `v` | present |
| 17.4 | `Object.groupBy`, `Promise.withResolvers`, `ArrayBuffer.prototype.transfer` | **absent** |
| 18.x | `Float16Array`, `Promise.try`, iterator helpers, `Uint8Array#toBase64`, `RegExp.escape` | **absent** |

Every 17.0 feature present, every 17.4 feature absent: the JS surface is the Safari 17.0–17.3 band,
i.e. WebKit trunk from roughly September 2023. `navigator.hardwareConcurrency` reports 4 and
`navigator.deviceMemory` reports 0 (the API is absent, not zero memory).

This dates the *feature* surface, not the security patch level. A vendor fork normally freezes the API
at a revision and back-ports security fixes on top, so an absent 17.4 API says nothing about whether a
2026 JSC fix was merged. It does mean default code paths and bytecode shapes match the 2023 engine, so
candidate bugs have to be from that base plus whatever back-ports Sony applied.

### Measured capability surface (p163, 2026-10-19)

`probes/phase13_webkit/p163-capability-map.js` ran the same way and returns the table below. The list
that used to sit here was inherited prose; this one is measured, and it confirms those absences rather
than repeating them.

| capability | result | how it was measured |
|---|---|---|
| JIT (DFG/FTL) | **off** | six batches of a 2 M-iteration integer loop all read 11.5-12.5 ns/iter, flat. A compiling engine falls to ~0.5 ns/iter by the third batch (measured on Node 24 for reference). |
| WebAssembly | absent | `typeof WebAssembly` is `undefined`; the 8-byte module header cannot even be constructed |
| SharedArrayBuffer | absent | `typeof` is `undefined`; `new SharedArrayBuffer(16)` unreachable |
| Atomics | object present | inert without SharedArrayBuffer |
| crossOriginIsolated | false | COOP/COEP headers not set on this origin |
| WebGL / WebGL2 / WebGPU | absent | `getContext('webgl')` and `('webgl2')` return null; `navigator.gpu` undefined |
| OffscreenCanvas | absent | |
| WebAudio, IndexedDB, ServiceWorker, WebRTC, WebCodecs | absent | `AudioContext`, `indexedDB`, `navigator.serviceWorker`, `RTCPeerConnection`, `VideoEncoder` all undefined |
| Geolocation, USB, Bluetooth, Gamepad, Notifications | absent | |
| Workers (classic and blob-URL) | **ok** | `new Worker(URL.createObjectURL(new Blob([...])))` constructs and accepts `postMessage` |
| CacheStorage | object present | `caches` exists |
| CompressionStream | present | |
| dynamic `import()` | ok | resolves a `data:text/javascript` module |
| ResizableArrayBuffer | ok | 16-byte buffer resized to 64 |
| Crypto | present | `crypto.subtle` |

The JIT row matters most: the fingerprint table above has claimed "Disabled (LLInt interpreter only)"
since the doc was written, but nothing in this repository measured it. It is now measured. Everything
that a page can reach here is interpreted, so bugs that require the optimising tiers (typer confusion,
speculation) are unreachable by construction, and the reachable classes narrow to the LLInt, the
parser and bytecode generator, the C++ runtime builtins, and WebCore's DOM/CSS.


### Crash oracle (p164, 2026-10-19)

`probes/phase13_webkit/p164-crash-oracle.js` turns a candidate payload into an unambiguous
survived-or-died reading. Each case is its own file, `p164-case-<name>.js`, loaded from `/raw/`
after a `V164-BEFORE-<name>` beacon; the loader's `onload` emits `V164-SURVIVED-<name>`. A thrown
exception still reaches `onload`, so a case that merely throws is reported as survived. Only a
memory-safety failure or a system kill ends the process between those two beacons, and the absence
of `SURVIVED` is the signal.

| case | expected log | purpose |
|---|---|---|
| `control` | BEFORE-control, SURVIVED-control, ORACLE-DONE | proves the pair is emitted |
| `oom` | BEFORE-oom, then nothing, plus the system memory toast | proves death is detectable |

Both legs are already demonstrated: the control case returned BEFORE->SURVIVED->ORACLE-DONE in 42 ms
in Chromium against this server, and the console's own 146 MB run shows the negative leg
(`CALLING` at 22:23:57.125, then silence and the out-of-memory toast).

The page also emits `V164-WATCHDOG-ALIVE` at 20 s, which separates a hung renderer from a dead one.

**Available APIs:** Workers, WebSocket, fetch, SubtleCrypto, Canvas 2D, ReadableStream, ResizableArrayBuffer, WeakRef, FinalizationRegistry, Proxy, BigInt, structuredClone

**Not available:** WebAssembly, SharedArrayBuffer, WebGL, WebAudio, IndexedDB, ServiceWorker

## Finding 1: Unpatched MetadataTable Integer Overflow (JSC Bug 317632)

`UnlinkedMetadataTable::finalize()` in JavaScriptCore uses an `unsigned` accumulator to sum metadata entry sizes. With 38,348,816 `op_call` sites at 112 bytes each:

```
38,348,816 × 112 = 4,295,067,392
uint32 wraps to 100,096
```

The allocator reserves ~100 KiB. The interpreter writes 4.29 GiB forward into heap memory.

**On-device results:**

| Probe | Test | Result |
|-------|------|--------|
| p141 | Overflow with stride=96 (wrong) | SIGSEGV — confirms OOB write occurs |
| p142 | Overflow with stride=112 (correct) | Overflow triggers |
| p143 | Targets placed before buffer | No corruption — sweep is forward only |
| p144 | Bait-and-switch heap groom | Forward write confirmed |
| p146 | Worker polls `.length` on target strings | All 14 report `.length` = 81400 — **RETRACTED as false positive**: 814-char literal × 100 = 81,400 (real length, no corruption) |

Scripts: `p142-heap-survive.js`, `p146-string-primary.js`

## Finding 2: Controlled Heap Corruption via Bait-and-Switch

The heap groom pattern from p146:

1. Main thread allocates 20 "bait" strings (~100 KiB each, Primary heap)
2. Worker allocates 14 "target" strings (~100 KiB each, same heap, higher addresses)
3. Free baits + GC pressure — metadata buffer takes a freed bait slot (first-fit)
4. Overflow sweep writes forward into target strings
5. Worker detects corruption via `.length` change and `charCodeAt()` scan

**On-device result (p146) — RETRACTED (2026-10-20):** the `.length = 81400` reports were the real string length, not corruption: the p146/p156 worker chunk literal is 814 characters, so the strings are 814 × 100 = 81,400 chars from birth and the `len !== 100000` check fires trivially. Definitive test: [V480 with loop-built 1000-char chunks reports 0 of 14 corrupted](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/analysis/false-positive-81400.md). The MetadataTable overflow itself stands (compile OK, call crash ~88s in); no string corruption is demonstrated.

## Finding 3: StringImpl Backing Data Stays Intact

**Probes:** p147, p148, p156

The overflow corrupts the JSString header (`m_fiber`), not the StringImpl character data.

| Probe | Test | Result |
|-------|------|--------|
| p147, p148 | Substring and main-thread views | StringImpl data intact, JSString.m_fiber corrupted |
| p156 | `charCodeAt` scan over intact-header strings | All return 0x41 within `[0, 100000)`; header-corrupt strings were only read 32 bytes deep |

**Impact (revised 2026-10-20):** there was no header corruption and no length-window change to analyze — the strings were 81,400 chars with 81,400 capacity. The earlier impact text and the length-window audit both analyzed the false positive.

The length value must exceed the real capacity before this becomes a read primitive; see [WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md) and probe `p161-length-window.js`.

Script: `p156-bait-switch.js`

## Finding 4: All Relapse WebKit Bugs Patched on 14.10

**Probe:** p160

Tested three independent Relapse WebKit exploit primitives:

| Bug | Technique | Result |
|-----|-----------|--------|
| Scope object leak | `super.foo` + Proxy receiver | `receiver === undefined` — **patched** |
| Symbol.toString disclosure | Large string with heap pointers | Length mismatch — **patched** |
| structuredClone type confusion | `history.replaceState` graph | No type confusion — **patched** |

Combined with the Lua-side results in this repo (AF_ROUTE KASLR probe 43o, AIO bypass probe 43p), the Relapse chain is dead on 14.10 across both entry vectors.

Script: `p160-relapse-test.js`

## Finding 5: A Popup Request Kills the Console's WebProcess

**Probes:** p169 (`p169-tap-popup.js`), p170 (`p170-stage-ladder.js`), p171
(`p171-popup-paths.js`)

The console's browser is fatal to popup requests, and the popup blocker's refusal is not the only
fatal path. `window.open` is refused and the WebProcess dies a few tens of milliseconds after the
page beacons the refusal. A `<a target="_blank">` click that really produces a new window kills it
too: the server serves the popup document, and nothing the page schedules afterwards ever runs.
What the new context does with the document does not matter: a popup that runs no script, one that
runs script but never messages its opener, and one that loads no document at all are all fatal. The
one popup request that does not kill is the one a sandboxed frame refuses before the popup blocker
is consulted. The console keeps running in every case: the guide can be reopened, and the system's
own network activity continues.

| run | context | markers | outcome |
|---|---|---|---|
| 08:12:10 | top-level `window.open`, real controller tap | `TAP` -> `PRE-OPEN-1` -> `POPUP-BLOCKED-1` | death ~65 ms after the refusal |
| 08:15:32 | top-level `window.open`, no tap (`?auto=1`) | `AUTO` -> `PRE-OPEN-1` -> `POPUP-BLOCKED-1` | death ~45 ms after the refusal |
| 08:20:28 | `window.open` inside a child frame | `IFRAME-POPUP-FRAME-LOADED` -> `IFRAME-POPUP-REFUSED` | death, no later marker |
| 08:57:50 | `window.open` inside a `sandbox="allow-scripts"` frame | `SANDBOX-RESULT-BLOCKED` -> `SANDBOX-ALIVE` -> `NEXT-LINK` | survives; the sandbox refuses before the popup blocker |
| 08:57:51 | `<a target="_blank">` click | `LINK-START`, popup document `200` at +0.113 s, popup script `200` at +0.266 s, no child message | death, no later marker |
| 09:04:24 | the same link click, after a guide reload | `LINK-START`, popup document `200` at +0.097 s, no popup script, no child message | death, no later marker |
| 09:37:30 | link to `/blank.html`, a document with no script | `STATIC-START`, popup document `200` at +0.168 s | death, no later marker |
| 09:39:07 | link to the probe in `?child=2`, script but no opener message | `SILENT-START`, popup document `200` at +0.092 s, popup script `200` at +0.239 s | death, no later marker |
| 09:43:38 | link to `about:blank`, a window that loads no document | `BLANK-START`, no server request - there is nothing to fetch | death, no later marker |

The user gesture is irrelevant: the console refuses the popup with a real tap as well, and the
p170 stage ladder shows the three preceding stages survive with their liveness markers intact
(`BASE-ALIVE`, `IFRAME-ALIVE`, `NESTED-ALIVE` at 4 s each) while the refusal stage kills the
process. So a bare page, one child frame, a frame inside a frame and twenty frames created and
removed in a row are all safe on the console.

p171 walks the request paths one at a time, and its chain stops at the first death. The sandbox row
is the control that keeps the result from reading as "the console dies when asked for a window": a
frame with `sandbox="allow-scripts"` and no `allow-popups` refuses the request itself, the page
beacons that refusal, stays alive and starts the next variant. The LINK rows then show the popup
blocker is not the trigger either. The click produced a real navigation request for
`/probe/p171-popup-paths.js?child=1`, the server served it, and in the 08:57 run it served the
popup's own script as well; after that the WebProcess stops and the page's 2.5 s
`LINK-RESULT-REQUESTED` timer never fires. That the popup really opened is read from the server's
access log, not from the child: both LINK popups died with their opener, so neither the opener
message nor any child marker arrived.

The STATIC and SILENT rows close the "it is the script" reading. STATIC served a popup document
that runs nothing at all and SILENT served the probe's `?child=2` mode, which runs script but never
touches the opener; both died at the same place as LINK, with no `<LABEL>-RESULT-REQUESTED` timer
and no child message. So neither the child's script nor its opener handshake is required.

BLANK closes the question. Its popup needs no server at all, so there is no fetch to read: the page
beacons `BLANK-START`, and the `<LABEL>-RESULT-REQUESTED` marker it would have sent 2.5 s later never
arrives. A window that loads nothing is as fatal as one that loads a script-free document, so the
death precedes the load - asking for a new top-level browsing context is already enough. The only
survivor remains the sandbox refusal, which never reaches the popup blocker; the blocker's own
refusal is fatal (p169). So the fatal step is the new-context request itself, not the window that
appears from it.

**Consequence for the upstream corpus.** The harvested case
`fast/scrolling/mac/event-dispatcher-timer-close-crash.html` is not testable on the console. Its
upstream fix is a use-after-free of `RemoteLayerTreeEventDispatcher`'s `RunLoop::Timer` on the
scrolling thread, and it needs a real popup window to arm the display-link observer. The console
either refuses the popup or kills the WebProcess shortly after the window is created, so the case
never reaches the code the test exercises either way. The corpus runner therefore stubs
`window.open` for the cases that use it (two of the 124), and the stub announces itself with a
`V166-POPUP-STUB` beacon so an altered case is never counted as an unmodified pass.

**What is not established.** The mechanism inside WebKit is unknown. The guide browser has no
inspector and no debugger can be attached, and the failure does not reproduce in desktop Chromium
155, which opens popups freely in headless mode, so neither the refusal nor the creation path is
entered there. What is established is the trigger and the effect: a popup request that reaches the
browser's window handling ends the WebProcess, whether it is refused or served. The popup that was
served ran as a separate browsing context, but whether it ran in the same process, and whether it
reached its script before the death, is not established — the 08:57 run fetched the popup's script
and the 09:04 run did not, and neither returned a marker. As recorded it is a denial of service
against the guide, not a controlled memory-safety primitive, and nothing here shows that it is
exploitable.

## Entry Method

The PS5 browser is reachable without hardware modification:

1. Run a DNS/HTTPS server on the local network
2. Point PS5 DNS settings to the server
3. Open Settings → User's Guide on the PS5
4. PS5 browser loads the exploit page from the redirected domain

No jailbroken PS4, no save file chain, no game purchase required. Probes communicate via HTTP beacon callbacks (XHR GET/POST) to the host server.

## Current Status

Snapshot status below; the [source repository](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) is authoritative for current progress.

| Stage | Status |
|-------|--------|
| Bug identification | Done |
| Trigger on device | Done |
| Heap grooming | Done |
| JSString corruption | Done |
| Data extraction (ASLR leak) | Not started — the 81400 "corruption" was a false positive (see Finding 2); no corruption primitive is demonstrated |
| Arbitrary read/write | Not started |

## Updates Since This Snapshot (2026-10-19)

- **p156 "reproduction" on a second console — same false positive (corrected 2026-10-20):** the 14/14 `.length` = 81400 reports were the literal string length (814-char chunk × 100), not corruption. The OOM-death-vs-beacon-ordering data from that console's 17 runs remains valid ([issue #6](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/issues/6)).
- **p160 (Relapse primitives) also confirmed dead on the second console** — independent reproduction of our PR #32 result (54/54, scope receiver `undefined`).
- **New best lead: CVE-2026-43715 (CSSFontFace UAF)** — source-verified against WK-1400 (`iterateClients()` re-entrant client removal via a `FontFace.prototype.then` getter), patched upstream, unpatched on PS5 14.10. Device test deployed, awaiting crash confirmation. Not blocked by the JS builtin wall that limits the stream-based bugs.
- **Kernel audit published** (their [KERNEL_AUDIT.md](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/docs/KERNEL_AUDIT.md)): Tier-1 candidates CVE-2026-7270 (assessed in this repo), CVE-2026-45251 (poll/select UAF, not yet assessed here), and CVE-2024-43102 (umtx — patch status reopened by our PR #41: `_umtx_op` is 454 and alive; earlier "umtx" tests hit 557).
- **Length-window audit** ([WEBKIT_LENGTH_WINDOW_AUDIT.md](WEBKIT_LENGTH_WINDOW_AUDIT.md)) — analyzed the false positive; its capacity question dissolves. The p161 probe it inspired remains correct (PR #43 fixed its blob construction) and now tests whether the correct-strings groom corrupts at all.

## Attribution

Research by [@Arn0Stride7](https://x.com/Arn0Stride7). Built with Claude Opus 4.6, GPT-6.1-Sol, DeepSeek v4.1-Flash, and other models. Full credits in the source repository.

## Finding 108: The shipped WorkerThread keeps pre-fix proxy references, but the guard makes them unreachable (probes poc-worker.html, wk_storm.js, 2026-10-26)

`Source/WebCore/workers/WorkerThread.h:139-142` in `WebKit_1400.zip` still declares
`WorkerLoaderProxy&`, `WorkerDebuggerProxy&`, `WorkerReportingProxy&` and
`WorkerBadgeProxy&`, the exact shape upstream replaced with raw pointers plus
`clearProxies()` in `926054f254` (bug 264222, 2023-12-20). That fix's crash was
`createCacheStorageConnection()` on the stale `WorkerLoaderProxy`:

```cpp
if (!workerThread->runLoop().terminated())
    mainThreadConnection = workerThread->workerLoaderProxy().createCacheStorageConnection();
```

On this build the `runLoop().terminated()` test is what keeps it safe. Measured:

| arm | setup | result |
|---|---|---|
| env | blob-URL worker | never runs (no beacon at all) |
| env | `/raw/wk_storm.js` worker | runs: `caches=object`, `navigator.storage/permissions=undefined` |
| `caches` | `caches.open()` in a worker, 900 ms window | promise never settles, no throw: the call hangs before the connection is built |
| fetch | 2 / 10 / 50 ms `terminate()` during a fetch storm | 200 page cycles, ~16,000 workers, zero deaths |
| nav | 10 workers storming, page navigates 120 ms later | 4 fleets, zero deaths |

So the stale reference is real in source but `Worker::terminate()` stops the run
loop before the proxy is freed, and the one call site that would bypass the check
(`WorkerThreadableLoader`'s `WorkerLoaderProxy& m_loaderProxy`) has its main-thread
tasks cancelled as part of the same stop. Recorded as unreachable rather than fixed.

## Finding 109: `WebSocket` exists but every connection fails before it reaches the server (2026-10-26)

The `caps` page reports `websocket=1` (the binding exists, `WebSocketEnabled` in
`UnifiedWebPreferences.yaml:7837` defaults to true and has no PlayStation override), but
on this build a WebSocket cannot be opened at all:

| test (probe `poc-wsdiag.js`) | result |
|---|---|
| `XMLHttpRequest('GET /ws?probe=1')` same origin | `400` from our server - the route is reachable |
| `new WebSocket('wss://' + location.host + '/ws')` | `onerror` in about 340 ms, **no request reaches the server** |
| `new WebSocket('wss://manuals.playstation.net/ws')` | `onerror`, no request |
| `new WebSocket('ws://' + location.host + '/ws')` (port 443) | `onerror`, no request |

`tools/webkit_server.py` logs every request it accepts and has a `/ws` route with a
working 101 handshake (the RFC 6455 accept vector verifies locally), so the absence of a
`GET /ws` line means the connection is refused inside the browser before any TCP
handshake - not by our TLS certificate and not by the port. A `wss` client on 8443 gets
the same outcome, and the earlier `unknown ca` alert from the standalone server only
confirms that non-443 ports never reach the certificate check.

Consequence: the frame parser and the `permessage-deflate` inflater are present in the
source but not reachable from the guide, so the 20-case mat in `tools/ws_cases.py` cannot
be driven from this firmware's browser. Any WebSocket work here is dead until a different
host (not the User's Guide) can run the page.

## 13. The FontFaceSet weak-wrapper window opens on 14.10 and does not fault here

Issue #155 describes a use-after-free in `FontFaceSet::load()`: the faces are collected
as `Vector<std::reference_wrapper<CSSFontFace>>` (`Source/WebCore/css/CSSFontFaceSet.cpp`,
`matchingFacesExcludingPreinstalledFonts`), the vector is iterated, and any `then` getter
on `FontFace.prototype` runs synchronously inside the loop - so a getter that removes the
victim stylesheet frees a `CSSFontFace` the loop is still holding. The published trigger
page uses the **dual-family** call `document.fonts.load('1em a, x','AB')`; a single-family
call never reaches that path, which is why an earlier page of ours (`ff155.html`) saw
nothing.

Replayed verbatim on 14.10 (page `ff155y.html`, capture
`results/webkit/server_20261029_100443.log`):

| beacon | time |
|---|---|
| `F155Y-PARSE` → `START` → `SETUP` → `CALL-LOAD` | 10:22:48.896 → .978 |
| `GETTER-ENTER` → `STYLE-REMOVED` → `LAYOUT-DONE` → `SPRAYED` | 10:22:49.078 → .365 |
| `CHECK-true` | 10:22:49.399 |
| `GETTER-RETURN` → `RESOLVED` | 10:22:49.435 → .470 |
| `FORCE-PRE` → `FORCE-POST-h21` | 10:22:49.575 → .614 |

So the window is real and the getter runs inside the load: after the victim stylesheet is
removed, `document.fonts.check('1em x')` still reports the face as present, and the load
promise still resolves and lays out at height 21. **No fault, no kill** - where the
14.10 bench in #155 reports 17/17 deaths immediately after `GETTER_RETURN`.

Two readings remain open: either the reclaimed object's contents are benign (the same
result lunarshe11 measured on 14.00 with a NUL fill), or the `CSSFontFace` is not actually
released on this path. The discriminating run is a **hostile spray**: fill the whole
256-byte reclaim buffer with `0x4141` (`ff155z.html`) instead of NULs with one marker.
If the engine reads a vtable or a pointer out of the freed object, the fill turns it into
`0x4141414141414141`; if it survives that too, nothing is dereferencing the freed slot and
the #155 crash needs a different trigger than the one published.

### 13a. `document.fonts.check()` is not an oracle here

`ff155w.html` (capture in `results/webkit/server_20261029_100443.log`, 10:25:52):

| phase | state | result |
|---|---|---|
| `P1` | family `x` **never defined at all** | `check('1em x')` = **true** |
| `P2` | `@font-face x` present | true |
| `P3` | stylesheet removed, outside any load | true |
| `P4` | removed inside the load getter | true, then `RESOLVED` |

So `check()` answers true for a family that does not exist on this build - it is
reporting "the string can be rendered", and the default-font fallback satisfies
that. The `CHECK=true` observation in issue #155 therefore carries no information
about a fake font object: it is the default answer, with or without a spray, with
or without a dangling `CSSFontFace`.

Combined with the two trigger runs (`ff155y`, `ff155z`, both NUL-marked and
`0x4141` fills, both surviving to `RESOLVED` and `h=21`), the published #155
sequence does not fault on 14.10 here, and its central piece of evidence does not
distinguish the claimed state from an empty one. `CSSFontFace` is
`WTF_MAKE_FAST_ALLOCATED_WITH_HEAP_IDENTIFIER` (an IsoHeap cell), which JS strings
cannot reclaim, so the "spray turns a string into a font" mechanism has no
allocator route even if the reference does dangle.

### 13b. Reclaim attempts on 14.10: the spray suppresses the death, and the fill does not matter

Every arm uses the same working trigger (the `ff155y` shape: `FontFace('a','local(Helvetica)',
{unicodeRange:'U+0041'})` primed with `void A.loaded`, a `<style id=victim-style>` with
`@font-face x`, a `then` getter that removes the stylesheet, calls
`document.fonts.delete(this)`, forces layout, sprays, and returns `undefined`), with a
120 ms layout force on `font-family: x` after the call.

| arm | getter fires | `fonts.delete` | spray (128 UTF-16 units = 256 B) | outcome |
|---|---|---|---|---|
| `ff155y` | yes | no | 2000 strings, NUL + `\u4141` at unit 64 | survived, `RESOLVED`, `h=21` |
| `ff155z` | yes | no | 2000 strings, all `\u4141` | survived, `h=21` |
| `ff155v` | yes | yes (`size` 1 -> 0) | 2000 strings, all NUL | survived, `h=21` |
| `ff155u` | yes | yes | 2000 strings, `\u4141` at units 64-65 (bytes 128..131 = `0x41…41`) | survived, `h=21` |

Read with Finding 12's numbers (without a spray the same trigger dies 4/5; with a 1000-rule
`@font-face` spray it survives 20/20), the spray arms all sit in the "suppressed" regime, and
placing a recognisable pointer at byte 128 makes no difference: nothing dereferences our fill.
So on 14.10 the observable either does not reclaim the freed cell with JS strings, or the layout
path never reads that offset. #155's phase 3 does not transfer as stated.

### 13c. The 14.10 death is a timing race in `load()`, not a reclaimable use-after-free

| arm | `fonts.delete` | getter work | outcome |
|---|---|---|---|
| `ff155n` | yes | nothing (returns immediately) | died, `GETTER-RETURN` last beacon |
| `ff155t` | yes | one 256 B string | died, same |
| `ff155u` | yes | 2000 strings, `0x41` at bytes 128..131 | survived, `h=21` |
| `ff155q` | yes | 2000 strings, **every** byte `0x41` | survived, `h=21` |
| `ff155r` | yes | 2000 strings allocated **before** the trigger | died, same |
| `ff155o` | yes | **3 ms spin, zero allocation** | survived, `h=21` |

`ff155q` should have been decisive and was not: if a sprayed string had taken the freed
`CSSFontFace`, every pointer-shaped field would be `0x4141414141414141` and the engine would
fault on first use. It survived. `ff155r` then removed allocator state as the cause (pre-filling
the free list before the trigger changes nothing), and `ff155o` closed it: **3 ms of pure CPU in
the getter, with no allocation at all, is enough to prevent the death**.

So the observable on 14.10 is a window that closes with the getter's duration - the promise
continuation races the client that `document.fonts.delete(this)` removed - not a freed object
being read. Contents never mattered (`u` and `v` behave identically; `q` with all-`0x41` behaves
like all-zero), which is what a timing race predicts and what a type confusion cannot.
Issue #155's phases 3-4 (string spray, byte 128 as a pointer) do not transfer to 14.10.


## 13d. The reclaim arms are not reproducible; no reclaim control is established (2026-10-29)

The arm table in 13b and the position bisect were both built on single runs, and the
same page does not repeat.

- `ff155rate.html` (no spray, ten triggers per load): died at iteration 0 in **3/3**
  loads, last beacon `RATE-0-LAY`. The no-spray death is stable.
- `ff155one.html` (one 274-byte 16-bit string per trigger, poison at units 0-1):
  died at iteration 0 in **3/3** loads, last beacon `SD-0-LAY`.
- `ff155cnt.html` (spray count 1, 2, 3 ... per trigger): iteration 0 - the same single
  string as `ff155one` iteration 0 - **survived**, and the load died on the
  three-string iteration.

So an identical arm produced both outcomes on different page loads, while the
no-spray arm and the one-string arm each produced a clean 3/3. Every earlier
single-run survivor (`ff155e/i/j/k/l/n2/o2/q/s/u/y2/c`) is therefore one sample of an
unknown distribution and cannot be read as "this content suppresses the death".

What is established: the trigger (Finding 12) frees a live `CSSFontFace` and the
WebProcess dies deterministically when nothing is allocated in the `then` getter.
What is not established: that any sprayed string ever occupies the freed cell, that
the death moves to a different site depending on our bytes, or that the byte at any
offset is read from our data. Without a crash address, an allocator probe, or a heap
leak in the WebProcess, those questions cannot be answered from JavaScript, and no
reclaim primitive can be claimed.

### 13d addendum: the 2000-string arm dies as well (2026-10-29)

`ff155big.html` - ten triggers per load, 2000 x 274-byte strings per getter - died at
`FB-0-LAY` on its first load, i.e. the arm that was the only reproducible survivor
(`ff155q`, `ff155v`, `ff155u`, all single samples) is not repeatable either. With no
spray 3/3, one string 6/6, 2000 strings 1/1, the honest reading is that this trigger
kills the WebProcess under every allocation we have tried, that all twelve earlier
"survivors" were single samples of an unlucky minority, and that no reclamation of the
freed `CSSFontFace` has ever been demonstrated on 14.10.

### 13d addendum 2: the first trigger is safe, the second is fatal, and bytes never matter

`ff155q.html` survived 2/2 (getter: remove, delete, layout, 2000 x 274-byte 16-bit
strings, `check('1em x')`, return). Two ladders - `ff155delay` (stall 12 ms then 11 ms)
and `ff155delay2` (stall 20 ms then 18 ms) - survived their **iteration 0** and died at
**iteration 1** in both cases, so the stall length is irrelevant and the ordinal of the
trigger is what changes the outcome. `ff155d3` repeated the experiment with the second
trigger spraying 2000 all-NUL strings instead of `0x4141`: it died at the same point
(`RET`), so the payload content is not the variable either.

Net: the trigger is safe exactly once per page load when it allocates, fatal on the
second use regardless of stall, size or content. Nothing we have sprayed - zeros,
`0x41`, 128- or 274-byte, one or two thousand - has ever changed the outcome, so no
reclamation of the freed `CSSFontFace` has been demonstrated, and with no crash address
and no allocator probe in JS there is no way to observe the reuse from the page.

## 13e. A controlled occupancy test: same-type allocation shifts the death and never gets written to (2026-10-29)

The `13d` arms varied the fill, the size class and the timing. The parametrized pages
below vary one thing at a time and always use the same trigger: a JS-added
`FontFace('a', 'local("Helvetica")', {unicodeRange:'U+0041'})`, a style rule for
family `x` with `unicode-range: U+0042`, `document.fonts.load('1em a, x', 'AB')`, and a
`FontFace.prototype.then` getter that removes the style and calls
`document.fonts.delete(this)` while the promise is being resolved. Every beacon is a
synchronous XMLHttpRequest inside the measured window, so the beacon count itself is
part of the allocation history.

| page | variation | outcome |
|---|---|---|
| `par3` | five in-page trials, no allocation | trials 0-2 resolve, **trial 3 dies after the getter returns** (2/2 identical) |
| `par7` | + 2000 x 274-byte `ArrayBuffer`s after each resolution (6000 held by trial 3) | dies at trial 3, unchanged |
| `par8` | getter reduced to six no-op beacons, no DOM work | **all five trials complete** |
| `par10` | `check()` moved out of the getter into the callback | dies at trial 3 - `check()` is irrelevant |
| `par11` | per-trial string sprays of length 40/45/56/60/80/96/128 | dies at trial 3, every class |
| `par12` | 400 fresh `FontFace` objects allocated inside the getter | **first trigger hangs** at `LOAD-CALLED`, no dialog |
| `par13` | one canary `FontFace` per trial, `family` read after resolution | trial 0 completes with `FAM-CANARY`, trial 1 **dies at the getter return** |

What this establishes:

- the death needs the DOM mutations (`par8`); it does not need `check()` (`par10`);
- neither fill, size class, timing, nor result-vector allocation changes the outcome
  (`par5`, `par7`, `par11`);
- allocating the same type does change the outcome (`par12` hangs, `par13` moves the
  death from the fourth trigger to the second), so the allocation order is part of the
  bug's state;
- the canary is never written: `family` still reads `CANARY` after the resolution, so no
  stale access to it is observed from JS.

Conclusion: the trigger is a deterministic-per-page renderer crash whose point moves with
heap layout, not a reclaimable use-after-free we can steer. Same-type allocation is the
only lever that moves it, and it produces a hang or an earlier crash rather than control.
There is no memory-disclosure or write primitive available from the page, so the line is
closed as a crash bug and not pursued further without a crash address or an allocator
probe that JS cannot provide.

## 13f. The upstream fix for this bug identifies the exact path; 14.10 is unpatched and the crash is real, but the reuse is the engine's own (2026-10-29)

The bug family is upstream WebKit **bug 312202**, fixed by commit
`5f0480f771ba1749663a8257eafca70af17b7cec` — *"Use-after-free in
`CSSFontFace::setStatus` and `CSSFontFace::pump`"*, cherry-picked to
`safari-7624-branch`. The fix replaces `std::reference_wrapper` with `Ref` in the
return value of `CSSFontFaceSet::matchingFacesExcludingPreinstalledFonts` and in the
locals of `FontFaceSet::load`. The 14.10 tree (`WebKit_1400`, `Configurations/Version.xcconfig`
= 616.1.27.211.1) still contains the `reference_wrapper` signature, so the firmware
**carries the vulnerable code**. Its regression test,
`LayoutTests/fast/text/fontface-setstatus-crash.html`, also gives the correct trigger
shape, which none of the pages in 13a-13e used:

- the JS face and the CSS face must share the **same family** so one
  `document.fonts.load('1em x', 'AB')` matches both into a single `matchingFaces` vector;
- the CSS source must be a **`url(...)`** so that face stays `Loading` while the JS
  `local()` face resolves synchronously *inside* `for (auto& face : matchingFaces) face.get().load();`;
- the free is `document.getElementById('s').sheet.deleteRule(0)` and the getter is gated
  on `this === A`.

Runs (`results/webkit/corpus/v156.html`-`v160.html`, server log
`results/webkit/server_20261029_100443.log`):

| page | variation | outcome |
|---|---|---|
| `v156` | upstream test verbatim + beacons, CSS source `/slowfont/?ms=5000` | getter fires inside `load()` (`V-GETTER-A → V-ALLOC → V-RULE-DELETED → V-LAYOUT → V-LOAD-RET`), survives |
| `v157` | + 4000 x 255-char `'A'` spray in the getter, before the layout force | survives to `V-TIMEOUT-ALIVE` |
| `v158` | no in-getter spray, spray at +1 s, beacon at +6 s | **dies right after `V-LAYOUT`**, inside `load()`, before `V-LOAD-RET` |
| `v159` | `A` added before the `<style>` is created (face first in the vector), spray in the getter | survives through +6 s |
| `v160` | status readback of both resolved faces with a 288-class zero spray | `FACE0-st-loaded`, `FACE1-st-loaded` — the style face's backing is **not** our bytes |

The second-trigger crash is the one reproducible death: `par33`/`par36` (eight trials, no
allocation at all) die after `TR1-RET`, three times out of three, and `par34`/`par37`
(same page plus a 4000 x 255-char pre-spray *between* trials) survive all trials, twice
out of two.

What this establishes, and what it does not:

- the vulnerable code path is present, reachable from a plain page load, and produces a
  renderer death at the point the fix describes;
- the death is allocation-sensitive (0/1 without a pre-spray, 2/2 with one), which is what
  a freed `CSSFontFace` being reused by the engine's **own** next allocation looks like;
- it is not steerable from JS: a uniform `'A'` fill and an all-NUL fill in the 288-byte
  class both survived, and the status readback never observed our bytes in the freed
  object. Without a controlled occupant at that class at that moment there is no field
  control, no cast, and no primitive — only "the engine reuses its own hole or the
  renderer dies".

Practical consequence: closing this needs an allocator-visible occupant (or a crash
address), neither of which the page can provide. The finding is recorded as a
vulnerability-presence result for 14.10, not as an exploitation path.

### 13f addendum: the suppression is allocation-shaped, not occupancy-shaped (2026-10-29)

Follow-up runs on the same second-trigger page:

| page | allocation between trials | outcome |
|---|---|---|
| `par33` / `par36` | none | dies after `TR1-RET` (3/3) |
| `par37` | 4000 x 255-char NUL, then 4000 x 255-char `'A'` | survives (2/2) |
| `par40` | 4002 attacker-authored `@font-face` rules (engine-created `CSSFontFace` objects) | **dies** |
| `par41` | exactly **one** 255-char string | survives |
| `par42` | exactly **one** 170-char string | survives |
| `par39` | 4000 x 255-char NUL, then `vec0[1].status` | `loaded` — the held wrapper's `Ref` keeps the backing alive, so a held vector cannot observe the free |

Volume is not the variable and the size class is not the variable: one allocation of either
class suppresses, while 4002 same-type engine objects do not. That is a timing/heap-state
effect, not an occupant we control. Combined with `v157`/`v159` (in-window spray with `'A'`
or NULs never turns into a fault, and `par24`'s scan never observes an engine write into a
string), the post-free access on this path is scalar-only: there is no pointer read that our
bytes could steer, and no refcount write that could be observed. Without a second bug (type
confusion) or an address leak, this cannot be converted into control.

### 13g: the crash is structural, and it is not ours (2026-10-29)

A real-font source replaced the never-completing `local()` face, which removed the OOM
that had been masquerading as the bug (`par45`: no CSS face at all, eight trials complete).
With `/realfont/?ms=300` serving a genuine `arial.ttf`:

| page | change | outcome |
|---|---|---|
| `par46` | real font, no spray | trial 0 reaches `LOAD-CALLED`, promise never settles |
| `par49` | ten timed trials, 288-class spray in the getter | dies at trial 1 |
| `par50` | same, 96-class spray | dies at trial 1 |
| `par51` | same, **no spray** | dies at trial 1 |
| `par52` | spray moved after the layout force (after the recalc that frees the face) | dies at trial 1 |
| `par53` | `document.fonts.delete` removed | dies, at trial 3 |
| `par54`/`par58` | 160-class spray after recalc / in the inter-trial gap | dies at trial 1 |
| `par55` | single trial | completes |
| `par56` | single trial + 3 s of watcher beacons | completes; nothing touches the freed face |
| `par57` | two trials 3 s apart | completes |
| `par59` | cache-busting font URL per trial | dies at trial 1 |

Every payload variant - size class, fill byte, placement inside the getter, placement
between trials, cache state - leaves the death unchanged, and a single trial never dies.
The fatal access is therefore engine-internal: it needs a second trial inside the same
document and within ~400 ms of the first, and no allocation we can make from JS reaches it.
There is no address oracle on the console (the WebProcess is replaced by the memory dialog),
so occupancy cannot be confirmed even if it were achieved.

`par60` closes the mechanism question: with the style removal scoped to **trial 0 only**,
all ten trials complete (`TR9-LOAD-CALLED`, `TR-DONE-all`). No payload, no cache state, no
delayed callback touches the freed face of trial 0. The fatal access requires the removal of
a *later* trial, i.e. two removals of style-connected font faces in one document while a
font load is pending. That is a two-trigger engine bug, reachable from a plain page, and it
is exactly the shape Sony's 14.10 build still has (`reference_wrapper` in
`matchingFacesExcludingPreinstalledFonts`).

Control runs that bound the trigger (2026-10-29, all on the 14.10 console):

| page | request state at removal | removals | outcome |
|---|---|---|---|
| `par55`/`par56` | in flight | one | completes, three seconds of watcher beacons clean |
| `par60` | in flight (trial 0 only) | one | ten trials complete |
| `par61` | `local(NonexistentFont)`, resolves to Failure | two | completes (`TR1-REJECTED`) |
| `par63` | `url(/slowfont/?ms=0)`, fails immediately | two | completes (`TR1-REJECTED`) |
| `par51` | `url(/realfont/?ms=300)`, in flight | two | dies at trial 1 |

So the crash needs a request that is still **in flight** at the moment its style is removed,
twice in one document. A failed or completed load never produces it.

The window is not addressable from JavaScript: the getter is the last JS that runs before
`FontFaceSet::load()` re-enters its loop, and no microtask, timer or XHR can execute between
the removal's style recalculation and the loop's next access to the same face. Every arm that
placed an occupant before the getter returned, after it, or between trials produced the
identical crash, which is what that structural limit predicts.

#### The occupant is real, and its bytes are consumed as an address (2026-10-29)

With the trigger fixed (two removals, font in flight) and the spray placed after the
recalculation in the 192-byte class:

| page | occupant content | result |
|---|---|---|
| `par65` | none | dies at trial 1 |
| `par64`, `par66` | 2000 x 175-char NUL (192 class) | **survives**, twice; `LEN-bad0` - no writes into any string |
| `par67` | same, filled `0x41` | **dies at trial 1** |
| `par68` | NUL fill with `0x41` x 8 at object offset **80** | **dies at trial 1** |

Offset 80 is where the member layout puts `WeakPtr<FontFace> m_wrapper`, the field
`FontFaceSet::load()` reads through `face.get().existingWrapper()`. The engine therefore takes
a qword out of our string and dereferences it: attacker-controlled bytes at a known object
offset, consumed as a pointer, inside the WebProcess.

That is a controlled-dereference primitive. Turning it into code execution needs a valid
address to place there - a leak in the WebProcess address space - and no leak has been found
on this surface yet. Zeros (the NUL build) leave the wrapper null, which is why the page
survives instead of crashing.

#### Canvas readback on this build (2026-10-29)

`canvas` works when it is **not** attached to the document: `getContext('2d')` returns null
once the element is appended (`leak2`, `leak4`), `fillRect` + `getImageData` returns the exact
pixel (`255,0,0,255`, `leak7`), `toDataURL` produces a real PNG, and `drawImage` of a PNG and
of an inline SVG paints correctly (`leak8`, 1024 painted pixels each). A 1024x768 BMP loads
with the right dimensions but contributes **zero** pixels (`leak6`), so the BMP path in this
build does not hand data to the canvas.

Consequence: canvas readback is a usable observation channel for filter and decoder work, but
nothing it has produced so far exposes uninitialised bytes: fresh typed arrays, `DataView`,
`ImageData`, `TextDecoder` invalid sequences, and truncated HTTP bodies all come back zeroed or
error out (`L5-ERR-status0`).

#### Leak sweep: twenty surfaces, no disclosure (2026-10-29)

The offset-80 dereference needs one WebProcess address to aim at, so the surface was swept
for a JS-reachable disclosure with a single-page harness (`results/webkit/corpus/suite1.html`,
`suite2.html`, local-only) that churns the 175-character string class before each readback:

| surface | result |
|---|---|
| `Uint8Array`, `Float64Array`, `DataView`, `ImageData`, `createImageData` | zeroed |
| cleared canvas, `ctx.filter` blur, shadow blur, `copy` composite | zeroed |
| PNG upscale, pattern fill, glyph rasterisation | painted uniformly, no stray bytes |
| truncated HTTP body (`Content-Length` > bytes sent) | `status 0` error, no buffer |
| `TextDecoder` invalid sequences, `Intl.DateTimeFormat`, `String.normalize` | clean |
| SVG filter fed by a valid image, and by a 404 | draws nothing at all on this build |
| `ReadableStream` BYOB reader | `getReader({mode:'byob'})` throws `TypeError` |
| `OffscreenCanvas`, `WebAssembly` | absent |

No surface handed engine memory to JS. The UAF therefore remains a controlled dereference
with no address source, and is recorded as such rather than as an exploitable primitive.

#### A present, deterministic grid abort (2026-10-29)

Upstream commit `228b9ba219` (2025-05-22, bug 293392) fixes a crash when a subgrid acquires a
line-name list (`subgrid [a] [b] [c]`) after a child was removed, because item placement on the
parent is skipped and a stale position is used during the next layout. The fix's regression test
`LayoutTests/fast/css-grid-layout/subgrid-with-line-name-list-crash.html` is **not** in the 14.10
tree, and 4 of the 8 pre-fix lines are still present in `Source/WebCore/rendering/RenderBox.cpp`.

`results/webkit/corpus/grid1.html` reproduces it: beacons print `G-START`, `G-SUBGRID-yes`,
`G-LAYOUT1`, `G-REMOVED`, `G-STYLED`, and the WebProcess dies on the following
`document.body.offsetHeight` (the console shows "There is not enough free system memory").

The fault is not memory corruption. `GridTrackSizingAlgorithm::copyUsedTrackSizesForSubgrid()`
in `Source/WebCore/rendering/GridTrackSizingAlgorithm.cpp` guards the copy with

```cpp
RELEASE_ASSERT((parentTracks.size() - 1) >= (numTracks - 1 + span.startLine()));
for (int i = 0; i < numTracks; i++)
    allTracks[i] = parentTracks[i + span.startLine()];
```

so the stale span trips the release assertion and aborts the process. `RELEASE_ASSERT` is always
compiled in, so the abort is deterministic and independent of heap state. This is a denial of
service (a page can kill the WebProcess on demand), not a read/write primitive, and is recorded
for completeness rather than pursued.

## 14. Unfixed WebKit UAFs on 14.10 are all second-stage only

Method: `.local/crashscan2.py` samples WebKit commits 2023-07-01..2026-10-29 that add a
`LayoutTests/**/*crash*` page, keeps the ones whose test file is absent from the 14.10 tree,
then measures how much of each commit's removed `Source/` code is still present verbatim in
`WebKit_1400.zip`. A ratio of 1.0 means the pre-fix code is what 14.10 ships.

Absent fixes whose pre-fix code is fully present (r=1.0), all reachable from a plain page:

| commit | defect | first stage? |
|---|---|---|
| `ebc83b8568` | `CachedLiveNodeList` gates deregistration on a WeakPtr-derived `hasValidCache()`, so `input.labels` after its `<label>` is collected leaves a freed list in `Document::m_listsInvalidatedAtDocument`; the next invalidation calls `invalidateCacheForDocument()` on freed memory | no - virtual call on a freed object |
| `0bab5af95d` | `ManualSlotAssignment::slotManualAssignmentDidChange` keeps a raw pointer into `m_slots` across a re-entrant `WeakHashMap` rehash (the layout-corpus `named-slot-assignment-…-crash` hang) | no - reads a freed bucket array |
| `eb617fc289` | `SVGAnimatedValueProperty::stopAnimation` drops `m_animVal` without `detach()`; a script-held `SVGAnimatedLength.animVal` keeps a dangling `m_owner`, and `len.value` calls `m_owner->attributeContextElement()` through it | no - virtual call on a freed object |
| `be08720593` | `DataListButtonElement::defaultEventHandler` UAF | no - same class |
| `9c6099bea0` | observed nodes collected during `MutationObserver` delivery | no - same class |

Each is a control-flow primitive that needs a valid address to place at the freed object's
offset 0. None reads attacker-visible data out of freed memory, so none is a first-stage
ASLR oracle on its own. The JS-readable reads that were checked and rejected:

- XPath `Value` uninitialized `m_bool`/`m_double` (`c4467fc5ae`): `toNumber()`/`toBoolean()`
  branch on `m_type` first and never read the uninitialized members; MSan-only.
- `[YARR]` surrogate fixes (`8c6275e144`, `7f53c2a455`): `readChecked()` returns
  `errorCodePoint`, so the failures are wrong match results, not out-of-bounds bytes.
- WebP/JPEG XL/AVIF frame-exceeds-canvas (`3f8ee96594`): `USE_AVIF OFF`, JPEG XL not built,
  and Sony's libwebp rejects the demuxed rect before `applyPostProcessing` runs.

Conclusion: closing the remaining gap needs either a leak primitive (none found) or a
second-stage primitive that does not require one.
