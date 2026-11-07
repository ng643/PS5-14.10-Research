## What this adds

The 14.10 User's Guide runs a WebKit built around Safari 17.0 (September 2023) inside a firmware shipped in 2026, so three years of upstream crash fixes are untested on it. WebKit's own layout tests reproduce those crashes, they are public, and each can be replayed on the console as a yes/no question.

**`tools/webkit_crash_corpus.py`** — three stages, commit metadata and public test files only, nothing executed:

| stage | what it does | why |
|---|---|---|
| `harvest` | commit search `crash repo:WebKit/WebKit committer-date:>2023-09-20`, keeping crash-shaped subjects and dropping resyncs/imports | finds the fixes that landed after the 17.0 branch point |
| `resolve` | one API call per commit for the files that commit *added* under `LayoutTests` | a test the fix commit added, not a path mentioned in passing by a WPT resync |
| `fetch` | downloads each test once, 160 KB cap | bounds the corpus |

534 crash commits resolved, 124 tests kept, 35 skipped for features p163 measured absent (JIT off, WebAssembly, `SharedArrayBuffer`, WebGL, WebAudio, IndexedDB, ServiceWorker, WebRTC, WebCodecs) — a test needing one of those cannot reach the bug it guards, so it would report a false pass.

**`probes/phase13_webkit/p166-corpus-runner.js`** — replays the corpus with per-case markers (`BEFORE`, `OK`, `ERR`, `STALL`, `GAP`, `CORPUS-DONE`) and a server-side resume point, so a run that dies at case *N* continues at *N*.

## Console results

| cases | result |
|---|---|
| 0–24 | 25/25 OK |
| 25–29 | 5/5 OK |
| 30 | died, six times, always `OK-30` then silence |

Case 30 is `fast/scrolling/mac/event-dispatcher-timer-close-crash.html` (2026-08-23, "Heap-use-after-free of RemoteLayerTreeEventDispatcher's RunLoop::Timer on the scrolling thread").

## Finding 5: a popup request kills the guide's WebProcess

The cause of the case-30 death is **not** the upstream use-after-free. The console kills the WebProcess on a popup request, and the popup blocker's refusal is only one of the fatal paths:

| run | context | markers | outcome |
|---|---|---|---|
| 08:12:10 | top-level `window.open`, real controller tap | `TAP` → `PRE-OPEN-1` → `POPUP-BLOCKED-1` | death ~65 ms after the refusal |
| 08:15:32 | top-level `window.open`, no tap (`?auto=1`) | `AUTO` → `PRE-OPEN-1` → `POPUP-BLOCKED-1` | death ~45 ms after the refusal |
| 08:20:28 | `window.open` inside a child frame | `IFRAME-POPUP-FRAME-LOADED` → `IFRAME-POPUP-REFUSED` | death, no later marker |
| 08:57:50 | `window.open` inside a `sandbox="allow-scripts"` frame | `SANDBOX-RESULT-BLOCKED` → `SANDBOX-ALIVE` → `NEXT-LINK` | survives; the sandbox refuses before the popup blocker |
| 08:57:51 | `<a target="_blank">` click | `LINK-START`, popup document `200` at +0.113 s, popup script `200` at +0.266 s, no child message | death, no later marker |
| 09:04:24 | the same link click, after a guide reload | `LINK-START`, popup document `200` at +0.097 s, no popup script, no child message | death, no later marker |

`p170-stage-ladder.js` walks the suspects in order of suspicion with a liveness marker per stage: a bare page, one child frame, a frame inside a frame and twenty frames created and removed in a row all survive (`BASE-ALIVE`, `IFRAME-ALIVE`, `NESTED-ALIVE`), while a refusal inside a frame is fatal. The gesture is irrelevant, so the trigger is the popup request itself.

`p171-popup-paths.js` then walks the request paths one variant at a time — `SANDBOX`, `LINK`, `STATIC`, `BLANK`, `SILENT`, `NOOPENER`, `EMPTY`, `FRAME`, `NAMED` — and the chain stops at the first death. The sandbox row is the control that keeps the result from reading as "the console dies when asked for a window": the frame refuses the request itself, the page beacons that refusal, stays alive and starts the next variant. The LINK rows show the popup blocker is not the trigger either — the click produced a real navigation request for the popup document, the server served it, and then the WebProcess stopped with the page's own 2.5 s timer never firing. That the popup really opened is read from the server's access log, not from the child: both LINK popups died with their opener, so neither the opener message nor a child marker arrived.

`STATIC` and `SILENT` closed the "it is the script" reading on the console. `STATIC` served a popup document that runs nothing at all (`200` at +0.168 s) and `SILENT` served the probe's `?child=2` mode, script but no opener message (`200` at +0.092 s, its script at +0.239 s); both died where LINK died, with no result timer. So neither the child's script nor the opener handshake is required, and the death follows the creation of a browsing context that loads something.

`BLANK` (`about:blank`) was fatal as well, and its popup needs no server at all, so there is no fetch to read: the page beacons `BLANK-START` and the 2.5 s result marker never arrives. A window that loads nothing kills exactly like one that serves a script-free document, so the death precedes the load. The trigger is the new-context request itself - the only popup request that survives is the sandbox one, which never reaches the popup blocker, while the blocker's own refusal is fatal (p169).

Consequence: the harvested case is not testable on this console. Its upstream fix needs a real popup window to arm the display-link observer, and the console either refuses the popup or kills the WebProcess shortly after the window is created, so the case never reaches the code it exercises either way. The runner therefore stubs `window.open` for the two cases that use it, and the stub announces itself with a `V166-POPUP-STUB` beacon, so an altered case is never counted as an unmodified pass.

**What is not established.** The mechanism inside WebKit is unknown: the guide browser has no inspector, and the failure does not reproduce in desktop Chromium 155, whose headless mode does not create the popup at all, so neither path is entered there. Whether the served popup ran in the same process, and whether it reached its script before the death, is not established — the 08:57 run fetched the popup's script and the 09:04 run did not, and neither returned a marker. As recorded this is a denial of service against the guide, not a controlled memory-safety primitive, and nothing here shows it is exploitable.

## Files

- `tools/webkit_crash_corpus.py` — harvester
- `probes/phase13_webkit/p166-corpus-runner.js` — corpus replay harness
- `probes/phase13_webkit/p167-popup-controls.js`, `p168-popup-depth.js` — popup/frame controls
- `probes/phase13_webkit/p169-tap-popup.js`, `p170-stage-ladder.js` — the two probes that isolate the trigger
- `probes/phase13_webkit/p171-popup-paths.js` — the popup request paths, one variant per page load
- `docs/WEBKIT_CORPUS.md` — pipeline, protocol, console results, limits
- `docs/WEBKIT_FINDINGS.md` — Finding 5
- `docs/CHANGELOG.md` — entry

The console harness (`tools/webkit_server.py`), the TLS material and the harvested third-party test files stay out of the repository; `.gitignore` now names them.

`python -m pytest tests -q` → 29 passed. `python -m unittest discover -s tools -p "test_*.py"` → 304 tests, OK.
