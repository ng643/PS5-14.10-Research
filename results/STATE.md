# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: 192.168.1.121:9026 (a probe death kills the game; only the user can relaunch)
- kernel_base: 0xFFFFFFFFCD000000
- kernel_base_measured: 2026-11-06 14:37 UTC, image 0xFFFFFFFFCD000000-0xFFFFFFFFD2C00000, stub 0xFFFFFFFFC0000000
- last_probe: 1340f
- active_question: ipv6 pktopts reclaim (IPV6_2292PKTOPTIONS free/use race) on 14.10
- next_action: read the 1339/1340 captures, then resume the kernel line
- open_risks: 622 killers 0x201/0x202/0x232/0x241; 637 wedge; kernel base moves per boot
- notes: -
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
