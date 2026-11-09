# Research state

Rewrite this block with `python tools/state.py set key=value`. It is the
only memory that survives a context compaction, so keep it current and
short. Volatile values (kernel base, console liveness) carry the time they
were measured; they are measurements, not truths.

<!-- STATE:BEGIN -->
- console: 192.168.1.121:9026 (a probe death kills the game; only the user can relaunch)
- kernel_base: 0xFFFFFFFFC1000000
- kernel_base_measured: 2026-11-09 10:05 UTC, image 0xFFFFFFFFC1000000-0xFFFFFFFFC6C00000 (unchanged across two game relaunches), stub 0xFFFFFFFFC0000000
- last_probe: 1343b
- active_question: ipv6 pktopts reclaim (IPV6_2292PKTOPTIONS free/use race) on 14.10
- next_action: publish the arg1/arg2/arg3 class pages and the run captures; then move active_question off pktopts (closed by IPV6_ANCILLARY_14_10.md)
- open_risks: 622 killers 0x201/0x202/0x232/0x241; 637 wedge; kernel base moves per boot
- notes: -
<!-- STATE:END -->

Session start: this block, then the last ten rows of `results/INDEX.md`,
then only the document section the active question names.
