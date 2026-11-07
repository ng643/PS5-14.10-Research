#!/usr/bin/env python3
"""Watch the beacon log for the p171 popup path chain.

Prints every V171 marker as it lands and exits when the chain is done, when
the console goes quiet for a while (it died), or after the time cap.
"""
import pathlib
import re
import sys
import time

LOGDIR = pathlib.Path(__file__).resolve().parent
DEADLINE = time.time() + float(sys.argv[1] if len(sys.argv) > 1 else 900)
QUIET = 60.0
MARK = re.compile(r"V171-[A-Za-z0-9]+-([A-Za-z0-9-]+)")


def newest_log():
    logs = sorted(LOGDIR.glob("server_*.log"))
    return logs[-1] if logs else None


def main():
    log = newest_log()
    if log is None:
        print("no log yet")
        return
    start_line = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    seen = set()
    last = time.time()
    while time.time() < DEADLINE:
        try:
            text = log.read_text(errors="replace")
        except OSError:
            text = ""
        lines = text.splitlines()[start_line:]
        for line in lines:
            m = MARK.search(line)
            if not m:
                continue
            tag = m.group(1)
            key = (tag, line)
            if key in seen:
                continue
            seen.add(key)
            print("MARK %s" % tag, flush=True)
            last = time.time()
            if tag == "ONLY-DONE-FRAME" or tag == "ALL-VARIANTS-DONE":
                print("CHAIN DONE", flush=True)
                return
        if seen and time.time() - last > QUIET:
            print("QUIET for %ds, the console stopped talking" % int(QUIET), flush=True)
            return
        time.sleep(1)
    print("TIME CAP", flush=True)


if __name__ == "__main__":
    main()
