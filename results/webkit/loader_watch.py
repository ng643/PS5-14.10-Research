"""Wait for the console's Lua loader to start listening, then run probe 80a."""
import os
import socket
import subprocess
import sys
import time

PS5 = os.environ.get("PS5_IP", "192.168.1.121")
PORT = int(os.environ.get("PS5_PORT", "9026"))
DEADLINE = time.time() + float(os.environ.get("WATCH_SECONDS", "1200"))
PROBE = "probes/phase17_new_vectors/80a_thr_create_cs43_threading.lua"


def is_up():
    s = socket.socket()
    s.settimeout(1.5)
    try:
        s.connect((PS5, PORT))
        return True
    except OSError:
        return False
    finally:
        s.close()


while time.time() < DEADLINE:
    if is_up():
        print("LOADER-UP %s:%d" % (PS5, PORT), flush=True)
        break
    time.sleep(5)
else:
    print("LOADER-NOT-UP", flush=True)
    sys.exit(2)

time.sleep(3)
env = dict(os.environ, PYTHONIOENCODING="utf-8")
cmd = [sys.executable, "tools/send_probe.py", PROBE,
       "--ip", PS5, "--port", str(PORT), "--save", "--metadata",
       "--total-timeout", "300"]
print("RUN %s" % " ".join(cmd), flush=True)
rc = subprocess.call(cmd, env=env)
print("SEND_PROBE-EXIT %d" % rc, flush=True)
