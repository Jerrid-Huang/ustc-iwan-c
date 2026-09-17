#!/usr/bin/env python3
"""Root-free regression suite for the relay's RFC1929 authentication loop.

Regression harness for R47-FIXA-I1 (the F0 / R47-FIXA-H1 fix at
relay_proxy.c rp_handle_socks: `pr > 0` -> `pr == 1`; the pre-fix code
treated the pr==2 verdict — a COMPLETE RFC1929 frame with a 64-byte
username — as a valid frame and evaluated the credentials with
UNINITIALIZED pass/plen, a crash/OOB that CI could not see because the
existing socks_handshake harness drives socks_flow (lwIP) and never the
relay's own auth loop).

Usage:
    python3 tests/relay_socks_harness.py [--harness PATH] [--token STR]

Each case runs the harness binary in a FRESH process (the relay's
peer-lockout table is file-static and must start clean per case):

  tokpr2    token mode: 5 x pr==2 frames, each answered {1,1} (counted),
            then the 6th connection from the same peer is dropped at
            accept() with no reply  -> pr==2 counts toward the lockout
            and the {1,1} wire contract holds (on pre-fix 434ef80 this
            same input crashes under ASan/UBSan).
  notokpr2  no-token (courtesy) mode: pr==2 answers {1,1}, no crash.
  pr0       token mode: 10 x malformed ulen=0 frames answered {1,1} but
            NOT counted (11th connection still served) -> R46-L4 split.

A case fails if the binary exits non-zero (crash, sanitizer report,
assertion) or prints RESULT ...: FAIL. Exits 0 iff all cases pass.
"""

import argparse
import os
import subprocess
import sys

# token passed to the tok-mode cases (the repo's other harnesses also
# default to --token seckey001)
DEFAULT_TOKEN = "seckey001"


def harness_path():
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    exe = "relay_socks_harness"
    if sys.platform.startswith("win"):
        exe += ".exe"
    return os.path.join(repo, "bin", exe)


def run_case(path, case, token, show_output):
    args = [path, "--case", case]
    if case != "notokpr2":
        args += ["--token", token]
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=90)
    except subprocess.TimeoutExpired:
        print(f"FAIL {case}: harness timed out (relay hung?)")
        return False
    out = proc.stdout
    err = proc.stderr
    ok = proc.returncode == 0 and (f"RESULT {case}: PASS" in out)
    if show_output:
        for line in out.splitlines():
            print(f"  {line}")
        for line in err.splitlines():
            print(f"  [stderr] {line}")
    # a sanitizer report or a crash shows the pr==2 crash even when the
    # harness died before printing a verdict
    if proc.returncode != 0:
        print(f"FAIL {case}: harness exit code {proc.returncode}")
        if "AddressSanitizer" in out + err or "runtime error:" in out + err:
            print("  -> sanitizer report above (the pre-fix pr==2 OOB/crash)")
        for line in (out + err).splitlines()[-12:]:
            print(f"  {line}")
    elif not ok:
        print(f"FAIL {case}: no PASS verdict in harness output")
    else:
        print(f"PASS {case}")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness", default=None,
                    help="path to relay_socks_harness binary "
                         "(default <repo>/bin/relay_socks_harness)")
    ap.add_argument("--token", default=DEFAULT_TOKEN,
                    help="relay auth token for the tokpr2/pr0 cases")
    ap.add_argument("--show-output", action="store_true",
                    help="print every harness PASS line")
    args = ap.parse_args()

    path = args.harness or harness_path()
    if not os.path.exists(path):
        print(f"FAIL: harness binary not found: {path} "
              f"(build with -DBUILD_TESTING=ON first)")
        return 1

    all_ok = True
    for case in ("tokpr2", "notokpr2", "pr0"):
        ok = run_case(path, case, args.token, args.show_output)
        all_ok = all_ok and ok
        if not ok:
            print(f"aborting after first failure ({case})")
            return 1

    print(f"RESULT: {'ALL PASS' if all_ok else 'FAILURES'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
