#!/usr/bin/env python3
"""Mirror the iWAN NT sources to the CI branch through the GitHub API.

The git transport to github.com is unreliable from this host (SSH pushes hang in
the middle of the pack transfer and HTTPS times out), while api.github.com is
reachable. So the branch is updated with the Git Data API instead: build a tree
with inline file contents on top of the current branch head, commit, move the
ref.

Usage: ci_push.py <mirror-root> [<path-prefix-in-repo>]

Only files under the mirror root are touched; nothing else in the branch moves.
"""
import json
import os
import subprocess
import sys

REPO = "Jerrid-Huang/ustc-iwan-c"
BRANCH = "ci/win-driver-build"


def call(method, path, payload=None):
    """One API call through gh.

    gh is used instead of urllib on purpose: Python's TLS stack dies with
    "UNEXPECTED_EOF_WHILE_READING" against api.github.com from this host, while
    gh (Go TLS) works on the same connection.
    """
    cmd = ["gh", "api", "-X", method, path]
    if payload is None:
        cmd.append("--jq")
        cmd.append(".")
        proc = subprocess.run(cmd, capture_output=True, text=True)
    else:
        cmd += ["--input", "-"]
        proc = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"gh api {method} {path} failed: {proc.stderr.strip()}")
    body = proc.stdout.strip()
    return json.loads(body) if body else {}


def main():
    root = os.path.abspath(sys.argv[1])
    prefix = (sys.argv[2] if len(sys.argv) > 2 else "iwan-nt").strip("/")

    head = call("GET", f"/repos/{REPO}/git/ref/heads/{BRANCH}")["object"]["sha"]
    base_tree = call("GET", f"/repos/{REPO}/git/commits/{head}")["tree"]["sha"]

    remote = call("GET", f"/repos/{REPO}/git/trees/{base_tree}?recursive=1")
    remote_paths = {e["path"] for e in remote["tree"] if e["type"] == "blob"}

    entries = []
    local_paths = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git" and d != "build"]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            repo_path = f"{prefix}/{rel}"
            local_paths.add(repo_path)
            with open(full, "rb") as handle:
                raw = handle.read()
            try:
                raw.decode("ascii")
            except UnicodeDecodeError:
                sys.exit(f"refusing to upload a non-ASCII file: {full}")
            entries.append({
                "path": repo_path,
                "mode": "100644",
                "type": "blob",
                "content": raw.decode("ascii"),
            })

    for stale in sorted(remote_paths):
        if stale.startswith(prefix + "/") and stale not in local_paths:
            entries.append({"path": stale, "mode": "100644", "type": "blob", "sha": None})

    tree = call("POST", f"/repos/{REPO}/git/trees",
                {"base_tree": base_tree, "tree": entries})
    message = sys.argv[3] if len(sys.argv) > 3 else "ci: sync iWAN NT sources"
    commit = call("POST", f"/repos/{REPO}/git/commits",
                  {"message": message, "tree": tree["sha"], "parents": [head]})
    call("PATCH", f"/repos/{REPO}/git/refs/heads/{BRANCH}",
         {"sha": commit["sha"], "force": False})
    print(f"{head[:7]} -> {commit['sha'][:7]} ({len(entries)} entries)")


if __name__ == "__main__":
    main()
