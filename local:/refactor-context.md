# Refactor context: iWAN C client (behavior-preserving split)

Repo: /home/uker/my/software/ustc-iwan-c
C11, cc -O2 -Wall -Wextra -Wno-unused-parameter -std=c11 -D_GNU_SOURCE.
Build: `make -B` (Makefile exists; objects -> build/, bins -> bin/).
ALREADY DONE (do not touch): common split into buffer.c/config.c/cli.c/addr.c; OIDC monolith split into src/oidc/; iwan_client.c rewritten with shared cli.

## Absolute rules
1. BEHAVIOR-PRESERVING ONLY. This is a shipped VPN client; the data plane cannot be tested here (no live server). Do NOT change control flow, state machines, timeouts, byte layouts, error messages, log lines, or default values. Extraction/moving code is allowed; rewrites of logic are NOT.
2. Keep the existing 4-space indent style. Braces: kernel-style opening brace on same line for functions is NOT required — the project mixes; KEEP the file's existing convention where you move code verbatim.
3. Every function you create must be SHORT (< ~60 lines), one job, with a one-line comment explaining it. Split monoliths into focused helpers.
4. No new global mutable state. Pass existing state via parameters or keep file-local statics where the original had them.
5. Preserve #include hygiene: each new .c includes what it uses; each new .h has an include guard IWAN_<NAME>_H.
6. DO NOT run formatters/linters. DO NOT run project-wide test suites. `make -B` must compile with zero new warnings; the ONLY pre-existing warning is `src/common/socks.c:232` -Wtype-limits — it was JUST FIXED, so it must be GONE (if you see it, your branch is stale).
7. Never touch: src/common/buffer.c, config.c, cli.c, cli.h, addr.c, addr.h, src/oidc/, src/iwan_client.c, src/iwan_client_oidc.c, Makefile.
8. After your edits, run `make -B` and verify it compiles clean; then run `./bin/iwan-client --help >/dev/null && ./bin/iwan-client-oidc -h >/dev/null` to confirm both binaries link and run.

## Acceptance for every agent
- Edits done, make -B clean, both binaries run.
- Report: files created/modified, function inventory before -> after (name: LOC), and a one-paragraph risk note.
